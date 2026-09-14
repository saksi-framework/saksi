package campaign

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// writeRealBallotStream writes n REAL protobuf ballots (each with a distinct
// 32-byte nullifier) plus the matching bundle. The resume path decodes every
// ballot's nullifier, so the crash/resume tests cannot use opaque hex the way
// the plain window tests do.
func writeRealBallotStream(t *testing.T, runDir string, n int) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < n; i++ {
		raw, err := proto.Marshal(&pb.Ballot{
			ElectionId: "run-1", PositionId: "president",
			CredentialPresentation: &pb.CredentialPresentation{
				Nullifier: &pb.Nullifier{Value: testNullifier(i)},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%s\n", hex.EncodeToString(raw))
	}
	if err := os.WriteFile(filepath.Join(runDir, BallotsFile), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return writeStreamBundle(t, runDir, n)
}

// testNullifier is ballot i's 32-byte nullifier: distinct, deterministic.
func testNullifier(i int) []byte {
	n := make([]byte, 32)
	binary.BigEndian.PutUint32(n[28:], uint32(i+1))
	return n
}

func testNullifierHex(i int) string { return hex.EncodeToString(testNullifier(i)) }

// sortedIndices returns set's keys in ascending order.
func sortedIndices(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for i := range set {
		out = append(out, i)
	}
	sort.Ints(out)
	return out
}

// rewriteReceiptsWithout drops index i's SubmitBallot row from receipts.csv,
// simulating a receipt lost to the crash for a ballot the chain did commit.
func rewriteReceiptsWithout(t *testing.T, runDir string, i int) {
	t.Helper()
	path := filepath.Join(runDir, "receipts.csv")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	drop := fmt.Sprintf("SubmitBallot,%d,", i)
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" && !strings.HasPrefix(line, drop) {
			kept = append(kept, line)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// appendOrphanReceipt appends a SubmitBallot receipt for an index the chain
// never committed.
func appendOrphanReceipt(t *testing.T, runDir string, i int) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(runDir, "receipts.csv"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "SubmitBallot,%d,tx-orphan,0,,,,\n", i); err != nil {
		t.Fatal(err)
	}
}

// latencyRows parses latencies.csv into index -> (segment, ok) for the rows of
// one segment.
func latencyRows(t *testing.T, runDir string, segment int) map[int]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(runDir, LatenciesCSV))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if got := strings.Count(string(data), "index,segment,ms,ok"); got != 1 {
		t.Fatalf("latencies.csv must have exactly 1 header, got %d", got)
	}
	out := map[int]string{}
	for _, line := range lines[1:] {
		cols := strings.Split(line, ",")
		if len(cols) != 4 {
			t.Fatalf("latencies.csv row %q has %d columns", line, len(cols))
		}
		seg, err := strconv.Atoi(cols[1])
		if err != nil {
			t.Fatalf("latencies.csv row %q: %v", line, err)
		}
		if seg != segment {
			continue
		}
		idx, err := strconv.Atoi(cols[0])
		if err != nil {
			t.Fatalf("latencies.csv row %q: %v", line, err)
		}
		out[idx] = cols[3]
	}
	return out
}

// journalEventsOfType returns every journal event with the given name.
func journalEventsOfType(t *testing.T, runDir, event string) []map[string]any {
	t.Helper()
	events, err := readJournalEvents(runDir)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	var out []map[string]any
	for _, ev := range events {
		if jstring(ev, "event") == event {
			out = append(out, ev)
		}
	}
	return out
}

// TestResumeAfterCrashSubmitsOnlyUncommittedBallots is the whole checkpoint /
// resume contract in one run: 1,000 ballots at concurrency 8, the ledger dies
// at ballot 500, and the resume re-drives ONLY what the chain does not already
// hold — proven against the fake's own accepted set, not against receipts.csv.
func TestResumeAfterCrashSubmitsOnlyUncommittedBallots(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeRealBallotStream(t, runDir, 1000)
	c := ElectionConfig{Mode: "onchain", Voters: 1000, Positions: 1, Candidates: 2, Concurrency: 8}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	led := &fakeLedger{blockSize: 10, FailAt: 500, RejectDuplicates: true, cancel: cancel}
	if err := e.submitOnChain(ctx, "run-1", c, led, path); err == nil {
		t.Fatal("want an error from the ledger failing at ballot 500")
	}
	led.FailAt = 0 // the "restart": the ledger is healthy again

	accepted := led.acceptedIndices()
	if len(accepted) == 0 || len(accepted) >= 1000 {
		t.Fatalf("fake accepted %d of 1000 ballots — want a partial window", len(accepted))
	}
	idx := sortedIndices(accepted)

	// A committed ballot whose receipt row was lost in the crash: it must be
	// skipped anyway (the chain, not receipts.csv, decides what is committed).
	receiptLess := idx[0]
	rewriteReceiptsWithout(t, runDir, receiptLess)
	// A receipt for an index the chain never committed: a finding, not a refusal.
	orphan := 999
	if accepted[orphan] {
		t.Fatalf("index %d was committed — pick an uncommitted index for the orphan receipt", orphan)
	}
	appendOrphanReceipt(t, runDir, orphan)
	// A committed ballot the chain snapshot does not list (a late commit racing
	// the snapshot): resubmitted, rejected as a double vote, recorded as replay.
	replayed := idx[len(idx)-1]
	led.hide(testNullifierHex(replayed))

	// negative-tests.csv must be untouched by the resume: chaincode rejections
	// in the ballot window are never negative-test results.
	negPath := filepath.Join(runDir, NegativeTestsFile)
	if err := os.WriteFile(negPath, []byte("scenario,result\nnone,pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	negBefore, err := os.ReadFile(negPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := e.resumeBallots(context.Background(), "run-1", c, led, led, path); err != nil {
		t.Fatalf("resume: %v", err)
	}

	// Every ballot is on chain exactly once.
	if got := len(led.acceptedIndices()); got != 1000 {
		t.Fatalf("chain holds %d ballots after the resume, want 1000", got)
	}

	// The resumed segment covers exactly the indices the chain snapshot lacked.
	rows := latencyRows(t, runDir, 1)
	want := map[int]bool{}
	for i := 0; i < 1000; i++ {
		if !accepted[i] || i == replayed {
			want[i] = true
		}
	}
	if len(rows) != len(want) {
		t.Fatalf("segment 1 has %d rows, want %d", len(rows), len(want))
	}
	for i := range want {
		if _, ok := rows[i]; !ok {
			t.Fatalf("index %d was not resubmitted", i)
		}
	}
	if _, ok := rows[receiptLess]; ok {
		t.Fatalf("index %d is committed on chain (receipt row lost) and must not be resubmitted", receiptLess)
	}
	if rows[replayed] != "replay" {
		t.Fatalf("index %d ok = %q, want replay", replayed, rows[replayed])
	}
	for i, ok := range rows {
		if i != replayed && ok != "commit" {
			t.Fatalf("index %d ok = %q, want commit", i, ok)
		}
	}

	// Every receipt the chain snapshot cannot account for is a finding: the
	// orphan row, and the replayed ballot whose late commit the snapshot missed.
	findings := map[int]bool{}
	for _, ev := range journalEventsOfType(t, runDir, "receipt_without_nullifier") {
		findings[jint(ev, "index")] = true
	}
	if len(findings) != 2 || !findings[orphan] || !findings[replayed] {
		t.Fatalf("receipt_without_nullifier findings = %v, want {%d, %d}", findings, orphan, replayed)
	}
	// One segment per window.
	if starts := journalEventsOfType(t, runDir, "segment.start"); len(starts) != 2 {
		t.Fatalf("want 2 segment.start events, got %d", len(starts))
	}
	if ia := journalEventsOfType(t, runDir, "interrupted_at"); len(ia) != 1 {
		t.Fatalf("want 1 interrupted_at event, got %d", len(ia))
	}
	// A resumed run is never a sustained-throughput measurement.
	ends := journalEventsOfType(t, runDir, "run.end")
	if len(ends) != 1 {
		t.Fatalf("want 1 run.end event, got %d", len(ends))
	}
	if ends[0]["sustained"] != false {
		t.Fatalf("run.end sustained = %v, want false", ends[0]["sustained"])
	}
	if got := jstring(ends[0], "scaling_limit"); got != "inconclusive" {
		t.Fatalf("run.end scaling_limit = %q, want inconclusive", got)
	}

	// receipts.csv keeps exactly one header across both windows.
	data, err := os.ReadFile(filepath.Join(runDir, "receipts.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), receiptsCSVHeader); got != 1 {
		t.Fatalf("receipts.csv has %d headers, want 1", got)
	}
	negAfter, err := os.ReadFile(negPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(negAfter) != string(negBefore) {
		t.Fatalf("negative-tests.csv changed:\n%s", negAfter)
	}
}

// TestCommittedSetIsTheChainSet: the committed set is ListNullifiers ∩ the
// bundle, by ballot index — receipts.csv has no say in it.
func TestCommittedSetIsTheChainSet(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeRealBallotStream(t, runDir, 40)
	c := ElectionConfig{Mode: "onchain", Concurrency: 4}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	led := &fakeLedger{FailAt: 20, cancel: cancel}
	if err := e.submitOnChain(ctx, "run-1", c, led, path); err == nil {
		t.Fatal("want an error from the ledger failing at ballot 20")
	}

	b, err := loadBundle(path)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := committedByIndex(runDir, b, led)
	if err != nil {
		t.Fatalf("committedByIndex: %v", err)
	}
	accepted := led.acceptedIndices()
	for i, ok := range committed {
		if ok != accepted[i] {
			t.Fatalf("index %d: committed=%v, chain accepted=%v", i, ok, accepted[i])
		}
	}
}

// crashedRun writes an n-ballot on-chain run and drives its window until the
// ledger dies at ballot fail, leaving exactly the interrupted state a resume
// starts from. The returned ledger is healthy again.
func crashedRun(t *testing.T, n, fail int) (*Executor, *fakeLedger, ElectionConfig, string, string) {
	t.Helper()
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeRealBallotStream(t, runDir, n)
	c := ElectionConfig{Mode: "onchain", Voters: n, Positions: 1, Candidates: 2, Concurrency: 4}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	led := &fakeLedger{FailAt: fail, cancel: cancel}
	if err := e.submitOnChain(ctx, "run-1", c, led, path); err == nil {
		t.Fatalf("want an error from the ledger failing at ballot %d", fail)
	}
	led.FailAt = 0
	return e, led, c, runDir, path
}

// TestResumeTagsCommittedFailuresAsReplay: a submission can fail and still
// have landed — an MVCC conflict or a lost connection costs us the commit
// status, not the ballot. The classification must come from the chain, not
// from the error text, so a generic "did not validate" for a ballot the chain
// holds is a replay, not a drop.
func TestResumeTagsCommittedFailuresAsReplay(t *testing.T) {
	e, led, c, runDir, path := crashedRun(t, 40, 20)
	stranded := 39 // never reached before the crash, so the resume submits it
	if led.acceptedIndices()[stranded] {
		t.Fatalf("index %d committed before the crash", stranded)
	}
	led.acceptButFail(testNullifierHex(stranded))

	if err := e.resumeBallots(context.Background(), "run-1", c, led, led, path); err != nil {
		t.Fatalf("a committed-but-failed ballot must not fail the resume: %v", err)
	}
	if got := latencyRows(t, runDir, 1)[stranded]; got != "replay" {
		t.Fatalf("index %d ok = %q, want replay", stranded, got)
	}
	ends := journalEventsOfType(t, runDir, "stage.ballots.end")
	if len(ends) == 0 || jint(ends[len(ends)-1], "dropped") != 0 {
		t.Fatalf("resumed window must report 0 dropped, got %v", ends)
	}
	if runEnd := journalEventsOfType(t, runDir, "run.end"); runEnd[0]["failed"] != false {
		t.Fatalf("run.end failed = %v, want false", runEnd[0]["failed"])
	}
}

// TestResumeFailsOnAGenuineDrop: a ballot that fails AND is absent from the
// chain is a lost vote. It stays a drop, and the resume says so.
func TestResumeFailsOnAGenuineDrop(t *testing.T) {
	e, led, c, runDir, path := crashedRun(t, 40, 20)
	lost := 39
	led.rejectBallot(testNullifierHex(lost))

	err := e.resumeBallots(context.Background(), "run-1", c, led, led, path)
	if err == nil {
		t.Fatal("want an error: a ballot that never landed is a drop")
	}
	if !strings.Contains(err.Error(), "did not commit") {
		t.Fatalf("error = %v, want it to name the uncommitted ballots", err)
	}
	if got := latencyRows(t, runDir, 1)[lost]; got != "drop" {
		t.Fatalf("index %d ok = %q, want drop", lost, got)
	}
	// Stamped interrupted, not ended: a ballot that still did not land leaves
	// the window open for the next resume.
	ends := journalEventsOfType(t, runDir, "stage.ballots.interrupted")
	if len(ends) == 0 || jint(ends[len(ends)-1], "dropped") != 1 || jint(ends[len(ends)-1], "segment") != 1 {
		t.Fatalf("resumed window must report 1 dropped, got %v", ends)
	}
}

// A resume whose ballots really drop must not strand the run: it stays
// resumable, and the next resume commits what is left and closes.
func TestALossyResumeStaysResumable(t *testing.T) {
	e, led, c, runDir, path := crashedRun(t, 40, 20)
	lost := testNullifierHex(39)
	led.rejectBallot(lost)
	if err := e.resumeAndClose(context.Background(), "run-1", c, led, led, path); err == nil ||
		!strings.Contains(err.Error(), "did not commit") {
		t.Fatalf("first resume: %v, want the dropped ballot named", err)
	}
	plan, err := planResume(runDir, c)
	if err != nil || plan.CloseOnly || plan.Segment != 2 {
		t.Fatalf("after a lossy resume: plan %+v err %v, want an open window for segment 2", plan, err)
	}
	led.mu.Lock()
	delete(led.reject, lost)
	led.mu.Unlock()
	if err := e.resumeAndClose(context.Background(), "run-1", c, led, led, path); err != nil {
		t.Fatalf("second resume: %v", err)
	}
	if got := len(led.acceptedIndices()); got != 40 {
		t.Fatalf("chain holds %d, want 40", got)
	}
	if names := led.callNames(); names[len(names)-1] != "CloseElection" {
		t.Fatalf("the second resume must close, calls end %v", names[len(names)-2:])
	}
	if _, err := os.Stat(filepath.Join(runDir, CeremonyFile)); err != nil {
		t.Fatalf("the ceremony must be open: %v", err)
	}
}

// TestResumeProceedsThroughTruncatedReceipts: receipts.csv is the file most
// likely to be mid-write when the process died. A torn last row is a warning
// on the journal, never a refusal — the chain, not this file, decides what is
// committed.
func TestResumeProceedsThroughTruncatedReceipts(t *testing.T) {
	e, led, c, runDir, path := crashedRun(t, 40, 20)
	receipts := filepath.Join(runDir, "receipts.csv")
	data, err := os.ReadFile(receipts)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receipts, data[:len(data)-10], 0o644); err != nil {
		t.Fatal(err)
	}

	if err := e.resumeBallots(context.Background(), "run-1", c, led, led, path); err != nil {
		t.Fatalf("a truncated receipts.csv must not refuse the resume: %v", err)
	}
	if warn := journalEventsOfType(t, runDir, "receipts_truncated"); len(warn) != 1 {
		t.Fatalf("want one receipts_truncated warning, got %d", len(warn))
	}
	if got := len(led.acceptedIndices()); got != 40 {
		t.Fatalf("chain holds %d ballots after the resume, want 40", got)
	}
}

// TestVerifyAfterResumeJudgesTheWholeRun: the interrupted first window is not
// the run. Once the resume has committed the rest, Verify's perf row must
// report the whole election as landed — and still refuse to call it a
// sustained-throughput measurement, because it took two windows.
func TestVerifyAfterResumeJudgesTheWholeRun(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeRealBallotStream(t, runDir, 40)
	c := ElectionConfig{Mode: "onchain", Voters: 40, Positions: 1, Candidates: 2, Concurrency: 4}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	led := &fakeLedger{FailAt: 20, cancel: cancel}
	if err := e.submitOnChain(ctx, "run-1", c, led, path); err == nil {
		t.Fatal("want an error from the ledger failing at ballot 20")
	}
	led.FailAt = 0
	if err := e.resumeBallots(context.Background(), "run-1", c, led, led, path); err != nil {
		t.Fatalf("resume: %v", err)
	}

	e.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(auditJSON), nil
	}
	if _, err := e.Verify(context.Background(), "run-1", c); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	cells := perfCells(t, runDir)
	if cells["committed"] != "40" || cells["dropped"] != "0" || cells["failed"] != "false" {
		t.Fatalf("committed/dropped/failed = %q/%q/%q, want 40/0/false",
			cells["committed"], cells["dropped"], cells["failed"])
	}
	if cells["sustained_tps"] != "" {
		t.Fatalf("sustained_tps = %q: a resumed run is not a sustained measurement", cells["sustained_tps"])
	}
	if cells["scaling_limit"] != "inconclusive" {
		t.Fatalf("scaling_limit = %q, want inconclusive", cells["scaling_limit"])
	}
}

// TestResumeAPIRefusesRunsItCannotResume: only an on-chain run with an
// interrupted ballot window may be resumed; everything else is a 409 with a
// reason, never a silently-started second window.
func TestResumeAPIRefusesRunsItCannotResume(t *testing.T) {
	dir := t.TempDir()
	store := NewRunStore(dir)
	c := good()
	c.Mode = "offline"
	runID, _, err := store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, NewExecutor(store, NewHub(), "saksi-demo", "", FabricConfig{}),
		NewHub(), FabricConfig{}, nil, time.Minute)

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/runs/"+runID+"/resume", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("offline run resume = %d, want 409 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "on-chain") {
		t.Fatalf("409 body must say why: %q", rec.Body.String())
	}
}

// TestResumeRefusesAClosedWindow: a run whose ballot window ended normally has
// nothing to resume.
func TestResumeRefusesAClosedWindow(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeRealBallotStream(t, runDir, 10)
	c := ElectionConfig{Mode: "onchain", Concurrency: 2}
	led := &fakeLedger{}
	if err := e.submitOnChain(context.Background(), "run-1", c, led, path); err != nil {
		t.Fatal(err)
	}
	if _, err := planResume(runDir, c); err == nil {
		t.Fatal("want a refusal for a run whose ballot window completed")
	}
	if err := e.resumeBallots(context.Background(), "run-1", c, led, led, path); err == nil {
		t.Fatal("resumeBallots must refuse a completed window")
	}
}

// TestBallotReaderDropsUnwantedLines: the resume reader must not park the
// lines it will never be asked for — at the capstone that would hold the whole
// committed population in memory.
func TestBallotReaderDropsUnwantedLines(t *testing.T) {
	dir := t.TempDir()
	writeBallotLinesFile(t, dir, 100)
	r, err := openBallotReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.wanted = func(i int) bool { return i%10 == 0 }

	for i := 0; i < 100; i += 10 {
		if _, err := r.At(i); err != nil {
			t.Fatalf("At(%d): %v", i, err)
		}
	}
	if len(r.ahead) != 0 {
		t.Fatalf("reader parked %d unwanted lines, want 0", len(r.ahead))
	}
}

// TestResumeAfterAHardKillIsNotSustained is the hard-kill case: the console
// died INSIDE the ballot window, so the journal carries stage.ballots.start and
// ballots.progress and no segment.end at all. The interrupted window therefore
// leaves no segment on record, and without care the resume finalises as the
// run's only segment — one segment, not interrupted, so "sustained", with the
// remainder's TPS published as the whole run's.
//
// A resumed run is sustained:false and has no whole-run TPS, whatever the
// journal survived.
func TestResumeAfterAHardKillIsNotSustained(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeRealBallotStream(t, runDir, 40)
	c := ElectionConfig{Mode: "onchain", Voters: 40, Positions: 1, Candidates: 2, Concurrency: 4}

	// The journal a kill -9 mid-window leaves behind: the window opened, 20
	// ballots were checkpointed, nothing closed it.
	writeJournalLines(t, runDir,
		`{"event":"stage.ballots.start","n":40,"concurrency":4,"segment":0}`,
		`{"event":"ballots.progress","done":20,"segment":0}`,
	)
	// The chain holds those 20.
	led := &fakeLedger{Ballots: map[string]string{}}
	for i := 0; i < 20; i++ {
		led.accept(testNullifierHex(i))
	}

	// The killed window is on the segment list even though it stamped no
	// segment.end: it ran, it just measured nothing.
	plan, err := planResume(runDir, c)
	if err != nil {
		t.Fatalf("planResume: %v", err)
	}
	if len(plan.segments) != 1 || plan.segments[0].Index != 0 || plan.segments[0].WindowMs != 0 ||
		plan.segments[0].TPS != 0 {
		t.Fatalf("segments = %+v, want one placeholder segment 0 with no window and no TPS", plan.segments)
	}

	if err := e.resumeBallots(context.Background(), "run-1", c, led, led, path); err != nil {
		t.Fatalf("resume: %v", err)
	}

	end := readRunEnd(t, runDir)
	if end["sustained"] != false {
		t.Fatalf("run.end sustained = %v, want false: the resume is one of two windows", end["sustained"])
	}
	if end["sustained_tps"] != nil {
		t.Fatalf("run.end sustained_tps = %v, want no figure: it would be the remainder's, not the run's",
			end["sustained_tps"])
	}
	if end["scaling_limit"] != "inconclusive" {
		t.Fatalf("run.end scaling_limit = %v, want \"inconclusive\"", end["scaling_limit"])
	}
	if end["resumed"] != true {
		t.Fatalf("run.end resumed = %v, want true: that is why there is no whole-run figure", end["resumed"])
	}
	// Two windows are on record: the killed one and the resume's.
	if segs, resumed := segmentsFromJournal(runDir); !resumed {
		t.Fatalf("segmentsFromJournal did not see the resume (segments %+v)", segs)
	}

	// And Verify, which writes the run's LAST run.end, must not undo it.
	e.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(auditJSON), nil
	}
	if _, err := e.Verify(context.Background(), "run-1", c); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	end = readRunEnd(t, runDir)
	if end["sustained"] != false || end["sustained_tps"] != nil ||
		end["scaling_limit"] != "inconclusive" || end["resumed"] != true {
		t.Fatalf("Verify overwrote the resumed verdict: %v", end)
	}
	if cells := perfCells(t, runDir); cells["sustained_tps"] != "" {
		t.Fatalf("perf.csv sustained_tps = %q, want empty", cells["sustained_tps"])
	}
}

// writeJournalLines seeds a run's journal.ndjson with hand-written events, for
// the crash shapes a live run cannot be made to produce.
func writeJournalLines(t *testing.T, runDir string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(runDir, JournalFile),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A resume that can only fail is refused before anything is dispatched: no
// Fabric (400), no bundle (409), nothing to resume (409).
func TestResumeAPIRefusesBeforeDispatch(t *testing.T) {
	interrupted := func(t *testing.T, s *Server, bundle bool) string {
		t.Helper()
		runID, dir, err := s.store.Create(onchainConfig(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		writeJournalLines(t, dir, `{"event":"stage.ballots.start","n":100}`,
			`{"event":"stage.ballots.interrupted","committed":50,"dropped":50}`)
		if bundle {
			writeRealBallotStream(t, dir, 100)
		}
		return runID
	}
	post := func(s *Server, runID string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/runs/"+runID+"/resume", nil))
		return rec
	}

	off, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	if rec := post(off, interrupted(t, off, true)); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Fabric") {
		t.Fatalf("no Fabric: want 400, got %d %s", rec.Code, rec.Body)
	}

	on, _ := gateServer(t, enabledFabric(), "abc", 1<<62)
	if rec := post(on, interrupted(t, on, false)); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "read bundle") {
		t.Fatalf("no bundle: want 409, got %d %s", rec.Code, rec.Body)
	}
	ended, dir, err := on.store.Create(onchainConfig(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeJournalLines(t, dir, `{"event":"stage.ballots.start","n":100}`, `{"event":"stage.ballots.end","dropped":0}`)
	writeRealBallotStream(t, dir, 100)
	if rec := post(on, ended); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "nothing to resume") {
		t.Fatalf("nothing to resume: want 409, got %d %s", rec.Code, rec.Body)
	}
	for _, s := range []*Server{off, on} {
		s.mu.Lock()
		busy := len(s.busy)
		s.mu.Unlock()
		if busy != 0 {
			t.Fatal("a refused resume must not claim the run")
		}
	}
}
