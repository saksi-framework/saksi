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
