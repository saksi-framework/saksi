package campaign

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// ballotHexFor builds the hex-encoded Ballot the fake chain serves for one
// nullifier. Only the nullifier is load-bearing here: the ledger cross-check
// digests the nullifier set, and the aggregate ciphertexts come from the
// audit's own output, never from these bytes.
func ballotHexFor(t *testing.T, nullifier []byte) string {
	t.Helper()
	raw, err := proto.Marshal(&pb.Ballot{
		ElectionId: "test", PositionId: "president",
		CredentialPresentation: &pb.CredentialPresentation{
			Nullifier: &pb.Nullifier{Value: nullifier},
		},
	})
	if err != nil {
		t.Fatalf("marshal ballot: %v", err)
	}
	return hex.EncodeToString(raw)
}

// paramsHexFor is a hex ElectionParameters with one contest and one trustee,
// so the ledger header's partial-decryption walk has something to ask for.
func paramsHexFor(t *testing.T, electionID string) string {
	t.Helper()
	raw, err := proto.Marshal(&pb.ElectionParameters{
		Version: 1, ElectionId: electionID,
		ContestIds: []string{"president/cand0"}, TrusteeIds: []string{"t0"}, Threshold: 1,
	})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	return hex.EncodeToString(raw)
}

// newLedgerRun builds an offline-shaped run folder holding n real ballots plus
// a header, and a fakeLedger whose accepted set and Ballots map hold exactly
// the same ballots. That is the "chain agrees with the console" baseline every
// test below perturbs.
func newLedgerRun(t *testing.T, n int) (*Executor, string, string, *fakeLedger) {
	t.Helper()
	e, runID, dir := newRun(t, "onchain")
	writeFakeStream(t, dir, n)

	led := &fakeLedger{Ballots: map[string]string{}}
	led.Params = paramsHexFor(t, runID)
	led.DKG = "bb"
	led.Tally = "tt"
	led.Partials = map[string]string{"president/cand0|t0": "p0"}
	for i := 0; i < n; i++ {
		nul := hex.EncodeToString([]byte{byte(i + 1)}) // writeFakeStream's nullifier for index i
		led.accept(nul)
		led.Ballots[nul] = ballotHexFor(t, []byte{byte(i + 1)})
	}
	return e, runID, dir, led
}

// passingAudit is a fake Runner standing in for `saksi-demo audit-stream`: the
// same clean two-contest verdict for whichever directory it is pointed at, so
// the local and ledger audits agree unless a test makes them disagree.
func passingAudit(agg string) Runner {
	return func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if agg == "" {
			agg = "aggaggagg"
		}
		return []byte(`{"overall":"pass","contests":[
			{"contest":"president/cand0","ground_truth":3,"decoded":3,"E":0,"pass":true,"aggregate_ciphertext":"` + agg + `"},
			{"contest":"president/cand1","ground_truth":3,"decoded":3,"E":0,"pass":true,"aggregate_ciphertext":"` + agg + `"}]}`), nil
	}
}

// readRunEnd returns the run.end event the run recorded, or fails the test.
func readRunEnd(t *testing.T, dir string) map[string]any {
	t.Helper()
	events, err := readJournalEvents(dir)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	for i := len(events) - 1; i >= 0; i-- {
		if jstring(events[i], "event") == "run.end" {
			return events[i]
		}
	}
	t.Fatalf("no run.end in the journal: %v", events)
	return nil
}

// TestLedgerAuditFlagsAMutatedBallot is the point of the whole cross-check: the
// chain serves a ballot the console never wrote, so the two nullifier sets
// differ and the run records ledger_matches_local=false — a finding, not an
// error.
func TestLedgerAuditFlagsAMutatedBallot(t *testing.T) {
	e, runID, dir, led := newLedgerRun(t, 3)
	e.run = passingAudit("")
	// The chain's copy of ballot 1 carries a different nullifier.
	led.Ballots[hex.EncodeToString([]byte{2})] = ballotHexFor(t, []byte{0xEE})

	sa, err := e.verify(context.Background(), runID, good(), led)
	if err != nil {
		t.Fatalf("a ledger mismatch is a finding, not an error: %v", err)
	}
	if sa.Overall != "pass" {
		t.Fatalf("the local audit still stands: %+v", sa)
	}
	if got := readRunEnd(t, dir)["ledger_matches_local"]; got != false {
		t.Fatalf("run.end ledger_matches_local = %v, want false", got)
	}
	csvData, err := os.ReadFile(filepath.Join(dir, CorrectnessFile))
	if err != nil {
		t.Fatalf("correctness.csv: %v", err)
	}
	if !strings.Contains(string(csvData), ",ledger,false") {
		t.Fatalf("correctness.csv has no failing ledger row:\n%s", csvData)
	}
}

// TestLedgerAuditAgreesWithTheConsole is the same run with the chain serving
// exactly what the console wrote.
func TestLedgerAuditAgreesWithTheConsole(t *testing.T) {
	e, runID, dir, led := newLedgerRun(t, 3)
	e.run = passingAudit("")

	if _, err := e.verify(context.Background(), runID, good(), led); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := readRunEnd(t, dir)["ledger_matches_local"]; got != true {
		t.Fatalf("run.end ledger_matches_local = %v, want true", got)
	}
	// Both directories are audited, and every row says which one it came from.
	csvData, err := os.ReadFile(filepath.Join(dir, CorrectnessFile))
	if err != nil {
		t.Fatalf("correctness.csv: %v", err)
	}
	got := string(csvData)
	if !strings.HasSuffix(strings.SplitN(got, "\n", 2)[0], ",source,ledger_matches_local") {
		t.Fatalf("correctness.csv header is missing the new columns:\n%s", got)
	}
	if strings.Count(got, ",local,true") != 2 || strings.Count(got, ",ledger,true") != 2 {
		t.Fatalf("want 2 local + 2 ledger rows:\n%s", got)
	}
	// The dump landed where audit-stream can read it.
	for _, f := range []string{"header.json", BallotsFile} {
		if _, err := os.Stat(filepath.Join(dir, LedgerDir, f)); err != nil {
			t.Fatalf("ledger/%s not written: %v", f, err)
		}
	}
}

// TestLedgerAuditFlagsADivergentTally covers the other half of the comparison:
// the same ballots, but the chain's own audit recovers a different aggregate
// ciphertext than the console's.
func TestLedgerAuditFlagsADivergentTally(t *testing.T) {
	e, runID, dir, led := newLedgerRun(t, 3)
	e.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		agg := "aaaa"
		if strings.HasSuffix(args[1], LedgerDir) {
			agg = "bbbb"
		}
		return passingAudit(agg)(context.Background(), name, args...)
	}

	if _, err := e.verify(context.Background(), runID, good(), led); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := readRunEnd(t, dir)["ledger_matches_local"]; got != false {
		t.Fatalf("run.end ledger_matches_local = %v, want false", got)
	}
}

// TestLedgerDumpAbortsOnGetBallotFailure: a chain that stops serving ballots
// mid-dump leaves the run with a local audit and an honest "not run" stamp —
// and proves the dump is streamed, since it stops after the failing fetch
// instead of having pulled every ballot first.
func TestLedgerDumpAbortsOnGetBallotFailure(t *testing.T) {
	e, runID, dir, led := newLedgerRun(t, 5)
	e.run = passingAudit("")
	led.FailGetBallotAt = 3

	sa, err := e.verify(context.Background(), runID, good(), led)
	if err != nil {
		t.Fatalf("a failed dump must not fail Verify: %v", err)
	}
	if sa.Overall != "pass" {
		t.Fatalf("the local audit must still run: %+v", sa)
	}
	end := readRunEnd(t, dir)
	if end["ledger_audit"] != "not run" {
		t.Fatalf("run.end ledger_audit = %v, want \"not run\"", end["ledger_audit"])
	}
	if _, ok := end["ledger_matches_local"]; ok {
		t.Fatalf("no comparison was possible, so none may be claimed: %v", end)
	}
	if n := led.getBallotCalls(); n != 3 {
		t.Fatalf("GetBallot called %d times, want 3 — the dump must stop at the failure, not batch every ballot", n)
	}
	// "not run" has to mean nothing is there: a prefix of the chain's ballots
	// left on disk is an artifact that would audit, and lie.
	if _, err := os.Stat(filepath.Join(dir, LedgerDir)); !os.IsNotExist(err) {
		t.Fatalf("the aborted dump must leave no ledger directory behind: %v", err)
	}
	// correctness.csv falls back to local-only rows with an empty verdict.
	csvData, err := os.ReadFile(filepath.Join(dir, CorrectnessFile))
	if err != nil {
		t.Fatalf("correctness.csv: %v", err)
	}
	if strings.Contains(string(csvData), ",ledger,") {
		t.Fatalf("no ledger rows may be written when the dump failed:\n%s", csvData)
	}
	if !strings.Contains(string(csvData), ",local,\n") {
		t.Fatalf("local rows must carry an empty ledger verdict:\n%s", csvData)
	}
}

// TestLedgerDumpStreamsOneBallotAtATime pins the streaming contract from the
// other side: one GetBallot per listed nullifier, in listing order, and the
// dumped file is written in that same order.
func TestLedgerDumpStreamsOneBallotAtATime(t *testing.T) {
	e, runID, dir, led := newLedgerRun(t, 4)
	e.run = passingAudit("")

	if _, err := e.verify(context.Background(), runID, good(), led); err != nil {
		t.Fatalf("verify: %v", err)
	}
	page, err := led.ListNullifiers(runID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := led.getBallotOrder(); len(got) != len(page.Nullifiers) {
		t.Fatalf("GetBallot calls = %d, want one per nullifier (%d)", len(got), len(page.Nullifiers))
	}
	for i, nul := range page.Nullifiers {
		if led.getBallotOrder()[i] != nul {
			t.Fatalf("GetBallot %d asked for %q, want the listed order %q", i, led.getBallotOrder()[i], nul)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, LedgerDir, BallotsFile))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i, nul := range page.Nullifiers {
		if lines[i] != led.Ballots[nul] {
			t.Fatalf("ledger ballot line %d is not the ballot the chain served for %q", i, nul)
		}
	}
}

// TestVerifyOfflineWritesNoLedgerRows: without a chain there is nothing to
// cross-check, so correctness.csv keeps its local rows and run.end says
// nothing about a ledger audit.
func TestVerifyOfflineWritesNoLedgerRows(t *testing.T) {
	e, runID, dir := newRun(t, "offline")
	writeFakeStream(t, dir, 2)
	e.run = passingAudit("")

	if _, err := e.Verify(context.Background(), runID, good()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, LedgerDir)); !os.IsNotExist(err) {
		t.Fatalf("an offline run must not write a ledger dump: %v", err)
	}
	if got, ok := readRunEnd(t, dir)["ledger_audit"]; ok {
		t.Fatalf("run.end ledger_audit = %v, want absent offline", got)
	}
}

// TestNullifierSetDigestIgnoresOrder is the property the whole comparison rests
// on: the chain hands its ballots back in its own order, so the digest of the
// same set must not depend on the order the lines were written in — and must
// still change the moment one of the nullifiers does.
func TestNullifierSetDigestIgnoresOrder(t *testing.T) {
	writeSet := func(nullifiers ...[]byte) string {
		dir := t.TempDir()
		var lines []string
		for _, n := range nullifiers {
			lines = append(lines, ballotHexFor(t, n))
		}
		if err := os.WriteFile(filepath.Join(dir, BallotsFile),
			[]byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	digest := func(dir string) string {
		d, err := nullifierSetDigest(dir)
		if err != nil {
			t.Fatalf("nullifierSetDigest: %v", err)
		}
		return d
	}
	a, b, c := []byte{1}, []byte{2}, []byte{3}
	forward := digest(writeSet(a, b, c))
	if got := digest(writeSet(c, a, b)); got != forward {
		t.Fatalf("a reordered set digested differently:\n %s\n %s", forward, got)
	}
	if got := digest(writeSet(c, b, a)); got != forward {
		t.Fatalf("a reversed set digested differently:\n %s\n %s", forward, got)
	}
	if got := digest(writeSet(a, b, []byte{4})); got == forward {
		t.Fatal("changing a nullifier must change the digest")
	}
	// The count is folded in, so a strict subset can never collide either.
	if got := digest(writeSet(a, b)); got == forward {
		t.Fatal("dropping a nullifier must change the digest")
	}
}

// TestLedgerDumpRejectsUndecodableChainParams: without decodable on-chain
// parameters there is no list of (contest, trustee) pairs to ask for, so a
// header claiming the election published no partial decryptions would be a
// fabrication. The dump fails instead, and the run says so.
func TestLedgerDumpRejectsUndecodableChainParams(t *testing.T) {
	e, runID, dir, led := newLedgerRun(t, 2)
	e.run = passingAudit("")
	led.Params = "not-hex"

	if _, err := e.verify(context.Background(), runID, good(), led); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := readRunEnd(t, dir)["ledger_audit"]; got != "not run" {
		t.Fatalf("run.end ledger_audit = %v, want \"not run\"", got)
	}
	if _, err := os.Stat(filepath.Join(dir, LedgerDir)); !os.IsNotExist(err) {
		t.Fatalf("the aborted dump must leave no ledger directory behind: %v", err)
	}
}

// TestLedgerHeaderIsAcceptedByAuditStream is the cross-language half, and the
// only test that proves the ledger dump is a real stream directory: generate an
// actual election with the real binary, serve those exact ballots and artifacts
// from a fake chain, dump them back out, and audit the DUMP with the real
// auditor. It must reach the same clean verdict the generated directory does —
// which it can only do if header.json's field set, the on-chain partial
// decryptions and the n-count all survived the round trip.
//
// Skipped unless saksi-demo is on PATH (CI's path; a dev box without the Rust
// build still runs everything else).
func TestLedgerHeaderIsAcceptedByAuditStream(t *testing.T) {
	bin, err := exec.LookPath("saksi-demo")
	if err != nil {
		t.Skip("saksi-demo not on PATH")
	}
	ctx := context.Background()
	dir := t.TempDir()
	const electionID = "ledger-audit-test"
	if _, err := execRunner(ctx, bin, "gen", "--stream", dir,
		"--voters", "2", "--positions", "1", "--candidates", "2",
		"--trustees", "3", "--threshold", "2", "--election-id", electionID,
		"--election-name", "Ledger Audit Test", "--distribution", "uniform"); err != nil {
		t.Fatalf("saksi-demo gen: %v", err)
	}

	var h struct {
		Params             string   `json:"params"`
		Dkg                string   `json:"dkg"`
		Tally              string   `json:"tally"`
		PartialDecryptions []string `json:"partial_decryptions"`
	}
	if err := readJSON(filepath.Join(dir, headerFile), &h); err != nil {
		t.Fatalf("read generated header: %v", err)
	}
	led := &fakeLedger{
		Ballots:  map[string]string{},
		Params:   h.Params,
		DKG:      h.Dkg,
		Tally:    h.Tally,
		Partials: map[string]string{},
	}
	for _, pdHex := range h.PartialDecryptions {
		raw, derr := hex.DecodeString(pdHex)
		if derr != nil {
			t.Fatalf("partial decryption is not hex: %v", derr)
		}
		var pd pb.PartialDecryption
		if err := proto.Unmarshal(raw, &pd); err != nil {
			t.Fatalf("decode partial decryption: %v", err)
		}
		led.Partials[pd.GetContestId()+"|"+pd.GetTrusteeId()] = pdHex
	}
	if err := scanBallotLines(dir, func(i int, line string) error {
		raw, derr := hex.DecodeString(line)
		if derr != nil {
			return derr
		}
		var b pb.Ballot
		if err := proto.Unmarshal(raw, &b); err != nil {
			return err
		}
		nul := hex.EncodeToString(b.GetCredentialPresentation().GetNullifier().GetValue())
		led.accept(nul)
		led.Ballots[nul] = line
		return nil
	}); err != nil {
		t.Fatalf("read generated ballots: %v", err)
	}

	if _, err := dumpLedger(dir, electionID, led); err != nil {
		t.Fatalf("dumpLedger: %v", err)
	}
	out, runErr := execRunner(ctx, bin, "audit-stream", filepath.Join(dir, LedgerDir), "--json")
	var sa StreamAudit
	if err := json.Unmarshal(out, &sa); err != nil {
		t.Fatalf("audit-stream rejected the ledger dump: %v (stdout: %s)", runErr, out)
	}
	if sa.Overall != "pass" {
		t.Fatalf("the dumped ledger must audit as cleanly as the generated run: %+v", sa)
	}
}
