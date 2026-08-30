package campaign

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSubmitter stands in for the bulletin client so the live attack path can
// be exercised without a Fabric network. It records what was submitted and
// returns whatever the test wants the chaincode to have said.
type fakeSubmitter struct {
	err error

	ballotCalls  []string
	partialCalls []string
	dkgCalls     []string
}

func (f *fakeSubmitter) SubmitBallot(h string) error {
	f.ballotCalls = append(f.ballotCalls, h)
	return f.err
}

func (f *fakeSubmitter) SubmitPartialDecryption(_, h string) error {
	f.partialCalls = append(f.partialCalls, h)
	return f.err
}

func (f *fakeSubmitter) PublishDKGTranscript(h string) error {
	f.dkgCalls = append(f.dkgCalls, h)
	return f.err
}

// liveRun writes a run folder shaped like a generated stream: a header with the
// hex fields the mutations touch, and two ballot lines.
func liveRun(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	header := map[string]any{
		"election_id":         "e2e",
		"dkg":                 "aabbcc",
		"partial_decryptions": []any{"1111", "2222"},
		"tally":               "3333",
	}
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "header.json"), raw, 0o644); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ballots.ndjson"),
		[]byte("aa00\nbb11\n"), 0o644); err != nil {
		t.Fatalf("write ballots: %v", err)
	}
	return dir
}

// A scenario that changes ballot line `idx` — enough to drive the submission
// path without building real protobuf ballots.
func flipLine(stage string, idx int) Scenario {
	return Scenario{
		ID: "test-" + stage, Stage: stage, Layer: LayerOffline,
		Action: "flip a line", Expected: "rejected", Property: "test",
		Mutate: func(dir string) error {
			lines, err := readBallotLines(dir)
			if err != nil {
				return err
			}
			raw, _ := hex.DecodeString(lines[idx])
			raw[0] ^= 0x01
			lines[idx] = hex.EncodeToString(raw)
			return writeBallotLines(dir, lines)
		},
	}
}

func testExec(t *testing.T) *Executor {
	t.Helper()
	return NewExecutor(NewRunStore(t.TempDir()), NewHub(), "saksi-demo", "", FabricConfig{})
}

// THE inversion. A chaincode rejection is the attack being defeated, so it must
// be recorded as PASS — and the ledger's own words must survive into the result,
// because that message is what the demonstration shows.
func TestLiveAttackRejectionIsAPass(t *testing.T) {
	dir := liveRun(t)
	sub := &fakeSubmitter{err: errString("contest \"president/cand0\" CDS well-formedness proof failed")}

	res := testExec(t).mountLiveAttack("run", dir, flipLine(StageBallots, 0), sub, "e2e")

	if res.Verdict != "PASS" {
		t.Fatalf("verdict = %q, want PASS: a rejected attack is the gate working", res.Verdict)
	}
	if !res.OnChain {
		t.Error("OnChain = false; a live submission must be recorded as such")
	}
	if !strings.Contains(res.Actual, "CDS well-formedness proof failed") {
		t.Errorf("the chaincode's message was lost: %q", res.Actual)
	}
}

// The mirror, and the one that actually matters: if the ledger ACCEPTS a
// tampered artifact that is a real security finding, and reporting it as a pass
// would hide a broken gate behind a green tick.
func TestLiveAttackAcceptanceIsAFailure(t *testing.T) {
	dir := liveRun(t)
	sub := &fakeSubmitter{err: nil} // the chaincode took it

	res := testExec(t).mountLiveAttack("run", dir, flipLine(StageBallots, 0), sub, "e2e")

	if res.Verdict != "FAIL" {
		t.Fatalf("verdict = %q, want FAIL: the ledger accepted a tampered ballot", res.Verdict)
	}
	if !strings.Contains(res.Actual, "NOT rejected") {
		t.Errorf("result should say the ledger accepted it, got %q", res.Actual)
	}
}

// The submitted ballot must be the one the attacker changed. Always sending
// index 0 would silently submit an untouched ballot for any mutation that
// targets a different one — which the chaincode would accept, producing a
// spurious FAIL.
func TestLiveAttackSubmitsTheChangedBallot(t *testing.T) {
	dir := liveRun(t)
	before, err := readBallotLines(dir)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	sub := &fakeSubmitter{err: errString("rejected")}

	testExec(t).mountLiveAttack("run", dir, flipLine(StageBallots, 1), sub, "e2e")

	if len(sub.ballotCalls) != 1 {
		t.Fatalf("expected exactly one ballot submission, got %d", len(sub.ballotCalls))
	}
	if sub.ballotCalls[0] == before[1] {
		t.Error("submitted the ORIGINAL ballot 1 — the mutation was not carried")
	}
	if sub.ballotCalls[0] == before[0] {
		t.Error("submitted ballot 0; the mutation was on ballot 1")
	}
}

// Each stage must reach for its own submission method.
func TestLiveAttackRoutesByStage(t *testing.T) {
	cases := []struct {
		stage                  string
		mutate                 func(dir string) error
		ballots, partials, dkg int
	}{
		{StageCeremony, func(dir string) error {
			return mutateHeader(dir, func(h map[string]any) error {
				h["partial_decryptions"] = []any{"1111", "9999"}
				return nil
			})
		}, 0, 1, 0},
		{StageDKG, func(dir string) error {
			return mutateHeader(dir, func(h map[string]any) error {
				h["dkg"] = "ddeeff"
				return nil
			})
		}, 0, 0, 1},
	}
	for _, tc := range cases {
		dir := liveRun(t)
		sub := &fakeSubmitter{err: errString("rejected")}
		sc := Scenario{ID: "t", Stage: tc.stage, Action: "a", Expected: "e", Property: "p", Mutate: tc.mutate}

		res := testExec(t).mountLiveAttack("run", dir, sc, sub, "e2e")

		if res.Verdict != "PASS" {
			t.Errorf("%s: verdict %q (%s)", tc.stage, res.Verdict, res.Actual)
		}
		if len(sub.ballotCalls) != tc.ballots || len(sub.partialCalls) != tc.partials ||
			len(sub.dkgCalls) != tc.dkg {
			t.Errorf("%s routed wrongly: ballots=%d partials=%d dkg=%d",
				tc.stage, len(sub.ballotCalls), len(sub.partialCalls), len(sub.dkgCalls))
		}
	}
}

// A mutation that changed nothing must not be submitted. Sending an untouched
// artifact would be accepted by the chaincode and reported as a failed gate,
// when in fact no attack was ever mounted.
func TestLiveAttackRefusesToSubmitAnUnchangedArtifact(t *testing.T) {
	dir := liveRun(t)
	sub := &fakeSubmitter{err: errString("rejected")}
	noop := Scenario{ID: "noop", Stage: StageBallots, Action: "a", Expected: "e", Property: "p",
		Mutate: func(string) error { return nil }}

	res := testExec(t).mountLiveAttack("run", dir, noop, sub, "e2e")

	if len(sub.ballotCalls) != 0 {
		t.Error("submitted an artifact the mutation never changed")
	}
	if res.Verdict != "FAIL" || !strings.Contains(res.Actual, "changed no ballot") {
		t.Errorf("expected a clear no-op failure, got %q / %q", res.Verdict, res.Actual)
	}
}

// The live path must never touch the real election's artifacts — it works on a
// copy, and the chaincode refuses the write.
func TestLiveAttackLeavesTheRealRunUntouched(t *testing.T) {
	dir := liveRun(t)
	ballotsBefore, _ := os.ReadFile(filepath.Join(dir, "ballots.ndjson"))
	headerBefore, _ := os.ReadFile(filepath.Join(dir, "header.json"))

	sub := &fakeSubmitter{err: errString("rejected")}
	testExec(t).mountLiveAttack("run", dir, flipLine(StageBallots, 0), sub, "e2e")

	ballotsAfter, _ := os.ReadFile(filepath.Join(dir, "ballots.ndjson"))
	headerAfter, _ := os.ReadFile(filepath.Join(dir, "header.json"))
	if string(ballotsBefore) != string(ballotsAfter) {
		t.Error("the live attack modified the real ballots.ndjson")
	}
	if string(headerBefore) != string(headerAfter) {
		t.Error("the live attack modified the real header.json")
	}
}

// close-stage attacks describe something missing or reordered across the whole
// ballot set, which no single submission expresses.
func TestLiveAttackSkipsUnmountableStages(t *testing.T) {
	dir := liveRun(t)
	sub := &fakeSubmitter{}
	sc := Scenario{ID: "t", Stage: StageClose, Action: "a", Expected: "e", Property: "p",
		Mutate: func(string) error { return nil }}

	res := testExec(t).mountLiveAttack("run", dir, sc, sub, "e2e")

	if res.Verdict != "SKIPPED" {
		t.Errorf("verdict = %q, want SKIPPED for a close-stage attack", res.Verdict)
	}
	if len(sub.ballotCalls)+len(sub.partialCalls)+len(sub.dkgCalls) != 0 {
		t.Error("a close-stage attack submitted something")
	}
}

// --- the pure diff helpers ------------------------------------------------

func TestFirstChangedBallotFindsTheMutatedIndex(t *testing.T) {
	src := liveRun(t)
	dst := liveRun(t)
	if err := writeBallotLines(dst, []string{"aa00", "cc22"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	idx, line, err := firstChangedBallot(src, dst)
	if err != nil {
		t.Fatalf("firstChangedBallot: %v", err)
	}
	if idx != 1 || line != "cc22" {
		t.Errorf("got index %d line %q, want 1 / cc22", idx, line)
	}
}

func TestChangedHeaderHelpersDetectNoChange(t *testing.T) {
	src := liveRun(t)
	dst := liveRun(t)
	if _, err := firstChangedHeaderList(src, dst, "partial_decryptions"); err == nil {
		t.Error("identical partial_decryptions reported a change")
	}
	if _, err := changedHeaderField(src, dst, "dkg"); err == nil {
		t.Error("identical dkg field reported a change")
	}
}

// errString is a minimal error whose message is the string itself.
type errString string

func (e errString) Error() string { return string(e) }
