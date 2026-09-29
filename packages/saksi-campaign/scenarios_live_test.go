package campaign

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
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
		ID: "test-" + stage, Stage: stage, Layer: LayerOffline, ChainGate: "cds",
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
	sub := &fakeSubmitter{err: errString("gate=cds: contest \"president/cand0\" CDS well-formedness proof failed")}

	res := testExec(t).mountLiveAttack("run", dir, flipLine(StageBallots, 0), sub, "e2e")

	if res.Verdict != "PASS" {
		t.Fatalf("verdict = %q, want PASS: a rejection by the declared gate is the gate working", res.Verdict)
	}
	if !res.OnChain {
		t.Error("OnChain = false; a live submission must be recorded as such")
	}
	if res.GateExpected != "cds" || res.GateObserved != "cds" {
		t.Errorf("gates expected/observed = %q/%q, want cds/cds", res.GateExpected, res.GateObserved)
	}
	if !strings.Contains(res.Actual, "CDS well-formedness proof failed") {
		t.Errorf("the chaincode's message was lost: %q", res.Actual)
	}
}

// The defect this rule exists for: a tampered proof mounted after the election
// closed is refused by the closed-election gate, which runs before the proof
// check. The ledger said no, but not to the proof — so it is not a pass.
func TestLiveAttackRejectedByAnotherGateIsInconclusive(t *testing.T) {
	dir := liveRun(t)
	sub := &fakeSubmitter{err: errString("gate=election-open: election \"e2e\" is not open for ballots")}

	res := testExec(t).mountLiveAttack("run", dir, flipLine(StageBallots, 0), sub, "e2e")

	if res.Verdict != "INCONCLUSIVE" {
		t.Fatalf("verdict = %q, want INCONCLUSIVE: the gate under test never ran", res.Verdict)
	}
	if res.GateObserved != "election-open" || res.GateExpected != "cds" {
		t.Errorf("gates expected/observed = %q/%q", res.GateExpected, res.GateObserved)
	}
	if want := `rejected by election-open: election "e2e" is not open for ballots`; res.Actual != want {
		t.Errorf("actual = %q, want %q", res.Actual, want)
	}
	if a, r := res.rejection(); a != 0 || r != 0 {
		t.Errorf("an inconclusive trial counted as attempted=%d rejected=%d; it is not a trial of the gate", a, r)
	}
}

// A rejection that names no gate — a chaincode deployed before gate ids, an
// endorsement timeout — cannot be attributed to the gate under test either.
func TestLiveAttackRejectedByAnUnidentifiedGateIsInconclusive(t *testing.T) {
	dir := liveRun(t)
	sub := &fakeSubmitter{err: errString("contest \"president/cand0\" CDS well-formedness proof failed")}

	res := testExec(t).mountLiveAttack("run", dir, flipLine(StageBallots, 0), sub, "e2e")

	if res.Verdict != "INCONCLUSIVE" || res.GateObserved != "" {
		t.Fatalf("verdict/observed = %q/%q, want INCONCLUSIVE with no observed gate", res.Verdict, res.GateObserved)
	}
	if !strings.Contains(res.Actual, "unidentified gate") {
		t.Errorf("actual should say the gate is unidentified: %q", res.Actual)
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
		sub := &fakeSubmitter{err: errString("gate=t: rejected")}
		sc := Scenario{ID: "t", Stage: tc.stage, Action: "a", Expected: "e", Property: "p", Mutate: tc.mutate, ChainGate: "t"}

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
	// Nothing was mounted, so nothing was tested: INCONCLUSIVE, never FAIL (a
	// gate letting an attack through) and never PASS.
	if res.Verdict != "INCONCLUSIVE" || !strings.Contains(res.Actual, "changed no ballot") {
		t.Errorf("expected a clear not-mounted result, got %q / %q", res.Verdict, res.Actual)
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

// The two attacks saksi-demo builds are mounted at the ballots pause against
// the ballot the window has not sent: the helper is asked for THAT ballot, what
// it prints is what reaches the ledger, and a refusal at the declared gate
// (issuer, selection) is a PASS.
func TestHelperBuiltBallotAttacksMountLiveAtTheirGate(t *testing.T) {
	for id, gate := range map[string]string{"self-issued-credential": "issuer", "overvote": "selection"} {
		t.Run(id, func(t *testing.T) {
			dir := t.TempDir()
			e := newTestExecutor(t, dir)
			attackRun(t, filepath.Join(dir, "run-1"), 4)
			var calls [][]string
			e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
				calls = append(calls, args)
				return fakeHelper(args)
			}
			var sc Scenario
			for _, s := range Registry() {
				if s.ID == id {
					sc = s
				}
			}
			var submitted []string
			res := e.mountBallotLive(context.Background(), "run-1", sc, 2, 0, func(h string) error {
				submitted = append(submitted, h)
				return errString("chaincode response 500, gate=" + gate + ": refused")
			})

			if res.Verdict != "PASS" || res.GateObserved != gate || !res.OnChain {
				t.Fatalf("verdict %q observed %q (%s), want a live PASS at %s", res.Verdict, res.GateObserved, res.Actual, gate)
			}
			if len(calls) != 1 || len(submitted) != 1 {
				t.Fatalf("helper calls %v, submissions %d; want one of each", calls, len(submitted))
			}
			runDir := filepath.Join(dir, "run-1")
			want := map[string][]string{
				"self-issued-credential": {"forge-ballot", runDir, "--position", "president", "--candidate", "0"},
				"overvote":               {"overvote-ballot", runDir, "2"},
			}[id]
			if strings.Join(calls[0], " ") != strings.Join(want, " ") {
				t.Errorf("helper called with %v, want %v", calls[0], want)
			}
			assertCarriesMutation(t, id, submitted[0])
		})
	}
}

// On an election created before the issuer binding (params with no issuer
// key) the chaincode skips the issuer and selection gates, so the two attacks
// saksi-demo builds would be committed if mounted live. Neither is: the forged
// credential runs simulated, where the header-based ballot.issuer_binding still
// catches it, and the overvote is SKIPPED, since ballot.selection_sum is
// skipped on such params too and a clean audit would be a false FAIL.
func TestLegacyElectionNeverMountsTheIssuerBoundAttacksLive(t *testing.T) {
	setParams := func(t *testing.T, runDir string, p *pb.ElectionParameters) {
		t.Helper()
		if err := mutateHeader(runDir, func(h map[string]any) error {
			h["params"] = hexProto(t, p)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ id, verdict, actual string }{
		{"self-issued-credential", "PASS", "on-chain: not mounted (legacy election, params carry no issuer key: the chaincode skips gate issuer) — rejected by auditor check ballot.issuer_binding"},
		{"overvote", "SKIPPED", "legacy election (params carry no issuer key)"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			dir := t.TempDir()
			e := newTestExecutor(t, dir)
			runDir := filepath.Join(dir, "run-1")
			attackRun(t, runDir, 3)
			setParams(t, runDir, &pb.ElectionParameters{ElectionId: "run-1"})
			e.run = fakeAuditor(declaredAuditGate)
			// Enabled, but nothing answers: a live mount would come back
			// SKIPPED "connect to Fabric".
			e.fabric = FabricConfig{PeerEndpoint: "127.0.0.1:1", GatewayPeer: "p", TLSCert: "x", MSPID: "m",
				Cert: "x", Key: "x", Channel: "c", Chaincode: "cc"}

			if err := e.RunStagedAttack(context.Background(), "run-1", ElectionConfig{Mode: "onchain"}, tc.id); err != nil {
				t.Fatal(err)
			}
			r := resultsByID(t, runDir)[tc.id]
			if r.Verdict != tc.verdict || r.OnChain || !strings.HasPrefix(r.Actual, tc.actual) {
				t.Errorf("verdict %q onChain %v actual %q; want %s, simulated, actual starting %q",
					r.Verdict, r.OnChain, r.Actual, tc.verdict, tc.actual)
			}
		})
	}

	// The same attacks on an election with an issuer key stay live.
	runDir := t.TempDir()
	attackRun(t, runDir, 1)
	setParams(t, runDir, &pb.ElectionParameters{ElectionId: "run-1", IssuerPublicKey: make([]byte, 32)})
	for _, sc := range Registry() {
		if legacyChainSkips(sc, runDir) {
			t.Errorf("%s treated as legacy on an election with an issuer key", sc.ID)
		}
	}
}

// A legacy election's audit always fails parameters.issuer_binding (no issuer
// key in its params). The scenario audit sets that one finding aside, so the
// unmutated copy is still a clean positive control, a mutation caught by its
// declared check is a PASS, and one nothing else catches is still a FAIL.
func TestLegacyElectionFindingIsSetAsideByTheScenarioAudit(t *testing.T) {
	for _, tc := range []struct {
		legacy  bool
		mutated string // failed checks after mutation, beside the legacy finding
		want    string
	}{
		{true, "ballot.issuer_binding", "PASS"},
		{true, "", "FAIL"},
		// On an election with an issuer key the finding is real: the control fails.
		{false, "ballot.issuer_binding", "INCONCLUSIVE"},
	} {
		dir := t.TempDir()
		attackRun(t, dir, 3)
		p := &pb.ElectionParameters{ElectionId: "run-1"}
		if !tc.legacy {
			p.IssuerPublicKey = make([]byte, 32)
		}
		if err := mutateHeader(dir, func(h map[string]any) error { h["params"] = hexProto(t, p); return nil }); err != nil {
			t.Fatal(err)
		}
		audits := 0
		e := testExec(t)
		e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if args[0] != "audit-stream" {
				return fakeHelper(args)
			}
			audits++
			checks := `{"check":"parameters.issuer_binding","detail":"no issuer key"}`
			if audits%2 == 0 && tc.mutated != "" {
				checks += `,{"check":"` + tc.mutated + `","detail":"d"}`
			}
			return []byte(`{"overall":"fail","failed_checks":[` + checks + `]}`), nil
		}
		var sc Scenario
		for _, s := range Registry() {
			if s.ID == "self-issued-credential" {
				sc = s
			}
		}
		res := e.runOneScenario(context.Background(), "run-1", dir, sc)
		if res.Verdict != tc.want {
			t.Errorf("legacy=%v mutated=%q: verdict %q (%s), want %s", tc.legacy, tc.mutated, res.Verdict, res.Actual, tc.want)
		}
	}
}
