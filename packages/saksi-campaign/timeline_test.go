package campaign

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	"github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk/bench"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// --- fixtures ---------------------------------------------------------------

func hexProto(t *testing.T, m proto.Message) string {
	t.Helper()
	raw, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

// attackRun writes a run folder the registry's mutations can act on: n
// decodable ballots, each with a CDS branch (response all zero — the fake
// chaincode below reads a nonzero first byte as a failed proof) and a distinct
// nullifier, plus a header whose DKG transcript and partial decryption are real
// protobufs, and the bundle that references the ballots.
func attackRun(t *testing.T, runDir string, n int) string {
	t.Helper()
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintln(&b, hexProto(t, &pb.Ballot{
			Version: 1, ElectionId: "run-1", PositionId: "president",
			Ciphertexts: []*pb.Ciphertext{{Pad: make([]byte, 32), Data: make([]byte, 32)}},
			WellFormednessProofs: []*pb.CDSProof{{Version: 1, Branches: []*pb.CDSProofBranch{
				{Response: make([]byte, 32)}}}},
			CredentialPresentation: &pb.CredentialPresentation{
				Nullifier:         &pb.Nullifier{Value: testNullifier(i)},
				PresentationProof: fakeSignature(),
			},
		}))
	}
	if err := os.WriteFile(filepath.Join(runDir, BallotsFile), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	header := map[string]any{
		"election_id": "run-1",
		"dkg": hexProto(t, &pb.DKGTranscript{Version: 1, ElectionId: "run-1", Threshold: 1,
			TrusteeCommitments: []*pb.TrusteeCommitment{{TrusteeId: "1", CoefficientCommitments: [][]byte{make([]byte, 32)}}}}),
		"partial_decryptions": []string{hexProto(t, &pb.PartialDecryption{Version: 1, TrusteeId: "1",
			ContestId: "president/cand0", Share: make([]byte, 32),
			Proof: &pb.ChaumPedersenProof{Version: 1, Response: make([]byte, 32)}})},
		"n": n,
	}
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "header.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return writeStreamBundle(t, runDir, n)
}

// fakeAuditor stands in for `saksi-demo audit-stream`. The first audit of a
// scenario copy is its positive control and passes; the next one is the audit
// of the mutated copy and fails naming `failed(scenarioID)`, or passes if that
// returns "" (an attack nothing caught).
func fakeAuditor(failed func(scenario string) string) Runner {
	var mu sync.Mutex
	calls := map[string]int{}
	return func(_ context.Context, _ string, args ...string) ([]byte, error) {
		dir := args[1]
		mu.Lock()
		calls[dir]++
		n := calls[dir]
		mu.Unlock()
		check := failed(strings.TrimPrefix(filepath.Base(dir), "live-"))
		if n%2 == 1 || check == "" {
			return []byte(`{"overall":"pass"}`), nil
		}
		return []byte(fmt.Sprintf(`{"overall":"fail","failed_checks":[{"check":%q,"detail":"fake detail"}]}`, check)), nil
	}
}

// declaredAuditGate makes the fake auditor name each scenario's own check.
func declaredAuditGate(id string) string {
	for _, sc := range Registry() {
		if sc.ID == id {
			return sc.AuditGate
		}
	}
	return ""
}

// fakeSignature is the 64-byte presentation-proof prefix the fake credential
// gate accepts: a marker first byte stands in for a verifying signature.
func fakeSignature() []byte {
	sig := make([]byte, 64)
	sig[0] = 0xC5
	return sig
}

// gatedLedger is fakeLedger with SubmitBallot's gates in the chaincode's order
// (decode, shape, credential, election open, nullifier unspent, CDS), each
// refusing with its "gate=<id>:" prefix, so a live mount can be classified end
// to end. The shape and credential gates are stand-ins (ciphertexts and a
// nullifier present; a marker signature) that no live mutation should trip:
// the proof that the real ones pass the real crypto is the chaincode's
// TestLiveAttackMutationsMeetTheirDeclaredGateFirst.
type gatedLedger struct {
	*fakeLedger
	gmu        sync.Mutex
	status     string
	spent      map[string]bool
	heightRead int // ChainInfo calls
}

func newGatedLedger() *gatedLedger {
	return &gatedLedger{fakeLedger: &fakeLedger{}, spent: map[string]bool{}}
}

func (g *gatedLedger) SubmitWithReceipt(fn string, args ...string) ([]byte, clientsdk.Receipt, error) {
	g.gmu.Lock()
	switch fn {
	case "CreateElection":
		g.status = "open"
	case "CloseElection":
		g.status = "closed"
	}
	g.gmu.Unlock()
	return g.fakeLedger.SubmitWithReceipt(fn, args...)
}

func (g *gatedLedger) Submit(fn string, args ...string) (string, uint64, error) {
	if fn == "SubmitBallot" {
		if err := g.ballotGates(args[0]); err != nil {
			return "", 0, fmt.Errorf("submit SubmitBallot: %w", err)
		}
	}
	return g.fakeLedger.Submit(fn, args...)
}

func (g *gatedLedger) ballotGates(h string) error {
	var b pb.Ballot
	raw, _ := hex.DecodeString(h)
	if err := proto.Unmarshal(raw, &b); err != nil {
		return fmt.Errorf("gate=decode: decode ballot: %w", err)
	}
	cp := b.GetCredentialPresentation()
	if len(b.GetCiphertexts()) == 0 || len(cp.GetNullifier().GetValue()) == 0 {
		return errors.New("gate=shape: ballot has no ciphertexts or no nullifier")
	}
	if p := cp.GetPresentationProof(); len(p) < 64 || p[0] != 0xC5 {
		return errors.New("gate=credential: credential signature verification failed")
	}
	g.gmu.Lock()
	defer g.gmu.Unlock()
	if g.status != "open" {
		return fmt.Errorf("gate=election-open: election %q is not open for ballots", b.GetElectionId())
	}
	nul := hex.EncodeToString(b.GetCredentialPresentation().GetNullifier().GetValue())
	if g.spent[nul] {
		return fmt.Errorf("gate=nullifier: nullifier already spent in election %q (double vote)", b.GetElectionId())
	}
	if b.WellFormednessProofs[0].Branches[0].Response[0] != 0 {
		return errors.New(`gate=cds: contest "president/cand0" CDS well-formedness proof failed`)
	}
	g.spent[nul] = true
	return nil
}

func (g *gatedLedger) ChainInfo() (uint64, []byte, error) {
	g.gmu.Lock()
	g.heightRead++
	g.gmu.Unlock()
	return g.fakeLedger.ChainInfo()
}

func (g *gatedLedger) electionStatus() string {
	g.gmu.Lock()
	defer g.gmu.Unlock()
	return g.status
}

// waitPause polls until the run's lifecycle holds at stage.
func waitPause(t *testing.T, e *Executor, runID, stage string, done <-chan error) PauseView {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("lifecycle finished (err %v) before pausing at %s", err, stage)
		default:
		}
		if v := e.PauseStatus(runID); v.Paused && v.Stage == stage && v.Running == "" {
			return v
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("lifecycle never paused at %s (now %+v)", stage, e.PauseStatus(runID))
	return PauseView{}
}

func resultsByID(t *testing.T, dir string) map[string]ScenarioResult {
	t.Helper()
	rs, err := readScenarioResults(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]ScenarioResult{}
	for _, r := range rs {
		out[r.Scenario] = r
	}
	return out
}

// --- per-scenario verdict classification -----------------------------------

// Every scenario is judged by the gate it declares, both ways it can be
// mounted: rejected by that gate is PASS, by another gate INCONCLUSIVE, by
// nothing FAIL.
func TestEveryScenarioIsJudgedByItsDeclaredGate(t *testing.T) {
	for _, sc := range Registry() {
		if sc.Layer == LayerChaincode {
			continue
		}
		t.Run(sc.ID, func(t *testing.T) {
			for _, tc := range []struct{ failed, want string }{
				{sc.AuditGate, "PASS"}, {"tally.shape", "INCONCLUSIVE"}, {"", "FAIL"},
			} {
				dir := t.TempDir()
				attackRun(t, dir, 3)
				e := testExec(t)
				e.run = fakeAuditor(func(string) string { return tc.failed })
				res := e.runOneScenario(context.Background(), "run-1", dir, sc)
				if res.Verdict != tc.want || res.GateExpected != sc.AuditGate || res.GateObserved != tc.failed {
					t.Errorf("simulated, auditor failed %q: verdict %q expected %q observed %q (%s), want %s",
						tc.failed, res.Verdict, res.GateExpected, res.GateObserved, res.Actual, tc.want)
				}
			}
			if !sc.LiveCapable() {
				return
			}
			for _, tc := range []struct {
				err  error
				want string
			}{
				{errString("gate=" + sc.ChainGate + ": refused"), "PASS"},
				{errString(`gate=election-open: election "run-1" is not open for ballots`), "INCONCLUSIVE"},
				{nil, "FAIL"},
			} {
				dir := t.TempDir()
				attackRun(t, dir, 3)
				sub := &fakeSubmitter{err: tc.err}
				res := testExec(t).mountLiveAttack("run-1", dir, sc, sub, "run-1")
				if res.Verdict != tc.want || res.GateExpected != sc.ChainGate || !res.OnChain {
					t.Errorf("live, ledger said %v: verdict %q expected %q (%s), want %s",
						tc.err, res.Verdict, res.GateExpected, res.Actual, tc.want)
				}
				if len(sub.ballotCalls) != 1 {
					t.Fatalf("submitted %d ballots, want the one tampered ballot", len(sub.ballotCalls))
				}
				assertCarriesMutation(t, sc.ID, sub.ballotCalls[0])
			}
		})
	}
}

// assertCarriesMutation checks the submitted ballot is broken in exactly the
// way its scenario names — which is what makes the gate it meets the right one.
func assertCarriesMutation(t *testing.T, id, h string) {
	t.Helper()
	var b pb.Ballot
	raw, _ := hex.DecodeString(h)
	err := proto.Unmarshal(raw, &b)
	switch id {
	case "corrupted-ballot-bytes":
		if err == nil {
			t.Error("corrupted ballot still decodes; it would not reach the decode gate")
		}
	case "tamper-ballot-proof":
		if err != nil || b.WellFormednessProofs[0].Branches[0].Response[0] == 0 {
			t.Errorf("proof not tampered (decode err %v)", err)
		}
	case "reused-nullifier":
		if err != nil || string(b.CredentialPresentation.Nullifier.Value) != string(testNullifier(0)) {
			t.Errorf("nullifier not reused from ballot 0 (decode err %v)", err)
		}
	}
}

// The simulated mutations target the field their scenario names and stay
// well-formed protobuf where the gate under test is not the decoder.
func TestSimulatedMutationsHitTheirDeclaredField(t *testing.T) {
	dir := t.TempDir()
	attackRun(t, dir, 2)
	h, err := headerMap(dir)
	if err != nil {
		t.Fatal(err)
	}

	pdHex, err := TamperPartialProof(h["partial_decryptions"].([]any)[0].(string))
	if err != nil {
		t.Fatal(err)
	}
	var pd pb.PartialDecryption
	if err := decodeHexProto(pdHex, &pd); err != nil || pd.Proof.Response[0] != 1 ||
		pd.ContestId != "president/cand0" || pd.Share[0] != 0 {
		t.Errorf("partial decryption mutation must flip the CP response and nothing else: %v %+v", err, &pd)
	}

	dkgHex, err := tamperDKGCommitment(h["dkg"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var dkg pb.DKGTranscript
	if err := decodeHexProto(dkgHex, &dkg); err != nil || dkg.TrusteeCommitments[0].CoefficientCommitments[0][0] != 1 ||
		dkg.Threshold != 1 || dkg.ElectionId != "run-1" {
		t.Errorf("DKG mutation must flip the commitment's low bit and nothing else: %v %+v", err, &dkg)
	}
}

// --- the timeline -----------------------------------------------------------

// The whole D1 contract against a fake ledger: the lifecycle pauses at each
// declared moment, in the declared state, mounts each ballot attack against the
// OPEN election so it meets its own gate, and then finishes the election with
// every real ballot committed and the pause excluded from the window.
func TestSecurityRunPausesAtEachDeclaredMoment(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	e.run = fakeAuditor(declaredAuditGate)
	const n = 10
	path := attackRun(t, runDir, n)
	led := newGatedLedger()
	c := ElectionConfig{Mode: "onchain", Voters: n, Positions: 1, Candidates: 2, Concurrency: 4,
		AttackPlan: &AttackPlan{Stages: []string{StageDKG, StageBallots, StageClose}, BallotsAt: 0.5}}

	done := make(chan error, 1)
	go func() { done <- e.submitOnChain(context.Background(), "run-1", c, led, path) }()

	// dkg: the election exists and is open; its transcript is not yet published.
	v := waitPause(t, e, "run-1", StageDKG, done)
	if got := led.callNames(); !reflect.DeepEqual(got, []string{"CreateElection"}) {
		t.Fatalf("at the dkg pause the chain has seen %v, want only CreateElection", got)
	}
	if led.electionStatus() != "open" || v.Mount.ElectionStatus != "open" || *v.Mount.BallotsCommitted != 0 ||
		v.Mount.BlockHeight == nil || !v.Live {
		t.Fatalf("dkg mount context = %+v", v)
	}
	if err := e.DecidePause("run-1", "run-all", ""); err != nil {
		t.Fatal(err)
	}

	// ballots: exactly ballots_at x N committed, the rest never sent, election open.
	v = waitPause(t, e, "run-1", StageBallots, done)
	if got := sortedIndices(led.acceptedIndices()); !reflect.DeepEqual(got, []int{0, 1, 2, 3, 4}) {
		t.Fatalf("committed at the ballots pause = %v, want ballots 0..4", got)
	}
	led.mu.Lock()
	attempts := led.ballots
	led.mu.Unlock()
	if attempts != 5 || led.electionStatus() != "open" || *v.Mount.BallotsCommitted != 5 {
		t.Fatalf("ballots pause: %d submissions, status %q, mount %+v; want 5, open, 5 committed",
			attempts, led.electionStatus(), v.Mount)
	}
	time.Sleep(300 * time.Millisecond) // the operator reads the panel: not submission time
	if err := e.DecidePause("run-1", "run", "tamper-ballot-proof"); err != nil {
		t.Fatal(err)
	}
	waitVerdict(t, runDir, "tamper-ballot-proof")
	if err := e.DecidePause("run-1", "run-all", ""); err != nil {
		t.Fatal(err)
	}

	// close: every ballot is in, including the real ballot 5 the attacks tampered copies of.
	v = waitPause(t, e, "run-1", StageClose, done)
	if led.electionStatus() != "closed" || v.Mount.ElectionStatus != "closed" || *v.Mount.BallotsCommitted != n {
		t.Fatalf("close mount context = %+v (chain status %q)", v.Mount, led.electionStatus())
	}
	if got := len(led.acceptedIndices()); got != n {
		t.Fatalf("committed after resume = %d, want %d", got, n)
	}
	if err := e.DecidePause("run-1", "skip", ""); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("lifecycle: %v", err)
	}

	got := resultsByID(t, runDir)
	for id, gate := range map[string]string{"tamper-ballot-proof": "cds", "reused-nullifier": "nullifier", "corrupted-ballot-bytes": "decode"} {
		r := got[id]
		if r.Verdict != "PASS" || !r.OnChain || r.GateObserved != gate || r.Mount.Stage != StageBallots ||
			r.Mount.ElectionStatus != "open" || *r.Mount.BallotsCommitted != 5 {
			t.Errorf("%s = %+v, want a live PASS at gate %s mounted mid-submission", id, r, gate)
		}
	}
	if r := got["tamper-dkg-transcript"]; r.Verdict != "PASS" || r.OnChain || r.Mount.Stage != StageDKG ||
		!strings.HasPrefix(r.Actual, "on-chain: not checked (shape/presence only, no caller authorization); caught by the auditor — ") {
		t.Errorf("tamper-dkg-transcript = %+v, want a simulated PASS saying the ledger does not check it", r)
	}
	if _, ok := got["dropped-ballot"]; ok {
		t.Error("the close stage was skipped, yet dropped-ballot has a verdict")
	}

	var pauses []string
	for _, ev := range journalEventsOfType(t, runDir, "attack.pause") {
		pauses = append(pauses, jstring(ev, "stage"))
	}
	if !reflect.DeepEqual(pauses, []string{StageDKG, StageBallots, StageClose}) {
		t.Errorf("journal pauses = %v", pauses)
	}
	resumes := journalEventsOfType(t, runDir, "attack.resume")
	if len(resumes) != 3 || jstring(resumes[2], "reason") != "skip" {
		t.Fatalf("journal resumes = %v", resumes)
	}
	pausedMs := jfloat(resumes[1], "paused_ms")
	ends := journalEventsOfType(t, runDir, "stage.ballots.end")
	if len(ends) != 1 || pausedMs < 300 || jfloat(ends[0], "window_ms") >= pausedMs {
		t.Errorf("window_ms %v must exclude the %v ms ballots pause", ends, pausedMs)
	}
	rows := latencyRows(t, runDir, 0)
	if len(rows) != n {
		t.Errorf("latencies.csv has %d rows, want one per ballot (%d)", len(rows), n)
	}
	for i := 0; i < n; i++ {
		if rows[i] != "commit" {
			t.Errorf("ballot %d latency row = %q, want commit", i, rows[i])
		}
	}
}

func waitVerdict(t *testing.T, dir, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := resultsByID(t, dir)[id]; ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no verdict for %s", id)
}

// A run with no attack plan must dispatch exactly as it did before the
// timeline existed: one dispatcher call over the whole population with the
// same options, no height read, no pause, nothing new in the journal.
func TestRunWithoutAnAttackPlanDispatchesExactlyAsBefore(t *testing.T) {
	type call struct {
		n    int
		opts bench.RunOpts
	}
	var calls []call
	orig := runBench
	runBench = func(ctx context.Context, n int, submit bench.SubmitFunc, opts bench.RunOpts) bench.RunResult {
		calls = append(calls, call{n, opts})
		return orig(ctx, n, submit, opts)
	}
	t.Cleanup(func() { runBench = orig })

	run := func(plan *AttackPlan) (*gatedLedger, string) {
		calls = nil
		dir := t.TempDir()
		runDir := filepath.Join(dir, "run-1")
		e := newTestExecutor(t, dir)
		e.run = fakeAuditor(declaredAuditGate)
		path := attackRun(t, runDir, 10)
		led := newGatedLedger()
		c := ElectionConfig{Mode: "onchain", Voters: 10, Positions: 1, Candidates: 2, Concurrency: 4, SendRate: 0,
			AttackPlan: plan}
		if plan != nil {
			plan.TimeoutS = 0.01 // unattended: the plan runs itself
		}
		if err := e.submitOnChain(context.Background(), "run-1", c, led, path); err != nil {
			t.Fatal(err)
		}
		return led, runDir
	}

	led, runDir := run(nil)
	if len(calls) != 1 || calls[0].n != 10 || calls[0].opts.Concurrency != 4 || calls[0].opts.SendRate != 0 ||
		calls[0].opts.MaxDuration != 0 || calls[0].opts.OnProgress == nil {
		t.Fatalf("dispatcher calls = %+v, want one over all 10 ballots with the configured options", calls)
	}
	if led.heightRead != 0 {
		t.Errorf("a run without a plan read the chain height %d times", led.heightRead)
	}
	events, err := readJournalEvents(runDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if strings.HasPrefix(jstring(ev, "event"), "attack.") {
			t.Errorf("a run without a plan journalled %v", ev)
		}
	}
	if _, err := os.Stat(filepath.Join(runDir, ScenarioStateFile)); err == nil {
		t.Error("a run without a plan recorded attack verdicts")
	}
	if cell := securityRunCell(ElectionConfig{}); cell != "" {
		t.Errorf("security_run for a plain run = %q, want empty", cell)
	}

	// The same run with a plan splits the window at ballots_at x N.
	run(&AttackPlan{Stages: []string{StageBallots}})
	if len(calls) != 2 || calls[0].n != 5 || calls[1].n != 5 {
		t.Fatalf("paused window dispatcher calls = %+v, want 5 then 5", calls)
	}
	if cell := securityRunCell(ElectionConfig{AttackPlan: &AttackPlan{}}); cell != "true" {
		t.Errorf("security_run for a security run = %q, want true", cell)
	}
}

// Offline, the stages pause in the same places — including the ceremony, which
// holds the tally back until its attacks are decided — and every attack is a
// simulation with no ledger state to record.
func TestOfflineSecurityRunPausesAndHoldsThePublish(t *testing.T) {
	store := NewRunStore(t.TempDir())
	c := good()
	c.AttackPlan = &AttackPlan{Stages: []string{StageDKG, StageCeremony}}
	runID, dir, err := store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	attackRun(t, dir, 4)
	writeBundle(t, dir, runID, 1, 3)
	e := NewExecutor(store, NewHub(), "saksi-demo", "", FabricConfig{})
	e.run = fakeAuditor(declaredAuditGate)
	ctx := context.Background()

	started := make(chan error, 1)
	go func() { started <- e.CeremonyStart(ctx, runID, c) }()
	v := waitPause(t, e, runID, StageDKG, started)
	if v.Live || v.Mount.ElectionStatus != "" || v.Mount.BallotsCommitted != nil || v.Mount.BlockHeight != nil {
		t.Fatalf("offline mount context claims ledger state: %+v", v)
	}
	if err := e.DecidePause(runID, "run-all", ""); err != nil {
		t.Fatal(err)
	}
	if err := <-started; err != nil {
		t.Fatalf("CeremonyStart: %v", err)
	}

	for _, tr := range []string{"1", "2"} {
		if err := e.CeremonySubmit(ctx, runID, c, tr); err != nil {
			t.Fatal(err)
		}
	}
	published := make(chan error, 1)
	go func() { published <- e.CeremonyPublish(ctx, runID, c) }()
	waitPause(t, e, runID, StageCeremony, published)
	if st, _ := e.CeremonyStatus(runID, c); st.Published {
		t.Fatal("the tally was published before the ceremony stage's attacks were decided")
	}
	if err := e.DecidePause(runID, "run-all", ""); err != nil {
		t.Fatal(err)
	}
	if err := <-published; err != nil {
		t.Fatalf("CeremonyPublish: %v", err)
	}
	if st, _ := e.CeremonyStatus(runID, c); !st.Published {
		t.Fatal("the tally was not published after the ceremony stage resumed")
	}

	got := resultsByID(t, dir)
	for id, stage := range map[string]string{"tamper-dkg-transcript": StageDKG, "tamper-partial-decryption": StageCeremony} {
		r := got[id]
		if r.Verdict != "PASS" || r.OnChain || r.Mount.Stage != stage || strings.Contains(r.Actual, "on-chain") {
			t.Errorf("%s = %+v, want an offline simulated PASS mounted at %s", id, r, stage)
		}
	}
}

// A pause the operator walks away from still carries out the plan.
func TestUnattendedPauseRunsTheStageAndContinues(t *testing.T) {
	store := NewRunStore(t.TempDir())
	c := good()
	c.AttackPlan = &AttackPlan{Stages: []string{StageDKG}, TimeoutS: 0.05}
	runID, dir, err := store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	attackRun(t, dir, 4)
	writeBundle(t, dir, runID, 1, 3)
	e := NewExecutor(store, NewHub(), "saksi-demo", "", FabricConfig{})
	e.run = fakeAuditor(declaredAuditGate)

	if err := e.CeremonyStart(context.Background(), runID, c); err != nil {
		t.Fatal(err)
	}
	if r := resultsByID(t, dir)["tamper-dkg-transcript"]; r.Verdict != "PASS" {
		t.Errorf("timed-out pause did not run its attack: %+v", r)
	}
	resumes := journalEventsOfType(t, dir, "attack.resume")
	if len(resumes) != 1 || jstring(resumes[0], "reason") != "timeout" {
		t.Errorf("resume events = %v, want one timeout", resumes)
	}
}

// --- config and API ---------------------------------------------------------

func TestValidateAttackPlan(t *testing.T) {
	ok := good()
	ok.AttackPlan = &AttackPlan{Stages: []string{StageDKG, StageBallots, StageClose, StageCeremony}, BallotsAt: 0.5}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a valid plan was refused: %v", err)
	}
	for name, mutate := range map[string]func(c *ElectionConfig){
		"skip_attacks":      func(c *ElectionConfig) { c.SkipAttacks = true },
		"campaign rep":      func(c *ElectionConfig) { c.Rep = &RepTag{Index: 1, Kind: "measured"} },
		"ground truth":      func(c *ElectionConfig) { c.Mode = ModeGroundTruth },
		"no stages":         func(c *ElectionConfig) { c.AttackPlan.Stages = nil },
		"unknown stage":     func(c *ElectionConfig) { c.AttackPlan.Stages = []string{"tally"} },
		"duplicate stage":   func(c *ElectionConfig) { c.AttackPlan.Stages = []string{StageDKG, StageDKG} },
		"ballots_at 1":      func(c *ElectionConfig) { c.AttackPlan.BallotsAt = 1 },
		"ballots_at < 0":    func(c *ElectionConfig) { c.AttackPlan.BallotsAt = -0.1 },
		"negative timeout":  func(c *ElectionConfig) { c.AttackPlan.TimeoutS = -1 },
		"one ballot to cut": func(c *ElectionConfig) { c.Voters, c.Positions = 1, 1 },
	} {
		c := good()
		c.AttackPlan = &AttackPlan{Stages: []string{StageBallots}, BallotsAt: 0.5}
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: plan accepted, want refused", name)
		}
	}
}

func TestPauseIndexKeepsACastAndAnUncastBallot(t *testing.T) {
	plan := func(at float64) *AttackPlan { return &AttackPlan{Stages: []string{StageBallots}, BallotsAt: at} }
	for _, tc := range []struct {
		p    *AttackPlan
		n    int
		want int
	}{
		{plan(0.5), 10, 5}, {plan(0), 10, 5}, {plan(0.01), 10, 1}, {plan(0.99), 10, 9},
		{plan(0.5), 1, 0}, {nil, 10, 0}, {&AttackPlan{Stages: []string{StageDKG}}, 10, 0},
	} {
		if got := tc.p.pauseIndex(tc.n); got != tc.want {
			t.Errorf("pauseIndex(%+v, %d) = %d, want %d", tc.p, tc.n, got, tc.want)
		}
	}
}

func TestPauseAPI(t *testing.T) {
	s, h, exec := testServer(t, nil)
	c := good()
	runID, _, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	get := func() PauseView {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/runs/"+runID+"/pause", nil))
		var v PauseView
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
			t.Fatalf("GET pause: %d %s", rec.Code, rec.Body)
		}
		return v
	}
	post := func(body map[string]string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, postJSON("/api/runs/"+runID+"/pause", body))
		return rec.Code
	}
	if get().Paused {
		t.Fatal("a run that is not running reports a pause")
	}
	if code := post(map[string]string{"action": "skip"}); code != http.StatusConflict {
		t.Fatalf("deciding a pause that does not exist = %d, want 409", code)
	}

	p := &stagePause{decide: make(chan pauseDecision, 1),
		view: PauseView{Paused: true, Stage: StageBallots, Scenarios: []string{"reused-nullifier"}}}
	exec.setPause(runID, p)
	if v := get(); !v.Paused || v.Stage != StageBallots {
		t.Fatalf("GET pause = %+v", v)
	}
	if code := post(map[string]string{"action": "run", "scenario": "dropped-ballot"}); code != http.StatusBadRequest {
		t.Errorf("running an attack of another stage = %d, want 400", code)
	}
	if code := post(map[string]string{"action": "explode"}); code != http.StatusBadRequest {
		t.Errorf("an unknown action = %d, want 400", code)
	}
	if code := post(map[string]string{"action": "run", "scenario": "reused-nullifier"}); code != http.StatusAccepted {
		t.Errorf("a valid decision = %d, want 202", code)
	}
	if d := <-p.decide; d.action != "run" || d.scenario != "reused-nullifier" {
		t.Errorf("decision delivered = %+v", d)
	}
}

// A step-7 "Run again" (the unstaged catalogue) must not erase a verdict
// mounted at a pause: negative-tests.csv is the only artifact carrying the live
// gate evidence. The re-run is journalled instead, and an unstaged result still
// replaces an unstaged one, and a staged one still replaces a staged one.
func TestUnstagedRerunNeverReplacesAStagedVerdict(t *testing.T) {
	store := NewRunStore(t.TempDir())
	c := good()
	runID, dir, err := store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	attackRun(t, dir, 3)
	e := NewExecutor(store, NewHub(), "saksi-demo", "", FabricConfig{})
	e.run = fakeAuditor(declaredAuditGate)

	committed, height := 5, uint64(9)
	live := ScenarioResult{Scenario: "tamper-ballot-proof", Stage: StageBallots, Verdict: "PASS", OnChain: true,
		Actual:       "rejected by chaincode gate cds (the declared gate): proof failed",
		Mount:        MountContext{Stage: StageBallots, ElectionStatus: "open", BallotsCommitted: &committed, BlockHeight: &height},
		GateExpected: "cds", GateObserved: "cds"}
	if err := e.saveScenarioResult(runID, dir, live); err != nil {
		t.Fatal(err)
	}

	// The wizard's step 7 posts /scenarios, which runs the catalogue unstaged.
	if err := e.RunScenarios(context.Background(), runID, []string{"tamper-ballot-proof", "dropped-ballot"}); err != nil {
		t.Fatal(err)
	}
	got := resultsByID(t, dir)
	if r := got["tamper-ballot-proof"]; !r.OnChain || r.Mount.Stage != StageBallots || r.GateObserved != "cds" {
		t.Fatalf("the unstaged re-run replaced the live verdict: %+v", r)
	}
	if r := got["dropped-ballot"]; r.Mount.Stage != StageUnstaged || r.Verdict != "PASS" {
		t.Errorf("a scenario with no staged verdict must still take the unstaged one: %+v", r)
	}
	rows := readCSVRows(t, dir)
	liveCol, stage := csvCol(t, rows[0], "live"), csvCol(t, rows[0], "mounted_stage")
	if rows[1][0] != "tamper-ballot-proof" || rows[1][liveCol] != "true" || rows[1][stage] != StageBallots {
		t.Errorf("negative-tests.csv lost the live row: %v", rows[1])
	}
	reruns := journalEventsOfType(t, dir, "attack.rerun.unstaged")
	if len(reruns) != 1 || jstring(reruns[0], "scenario") != "tamper-ballot-proof" ||
		jstring(reruns[0], "verdict") != "PASS" || jstring(reruns[0], "kept_mounted_stage") != StageBallots {
		t.Fatalf("journal = %v, want one attack.rerun.unstaged for tamper-ballot-proof keeping %s", reruns, StageBallots)
	}

	// Unstaged over unstaged still updates in place ...
	if err := e.RunScenarios(context.Background(), runID, []string{"dropped-ballot"}); err != nil {
		t.Fatal(err)
	}
	if n := len(journalEventsOfType(t, dir, "attack.rerun.unstaged")); n != 1 {
		t.Errorf("an unstaged re-run over an unstaged verdict was held back (%d journal events)", n)
	}
	// ... and a verdict from a later pause replaces the earlier staged one.
	again := live
	again.Mount.Stage, again.Verdict, again.GateObserved = StageBallots, "INCONCLUSIVE", "election-open"
	if err := e.saveScenarioResult(runID, dir, again); err != nil {
		t.Fatal(err)
	}
	if r := resultsByID(t, dir)["tamper-ballot-proof"]; r.Verdict != "INCONCLUSIVE" {
		t.Errorf("a staged verdict did not replace a staged verdict: %+v", r)
	}
}

// --- review fix round 1 -------------------------------------------------------

// A window that stops before its pause point (its time bound, or a cancel)
// never mounts the ballots stage, and the journal says so instead of staying
// silent about a stage the plan listed.
func TestWindowStoppedBeforeThePauseIsJournalledAsNotMounted(t *testing.T) {
	orig := runBench
	runBench = func(_ context.Context, n int, _ bench.SubmitFunc, _ bench.RunOpts) bench.RunResult {
		return bench.RunResult{Stopped: true, LastIndex: -1, ByIndex: make([]time.Duration, n), OK: make([]bool, n)}
	}
	t.Cleanup(func() { runBench = orig })

	dir := t.TempDir()
	e := newTestExecutor(t, dir)
	c := ElectionConfig{Mode: "onchain", Voters: 10, Positions: 1, AttackPlan: &AttackPlan{Stages: []string{StageBallots}}}
	res := e.pausedWindow(context.Background(), "run-1", c, newGatedLedger(), 10, 5,
		func(int) error { return nil }, bench.RunOpts{Concurrency: 2})

	if !res.Stopped || res.LastIndex != -1 || len(res.OK) != 10 {
		t.Fatalf("joined result = %+v, want a stopped window over 10 slots", res)
	}
	runDir := filepath.Join(dir, "run-1")
	if p := journalEventsOfType(t, runDir, "attack.pause"); len(p) != 0 {
		t.Errorf("a stage that was never reached journalled a pause: %v", p)
	}
	r := journalEventsOfType(t, runDir, "attack.resume")
	if len(r) != 1 || jstring(r[0], "reason") != "not mounted: window stopped" || jstring(r[0], "stage") != StageBallots {
		t.Fatalf("attack.resume = %v, want one {stage: ballots, reason: not mounted: window stopped}", r)
	}
}

// The all-in-one /submit path pauses at the ceremony stage between the
// partial decryptions and PublishTally, like the step-by-step ceremony does.
func TestSubmitPathPausesAtCeremonyBeforePublishTally(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	attackRun(t, runDir, 4)
	// A bundle with partial decryptions, so the pause's place between the
	// last partial and PublishTally is observable.
	path := filepath.Join(runDir, "bundle.json")
	raw, err := json.Marshal(onChainBundle{ElectionID: "run-1", Params: "aa", DKG: "bb", Tally: "tt",
		BallotsFile: BallotsFile, BallotCount: 4, PartialDecryptions: []string{"p0", "p1"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	led := newGatedLedger()
	c := ElectionConfig{Mode: "onchain", Voters: 4, Positions: 1, Candidates: 2, Concurrency: 2,
		AttackPlan: &AttackPlan{Stages: []string{StageCeremony}}}

	done := make(chan error, 1)
	go func() { done <- e.submitOnChain(context.Background(), "run-1", c, led, path) }()
	v := waitPause(t, e, "run-1", StageCeremony, done)
	atPause := led.callNames()
	if last := atPause[len(atPause)-1]; last != "SubmitPartialDecryption" || slices.Contains(atPause, "PublishTally") {
		t.Fatalf("at the ceremony pause the chain has seen %v; want the last call to be SubmitPartialDecryption and no PublishTally", atPause)
	}
	if n := strings.Count(strings.Join(atPause, ","), "SubmitPartialDecryption"); n != 2 {
		t.Errorf("partials committed before the pause = %d, want both", n)
	}
	if v.Mount.ElectionStatus != "closed" || v.Mount.BallotsCommitted == nil || *v.Mount.BallotsCommitted != 4 {
		t.Errorf("ceremony mount context = %+v", v.Mount)
	}
	if err := e.DecidePause("run-1", "skip", ""); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if after := led.callNames()[len(atPause):]; len(after) == 0 || after[0] != "PublishTally" {
		t.Errorf("first ledger calls after the pause = %v, want PublishTally", after)
	}
}

// A security run's window may well be one uninterrupted segment, but its
// throughput is perturbed by design: it never yields a sustained TPS or a
// scaling verdict, and run.end says why.
func TestFinaliseSecurityRunHasNoScalingVerdict(t *testing.T) {
	seg := Segment{Index: 0, Committed: 1000, WindowMs: 10000, TPS: 100, DriverCeilingTPS: 1000}
	in := FinaliseInput{Voters: 1000, Positions: 1, Segments: []Segment{seg}, ReconcileOK: true,
		EByContest: map[string]int64{}}
	if plain := Finalise(nil, in); plain.SustainedTPS == nil || plain.ScalingLimit == "inconclusive" {
		t.Fatalf("control: a plain sustained run = %+v, want a sustained TPS and a verdict", plain)
	}

	dir := t.TempDir()
	j, err := OpenJournal(dir, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	in.SecurityRun = true
	got := Finalise(j, in)
	j.Close()
	if got.SustainedTPS != nil || got.ScalingLimit != "inconclusive" {
		t.Errorf("security run = %+v, want no sustained TPS and scaling_limit inconclusive", got)
	}
	ends := journalEventsOfType(t, dir, "run.end")
	if len(ends) != 1 || ends[0]["security_run"] != true || ends[0]["sustained_tps"] != nil ||
		jstring(ends[0], "scaling_limit") != "inconclusive" {
		t.Errorf("run.end = %v, want security_run true, sustained_tps null, scaling_limit inconclusive", ends)
	}
}

// An audit document that is neither pass nor fail says nothing about whether
// the attack got through: INCONCLUSIVE, never FAIL.
func TestAuditWithoutAVerdictIsInconclusive(t *testing.T) {
	sc := Registry()[0]
	for _, overall := range []string{"", "error", "PASS"} {
		var res ScenarioResult
		classifyAudit(&res, sc, StreamAudit{Overall: overall}, true)
		if res.Verdict != "INCONCLUSIVE" {
			t.Errorf("overall=%q: verdict %q, want INCONCLUSIVE", overall, res.Verdict)
		}
	}
	var res ScenarioResult
	classifyAudit(&res, sc, StreamAudit{Overall: "pass"}, true)
	if res.Verdict != "FAIL" {
		t.Errorf("overall=pass: verdict %q, want FAIL", res.Verdict)
	}
}

// "All scenarios upheld their security property" is claimed only when every
// mounted scenario was rejected by its declared gate.
func TestCatalogueSummaryClaimsAllUpheldOnlyWhenEveryMountedOnePassed(t *testing.T) {
	for _, tc := range []struct {
		failed func(string) string
		want   string
	}{
		{declaredAuditGate, "all scenarios upheld their security property"},
		{func(string) string { return "tally.shape" }, "0 of 2 mounted scenario(s) rejected by their declared gate"},
	} {
		store := NewRunStore(t.TempDir())
		runID, dir, err := store.Create(good(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		attackRun(t, dir, 3)
		hub := NewHub()
		e := NewExecutor(store, hub, "saksi-demo", "", FabricConfig{})
		e.run = fakeAuditor(tc.failed)
		ch, cancel := hub.Subscribe(runID)
		if err := e.RunScenarios(context.Background(), runID,
			[]string{"tamper-ballot-proof", "dropped-ballot", "reordered-ballots"}); err != nil {
			t.Fatal(err)
		}
		cancel()
		var last Event
		for ev := range ch {
			if ev.Phase == "scenarios" && ev.Level == "done" {
				last = ev
			}
		}
		if !strings.HasPrefix(last.Msg, tc.want) {
			t.Errorf("summary = %q, want it to start %q", last.Msg, tc.want)
		}
	}

	// Nothing mounted (reordered-ballots alone is always SKIPPED): claiming
	// every property upheld would be vacuous.
	store := NewRunStore(t.TempDir())
	runID, dir, err := store.Create(good(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	attackRun(t, dir, 3)
	hub := NewHub()
	e := NewExecutor(store, hub, "saksi-demo", "", FabricConfig{})
	ch, cancel := hub.Subscribe(runID)
	if err := e.RunScenarios(context.Background(), runID, []string{"reordered-ballots"}); err != nil {
		t.Fatal(err)
	}
	cancel()
	for ev := range ch {
		if ev.Phase == "scenarios" && ev.Level == "done" && ev.Msg != "no scenario was mounted, so no security property was tested" {
			t.Errorf("summary with nothing mounted = %q", ev.Msg)
		}
	}
}

// An offline /run-all never reaches a pause, so an attack plan there would be
// silently ignored on a run still marked security_run: refused with a pointer
// to the step-by-step ceremony. The same plan stays valid for that flow, and
// run-all without a plan is untouched.
func TestOfflineRunAllRefusesAnAttackPlan(t *testing.T) {
	_, h, _ := testServer(t, nil)
	c := good()
	c.AttackPlan = &AttackPlan{Stages: []string{StageDKG}}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postJSON("/run-all", c))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "step-by-step ceremony") {
		t.Fatalf("offline /run-all with a plan = %d %q, want 400 pointing at the step-by-step ceremony", rec.Code, rec.Body)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("the offline plan must stay valid for the step-by-step flow: %v", err)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, postJSON("/generate", c))
	if rec.Code != http.StatusAccepted {
		t.Errorf("/generate with an offline plan = %d, want 202", rec.Code)
	}
	c.AttackPlan = nil
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, postJSON("/run-all", c))
	if rec.Code != http.StatusAccepted {
		t.Errorf("offline /run-all without a plan = %d, want 202", rec.Code)
	}
}

// Several endorsers can each attach a message. If any of them names a gate
// other than the declared one, the attack did not meet the gate under test
// everywhere: INCONCLUSIVE, with every observed gate recorded.
func TestLiveAttackNamingAnotherGateAnywhereIsInconclusive(t *testing.T) {
	sc := Scenario{ID: "t", ChainGate: "cds"}
	var res ScenarioResult
	classifyLive(&res, sc, errString("submit SubmitBallot: failed to endorse; chaincode response 500, gate=cds: proof failed; "+
		"chaincode response 500, gate=election-open: election \"e\" is not open for ballots"))
	if res.Verdict != "INCONCLUSIVE" || res.GateObserved != "cds;election-open" {
		t.Fatalf("verdict/observed = %q/%q, want INCONCLUSIVE with cds;election-open", res.Verdict, res.GateObserved)
	}
	if want := "rejected by election-open: election \"e\" is not open for ballots"; res.Actual != want {
		t.Errorf("actual = %q, want %q", res.Actual, want)
	}

	res = ScenarioResult{}
	classifyLive(&res, sc, errString("chaincode response 500, gate=cds: proof failed; chaincode response 500, gate=cds: proof failed"))
	if res.Verdict != "PASS" || res.GateObserved != "cds" || res.Actual != "rejected by chaincode gate cds (the declared gate): proof failed" {
		t.Errorf("two endorsers both at the declared gate = %+v, want PASS", res)
	}
}

// A decision is either applied or refused: once a run-all or skip is accepted,
// or the wait has run out, later decisions get 409 instead of a 202 that is
// silently dropped; a decision queued before the wait ran out is still applied.
func TestDecisionsAfterTheStageClosesAreRefusedNotDropped(t *testing.T) {
	e := testExec(t)
	view := PauseView{Paused: true, Stage: StageBallots, Scenarios: []string{"reused-nullifier"}}

	p := &stagePause{decide: make(chan pauseDecision, 8), view: view}
	e.setPause("r", p)
	if err := e.DecidePause("r", "run-all", ""); err != nil {
		t.Fatal(err)
	}
	if err := e.DecidePause("r", "run", "reused-nullifier"); !errors.Is(err, errPauseEnded) {
		t.Errorf("a decision after run-all = %v, want errPauseEnded", err)
	}

	p = &stagePause{decide: make(chan pauseDecision, 8), view: view}
	e.setPause("r", p)
	if err := e.DecidePause("r", "run", "reused-nullifier"); err != nil {
		t.Fatal(err)
	}
	if p.closeIfIdle() {
		t.Fatal("the wait closed the stage with a decision still queued; that decision would be dropped")
	}
	<-p.decide // the loop applies it
	if !p.closeIfIdle() {
		t.Fatal("an idle stage did not close when the wait ran out")
	}
	if err := e.DecidePause("r", "skip", ""); !errors.Is(err, errPauseEnded) {
		t.Errorf("a decision after the timeout = %v, want errPauseEnded", err)
	}

	// Over HTTP that refusal is a 409.
	s, h, exec := testServer(t, nil)
	runID, _, err := s.store.Create(good(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	closed := &stagePause{decide: make(chan pauseDecision, 1), view: view, closed: true}
	exec.setPause(runID, closed)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postJSON("/api/runs/"+runID+"/pause", map[string]string{"action": "skip"}))
	if rec.Code != http.StatusConflict {
		t.Errorf("POST to a closed stage = %d, want 409", rec.Code)
	}
}
