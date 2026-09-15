package campaign

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// NegativeTestsFile is the per-run negative/vulnerability results CSV.
const NegativeTestsFile = "negative-tests.csv"

// ScenarioStateFile accumulates scenario verdicts across calls. The CSV is a
// derived export and is rewritten in full from this file, so running scenarios
// one at a time (as the wizard does, a step per attack) cannot truncate the
// export to whichever subset happened to run last.
const ScenarioStateFile = "scenarios.json"

// Layer names the verifier that PROVABLY rejects an attack, so a scenario is
// only ever asserted against the layer that actually catches it (asserting
// otherwise would be a false FAIL, not a finding).
type Layer int

const (
	// LayerOffline: rejected by the offline auditor (audit-stream).
	LayerOffline Layer = iota
	// LayerChaincode: not rejected by the offline auditor. The only scenario
	// here, reordered-ballots, is rejected by nothing: see its registry entry.
	LayerChaincode
)

func (l Layer) String() string {
	if l == LayerChaincode {
		return "chaincode"
	}
	return "offline"
}

// Scenario is one negative/vulnerability test: a single mutation of a generated
// run plus the layer + property it exercises.
type Scenario struct {
	ID       string
	Property string // security property the rejection upholds
	Layer    Layer
	Action   string // human description of the mutation
	Expected string // human description of the expected rejection
	// Stage is the point in the election lifecycle this attack belongs to, so
	// the wizard can offer it while the election is running rather than only
	// after the count. Kept beside the mutation, exactly as Action/Expected
	// are, so the page never hardcodes which attack happens when.
	Stage  string
	Mutate func(dir string) error

	// The gate this attack tests. A verdict is PASS only when THIS gate
	// rejected the attack: a rejection by any other check says nothing about
	// it (see classifyLive / classifyAudit).
	//
	// ChainGate is the chaincode gate id ("gate=<id>:" in its rejection) that
	// must refuse the attack when it is submitted to a live election. Empty
	// when no on-chain gate checks what the attack breaks: such an attack is
	// never submitted live, because the ledger would accept it and poison the
	// election it was meant to test.
	ChainGate string
	// AuditGate is the auditor check id (audit-stream's failed_checks) that
	// must fail when the attack runs as a simulation against a copy.
	AuditGate string
	// OnChainNote says what the ledger does with this attack when ChainGate is
	// empty, so a simulated row recorded during a live election cannot be read
	// as a ledger rejection. For the DKG and partial-decryption attacks it is
	// a weakness, not a design choice: the chaincode checks only shape and
	// presence and never asks who is calling, so any channel client can publish
	// a transcript or a share first and the real one is then refused as a
	// duplicate (see the runbook's attack findings).
	OnChainNote string
	// MutateBallot is the ballot-stage mutation on single ballots, for the
	// mid-submission mount: target is a ballot the window has not submitted,
	// committed one it already has. Nil for attacks on anything but a ballot.
	MutateBallot func(target, committed string) (string, error)
}

// Lifecycle stages an attack can be mounted at. They map onto wizard steps:
// dkg/ballots/close are all inside step 4 (Encrypt & record) in submission
// order, ceremony is step 5.
const (
	StageDKG      = "dkg"      // before any ballot is submitted
	StageBallots  = "ballots"  // while ballots are being submitted
	StageClose    = "close"    // after CloseElection, before decryption
	StageCeremony = "ceremony" // during the trustee ceremony
)

// StageOrder is the lifecycle order, for rendering.
var StageOrder = []string{StageDKG, StageBallots, StageClose, StageCeremony}

// ScenariosForStage returns the attacks that belong at one lifecycle stage.
func ScenariosForStage(stage string) []Scenario {
	var out []Scenario
	for _, sc := range Registry() {
		if sc.Stage == stage {
			out = append(out, sc)
		}
	}
	return out
}

// ScenarioResult is one row of negative-tests.csv.
type ScenarioResult struct {
	Scenario string
	Layer    string
	Action   string
	Expected string
	Actual   string
	// Verdict: PASS (rejected by the declared gate) | INCONCLUSIVE (rejected by
	// another gate, or not mounted faithfully) | FAIL (nothing rejected it) |
	// SKIPPED (never mounted).
	Verdict  string
	Property string
	// OnChain records whether the attack was really submitted to the ledger
	// and refused by the chaincode, or simulated against a copy of the run.
	// The distinction matters in the export: only one of them is evidence
	// about the deployed system.
	OnChain bool
	Stage   string
	// Mount is the state of the election when the attack was mounted.
	Mount MountContext
	// GateExpected is the declared gate for the way the attack was mounted (a
	// chaincode gate id live, an auditor check id simulated); GateObserved is
	// what actually refused it: the chaincode gate id, or every failed auditor
	// check ";"-joined.
	GateExpected string
	GateObserved string
}

// Registry is the offline-detectable attack catalog. Each entry is grounded in
// an existing auditor tamper test (independent_verification.rs / tests.rs), so
// the offline auditor is proven to reject it, except reordered-ballots, which
// no verifier checks (LayerChaincode, always SKIPPED).
func Registry() []Scenario {
	return []Scenario{
		{
			ID: "tamper-ballot-proof", Stage: StageBallots, Property: "ballot well-formedness (CDS proof)",
			Layer: LayerOffline, Action: "flip a byte in a ballot's CDS proof response",
			Expected:  "rejected by the CDS proof check (chaincode gate cds live, auditor ballot.cds_proof simulated)",
			ChainGate: "cds", AuditGate: "ballot.cds_proof",
			Mutate: func(dir string) error {
				return editBallotLines(dir, func(lines []string) error {
					var err error
					lines[0], err = tamperBallotProof(lines[0])
					return err
				})
			},
			MutateBallot: func(target, _ string) (string, error) { return tamperBallotProof(target) },
		},
		{
			ID: "reused-nullifier", Stage: StageBallots, Property: "no double voting (per-position nullifier)",
			Layer: LayerOffline, Action: "copy a cast ballot's nullifier onto another ballot",
			Expected:  "rejected as a double vote (chaincode gate nullifier live, auditor nullifier.unique simulated)",
			ChainGate: "nullifier", AuditGate: "nullifier.unique",
			Mutate: func(dir string) error {
				return editBallotLines(dir, func(lines []string) error {
					if len(lines) < 2 {
						return fmt.Errorf("need >=2 ballots to reuse a nullifier")
					}
					var err error
					lines[1], err = reuseNullifier(lines[1], lines[0])
					return err
				})
			},
			MutateBallot: reuseNullifier,
		},
		{
			ID: "dropped-ballot", Stage: StageClose, Property: "ballot-box completeness",
			Layer: LayerOffline, Action: "remove one committed ballot line",
			Expected:    "auditor rejects: stream.completeness (fewer ballots than the header declares)",
			AuditGate:   "stream.completeness",
			OnChainNote: "on-chain: not mountable as one submission (a dropped ballot is an absence across the set)",
			Mutate: func(dir string) error {
				lines, err := readBallotLines(dir)
				if err != nil {
					return err
				}
				if len(lines) < 2 {
					return fmt.Errorf("need >=2 ballots to drop one")
				}
				return writeBallotLines(dir, lines[1:])
			},
		},
		{
			// No gate checks ordering. The stateless auditor recomputes the same
			// tally and proofs whatever the ballot order (verified: it passed a
			// reordered run), and the chaincode keys ballots by nullifier with no
			// ordering or digest check at all. The scenario stays in the catalogue
			// so the gap is on record, and it is never mounted.
			ID: "reordered-ballots", Stage: StageClose, Property: "ledger integrity (ordering)",
			Layer: LayerChaincode, Action: "swap the first two ballot lines",
			Expected: "no gate: ordering is not checked on-chain or by the stateless auditor",
			Mutate: func(dir string) error {
				lines, err := readBallotLines(dir)
				if err != nil {
					return err
				}
				if len(lines) < 2 {
					return fmt.Errorf("need >=2 ballots to reorder")
				}
				lines[0], lines[1] = lines[1], lines[0]
				return writeBallotLines(dir, lines)
			},
		},
		{
			ID: "corrupted-ballot-bytes", Stage: StageBallots, Property: "wire integrity",
			Layer: LayerOffline, Action: "corrupt a ballot's first wire byte so the protobuf no longer parses",
			Expected:  "rejected as undecodable (chaincode gate decode live, auditor ballot.decode simulated)",
			ChainGate: "decode", AuditGate: "ballot.decode",
			Mutate: func(dir string) error {
				return editBallotLines(dir, func(lines []string) error {
					var err error
					lines[0], err = corruptBallotWire(lines[0])
					return err
				})
			},
			MutateBallot: func(target, _ string) (string, error) { return corruptBallotWire(target) },
		},
		{
			ID: "tamper-partial-decryption", Stage: StageCeremony, Property: "threshold-decryption integrity",
			Layer: LayerOffline, Action: "flip a byte in a trustee's Chaum-Pedersen proof response",
			Expected:    "auditor rejects: decryption.cp_proof (the proof does not verify)",
			AuditGate:   "decryption.cp_proof",
			OnChainNote: "on-chain: not checked (shape/presence only, no caller authorization)",
			Mutate: func(dir string) error {
				return mutateHeader(dir, func(h map[string]any) error {
					arr, ok := h["partial_decryptions"].([]any)
					if !ok || len(arr) == 0 {
						return fmt.Errorf("no partial_decryptions in header")
					}
					s, _ := arr[0].(string)
					tampered, err := TamperPartialProof(s)
					if err != nil {
						return err
					}
					arr[0] = tampered
					h["partial_decryptions"] = arr
					return nil
				})
			},
		},
		{
			ID: "tamper-dkg-transcript", Stage: StageDKG, Property: "DKG transcript integrity",
			Layer: LayerOffline, Action: "flip a byte in a trustee's DKG coefficient commitment",
			Expected:    "auditor rejects: dkg.decode (the commitment is not a valid point)",
			AuditGate:   "dkg.decode",
			OnChainNote: "on-chain: not checked (shape/presence only, no caller authorization)",
			Mutate: func(dir string) error {
				return mutateHeader(dir, func(h map[string]any) error {
					s, ok := h["dkg"].(string)
					if !ok || s == "" {
						return fmt.Errorf("no dkg in header")
					}
					tampered, err := tamperDKGCommitment(s)
					if err != nil {
						return err
					}
					h["dkg"] = tampered
					return nil
				})
			},
		},
	}
}

// RunScenarios runs the selected scenarios (all if list is empty) over the run,
// writing negative-tests.csv into the source run folder. Each scenario runs on a
// fresh COPY of the run (never mutating the source), with a positive control
// (the unmutated copy must audit clean) so a false green is impossible.
func (e *Executor) RunScenarios(ctx context.Context, runID string, list []string) error {
	srcDir, err := e.store.Dir(runID)
	if err != nil {
		return err
	}
	selected := selectScenarios(list)
	e.publish(runID, "scenarios", "info", fmt.Sprintf("running %d scenario(s)…", len(selected)))

	var results []ScenarioResult
	for _, sc := range selected {
		res := e.runOneScenario(ctx, runID, srcDir, sc)
		// The catalogue runs against the generated artifacts, not at a
		// lifecycle pause: nothing about the election's state is claimed.
		res.Mount = MountContext{Stage: StageUnstaged}
		results = append(results, res)
	}

	// Merge into the accumulated set before exporting: a caller running a
	// single scenario must not erase the verdicts of the other six.
	merged, held, err := mergeScenarioResults(srcDir, results)
	if err != nil {
		return err
	}
	e.journalHeldBack(runID, merged, held)
	if err := writeNegativeTestsCSV(filepath.Join(srcDir, NegativeTestsFile), merged); err != nil {
		return err
	}
	fails, passes, mounted := 0, 0, 0
	for _, r := range results {
		switch r.Verdict {
		case "FAIL":
			fails++
		case "PASS":
			passes++
		}
		if r.Verdict != "SKIPPED" {
			mounted++
		}
	}
	switch {
	case fails > 0:
		e.publish(runID, "scenarios", "error",
			fmt.Sprintf("%d scenario(s) FAILED — a gate that should have rejected did not", fails))
	case mounted == 0:
		e.publish(runID, "scenarios", "done", "no scenario was mounted, so no security property was tested")
	case passes == mounted:
		e.publish(runID, "scenarios", "done", "all scenarios upheld their security property")
	default:
		e.publish(runID, "scenarios", "done", fmt.Sprintf(
			"%d of %d mounted scenario(s) rejected by their declared gate; the rest are INCONCLUSIVE, not passes",
			passes, mounted))
	}
	return nil
}

func (e *Executor) runOneScenario(ctx context.Context, runID, srcDir string, sc Scenario) ScenarioResult {
	res := ScenarioResult{
		Scenario: sc.ID, Layer: sc.Layer.String(), Action: sc.Action,
		Expected: sc.Expected, Property: sc.Property, Stage: sc.Stage,
		GateExpected: sc.AuditGate,
	}

	// An attack no verifier checks is never mounted: asserting it against the
	// auditor would be a false FAIL, and no network would change that.
	if sc.Layer == LayerChaincode {
		res.Verdict, res.Actual = "SKIPPED", "no gate exists to test"
		e.publish(runID, "scenarios", "info", sc.ID+": skipped (no gate exists to test)")
		return res
	}

	// A trial that could not be set up faithfully is INCONCLUSIVE, never FAIL:
	// FAIL is the claim that a gate let an attack through, and nothing was
	// attempted here.
	scenDir := filepath.Join(srcDir, "scenarios", sc.ID)
	if err := copyStream(srcDir, scenDir); err != nil {
		res.Verdict, res.Actual = "INCONCLUSIVE", "not mounted: could not copy run: "+err.Error()
		return res
	}

	// Positive control: the unmutated copy MUST audit clean, else a rejection
	// after mutation could be for an unrelated reason (false green).
	if sa, ok := e.auditStream(ctx, scenDir); !ok || sa.Overall != "pass" {
		res.Verdict, res.Actual = "INCONCLUSIVE", "not mounted: positive control did not pass on the unmutated copy"
		return res
	}

	if err := sc.Mutate(scenDir); err != nil {
		res.Verdict, res.Actual = "INCONCLUSIVE", "not mounted: mutation error: "+err.Error()
		return res
	}

	sa, ok := e.auditStream(ctx, scenDir)
	classifyAudit(&res, sc, sa, ok)
	level := "info"
	if res.Verdict == "FAIL" {
		level = "error"
	}
	e.publish(runID, "scenarios", level, sc.ID+": "+res.Verdict+" — "+res.Actual)
	return res
}

// classifyAudit decides a simulated attack's verdict from the auditor's own
// account of which checks failed.
//
// PASS needs the declared check among the failures. The auditor never stops
// at the first failure, so others may fail beside it (a reused nullifier also
// breaks the CDS proof bound to it); they are recorded, not held against the
// verdict. A failed audit that does not include the declared check is
// INCONCLUSIVE: something caught the attack, but not the gate under test.
func classifyAudit(res *ScenarioResult, sc Scenario, sa StreamAudit, ok bool) {
	res.GateExpected = sc.AuditGate
	switch {
	case !ok:
		res.Verdict = "INCONCLUSIVE"
		res.Actual = "rejected by an unidentified gate: audit-stream produced no valid result (it refused the input before auditing)"
		return
	case sa.Overall == "pass":
		res.Verdict, res.Actual = "FAIL", "NOT rejected — the audit passed a mutated run"
		return
	case sa.Overall != "fail":
		// Neither verdict: nothing says the attack got through, or what caught it.
		res.Verdict = "INCONCLUSIVE"
		res.Actual = fmt.Sprintf("rejected by an unidentified gate: audit-stream reported overall=%q, neither pass nor fail", sa.Overall)
		return
	}
	ids := make([]string, 0, len(sa.FailedChecks))
	for _, f := range sa.FailedChecks {
		ids = append(ids, f.Check)
	}
	res.GateObserved = strings.Join(ids, ";")
	for _, f := range sa.FailedChecks {
		if sc.AuditGate != "" && f.Check == sc.AuditGate {
			res.Verdict = "PASS"
			res.Actual = "rejected by auditor check " + f.Check + " (the declared gate): " + truncateErr(f.Detail)
			return
		}
	}
	res.Verdict = "INCONCLUSIVE"
	if len(sa.FailedChecks) == 0 {
		res.Actual = "rejected by an unidentified gate: the audit failed without naming a check " +
			"(this saksi-demo predates failed_checks — rebuild it)"
		return
	}
	res.Actual = "rejected by " + sa.FailedChecks[0].Check + ", not the declared " + sc.AuditGate + ": " +
		truncateErr(sa.FailedChecks[0].Detail)
}

// auditStream shells audit-stream --json and returns the parsed result plus
// whether the output was valid (an unparseable result means the tool refused
// the input before auditing — a rejection, but by no check it names).
func (e *Executor) auditStream(ctx context.Context, dir string) (StreamAudit, bool) {
	out, _ := e.run(ctx, e.demoBin, "audit-stream", dir, "--json")
	var sa StreamAudit
	if json.Unmarshal(out, &sa) != nil {
		return StreamAudit{}, false
	}
	return sa, true
}

func selectScenarios(list []string) []Scenario {
	all := Registry()
	if len(list) == 0 {
		return all
	}
	want := make(map[string]bool, len(list))
	for _, id := range list {
		want[id] = true
	}
	var out []Scenario
	for _, sc := range all {
		if want[sc.ID] {
			out = append(out, sc)
		}
	}
	return out
}

// --- ballot / header mutation helpers --------------------------------------

// readBallotLines scans the stream rather than slurping it, so one oversized
// line fails by number instead of the whole file arriving as one string. The
// slice IS the whole population: a mutation that drops, reorders or rewrites a
// line has to rewrite the file, which needs every other line. That bounds the
// negative-test scenarios to demo-scale runs — the measured tiers stream
// through scanBallotLines and never come here.
func readBallotLines(dir string) ([]string, error) {
	var lines []string
	err := scanBallotLines(dir, func(_ int, line string) error {
		if line != "" {
			lines = append(lines, line)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return lines, nil
}

func writeBallotLines(dir string, lines []string) error {
	body := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(filepath.Join(dir, BallotsFile), []byte(body), 0o644)
}

// editBallotLines rewrites a run's ballots.ndjson through fn.
func editBallotLines(dir string, fn func(lines []string) error) error {
	lines, err := readBallotLines(dir)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return fmt.Errorf("no ballots")
	}
	if err := fn(lines); err != nil {
		return err
	}
	return writeBallotLines(dir, lines)
}

// editBallot decodes one hex ballot, applies fn, and re-encodes it — the
// decode→mutate→re-encode path, so a mutation changes exactly the field it
// names and the result is still a well-formed protobuf.
func editBallot(hexLine string, fn func(*pb.Ballot) error) (string, error) {
	var b pb.Ballot
	if err := decodeHexProto(hexLine, &b); err != nil {
		return "", fmt.Errorf("ballot: %w", err)
	}
	if err := fn(&b); err != nil {
		return "", err
	}
	return encodeHexProto(&b)
}

func decodeHexProto(hexStr string, m proto.Message) error {
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return fmt.Errorf("not hex: %w", err)
	}
	return proto.Unmarshal(raw, m)
}

func encodeHexProto(m proto.Message) (string, error) {
	enc, err := proto.Marshal(m)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(enc), nil
}

// tamperBallotProof flips the low bit of the first CDS branch's response. The
// scalar stays canonical, so the proof is well-formed and simply wrong: only
// proof verification can catch it.
func tamperBallotProof(hexLine string) (string, error) {
	return editBallot(hexLine, func(b *pb.Ballot) error {
		if len(b.WellFormednessProofs) == 0 || len(b.WellFormednessProofs[0].Branches) == 0 ||
			len(b.WellFormednessProofs[0].Branches[0].Response) == 0 {
			return fmt.Errorf("ballot has no CDS proof to tamper")
		}
		b.WellFormednessProofs[0].Branches[0].Response[0] ^= 0x01
		return nil
	})
}

// reuseNullifier gives target the nullifier of committed, an already-cast
// ballot. The credential signature covers the commitment, not the nullifier,
// so the ballot still passes every check up to the double-vote one.
func reuseNullifier(target, committed string) (string, error) {
	var donor pb.Ballot
	if err := decodeHexProto(committed, &donor); err != nil {
		return "", fmt.Errorf("no committed ballot to take a nullifier from: %w", err)
	}
	val := donor.GetCredentialPresentation().GetNullifier().GetValue()
	if len(val) == 0 {
		return "", fmt.Errorf("the committed ballot has no nullifier")
	}
	return editBallot(target, func(b *pb.Ballot) error {
		if b.GetCredentialPresentation().GetNullifier() == nil {
			return fmt.Errorf("target ballot has no nullifier")
		}
		if string(b.CredentialPresentation.Nullifier.Value) == string(val) {
			return fmt.Errorf("target and committed ballot already share a nullifier")
		}
		b.CredentialPresentation.Nullifier.Value = append([]byte(nil), val...)
		return nil
	})
}

// corruptBallotWire sets the first tag byte's wire type to 7, which protobuf
// reserves: the ballot then fails to parse in every decoder, deterministically.
// A byte flipped at a random offset usually lands inside a proof and is caught
// by proof verification instead, which would make this a second copy of
// tamper-ballot-proof rather than a test of the decode gate.
func corruptBallotWire(hexLine string) (string, error) {
	raw, err := hex.DecodeString(hexLine)
	if err != nil || len(raw) == 0 {
		return "", fmt.Errorf("ballot is not decodable hex")
	}
	if raw[0]&0x07 == 0x07 {
		return "", fmt.Errorf("ballot already starts with a reserved wire type")
	}
	raw[0] |= 0x07
	return hex.EncodeToString(raw), nil
}

// TamperPartialProof flips the low bit of a partial decryption's
// Chaum-Pedersen response: a well-formed proof that does not verify. (Flipping
// the last hex character, as this scenario once did, rewrote the contest id.)
// Exported so a driver outside this package (cmd/samplechain) can apply the
// exact same mutation a staged attack does, rather than reimplementing it.
func TamperPartialProof(hexStr string) (string, error) {
	var pd pb.PartialDecryption
	if err := decodeHexProto(hexStr, &pd); err != nil {
		return "", fmt.Errorf("partial decryption: %w", err)
	}
	if len(pd.GetProof().GetResponse()) == 0 {
		return "", fmt.Errorf("partial decryption has no Chaum-Pedersen response to tamper")
	}
	pd.Proof.Response[0] ^= 0x01
	return encodeHexProto(&pd)
}

// tamperDKGCommitment flips the low bit of trustee 0's constant-term
// commitment, the same mutation as the auditor's own tamper test. A canonical
// ristretto255 encoding has that bit clear, so the point no longer decodes.
func tamperDKGCommitment(hexStr string) (string, error) {
	var t pb.DKGTranscript
	if err := decodeHexProto(hexStr, &t); err != nil {
		return "", fmt.Errorf("DKG transcript: %w", err)
	}
	if len(t.GetTrusteeCommitments()) == 0 || len(t.TrusteeCommitments[0].GetCoefficientCommitments()) == 0 ||
		len(t.TrusteeCommitments[0].CoefficientCommitments[0]) == 0 {
		return "", fmt.Errorf("DKG transcript has no coefficient commitment to tamper")
	}
	t.TrusteeCommitments[0].CoefficientCommitments[0][0] ^= 0x01
	return encodeHexProto(&t)
}

func mutateHeader(dir string, fn func(map[string]any) error) error {
	path := filepath.Join(dir, "header.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		return err
	}
	if err := fn(h); err != nil {
		return err
	}
	out, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

func copyStream(srcDir, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"header.json", BallotsFile} {
		data, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			return fmt.Errorf("copy %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(dstDir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// ScenarioListing is one attack as the wizard renders it: the briefing (what
// the attack does, what it targets, what Saksi is expected to do about it)
// joined with this run's verdict, if it has been exercised yet.
//
// The briefing text is served from Registry() rather than duplicated in the
// page so it cannot drift away from the code that performs the mutation.
type ScenarioListing struct {
	ID       string `json:"id"`
	Property string `json:"property"`
	Layer    string `json:"layer"`
	Action   string `json:"action"`
	Expected string `json:"expected"`
	Verdict  string `json:"verdict"` // "" until the scenario has been run
	Actual   string `json:"actual"`
	Stage    string `json:"stage"`
	Live     bool   `json:"live"`     // can be mounted against a running ledger
	WasLive  bool   `json:"was_live"` // this verdict came from a real submission
	// The gates this attack declares, one per way of mounting it, and what the
	// recorded verdict expected and observed.
	ChainGate    string `json:"chain_gate"`
	AuditGate    string `json:"audit_gate"`
	GateExpected string `json:"gate_expected"`
	GateObserved string `json:"gate_observed"`
	MountedStage string `json:"mounted_stage"`
}

// ScenarioListings returns every registered attack for a run, in Registry
// order, each carrying its verdict if one has been recorded.
func ScenarioListings(dir string) ([]ScenarioListing, error) {
	done, err := readScenarioResults(dir)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]ScenarioResult, len(done))
	for _, r := range done {
		byID[r.Scenario] = r
	}

	reg := Registry()
	out := make([]ScenarioListing, 0, len(reg))
	for _, sc := range reg {
		l := ScenarioListing{
			ID: sc.ID, Property: sc.Property, Layer: sc.Layer.String(),
			Action: sc.Action, Expected: sc.Expected,
			Stage: sc.Stage, Live: sc.LiveCapable(),
			ChainGate: sc.ChainGate, AuditGate: sc.AuditGate,
		}
		if r, ok := byID[sc.ID]; ok {
			l.Verdict, l.Actual, l.WasLive = r.Verdict, r.Actual, r.OnChain
			l.GateExpected, l.GateObserved, l.MountedStage = r.GateExpected, r.GateObserved, r.Mount.Stage
		}
		out = append(out, l)
	}
	return out, nil
}

// readScenarioResults returns the verdicts accumulated for a run so far. A
// missing file is not an error — it is a run whose scenarios have not been
// exercised yet.
func readScenarioResults(dir string) ([]ScenarioResult, error) {
	data, err := os.ReadFile(filepath.Join(dir, ScenarioStateFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []ScenarioResult
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", ScenarioStateFile, err)
	}
	return out, nil
}

// mergeScenarioResults upserts fresh results into the accumulated set and
// persists it, returning the whole set ordered by Registry() so the CSV export
// has a stable row order no matter what sequence produced the verdicts.
//
// One exception to "fresh replaces prior": a result mounted outside any pause
// (unstaged — the step-7 catalogue, or /attack on its own) never replaces one
// mounted at a lifecycle pause. The staged row is the evidence of what the
// gate did to the attack at the moment it belongs to, often a live submission,
// and negative-tests.csv is the only artifact that carries it; a later
// simulated re-run must not erase it. Such results are returned in held for
// the caller to journal instead.
func mergeScenarioResults(dir string, fresh []ScenarioResult) (merged, held []ScenarioResult, err error) {
	prior, err := readScenarioResults(dir)
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[string]ScenarioResult, len(prior)+len(fresh))
	for _, r := range prior {
		byID[r.Scenario] = r
	}
	// Fresh results replace prior ones: re-running a scenario updates its row
	// rather than appending a second one for the same id.
	for _, r := range fresh {
		if p, ok := byID[r.Scenario]; ok && p.staged() && !r.staged() {
			held = append(held, r)
			continue
		}
		byID[r.Scenario] = r
	}

	for _, sc := range Registry() {
		if r, ok := byID[sc.ID]; ok {
			merged = append(merged, r)
		}
	}

	data, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, ScenarioStateFile), data, 0o644); err != nil {
		return nil, nil, err
	}
	return merged, held, nil
}

// staged reports a verdict mounted at a lifecycle pause of the attack timeline.
func (r ScenarioResult) staged() bool {
	return r.Mount.Stage != "" && r.Mount.Stage != StageUnstaged
}

// journalHeldBack records each unstaged re-run mergeScenarioResults kept out
// of negative-tests.csv, so the re-run is on record without displacing the
// verdict mounted at its pause.
func (e *Executor) journalHeldBack(runID string, merged, held []ScenarioResult) {
	if len(held) == 0 {
		return
	}
	kept := make(map[string]string, len(merged))
	for _, r := range merged {
		kept[r.Scenario] = r.Mount.Stage
	}
	j := e.journalFor(runID)
	defer j.Close()
	for _, r := range held {
		_ = j.Stamp("attack.rerun.unstaged", map[string]any{
			"scenario": r.Scenario, "verdict": r.Verdict, "actual": r.Actual, "live": r.OnChain,
			"gate_expected": r.GateExpected, "gate_observed": r.GateObserved,
			"kept_mounted_stage": kept[r.Scenario],
		})
		e.publish(runID, "attack", "info", fmt.Sprintf(
			"%s: unstaged re-run (%s) recorded in the journal; negative-tests.csv keeps the verdict mounted at %s",
			r.Scenario, r.Verdict, kept[r.Scenario]))
	}
}

func writeNegativeTestsCSV(path string, results []ScenarioResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write([]string{
		"scenario", "stage", "layer", "action", "expected", "actual", "verdict", "property", "on_chain",
		"attempted", "rejected", "rate",
		// Mount context: where in the lifecycle the attack was mounted and what
		// the election looked like then, and which gate was meant to refuse it
		// against which one did.
		"mounted_stage", "election_status", "ballots_committed", "block_height", "live",
		"gate_expected", "gate_observed",
	}); err != nil {
		return err
	}
	var totalAttempted, totalRejected int
	for _, r := range results {
		attempted, rejected := r.rejection()
		totalAttempted, totalRejected = totalAttempted+attempted, totalRejected+rejected
		if err := w.Write([]string{
			r.Scenario, r.Stage, r.Layer, r.Action, r.Expected, r.Actual, r.Verdict, r.Property,
			strconv.FormatBool(r.OnChain),
			strconv.Itoa(attempted), strconv.Itoa(rejected), rejectionRate(attempted, rejected),
			r.Mount.Stage, r.Mount.ElectionStatus, optInt(r.Mount.BallotsCommitted), optUint(r.Mount.BlockHeight),
			strconv.FormatBool(r.OnChain), r.GateExpected, r.GateObserved,
		}); err != nil {
			return err
		}
	}
	// Totals last: the paper quotes one rejection rate for the whole catalog.
	if err := w.Write([]string{
		"summary", "", "", "", "", "", "", "", "",
		strconv.Itoa(totalAttempted), strconv.Itoa(totalRejected),
		rejectionRate(totalAttempted, totalRejected),
		"", "", "", "", "", "", "",
	}); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}

// rejection counts one scenario's attack attempts and refusals by the gate it
// declares. One mounting per scenario, live or simulated; a PASS verdict IS
// the refusal (the verdict is inverted — see mountLiveAttack). SKIPPED was never
// mounted and INCONCLUSIVE never reached, or was not refused by, the gate under
// test: neither is a trial of that gate, so both count as no attempt — rather
// than as an attack that got through, or as one the gate stopped.
func (r ScenarioResult) rejection() (attempted, rejected int) {
	switch r.Verdict {
	case "PASS":
		return 1, 1
	case "FAIL":
		return 1, 0
	}
	return 0, 0
}

func optInt(v *int) string {
	if v == nil {
		return ""
	}
	return strconv.Itoa(*v)
}

func optUint(v *uint64) string {
	if v == nil {
		return ""
	}
	return strconv.FormatUint(*v, 10)
}

// rejectionRate is blank when nothing was attempted: 0/0 is not 0%.
func rejectionRate(attempted, rejected int) string {
	if attempted == 0 {
		return ""
	}
	return strconv.FormatFloat(float64(rejected)/float64(attempted), 'f', 2, 64)
}

// LiveCapable reports whether this attack may be submitted to a running
// ledger: only when an on-chain gate exists to refuse it. Without one the
// ledger would accept the tampered artifact into the real election (a DKG
// transcript or a partial decryption the chaincode only shape-checks), so the
// attack runs simulated instead. `close`-stage attacks are about what is
// MISSING or REORDERED across the whole ballot set, which no single submission
// expresses, so they have no chain gate either.
func (s Scenario) LiveCapable() bool {
	return s.ChainGate != ""
}

// attackSubmitter is the slice of the bulletin client a live attack needs.
// Narrowing it to three methods is what lets the verdict logic — which INVERTS,
// treating a rejection as a pass — be tested without a Fabric network.
// *clientsdk.BulletinClient satisfies it as it stands.
type attackSubmitter interface {
	SubmitBallot(ballotHex string) error
	SubmitPartialDecryption(electionID, partialHex string) error
	PublishDKGTranscript(transcriptHex string) error
}

// runLiveScenario mounts a REAL attack against the running election: dial the
// peer, then hand off to mountLiveAttack.
func (e *Executor) runLiveScenario(ctx context.Context, runID, srcDir string, sc Scenario) ScenarioResult {
	res := newLiveResult(sc)
	if !sc.LiveCapable() {
		res.Verdict = "SKIPPED"
		res.Actual = "no on-chain gate refuses this attack — it runs as a simulation instead"
		return res
	}
	conn, err := e.fabric.Connect()
	if err != nil {
		res.Verdict, res.Actual = "SKIPPED", "connect to Fabric: "+err.Error()
		return res
	}
	defer conn.Close()

	b, err := e.readBundle(runID)
	if err != nil {
		res.Verdict, res.Actual = "INCONCLUSIVE", "not mounted: read bundle: "+err.Error()
		return res
	}
	// What the election looks like right now, read from the chain itself.
	mc := MountContext{Stage: StageUnstaged, BallotsCommitted: committedFromMetrics(srcDir),
		BlockHeight: chainHeight(conn.Ledger())}
	if st, err := conn.Bulletin.GetElectionStatus(b.ElectionID); err == nil {
		mc.ElectionStatus = st
		if _, err := conn.Bulletin.GetTally(b.ElectionID); err == nil {
			mc.ElectionStatus = "published"
		}
	}
	res = e.mountLiveAttack(runID, srcDir, sc, conn.Bulletin, b.ElectionID)
	res.Mount = mc
	return res
}

func newLiveResult(sc Scenario) ScenarioResult {
	return ScenarioResult{
		Scenario: sc.ID, Layer: sc.Layer.String(), Action: sc.Action,
		Expected: sc.Expected, Property: sc.Property, Stage: sc.Stage, OnChain: true,
		GateExpected: sc.ChainGate,
	}
}

// gateID finds the chaincode's "gate=<id>:" marker in a rejection.
var gateID = regexp.MustCompile(`gate=([a-z][a-z0-9-]*):\s*`)

// classifyLive decides a live submission's verdict from what the ledger said.
//
// The chaincode refuses a submission at the FIRST check it fails, in a fixed
// order (SubmitBallot: decode, shape, credential signature, election exists,
// election open, nullifier unspent, then CDS), so a rejection only says
// something about the gate that produced it. A tampered proof submitted to a
// closed election is refused as "not open for ballots" and never reaches the
// proof check: that is INCONCLUSIVE, not a pass for the proof gate. A rejection
// that names no gate (a chaincode deployed before gate ids, a timeout, a
// transport error) cannot be attributed either.
func classifyLive(res *ScenarioResult, sc Scenario, submitErr error) {
	res.GateExpected = sc.ChainGate
	if submitErr == nil {
		res.Verdict, res.Actual = "FAIL", "NOT rejected — the ledger accepted a tampered artifact"
		return
	}
	text := clientsdk.ErrorText(submitErr)
	locs := gateID.FindAllStringSubmatchIndex(text, -1)
	if len(locs) == 0 {
		res.Verdict = "INCONCLUSIVE"
		res.Actual = "rejected by an unidentified gate (the error names no gate id — a chaincode " +
			"deployed before gate ids, or a transport failure): " + truncateErr(text)
		return
	}
	// Every gate the endorsers named must be the declared one. Several
	// endorsers can each attach a message; if any of them refused at another
	// gate, the attack did not reach the gate under test everywhere.
	var ids []string
	other := -1
	for i, loc := range locs {
		id := text[loc[2]:loc[3]]
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
		if other < 0 && id != sc.ChainGate {
			other = i
		}
	}
	res.GateObserved = strings.Join(ids, ";")
	// One endorser's reason runs to the "; " ErrorText put before the next
	// endorser's message.
	reasonAt := func(i int) string {
		r := text[locs[i][1]:]
		if i+1 < len(locs) {
			r = text[locs[i][1]:locs[i+1][0]]
			if k := strings.LastIndex(r, "; "); k >= 0 {
				r = r[:k]
			}
		}
		return truncateErr(r)
	}
	if sc.ChainGate != "" && other < 0 {
		res.Verdict = "PASS"
		res.Actual = "rejected by chaincode gate " + sc.ChainGate + " (the declared gate): " + reasonAt(0)
		return
	}
	i := max(other, 0)
	res.Verdict = "INCONCLUSIVE"
	res.Actual = "rejected by " + text[locs[i][2]:locs[i][3]] + ": " + reasonAt(i)
}

// mountLiveAttack applies the mutation and submits the tampered artifact,
// expecting the chaincode to refuse it. Its rejection message is the result.
//
// THE VERDICT IS INVERTED HERE, and that is the whole point: an error is PASS,
// because the ledger did its job; a successful commit is FAIL, because a
// tampered artifact the ledger accepted is a genuine finding. Getting this
// backwards would report a broken gate as green, so it is tested directly.
//
// Nothing here can corrupt the real election: the mutation is applied to a
// COPY, and the chaincode declines the write.
func (e *Executor) mountLiveAttack(
	runID, srcDir string, sc Scenario, sub attackSubmitter, electionID string,
) ScenarioResult {
	res := newLiveResult(sc)

	scenDir := filepath.Join(srcDir, "scenarios", "live-"+sc.ID)
	if err := copyStream(srcDir, scenDir); err != nil {
		res.Verdict, res.Actual = "INCONCLUSIVE", "not mounted: could not copy run: "+err.Error()
		return res
	}
	if err := sc.Mutate(scenDir); err != nil {
		res.Verdict, res.Actual = "INCONCLUSIVE", "not mounted: mutation error: "+err.Error()
		return res
	}

	var submitErr error
	switch sc.Stage {
	case StageBallots:
		// Submit whichever ballot the attacker actually changed, so one code
		// path serves every ballot-stage mutation regardless of which index it
		// touched.
		idx, hexLine, err := firstChangedBallot(srcDir, scenDir)
		if err != nil {
			res.Verdict, res.Actual = "INCONCLUSIVE", "not mounted: "+err.Error()
			return res
		}
		e.publish(runID, "attack", "info",
			fmt.Sprintf("%s: submitting tampered ballot %d to the peer…", sc.ID, idx))
		submitErr = sub.SubmitBallot(hexLine)
	case StageCeremony:
		hexVal, err := firstChangedHeaderList(srcDir, scenDir, "partial_decryptions")
		if err != nil {
			res.Verdict, res.Actual = "INCONCLUSIVE", "not mounted: "+err.Error()
			return res
		}
		e.publish(runID, "attack", "info", sc.ID+": submitting tampered partial decryption…")
		submitErr = sub.SubmitPartialDecryption(electionID, hexVal)
	case StageDKG:
		hexVal, err := changedHeaderField(srcDir, scenDir, "dkg")
		if err != nil {
			res.Verdict, res.Actual = "INCONCLUSIVE", "not mounted: "+err.Error()
			return res
		}
		e.publish(runID, "attack", "info", sc.ID+": submitting tampered DKG transcript…")
		submitErr = sub.PublishDKGTranscript(hexVal)
	default:
		res.Verdict = "SKIPPED"
		res.Actual = "stage " + sc.Stage + " is not mountable as a single submission"
		return res
	}

	classifyLive(&res, sc, submitErr)
	level := "info"
	if res.Verdict == "FAIL" {
		level = "error"
	}
	e.publish(runID, "attack", level, sc.ID+": "+res.Verdict+" — "+res.Actual)
	return res
}

// truncateErr keeps a chaincode error readable in a UI chip. Fabric wraps
// endorsement failures in a lot of envelope detail; the useful part is first.
func truncateErr(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}

// firstChangedBallot returns the index and hex of the first ballot line the
// mutation altered.
func firstChangedBallot(srcDir, scenDir string) (int, string, error) {
	before, err := readBallotLines(srcDir)
	if err != nil {
		return 0, "", fmt.Errorf("read original ballots: %w", err)
	}
	after, err := readBallotLines(scenDir)
	if err != nil {
		return 0, "", fmt.Errorf("read mutated ballots: %w", err)
	}
	for i := range after {
		if i >= len(before) || before[i] != after[i] {
			return i, after[i], nil
		}
	}
	return 0, "", fmt.Errorf("mutation changed no ballot line, so there is nothing to submit")
}

// firstChangedHeaderList returns the first altered element of a hex-string list
// in header.json (e.g. partial_decryptions).
func firstChangedHeaderList(srcDir, scenDir, field string) (string, error) {
	before, err := headerList(srcDir, field)
	if err != nil {
		return "", err
	}
	after, err := headerList(scenDir, field)
	if err != nil {
		return "", err
	}
	for i := range after {
		if i >= len(before) || before[i] != after[i] {
			return after[i], nil
		}
	}
	return "", fmt.Errorf("mutation changed no %s entry", field)
}

// changedHeaderField returns a mutated scalar hex field from header.json.
func changedHeaderField(srcDir, scenDir, field string) (string, error) {
	after, err := headerField(scenDir, field)
	if err != nil {
		return "", err
	}
	before, err := headerField(srcDir, field)
	if err != nil {
		return "", err
	}
	if before == after {
		return "", fmt.Errorf("mutation changed no %s field", field)
	}
	return after, nil
}

func headerMap(dir string) (map[string]any, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "header.json"))
	if err != nil {
		return nil, fmt.Errorf("read header.json: %w", err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("parse header.json: %w", err)
	}
	return h, nil
}

func headerList(dir, field string) ([]string, error) {
	h, err := headerMap(dir)
	if err != nil {
		return nil, err
	}
	arr, ok := h[field].([]any)
	if !ok {
		return nil, fmt.Errorf("header.json has no %s list", field)
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out, nil
}

func headerField(dir, field string) (string, error) {
	h, err := headerMap(dir)
	if err != nil {
		return "", err
	}
	s, ok := h[field].(string)
	if !ok {
		return "", fmt.Errorf("header.json has no %s field", field)
	}
	return s, nil
}

// RunStagedAttack runs one attack at its lifecycle stage: really, against the
// ledger, when a network is configured; simulated against a copy otherwise.
func (e *Executor) RunStagedAttack(ctx context.Context, runID string, c ElectionConfig, id string) error {
	srcDir, err := e.store.Dir(runID)
	if err != nil {
		return err
	}
	var sc *Scenario
	for _, cand := range Registry() {
		if cand.ID == id {
			s := cand
			sc = &s
			break
		}
	}
	if sc == nil {
		return fmt.Errorf("unknown scenario %q", id)
	}

	// Outside a lifecycle pause (see timeline.go) the attack lands on whatever
	// state the election is in now — after the lifecycle, a closed one, where a
	// ballot attack is refused by the closed-election gate before the gate it
	// tests. The verdict rules report exactly that.
	var res ScenarioResult
	if e.onChainRun(c) && sc.LiveCapable() {
		res = e.runLiveScenario(ctx, runID, srcDir, *sc)
	} else {
		res = e.simulateStaged(ctx, runID, srcDir, *sc, e.onChainRun(c))
		res.Mount = MountContext{Stage: StageUnstaged}
	}
	return e.saveScenarioResult(runID, srcDir, res)
}

// saveScenarioResult upserts one verdict into the run's accumulated set,
// rewrites negative-tests.csv from it, and announces it on the attack stream.
func (e *Executor) saveScenarioResult(runID, srcDir string, res ScenarioResult) error {
	merged, held, err := mergeScenarioResults(srcDir, []ScenarioResult{res})
	if err != nil {
		return err
	}
	e.journalHeldBack(runID, merged, held)
	if err := writeNegativeTestsCSV(filepath.Join(srcDir, NegativeTestsFile), merged); err != nil {
		return err
	}
	if res.Verdict == "FAIL" {
		e.publish(runID, "attack", "error", res.Scenario+" FAILED — a gate that should have rejected did not")
	} else {
		e.publish(runID, "attack", "done", res.Scenario+": "+res.Verdict)
	}
	return nil
}

// simulateStaged runs sc against a copy of the run. onChain says the real
// election is on a ledger: the row then also says what that ledger does with
// an attack it has no gate for, so a simulated rejection recorded during a
// live election is never read as the ledger's.
func (e *Executor) simulateStaged(ctx context.Context, runID, srcDir string, sc Scenario, onChain bool) ScenarioResult {
	res := e.runOneScenario(ctx, runID, srcDir, sc)
	if onChain && sc.OnChainNote != "" && res.Verdict != "SKIPPED" {
		note := sc.OnChainNote
		if res.Verdict == "PASS" {
			note += "; caught by the auditor"
		}
		res.Actual = note + " — " + res.Actual
	}
	return res
}
