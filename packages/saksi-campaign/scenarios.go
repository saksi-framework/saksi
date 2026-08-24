package campaign

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	// LayerChaincode: only rejected at on-chain endorsement (network-gated).
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
	Mutate   func(dir string) error
}

// ScenarioResult is one row of negative-tests.csv.
type ScenarioResult struct {
	Scenario string
	Layer    string
	Action   string
	Expected string
	Actual   string
	Verdict  string // PASS | FAIL | SKIPPED
	Property string
}

// Registry is the offline-detectable attack catalog. Each entry is grounded in
// an existing auditor tamper test (independent_verification.rs / tests.rs), so
// the offline auditor is proven to reject it. Endorsement-only attacks (e.g. a
// ballot submitted after close) would be LayerChaincode and are network-gated.
func Registry() []Scenario {
	return []Scenario{
		{
			ID: "tamper-ballot-proof", Property: "ballot well-formedness (CDS proof)",
			Layer: LayerOffline, Action: "flip a byte in a ballot's CDS proof response",
			Expected: "auditor rejects: proof verification fails",
			Mutate: func(dir string) error {
				return mutateBallot(dir, 0, func(b *pb.Ballot) error {
					if len(b.WellFormednessProofs) == 0 || len(b.WellFormednessProofs[0].Branches) == 0 {
						return fmt.Errorf("ballot has no CDS proof to tamper")
					}
					flipBytes(b.WellFormednessProofs[0].Branches[0].Response)
					return nil
				})
			},
		},
		{
			ID: "reused-nullifier", Property: "no double voting (per-position nullifier)",
			Layer: LayerOffline, Action: "copy ballot 0's nullifier onto ballot 1",
			Expected: "auditor rejects: duplicate nullifier",
			Mutate: func(dir string) error {
				b0, err := readBallot(dir, 0)
				if err != nil {
					return err
				}
				if b0.CredentialPresentation == nil || b0.CredentialPresentation.Nullifier == nil {
					return fmt.Errorf("ballot 0 has no nullifier")
				}
				val := b0.CredentialPresentation.Nullifier.Value
				return mutateBallot(dir, 1, func(b *pb.Ballot) error {
					if b.CredentialPresentation == nil || b.CredentialPresentation.Nullifier == nil {
						return fmt.Errorf("ballot 1 has no nullifier")
					}
					b.CredentialPresentation.Nullifier.Value = append([]byte(nil), val...)
					return nil
				})
			},
		},
		{
			ID: "dropped-ballot", Property: "ballot-box completeness",
			Layer: LayerOffline, Action: "remove one committed ballot line",
			Expected: "auditor rejects: ballot count / ledger digest mismatch",
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
			// Ordering is a LEDGER property: the stateless auditor recomputes the
			// same tally + proofs regardless of ballot order, so audit-stream does
			// NOT reject a reorder (verified: it passed a reordered run). The chain's
			// ledger digest binds order — hence LayerChaincode, network-gated.
			ID: "reordered-ballots", Property: "ledger integrity (ordering)",
			Layer: LayerChaincode, Action: "swap the first two ballot lines",
			Expected: "chaincode rejects: ledger digest mismatch",
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
			ID: "corrupted-ballot-bytes", Property: "wire integrity",
			Layer: LayerOffline, Action: "flip a byte in a ballot's wire bytes",
			Expected: "auditor rejects: ballot does not decode / proof fails",
			Mutate: func(dir string) error {
				lines, err := readBallotLines(dir)
				if err != nil {
					return err
				}
				if len(lines) == 0 {
					return fmt.Errorf("no ballots")
				}
				raw, err := hex.DecodeString(lines[0])
				if err != nil || len(raw) == 0 {
					return fmt.Errorf("ballot 0 not decodable hex")
				}
				raw[len(raw)/2] ^= 0x01
				lines[0] = hex.EncodeToString(raw)
				return writeBallotLines(dir, lines)
			},
		},
		{
			ID: "tamper-partial-decryption", Property: "threshold-decryption integrity",
			Layer: LayerOffline, Action: "flip a byte in a trustee's partial decryption",
			Expected: "auditor rejects: Chaum-Pedersen proof fails",
			Mutate: func(dir string) error {
				return mutateHeader(dir, func(h map[string]any) error {
					arr, ok := h["partial_decryptions"].([]any)
					if !ok || len(arr) == 0 {
						return fmt.Errorf("no partial_decryptions in header")
					}
					s, _ := arr[0].(string)
					arr[0] = flipHexString(s)
					h["partial_decryptions"] = arr
					return nil
				})
			},
		},
		{
			ID: "tamper-dkg-transcript", Property: "DKG transcript integrity",
			Layer: LayerOffline, Action: "flip a byte in the DKG transcript",
			Expected: "auditor rejects: DKG transcript invalid",
			Mutate: func(dir string) error {
				return mutateHeader(dir, func(h map[string]any) error {
					s, ok := h["dkg"].(string)
					if !ok || s == "" {
						return fmt.Errorf("no dkg in header")
					}
					h["dkg"] = flipHexString(s)
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
		results = append(results, e.runOneScenario(ctx, runID, srcDir, sc))
	}

	// Merge into the accumulated set before exporting: a caller running a
	// single scenario must not erase the verdicts of the other six.
	merged, err := mergeScenarioResults(srcDir, results)
	if err != nil {
		return err
	}
	if err := writeNegativeTestsCSV(filepath.Join(srcDir, NegativeTestsFile), merged); err != nil {
		return err
	}
	fails := 0
	for _, r := range results {
		if r.Verdict == "FAIL" {
			fails++
		}
	}
	if fails == 0 {
		e.publish(runID, "scenarios", "done", "all scenarios upheld their security property")
	} else {
		e.publish(runID, "scenarios", "error",
			fmt.Sprintf("%d scenario(s) FAILED — a gate that should have rejected did not", fails))
	}
	return nil
}

func (e *Executor) runOneScenario(ctx context.Context, runID, srcDir string, sc Scenario) ScenarioResult {
	res := ScenarioResult{
		Scenario: sc.ID, Layer: sc.Layer.String(), Action: sc.Action,
		Expected: sc.Expected, Property: sc.Property,
	}

	// Chaincode-only attacks are not offline-detectable — never assert them
	// against the offline auditor (that would be a false FAIL).
	if sc.Layer == LayerChaincode {
		res.Verdict, res.Actual = "SKIPPED", "chaincode-only — requires a live Fabric network"
		e.publish(runID, "scenarios", "info", sc.ID+": skipped (chaincode-only)")
		return res
	}

	scenDir := filepath.Join(srcDir, "scenarios", sc.ID)
	if err := copyStream(srcDir, scenDir); err != nil {
		res.Verdict, res.Actual = "FAIL", "could not copy run: "+err.Error()
		return res
	}

	// Positive control: the unmutated copy MUST audit clean, else a rejection
	// after mutation could be for an unrelated reason (false green).
	if sa, ok := e.auditStream(ctx, scenDir); !ok || sa.Overall != "pass" {
		res.Verdict, res.Actual = "FAIL", "positive control did not pass on the unmutated copy"
		return res
	}

	if err := sc.Mutate(scenDir); err != nil {
		res.Verdict, res.Actual = "FAIL", "mutation error: "+err.Error()
		return res
	}

	sa, ok := e.auditStream(ctx, scenDir)
	rejected := !ok || sa.Overall == "fail"
	if rejected {
		res.Verdict = "PASS"
		if !ok {
			res.Actual = "auditor rejected: audit-stream reported no valid result"
		} else {
			res.Actual = "auditor rejected: overall=fail"
		}
		e.publish(runID, "scenarios", "info", sc.ID+": PASS (attack rejected)")
	} else {
		res.Verdict = "FAIL"
		res.Actual = "NOT rejected — the audit passed a mutated run"
		e.publish(runID, "scenarios", "error", sc.ID+": FAIL — attack was not rejected")
	}
	return res
}

// auditStream shells audit-stream --json and returns the parsed result plus
// whether the output was valid (an unparseable result means the tool rejected /
// crashed on the mutation, which for a scenario counts as a rejection).
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

func readBallotLines(dir string) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "ballots.ndjson"))
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	return lines, nil
}

func writeBallotLines(dir string, lines []string) error {
	body := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(filepath.Join(dir, "ballots.ndjson"), []byte(body), 0o644)
}

func readBallot(dir string, idx int) (*pb.Ballot, error) {
	lines, err := readBallotLines(dir)
	if err != nil {
		return nil, err
	}
	if idx >= len(lines) {
		return nil, fmt.Errorf("ballot %d out of range (have %d)", idx, len(lines))
	}
	raw, err := hex.DecodeString(lines[idx])
	if err != nil {
		return nil, fmt.Errorf("ballot %d not hex: %w", idx, err)
	}
	var b pb.Ballot
	if err := proto.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("decode ballot %d: %w", idx, err)
	}
	return &b, nil
}

// mutateBallot decodes ballot idx, applies fn, re-encodes it in place — the
// decode→mutate→re-encode path (never byte surgery on the wire form).
func mutateBallot(dir string, idx int, fn func(*pb.Ballot) error) error {
	lines, err := readBallotLines(dir)
	if err != nil {
		return err
	}
	if idx >= len(lines) {
		return fmt.Errorf("ballot %d out of range (have %d)", idx, len(lines))
	}
	raw, err := hex.DecodeString(lines[idx])
	if err != nil {
		return err
	}
	var b pb.Ballot
	if err := proto.Unmarshal(raw, &b); err != nil {
		return err
	}
	if err := fn(&b); err != nil {
		return err
	}
	enc, err := proto.Marshal(&b)
	if err != nil {
		return err
	}
	lines[idx] = hex.EncodeToString(enc)
	return writeBallotLines(dir, lines)
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

// flipBytes flips one bit of the first byte of b (in place).
func flipBytes(b []byte) {
	if len(b) > 0 {
		b[0] ^= 0x01
	}
}

// flipHexString flips the last hex nibble to a different value.
func flipHexString(s string) string {
	if s == "" {
		return "01"
	}
	b := []byte(s)
	last := len(b) - 1
	if b[last] == '0' {
		b[last] = '1'
	} else {
		b[last] = '0'
	}
	return string(b)
}

func copyStream(srcDir, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"header.json", "ballots.ndjson"} {
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
		}
		if r, ok := byID[sc.ID]; ok {
			l.Verdict, l.Actual = r.Verdict, r.Actual
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
func mergeScenarioResults(dir string, fresh []ScenarioResult) ([]ScenarioResult, error) {
	prior, err := readScenarioResults(dir)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]ScenarioResult, len(prior)+len(fresh))
	for _, r := range prior {
		byID[r.Scenario] = r
	}
	// Fresh results replace prior ones: re-running a scenario updates its row
	// rather than appending a second one for the same id.
	for _, r := range fresh {
		byID[r.Scenario] = r
	}

	var merged []ScenarioResult
	for _, sc := range Registry() {
		if r, ok := byID[sc.ID]; ok {
			merged = append(merged, r)
		}
	}

	data, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, ScenarioStateFile), data, 0o644); err != nil {
		return nil, err
	}
	return merged, nil
}

func writeNegativeTestsCSV(path string, results []ScenarioResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write([]string{
		"scenario", "layer", "action", "expected", "actual", "verdict", "property",
	}); err != nil {
		return err
	}
	for _, r := range results {
		if err := w.Write([]string{
			r.Scenario, r.Layer, r.Action, r.Expected, r.Actual, r.Verdict, r.Property,
		}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
