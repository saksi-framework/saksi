package campaign

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// CorrectnessFile is the per-contest cross-check CSV written by Verify.
const CorrectnessFile = "correctness.csv"

// ContestCorrectness mirrors the Rust `audit-stream --json` per-contest row.
type ContestCorrectness struct {
	Contest             string `json:"contest"`
	GroundTruth         uint64 `json:"ground_truth"`
	Decoded             uint64 `json:"decoded"`
	E                   int64  `json:"E"`
	Pass                bool   `json:"pass"`
	PublishedTally      uint64 `json:"published_tally"`
	AggregateCiphertext string `json:"aggregate_ciphertext"`
	RecoveredPoint      string `json:"recovered_point"`
}

// StreamAudit mirrors the Rust `audit-stream --json` document.
type StreamAudit struct {
	Overall  string               `json:"overall"` // pass | fail
	Contests []ContestCorrectness `json:"contests"`
}

// Runner shells an external command and returns its stdout. Injected so tests
// can drive the executors without the real saksi-demo binary.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// execRunner is the production Runner: run the command, return stdout even on a
// non-zero exit (Verify inspects stdout regardless of exit code), and fold
// stderr into the error.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("%s exited with error: %w: %s",
			name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Executor runs the phase pipeline over a run folder, shelling the parameterized
// saksi-demo (offline) or an on-chain driver.
type Executor struct {
	store   *RunStore
	hub     *Hub
	demoBin string // path to the saksi-demo binary (Generate/Verify)
	consBin string // path to the on-chain console driver (Submit); "" = none
	fabric  FabricConfig
	run     Runner
}

// NewExecutor wires the production runner. demoBin is the saksi-demo path;
// consBin is the on-chain driver (may be "" — on-chain Submit then errors
// clearly instead of hanging). fabric is the live-network connection config
// (zero-value = on-chain gateway mode unavailable; unused for now, consumed by
// a later task).
func NewExecutor(store *RunStore, hub *Hub, demoBin, consBin string, fabric FabricConfig) *Executor {
	return &Executor{store: store, hub: hub, demoBin: demoBin, consBin: consBin, fabric: fabric, run: execRunner}
}

func (e *Executor) publish(runID, phase, level, msg string) {
	if e.hub != nil {
		e.hub.Publish(runID, Event{Phase: phase, Level: level, Msg: msg})
	}
}

// Generate shells `saksi-demo gen --stream <dir> …` to write the run's stream
// artifacts (header.json + ballots.ndjson). The election id is the run id
// (unique, cryptographically bound); the election name + trustee names are the
// display metadata carried in the header.
func (e *Executor) Generate(ctx context.Context, runID string, c ElectionConfig) error {
	dir, err := e.store.Dir(runID)
	if err != nil {
		return err
	}
	args := []string{
		"gen", "--stream", dir,
		"--voters", strconv.Itoa(c.Voters),
		"--positions", strconv.Itoa(c.Positions),
		"--candidates", strconv.Itoa(c.Candidates),
		"--trustees", strconv.Itoa(len(c.Trustees)),
		"--threshold", strconv.Itoa(c.Threshold),
		"--election-id", runID,
		"--election-name", c.Name,
		"--trustee-names", strings.Join(c.TrusteeNames(), ","),
		"--distribution", c.Distribution,
	}
	e.publish(runID, "generate", "info", fmt.Sprintf(
		"generating %d voters × %d positions × %d candidates (%d-of-%d)…",
		c.Voters, c.Positions, c.Candidates, c.Threshold, len(c.Trustees)))
	if _, err := e.run(ctx, e.demoBin, args...); err != nil {
		e.publish(runID, "generate", "error", err.Error())
		return err
	}
	// Flatten the stream into CSVs (ballots.csv + election.csv) so every export
	// is a proper spreadsheet.
	if err := writeDerivedCSVs(dir, c); err != nil {
		e.publish(runID, "generate", "error", "csv export failed: "+err.Error())
		return err
	}
	e.publish(runID, "generate", "done", "ballots generated (+ ballots.csv, election.csv)")
	return nil
}

// Verify shells `saksi-demo audit-stream <dir> --json`, then writes
// correctness.csv from the STRUCTURED output (no finding-string parsing).
//
// Three outcomes are kept distinct (codex #12): a clean audit (overall=pass), a
// real audit rejection (overall=fail — the tool WORKED, returned as a result,
// not a Go error), and a crash / unparseable output (a Go error). Only the last
// returns err.
func (e *Executor) Verify(ctx context.Context, runID string) (StreamAudit, error) {
	dir, err := e.store.Dir(runID)
	if err != nil {
		return StreamAudit{}, err
	}
	e.publish(runID, "verify", "info", "auditing run…")
	out, runErr := e.run(ctx, e.demoBin, "audit-stream", dir, "--json")

	var sa StreamAudit
	if jsonErr := json.Unmarshal(out, &sa); jsonErr != nil {
		// Unparseable stdout means the binary crashed / drifted — a real error,
		// never silently read as "audit fail".
		e.publish(runID, "verify", "error", "audit-stream produced no valid result")
		return StreamAudit{}, fmt.Errorf("audit-stream crashed: %v (output: %s)",
			runErr, truncate(out, 200))
	}
	dkgHash, tallyHash, ballotsHash := runDigests(dir)
	if err := writeCorrectnessCSV(filepath.Join(dir, CorrectnessFile), sa, dkgHash, tallyHash, ballotsHash); err != nil {
		return sa, err
	}
	if sa.Overall == "pass" {
		e.publish(runID, "verify", "done", "audit PASS (E=0 on every contest)")
	} else {
		e.publish(runID, "verify", "error", "audit FAIL (see correctness.csv)")
	}
	return sa, nil
}

// Submit is a no-op offline (documented) and drives the on-chain lifecycle when
// the mode is on-chain. On-chain requires a reachable Fabric network; without a
// configured driver it returns a clear error rather than hanging.
func (e *Executor) Submit(ctx context.Context, runID string, c ElectionConfig) error {
	if c.Mode == "offline" {
		e.publish(runID, "submit", "done", "offline mode: nothing submitted on-chain")
		return nil
	}
	dir, err := e.store.Dir(runID)
	if err != nil {
		return err
	}
	if e.consBin == "" {
		err := fmt.Errorf("on-chain submit requires a reachable Fabric network (no driver configured)")
		e.publish(runID, "submit", "error", err.Error())
		return err
	}
	e.publish(runID, "submit", "info", "submitting on-chain…")
	if _, err := e.run(ctx, e.consBin, "submit", dir); err != nil {
		e.publish(runID, "submit", "error", err.Error())
		return err
	}
	e.publish(runID, "submit", "done", "submitted + reconciled on-chain")
	return nil
}

// writeCorrectnessCSV writes the per-contest proof of correctness: the seeded
// ground truth, the value REAL threshold decryption recovered (decoded), E, and
// the cryptographic evidence needed to re-verify it — the recovered plaintext
// point, the aggregate (encrypted) tally it came from, and the run's artifact
// hashes (DKG, tally, ballot-set). Each row is self-contained proof.
func writeCorrectnessCSV(path string, sa StreamAudit, dkgHash, tallyHash, ballotsHash string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write([]string{
		"contest", "ground_truth", "decoded", "E", "pass",
		"published_tally", "recovered_point", "aggregate_ciphertext",
		"dkg_sha256", "tally_sha256", "ballots_sha256",
	}); err != nil {
		return err
	}
	for _, c := range sa.Contests {
		row := []string{
			c.Contest,
			strconv.FormatUint(c.GroundTruth, 10),
			strconv.FormatUint(c.Decoded, 10),
			strconv.FormatInt(c.E, 10),
			strconv.FormatBool(c.Pass),
			strconv.FormatUint(c.PublishedTally, 10),
			c.RecoveredPoint,
			c.AggregateCiphertext,
			dkgHash,
			tallyHash,
			ballotsHash,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

func truncate(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
