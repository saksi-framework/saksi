package campaign

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	"github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk/bench"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
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
	// TimingsMs is the auditor's own per-stage in-process timing, copied
	// verbatim into timings.json. Absent from pre-v2 audit documents, which
	// decode as zeros.
	TimingsMs TimingsMs `json:"timings_ms"`
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

	receiptsMu sync.Mutex
	receipts   map[string]*receiptsWriter // runID -> its open receiptsWriter (see openReceiptsFor/closeReceipts)
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
	// The journal is created here, at the run's first stage, and reopened for
	// appending by every later stage (journalFor).
	env := CollectEnv(e.demoBin)
	j, jerr := OpenJournal(dir, env)
	if jerr != nil {
		e.publish(runID, "generate", "info", "run journal unavailable: "+jerr.Error())
	}
	defer j.Close()
	_ = j.Stamp("run.start", map[string]any{
		"run_id": runID, "mode": c.Mode, "voters": c.Voters,
		"positions": c.Positions, "candidates": c.Candidates,
		"distribution": c.Distribution,
	})
	if c.Rep != nil {
		_ = j.Stamp("rep.start", map[string]any{"index": c.Rep.Index, "kind": c.Rep.Kind})
	}
	e.recordCommit(runID, env)
	_ = j.Stamp("stage.generate.start", nil)

	if c.Mode == ModeGroundTruth {
		err := e.generateGroundTruth(ctx, runID, c, dir)
		_ = j.Stamp("stage.generate.end", stageEnd(err))
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
		_ = j.Stamp("stage.generate.end", stageEnd(err))
		return err
	}
	// Flatten the stream into CSVs (ballots.csv + election.csv) so every export
	// is a proper spreadsheet.
	if err := writeDerivedCSVs(dir, c); err != nil {
		e.publish(runID, "generate", "error", "csv export failed: "+err.Error())
		_ = j.Stamp("stage.generate.end", stageEnd(err))
		return err
	}
	e.publish(runID, "generate", "done", "ballots generated (+ ballots.csv, election.csv)")
	_ = j.Stamp("stage.generate.end", stageEnd(nil))
	return nil
}

// journalFor reopens the run's journal for appending. It never writes a second
// environment snapshot — that belongs to OpenJournal at run.start. A run folder
// without a journal (or an unwritable one) yields nil, and every Journal method
// is nil-safe, so instrumentation can never fail a phase.
func (e *Executor) journalFor(runID string) *Journal {
	dir, err := e.store.Dir(runID)
	if err != nil {
		return nil
	}
	path := filepath.Join(dir, JournalFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil
	}
	j := newJournal(f, time.Now())
	j.path = path
	return j
}

// stageEnd is the standard stage.*.end payload: ok, plus the error if not.
func stageEnd(err error) map[string]any {
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	return map[string]any{"ok": true}
}

// recordCommit pins the code the run executed against into run.json, from the
// environment snapshot the journal already recorded.
func (e *Executor) recordCommit(runID string, env map[string]any) {
	dir, err := e.store.Dir(runID)
	if err != nil {
		return
	}
	path := filepath.Join(dir, RunFile)
	var rec RunRecord
	if err := readJSON(path, &rec); err != nil {
		return
	}
	commit := map[string]string{}
	for _, k := range []string{"git_head_saksi", "git_head_console"} {
		if v, ok := env[k].(string); ok && v != "" {
			commit[k] = v
		}
	}
	rec.Commit = commit
	_ = writeJSON(path, rec)
}

// generateGroundTruth shells `saksi-demo gen-ground-truth`, producing only the
// Stage-4 plaintext tables (paper Appendix A / Figure 3.1) and no ciphertexts.
//
// The other phases have nothing to act on afterwards — there are no ballots to
// submit, audit, or mutate — so Submit/Verify/Scenarios refuse this mode
// explicitly rather than failing obscurely on missing files. Skipping
// writeDerivedCSVs is deliberate for the same reason: ballots.csv and
// election.csv describe ciphertexts that were never produced.
func (e *Executor) generateGroundTruth(ctx context.Context, runID string, c ElectionConfig, dir string) error {
	args := []string{
		"gen-ground-truth",
		"--out-dir", dir,
		"--voters", strconv.Itoa(c.Voters),
		"--positions", strconv.Itoa(c.Positions),
		"--candidates", strconv.Itoa(c.Candidates),
		"--election-id", runID,
		"--distribution", c.Distribution,
	}
	e.publish(runID, "generate", "info", fmt.Sprintf(
		"generating ground truth for %d voters × %d positions × %d candidates (no encryption)…",
		c.Voters, c.Positions, c.Candidates))
	if _, err := e.run(ctx, e.demoBin, args...); err != nil {
		e.publish(runID, "generate", "error", err.Error())
		return err
	}
	e.publish(runID, "generate", "done",
		"ground truth generated (ground-truth-ballots.csv, ground-truth-summary.csv)")
	return nil
}

// groundTruthOnly reports whether the run produced plaintext ground truth and
// nothing else, so a phase that needs ballots can refuse with a clear reason.
func groundTruthOnly(c ElectionConfig) bool { return c.Mode == ModeGroundTruth }

// Verify shells `saksi-demo audit-stream <dir> --json`, then writes
// correctness.csv from the STRUCTURED output (no finding-string parsing).
//
// Three outcomes are kept distinct (codex #12): a clean audit (overall=pass), a
// real audit rejection (overall=fail — the tool WORKED, returned as a result,
// not a Go error), and a crash / unparseable output (a Go error). Only the last
// returns err.
//
// An on-chain run additionally audits the chain's OWN record of itself (see
// ledger_dump.go). A chain that cannot be reached costs the cross-check, never
// the audit: the local audit is what this phase owes the caller.
func (e *Executor) Verify(ctx context.Context, runID string, c ElectionConfig) (StreamAudit, error) {
	if c.Mode != "onchain" || !e.fabric.Enabled() {
		return e.verify(ctx, runID, c, nil)
	}
	conn, err := e.fabric.Connect()
	if err != nil {
		e.publish(runID, "verify", "info", "ledger audit skipped: "+err.Error())
		return e.verify(ctx, runID, c, nil)
	}
	defer conn.Close()
	return e.verify(ctx, runID, c, conn.Bulletin)
}

// verify is Verify's body with the chain injected, so the ledger audit is
// testable without a network.
func (e *Executor) verify(ctx context.Context, runID string, c ElectionConfig, lr ledgerReader) (StreamAudit, error) {
	dir, err := e.store.Dir(runID)
	if err != nil {
		return StreamAudit{}, err
	}
	j := e.journalFor(runID)
	defer j.Close()
	_ = j.Stamp("stage.verify.start", nil)

	// The chain's own record is dumped and audited FIRST: it is the evidence
	// the console did not write, and a reader who only gets one of the two
	// should get that one.
	lc := e.auditLedger(ctx, runID, dir, lr)

	e.publish(runID, "verify", "info", "auditing run…")
	out, runErr := e.run(ctx, e.demoBin, "audit-stream", dir, "--json")

	var sa StreamAudit
	if jsonErr := json.Unmarshal(out, &sa); jsonErr != nil {
		// Unparseable stdout means the binary crashed / drifted — a real error,
		// never silently read as "audit fail".
		e.publish(runID, "verify", "error", "audit-stream produced no valid result")
		crashErr := fmt.Errorf("audit-stream crashed: %v (output: %s)", runErr, truncate(out, 200))
		_ = j.Stamp("stage.verify.end", stageEnd(crashErr))
		e.finalise(j, dir, runID, c, sa, crashErr, lc)
		return StreamAudit{}, crashErr
	}
	// timings.json is the auditor's own in-process stage timing, kept as a
	// standalone artifact so perf.csv's *_inproc_ms columns have a source a
	// reader can check.
	_ = writeJSON(filepath.Join(dir, TimingsFile), sa.TimingsMs)

	e.recordLedgerVerdict(runID, dir, sa, lc)

	dkgHash, tallyHash, ballotsHash := runDigests(dir)
	if err := writeCorrectnessCSV(filepath.Join(dir, CorrectnessFile), sa, dkgHash, tallyHash, ballotsHash, lc); err != nil {
		_ = j.Stamp("stage.verify.end", stageEnd(err))
		e.finalise(j, dir, runID, c, sa, err, lc)
		return sa, err
	}
	if sa.Overall == "pass" {
		e.publish(runID, "verify", "done", "audit PASS (E=0 on every contest)")
	} else {
		e.publish(runID, "verify", "error", "audit FAIL (see correctness.csv)")
	}
	_ = j.Stamp("stage.verify.end", map[string]any{"ok": true, "overall": sa.Overall})
	e.finalise(j, dir, runID, c, sa, nil, lc)
	return sa, nil
}

// auditLedger dumps the chain's own record of the run into <dir>/ledger/ and
// audits that directory with the same auditor the console's own directory
// gets. nil lr (no chain) yields a nil result and no ledger dump at all.
//
// A dump or audit that fails is stamped "not run" and nothing else: the chain
// going away mid-dump is an instrumentation loss, not a verdict on the run, and
// Verify continues with the local audit.
func (e *Executor) auditLedger(ctx context.Context, runID, dir string, lr ledgerReader) *ledgerCheck {
	if lr == nil {
		return nil
	}
	e.publish(runID, "verify", "info", "dumping the chain's own record of this election…")
	n, err := dumpLedger(dir, runID, lr)
	if err != nil {
		e.publish(runID, "verify", "error", "ledger audit not run: "+err.Error())
		return &ledgerCheck{status: "not run"}
	}
	out, runErr := e.run(ctx, e.demoBin, "audit-stream", filepath.Join(dir, LedgerDir), "--json")
	var sa StreamAudit
	if jsonErr := json.Unmarshal(out, &sa); jsonErr != nil {
		e.publish(runID, "verify", "error", fmt.Sprintf(
			"ledger audit not run: audit-stream produced no valid result for the ledger dump: %v (output: %s)",
			runErr, truncate(out, 200)))
		return &ledgerCheck{status: "not run"}
	}
	e.publish(runID, "verify", "info", fmt.Sprintf(
		"audited %d ballots read back from the chain: %s", n, sa.Overall))
	return &ledgerCheck{status: "ok", audit: sa}
}

// recordLedgerVerdict fills in the ledger check's verdict: whether the chain holds
// the same ballots and recovered the same aggregate ciphertexts as the console.
// A disagreement is a FINDING — reported red, written to correctness.csv and
// run.end — never an error, because "the chain says something else" is exactly
// the result this instrument exists to be able to report.
func (e *Executor) recordLedgerVerdict(runID, dir string, sa StreamAudit, lc *ledgerCheck) {
	if lc == nil || lc.status != "ok" {
		return
	}
	same, err := compareLedger(dir, sa, lc.audit)
	if err != nil {
		e.publish(runID, "verify", "error", "ledger audit not run: "+err.Error())
		lc.status, lc.matches = "not run", ""
		return
	}
	lc.matches = strconv.FormatBool(same)
	if same {
		e.publish(runID, "verify", "info", "ledger audit: the chain's record matches this console's")
	} else {
		e.publish(runID, "verify", "error",
			"ledger audit MISMATCH: the chain's ballots or tally differ from this console's (see correctness.csv)")
	}
}

// finalise closes the run out: the run.end verdict, then the perf.csv row it
// carries. Instrumentation failures are reported, never fatal — the audit
// result the caller asked for has already been decided.
func (e *Executor) finalise(j *Journal, dir, runID string, c ElectionConfig, sa StreamAudit, stageErr error, lc *ledgerCheck) {
	fin := Finalise(j, finaliseInput(dir, c, sa, stageErr, lc))
	if err := writePerfRow(dir, runID, c, fin); err != nil {
		e.publish(runID, "verify", "info", "perf.csv not written: "+err.Error())
	}
}

// finaliseInput assembles the run-failed predicate's inputs. Without a
// submission window (offline runs) there is nothing to reconcile and no
// segment, so only the audit's per-contest E decides the verdict.
func finaliseInput(dir string, c ElectionConfig, sa StreamAudit, stageErr error, lc *ledgerCheck) FinaliseInput {
	in := FinaliseInput{
		Voters: c.Voters, Positions: c.Positions,
		ReconcileOK: true, StageErr: stageErr,
		EByContest: make(map[string]int64, len(sa.Contests)),
	}
	for _, ct := range sa.Contests {
		in.EByContest[ct.Contest] = ct.E
	}
	if lc != nil {
		in.LedgerAudit = lc.status
		if lc.matches != "" {
			m := lc.matches == "true"
			in.LedgerMatchesLocal = &m
		}
	}
	var sm submitMetrics
	if readJSON(filepath.Join(dir, submitMetricsFile), &sm) != nil {
		return in
	}
	in.Dropped = sm.Dropped
	// bench.Reconcile is the single definition of "every ballot landed", and
	// its message names which half of that failed.
	//
	// A time-bounded window never intended to dispatch the whole population,
	// so holding it against the planned total would fail it for doing exactly
	// what it was told. What it still owes is that every ballot it DID
	// dispatch committed, which is the "committed != submitted" half.
	expected := sm.Expected
	if sm.Bounded {
		expected = sm.Submitted
	}
	in.ReconcileErr = bench.Reconcile(sm.Submitted, sm.Committed, expected)
	in.ReconcileOK = in.ReconcileErr == nil
	in.Interrupted = sm.Stopped
	in.Bounded = sm.Bounded
	in.Segments = []Segment{{
		Index: 0, Committed: sm.Committed, WindowMs: sm.WindowMs,
		TPS: sm.CommittedTPS, P50Ms: sm.LatencyP50Ms,
		DriverCeilingTPS: sm.DriverCeilingTPS,
	}}
	// A resumed run has one segment per window, and the journal is the only
	// place that records them all — submit-metrics.json carries run-level
	// totals, not the per-window split. One window in, one window out, so this
	// changes nothing for a run that was never resumed.
	if segs := segmentsFromJournal(dir); len(segs) > 0 {
		in.Segments = segs
	}
	return in
}

// Submit is a no-op offline (documented). On-chain, when a live Fabric network
// is configured (FabricConfig.Enabled), it shells `saksi-demo gen` to produce a
// one-blob bundle for this run, connects, and drives the full lifecycle via
// submitOnChain. Without a live network it falls back to the legacy console
// driver (consBin), which errors clearly rather than hanging if unconfigured.
func (e *Executor) Submit(ctx context.Context, runID string, c ElectionConfig) error {
	if groundTruthOnly(c) {
		e.publish(runID, "submit", "done",
			"ground-truth mode: no ballots were encrypted, so there is nothing to submit")
		return nil
	}
	if c.Mode == "offline" {
		e.publish(runID, "submit", "done", "offline mode: nothing submitted on-chain")
		return nil
	}
	dir, err := e.store.Dir(runID)
	if err != nil {
		return err
	}
	if e.fabric.Enabled() {
		bundlePath, err := e.generateBundle(runID)
		if err != nil {
			e.publish(runID, "submit", "error", "bundle: "+err.Error())
			return err
		}
		conn, err := e.fabric.Connect()
		if err != nil {
			e.publish(runID, "submit", "error", "connect to Fabric: "+err.Error())
			return err
		}
		defer conn.Close()
		return e.submitOnChain(ctx, runID, c, conn.Ledger(), bundlePath)
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

// onChainBundle mirrors the JSON emitted by `saksi-demo gen` (fields the
// on-chain lifecycle needs; same shape as cmd/saksi-console's bundle).
type onChainBundle struct {
	ElectionID string `json:"election_id"`
	Params     string `json:"params"`
	DKG        string `json:"dkg"`
	// BallotsFile names the ndjson stream holding the population. The ballots
	// are REFERENCED, never inlined: a 1M-voter bundle would otherwise have to
	// be parsed into memory whole before the first ballot could be submitted.
	BallotsFile        string   `json:"ballots_file"`
	BallotCount        int      `json:"ballot_count"`
	PartialDecryptions []string `json:"partial_decryptions"`
	Tally              string   `json:"tally"`
}

// submitOnChain drives the full election lifecycle over led in order —
// CreateElection, PublishDKGTranscript, SubmitBallot×each, CloseElection,
// SubmitPartialDecryption×each, PublishTally — recording a receipt after every
// committed step (via the run's receiptsWriter) so a mid-lifecycle failure leaves the
// already-committed steps' evidence on disk. Chaincode arg forms mirror
// cmd/saksi-console/main.go's calls.
func (e *Executor) submitOnChain(ctx context.Context, runID string, c ElectionConfig, led clientsdk.Ledger, bundlePath string) error {
	b, step, err := e.lifecycle(runID, led, bundlePath, "submit")
	if err != nil {
		return err
	}
	defer e.closeReceipts(runID)
	if err := e.setupOnChain(ctx, runID, c, b, led, step); err != nil {
		return err
	}
	for i, pd := range b.PartialDecryptions {
		if err := step(ctx, "SubmitPartialDecryption", strconv.Itoa(i), "SubmitPartialDecryption", b.ElectionID, pd); err != nil {
			return err
		}
	}
	if err := step(ctx, "PublishTally", "", "PublishTally", b.Tally); err != nil {
		return err
	}
	e.publish(runID, "submit", "done", "full lifecycle committed on-chain")
	return nil
}

// lifecycleStep commits one chaincode call, records its ledger receipt, and
// streams a progress line. Shared by the all-in-one Submit path and the
// step-at-a-time ceremony path so both produce identical receipts and events.
type lifecycleStep func(ctx context.Context, event, ref, fn string, args ...string) error

// lifecycle loads the run's cached bundle and returns it with a step function
// bound to this run. phase names the SSE phase the steps publish under
// ("submit" for the all-in-one path, "ceremony" for the trustee ceremony).
//
// The bundle is READ, never regenerated: `saksi-demo gen` draws from OsRng, so
// a second generation would produce different shares — and CreateElection would
// then reject the run as a duplicate. Every ceremony click must see the same
// bundle the election was created from.
func (e *Executor) lifecycle(runID string, led clientsdk.Ledger, bundlePath, phase string) (*onChainBundle, lifecycleStep, error) {
	b, err := loadBundle(bundlePath)
	if err != nil {
		return nil, nil, err
	}
	runDir, err := e.store.Dir(runID)
	if err != nil {
		return nil, nil, err
	}
	w, err := e.openReceiptsFor(runID, runDir)
	if err != nil {
		return nil, nil, err
	}

	step := func(ctx context.Context, event, ref, fn string, args ...string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, receipt, err := led.SubmitWithReceipt(fn, args...)
		if err != nil {
			e.publish(runID, phase, "error", fmt.Sprintf("%s %s: %v", event, ref, err))
			return fmt.Errorf("%s: %w", event, err)
		}
		ev := TrailEvent{Event: event, Ref: ref, Receipt: receipt}
		// SubmitBallot goes only to receipts.csv; every other lifecycle event
		// goes to both receipts.csv and trail.ndjson.
		if event == "SubmitBallot" {
			err = w.Append(ev)
		} else {
			err = w.Lifecycle(ev)
		}
		if err != nil {
			return err
		}
		e.publish(runID, phase, "info", fmt.Sprintf("%s %s committed: block %d tx %s",
			event, ref, receipt.BlockNumber, receipt.TxID))
		return nil
	}
	return b, step, nil
}

// openReceiptsFor returns the run's receiptsWriter, opening it lazily (and
// caching it on the Executor) if this is the first live caller for runID, and
// incrementing its refcount either way. Later steps on the same run — and a
// later benchmark task reusing the writer after a window — reuse the same
// open file handles rather than reopening. Every successful call here must be
// matched by exactly one closeReceipts call, or the writer (and its open
// files) leaks.
func (e *Executor) openReceiptsFor(runID, runDir string) (*receiptsWriter, error) {
	e.receiptsMu.Lock()
	defer e.receiptsMu.Unlock()
	if w, ok := e.receipts[runID]; ok {
		w.refs++
		return w, nil
	}
	w, err := openReceipts(runDir)
	if err != nil {
		return nil, err
	}
	w.refs = 1
	if e.receipts == nil {
		e.receipts = make(map[string]*receiptsWriter)
	}
	e.receipts[runID] = w
	return w, nil
}

// closeReceipts releases this caller's reference to runID's receiptsWriter,
// closing the underlying files and forgetting the writer only once every
// caller that opened it (openReceiptsFor) has released it — a concurrent
// second caller sharing the same cached writer (e.g. two overlapping ceremony
// actions on the same run) can otherwise have it closed out from under a
// still-in-flight Append/Lifecycle write. Called at the end of submitOnChain
// and at the end of each ceremony action.
func (e *Executor) closeReceipts(runID string) error {
	e.receiptsMu.Lock()
	w, ok := e.receipts[runID]
	if !ok {
		e.receiptsMu.Unlock()
		return nil
	}
	w.refs--
	if w.refs > 0 {
		e.receiptsMu.Unlock()
		return nil
	}
	delete(e.receipts, runID)
	e.receiptsMu.Unlock()
	return w.Close()
}

// setupOnChain runs the lifecycle prefix that must precede any trustee action:
// CreateElection, PublishDKGTranscript, every SubmitBallot, then CloseElection.
// It stops there — the chaincode only accepts partial decryptions once the
// election is closed (contract.go's status gate), and the ceremony hands the
// next move to the trustees.
func (e *Executor) setupOnChain(ctx context.Context, runID string, c ElectionConfig, b *onChainBundle, led clientsdk.Ledger, step lifecycleStep) error {
	if err := step(ctx, "CreateElection", "", "CreateElection", b.Params); err != nil {
		return err
	}
	if err := step(ctx, "PublishDKGTranscript", "", "PublishDKGTranscript", b.DKG); err != nil {
		return err
	}
	if err := e.submitBallots(ctx, runID, c, b, led); err != nil {
		return err
	}
	return step(ctx, "CloseElection", "", "CloseElection", b.ElectionID)
}

// landedTx is one ballot as the timed window left it: which index it was, and
// where it committed. Receipts are fetched for these AFTER the window.
type landedTx struct {
	index int
	txID  string
	block uint64
}

// submitBallots is the measured ballot window.
//
// Only Submit (SubmitAsync → commit status) runs inside it: no qscc call, no
// receipt fetch, no file write. Anything else in there would be timed as if it
// were the chain's cost. Receipts are collected afterwards with ONE
// ReceiptsForBlock per distinct block, so a 1,000-ballot run that lands in 100
// blocks makes 100 fetches, not 1,000.
//
// The population is streamed: bench.Run's workers pull one line each from a
// single forward scan of ballots.ndjson (see ballotReader).
func (e *Executor) submitBallots(ctx context.Context, runID string, c ElectionConfig, b *onChainBundle, led clientsdk.Ledger) error {
	dir, err := e.store.Dir(runID)
	if err != nil {
		return err
	}
	if b.BallotsFile == "" {
		return fmt.Errorf("bundle.json has no \"ballots_file\" field: this run's bundle predates the streaming ballot format — delete bundle.json and re-run the ceremony to regenerate it")
	}
	// Validate the whole stream before committing anything: a truncated or
	// non-hex line must fail the run, not land as a prefix of an election.
	count, err := validateBallots(dir)
	if err != nil {
		return err
	}
	if count != b.BallotCount {
		return fmt.Errorf("bundle ballot_count is %d but %s holds %d ballots", b.BallotCount, b.BallotsFile, count)
	}

	reader, err := openBallotReader(dir)
	if err != nil {
		return err
	}
	defer reader.Close()

	w, err := e.openReceiptsFor(runID, dir)
	if err != nil {
		return err
	}
	defer e.closeReceipts(runID)

	j := e.journalFor(runID)
	defer j.Close()

	concurrency := c.submitConcurrency()
	startBytes, haveBytes := e.ledgerBytes()
	start := map[string]any{"n": count, "concurrency": concurrency, "send_rate": c.SendRate}
	if haveBytes {
		start["ledger_bytes"] = startBytes
	}
	_ = j.Stamp("stage.ballots.start", start)
	seg := map[string]any{"index": 0}
	// A burst (or any other tagged repetition) is its own segment: the tag is
	// what lets a reader tell a burst window from the measured one.
	if c.Rep != nil && c.Rep.Kind != "" {
		seg["tag"] = c.Rep.Kind
	}
	_ = j.Stamp("segment.start", seg)
	e.publish(runID, "ceremony", "info",
		fmt.Sprintf("submitting %d ballots (%d in flight)…", count, concurrency))

	var mu sync.Mutex
	landed := make([]landedTx, 0, count)
	var readErr error

	stopSampler := e.startSampler(ctx, j)
	res := bench.Run(ctx, count, func(i int) error {
		line, err := reader.At(i)
		if err != nil {
			mu.Lock()
			if readErr == nil {
				readErr = err
			}
			mu.Unlock()
			return err
		}
		txID, block, err := led.Submit("SubmitBallot", line)
		if err != nil {
			return err
		}
		mu.Lock()
		landed = append(landed, landedTx{index: i, txID: txID, block: block})
		mu.Unlock()
		return nil
	}, bench.RunOpts{
		Concurrency: concurrency,
		SendRate:    c.SendRate,
		MaxDuration: c.Window(),
		OnProgress: func(done int) {
			_ = j.Stamp("ballots.progress", map[string]any{"done": done})
		},
	})
	samples := stopSampler()
	bounded := windowWasBounded(ctx, c, res)

	endBytes, haveEndBytes := e.ledgerBytes()
	end := map[string]any{
		"submitted": res.Submitted, "committed": res.Committed, "dropped": res.Dropped,
		"window_ms": res.Window.Milliseconds(), "stopped": res.Stopped,
	}
	if bounded {
		end["bounded"] = true
	}
	if haveEndBytes {
		end["ledger_bytes"] = endBytes
	}
	// A bounded window is CLOSED, not left open: stage.ballots.end, so a later
	// resume does not offer to "finish" a sweep step that already ended as
	// instructed.
	stampWindowEnd(j, end, res.Stopped && !bounded)
	stampSegmentEnd(j, segmentOf(0, res, res.Committed))

	if readErr != nil {
		return readErr
	}
	e.collectReceipts(runID, j, w, led, landed)
	if err := writeLatenciesCSV(dir, res, 0); err != nil {
		return err
	}
	if err := e.writeSubmitMetrics(dir, c, res, samples, count, bounded, startBytes, endBytes, haveBytes && haveEndBytes); err != nil {
		return err
	}
	if res.Dropped > 0 {
		return fmt.Errorf("%d of %d ballots did not commit", res.Dropped, res.Submitted)
	}
	e.publish(runID, "ceremony", "info",
		fmt.Sprintf("%d ballots committed in %s", res.Committed, res.Window.Round(time.Millisecond)))
	return nil
}

// collectReceipts fetches ledger receipts for the window's transactions one
// block at a time, in ascending block order, and appends each to receipts.csv
// (never to trail.ndjson — per-ballot events would drown the lifecycle trail).
// A block that cannot be fetched is stamped and skipped: the ballots committed,
// and losing their receipts must not fail the run.
func (e *Executor) collectReceipts(runID string, j *Journal, w *receiptsWriter, led clientsdk.Ledger, landed []landedTx) {
	sort.Slice(landed, func(i, k int) bool { return landed[i].index < landed[k].index })
	byBlock := make(map[uint64][]landedTx)
	for _, l := range landed {
		byBlock[l.block] = append(byBlock[l.block], l)
	}
	blocks := make([]uint64, 0, len(byBlock))
	for n := range byBlock {
		blocks = append(blocks, n)
	}
	sort.Slice(blocks, func(i, k int) bool { return blocks[i] < blocks[k] })

	for _, n := range blocks {
		items := byBlock[n]
		txIDs := make([]string, len(items))
		for i, it := range items {
			txIDs[i] = it.txID
		}
		receipts, err := led.ReceiptsForBlock(n, txIDs)
		if err != nil {
			_ = j.Stamp("receipts.missing", map[string]any{"block": n, "count": len(items)})
			e.publish(runID, "ceremony", "info",
				fmt.Sprintf("receipts for block %d unavailable (%d ballots): %v", n, len(items), err))
			continue
		}
		byTx := make(map[string]clientsdk.Receipt, len(receipts))
		for _, r := range receipts {
			byTx[r.TxID] = r
		}
		for _, it := range items {
			r, ok := byTx[it.txID]
			if !ok {
				// The transaction committed (Submit said so) but the block as
				// served now does not carry it. Record what is known rather
				// than dropping the row.
				r = clientsdk.Receipt{TxID: it.txID, BlockNumber: it.block}
			}
			_ = w.Append(TrailEvent{Event: "SubmitBallot", Ref: strconv.Itoa(it.index), Receipt: r})
		}
	}
}

// windowWasBounded reports that the window stopped because it reached its own
// time bound, rather than because it was cut short.
//
// All three conditions matter: a window with no bound cannot have hit one; a
// cancelled context is an interruption even if the bound would also have
// fired; and a window that dropped a ballot failed regardless of why it ended.
func windowWasBounded(ctx context.Context, c ElectionConfig, res bench.RunResult) bool {
	return c.Window() > 0 && res.Stopped && res.Dropped == 0 && ctx.Err() == nil
}

// writeSubmitMetrics hands the ballot window's measurements to Verify, which
// runs as a separate phase and cannot see them any other way.
func (e *Executor) writeSubmitMetrics(dir string, c ElectionConfig, res bench.RunResult, samples Samples, expected int, bounded bool, startBytes, endBytes int64, haveBytes bool) error {
	stats := bench.Summary(res.Latencies)
	toMs := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }
	sm := submitMetrics{
		WindowMs:         res.Window.Milliseconds(),
		Submitted:        res.Submitted,
		Committed:        res.Committed,
		Dropped:          res.Dropped,
		Expected:         expected,
		CommittedTPS:     bench.ThroughputTPS(res.Committed, res.Window),
		DriverCeilingTPS: res.DriverCeilingTPS(),
		Concurrency:      res.Concurrency,
		SendRate:         c.SendRate,
		Stopped:          res.Stopped,
		Bounded:          bounded,
		LatencyMinMs:     toMs(stats.Min),
		LatencyP50Ms:     toMs(stats.Median),
		LatencyMeanMs:    toMs(stats.Mean),
		LatencyP95Ms:     toMs(stats.P95),
		LatencyP99Ms:     toMs(stats.P99),
		LatencyStdDevMs:  toMs(stats.StdDev),
		PeakCPUPct:       map[string]float64{},
		PeakMemMB:        map[string]float64{},
	}
	for name, st := range samples.PerContainer {
		role := containerRole(name)
		if role == "" {
			continue
		}
		if v, ok := sm.PeakCPUPct[role]; !ok || st.PeakCPU > v {
			sm.PeakCPUPct[role] = st.PeakCPU
		}
		mem := float64(st.PeakMem) / (1024 * 1024)
		if v, ok := sm.PeakMemMB[role]; !ok || mem > v {
			sm.PeakMemMB[role] = mem
		}
	}
	if haveBytes {
		delta := endBytes - startBytes
		sm.LedgerBytesDelta = &delta
	}
	return writeJSON(filepath.Join(dir, submitMetricsFile), sm)
}

// containerRole maps a sampled container name to the perf.csv role column it
// belongs to. Anything else is not a role the schema reports.
func containerRole(name string) string {
	switch {
	case name == "client":
		return "client"
	case strings.HasPrefix(name, "peer"):
		return "peer"
	case strings.HasPrefix(name, "orderer"):
		return "orderer"
	}
	return ""
}

// startSampler runs the docker-stats sampler for the duration of the ballot
// window. Only a live network has containers worth sampling, so the offline
// and test paths never shell out to docker at all.
func (e *Executor) startSampler(ctx context.Context, j *Journal) func() Samples {
	if !e.fabric.Enabled() {
		return func() Samples { return Samples{PerContainer: map[string]ContainerStats{}} }
	}
	return StartSampler(ctx, j, samplerContainers(), 0)
}

// ledgerBytes probes the on-disk ledger size, if a peer volume path was
// configured. Reported as a delta across the ballot window.
func (e *Executor) ledgerBytes() (int64, bool) {
	if e.fabric.PeerVolume == "" {
		return 0, false
	}
	n, err := LedgerBytes(e.fabric.PeerVolume)
	if err != nil {
		return 0, false
	}
	return n, true
}

// writeCorrectnessCSV writes the per-contest proof of correctness: the seeded
// ground truth, the value REAL threshold decryption recovered (decoded), E, and
// the cryptographic evidence needed to re-verify it — the recovered plaintext
// point, the aggregate (encrypted) tally it came from, and the run's artifact
// hashes (DKG, tally, ballot-set). Each row is self-contained proof.
//
// An on-chain run whose ledger audit ran contributes a SECOND block of rows,
// source=ledger, holding the same audit run over the record read back from the
// chain, and every row carries the ledger_matches_local verdict. Without a
// ledger audit the file is source=local rows with that column empty.
func writeCorrectnessCSV(path string, sa StreamAudit, dkgHash, tallyHash, ballotsHash string, lc *ledgerCheck) error {
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
		"source", "ledger_matches_local",
	}); err != nil {
		return err
	}
	matches := ""
	if lc != nil {
		matches = lc.matches
	}
	// Each block of rows carries the provenance hashes of the directory IT was
	// audited from, so a source=ledger row is checkable against the ledger
	// dump rather than pointing at the console's artifacts.
	writeRows := func(source, dkgHash, tallyHash, ballotsHash string, contests []ContestCorrectness) error {
		for _, c := range contests {
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
				source,
				matches,
			}
			if err := w.Write(row); err != nil {
				return err
			}
		}
		return nil
	}
	if err := writeRows("local", dkgHash, tallyHash, ballotsHash, sa.Contests); err != nil {
		return err
	}
	if lc != nil && lc.status == "ok" {
		lDkg, lTally, lBallots := runDigests(filepath.Join(filepath.Dir(path), LedgerDir))
		if err := writeRows("ledger", lDkg, lTally, lBallots, lc.audit.Contests); err != nil {
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

// ---- Checkpoint / resume ---------------------------------------------------
//
// A ballot window that dies mid-flight (peer restart, cancelled run, killed
// console) leaves an election half-committed. Re-running it would resubmit
// every ballot and the chaincode would reject the already-spent nullifiers as
// double votes, so the run has to know what the CHAIN holds before it submits
// anything: the committed set is ListNullifiers intersected with this run's
// ballots, by index. receipts.csv is only a cross-check — it is written by us,
// after the fact, and a crash is exactly when it is least trustworthy.

// nullifierPageSize is how many committed nullifiers one ListNullifiers page
// asks for, matching the chaincode's own per-page cap.
const nullifierPageSize = 10000

// nullifierLister reads an election's committed nullifiers, one page at a
// time. *clientsdk.BulletinClient satisfies it; it is deliberately a
// one-method interface rather than an addition to clientsdk.Ledger, which is
// the transaction surface.
type nullifierLister interface {
	ListNullifiers(electionID string, pageSize int, bookmark string) (clientsdk.NullifierPage, error)
}

// loadBundle reads a run's cached on-chain bundle from path.
func loadBundle(path string) (*onChainBundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	var b onChainBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	return &b, nil
}

// Resume re-drives an interrupted ballot window against the live network,
// submitting only what the chain does not already hold. Same connection path
// as Submit — the ledger for the transactions, the bulletin client for the
// committed set.
func (e *Executor) Resume(ctx context.Context, runID string, c ElectionConfig) error {
	path, err := e.bundlePath(runID)
	if err != nil {
		return err
	}
	if !e.fabric.Enabled() {
		return errNoFabric()
	}
	conn, err := e.fabric.Connect()
	if err != nil {
		e.publish(runID, "submit", "error", "connect to Fabric: "+err.Error())
		return err
	}
	defer conn.Close()
	return e.resumeBallots(ctx, runID, c, conn.Ledger(), conn.Bulletin, path)
}

// resumeBallots is the resumed ballot window: one more segment, over the
// indices the chain does not hold.
func (e *Executor) resumeBallots(ctx context.Context, runID string, c ElectionConfig,
	led clientsdk.Ledger, nl nullifierLister, bundlePath string) error {
	dir, err := e.store.Dir(runID)
	if err != nil {
		return err
	}
	b, err := loadBundle(bundlePath)
	if err != nil {
		return err
	}
	plan, err := planResume(dir, c)
	if err != nil {
		return err
	}

	j := e.journalFor(runID)
	defer j.Close()

	byNullifier, err := nullifierIndex(dir, b.BallotCount)
	if err != nil {
		return err
	}
	committed, err := chainCommitted(byNullifier, b, nl)
	if err != nil {
		return err
	}
	crossCheckReceipts(dir, j, committed)

	if !plan.stamped {
		_ = j.Stamp("interrupted_at", map[string]any{"last_done": plan.lastDone})
	}
	pending := make([]int, 0, len(committed))
	for i, ok := range committed {
		if !ok {
			pending = append(pending, i)
		}
	}
	_ = j.Stamp("segment.start", map[string]any{"index": plan.Segment, "pending": len(pending)})
	e.publish(runID, "submit", "info", fmt.Sprintf(
		"resuming: %d of %d ballots are already on chain, %d to submit",
		len(committed)-len(pending), len(committed), len(pending)))

	reader, err := openBallotReader(dir)
	if err != nil {
		return err
	}
	defer reader.Close()
	// Committed indices are never requested, so their lines must be dropped as
	// the scan passes them rather than parked for a caller that never comes.
	reader.wanted = func(i int) bool { return i >= 0 && i < len(committed) && !committed[i] }

	w, err := e.openReceiptsFor(runID, dir)
	if err != nil {
		return err
	}
	defer e.closeReceipts(runID)

	concurrency := c.submitConcurrency()
	_ = j.Stamp("stage.ballots.start", map[string]any{
		"n": len(pending), "concurrency": concurrency,
		"send_rate": c.SendRate, "segment": plan.Segment,
	})

	var mu sync.Mutex
	landed := make([]landedTx, 0, len(pending))
	var readErr error

	res := bench.Run(ctx, len(pending), func(k int) error {
		i := pending[k]
		line, err := reader.At(i)
		if err != nil {
			mu.Lock()
			if readErr == nil {
				readErr = err
			}
			mu.Unlock()
			return err
		}
		txID, block, err := led.Submit("SubmitBallot", line)
		if err != nil {
			return err
		}
		mu.Lock()
		landed = append(landed, landedTx{index: i, txID: txID, block: block})
		mu.Unlock()
		return nil
	}, bench.RunOpts{
		Concurrency: concurrency,
		SendRate:    c.SendRate,
		OnProgress: func(done int) {
			_ = j.Stamp("ballots.progress", map[string]any{"done": done, "segment": plan.Segment})
		},
	})

	// A submission can fail and still have landed: the peer's commit status
	// can be lost to an MVCC conflict or a broken connection while the ballot
	// itself is ordered and committed. So a failure is never classified by its
	// error text — the chain is re-read once and every failed index whose
	// nullifier is now on it is a replay, not a drop.
	replays := e.replayedIndices(j, byNullifier, b, nl, pending, res)
	replayed := len(replays)
	dropped := res.Dropped - replayed
	if dropped < 0 {
		dropped = 0
	}
	onChain := res.Committed + replayed

	stampWindowEnd(j, map[string]any{
		"submitted": res.Submitted, "committed": res.Committed, "replayed": replayed,
		"dropped": dropped, "window_ms": res.Window.Milliseconds(),
		"stopped": res.Stopped, "segment": plan.Segment,
	}, res.Stopped)
	seg := segmentOf(plan.Segment, res, onChain)
	stampSegmentEnd(j, seg)

	if readErr != nil {
		return readErr
	}
	e.collectReceipts(runID, j, w, led, landed)
	if err := appendLatenciesCSV(dir, res, plan.Segment,
		func(k int) int { return pending[k] },
		func(k int) bool { return replays[k] }); err != nil {
		return err
	}

	in := FinaliseInput{
		Voters: c.Voters, Positions: c.Positions,
		Segments: append(plan.segments, seg), Dropped: dropped,
		Interrupted: res.Stopped, EByContest: map[string]int64{},
	}
	in.ReconcileErr = bench.Reconcile(res.Submitted, onChain, len(pending))
	in.ReconcileOK = in.ReconcileErr == nil
	Finalise(j, in)

	if err := rollUpSubmitMetrics(dir, len(committed)-len(pending), res, onChain, dropped); err != nil {
		e.publish(runID, "submit", "info", "submit metrics not updated: "+err.Error())
	}

	if dropped > 0 {
		return fmt.Errorf("%d of %d resubmitted ballots did not commit", dropped, res.Submitted)
	}
	e.publish(runID, "submit", "done", fmt.Sprintf(
		"segment %d committed %d ballots (%d were already on chain)", plan.Segment, res.Committed, replayed))
	return nil
}

// replayedIndices classifies the window's failures against the chain: it
// re-reads the committed set once and returns the failed slots whose ballot is
// on chain anyway. Those are replays (the ballot landed; only our knowledge of
// it was lost), never drops, and never negative-test results — writeNegativeTestsCSV
// reads scenario results only and never sees a latency row.
//
// If the refresh itself fails there is no evidence of a replay, so every
// failure stays a drop: the run fails loudly rather than quietly forgiving
// ballots that may really be missing.
func (e *Executor) replayedIndices(j *Journal, byNullifier map[[32]byte]int, b *onChainBundle,
	nl nullifierLister, pending []int, res bench.RunResult) map[int]bool {
	replays := map[int]bool{}
	failed := make([]int, 0, res.Dropped)
	for k := 0; k <= res.LastIndex && k < len(res.OK); k++ {
		if !res.OK[k] {
			failed = append(failed, k)
		}
	}
	if len(failed) == 0 {
		return replays
	}
	committed, err := chainCommitted(byNullifier, b, nl)
	if err != nil {
		_ = j.Stamp("replay_check_failed", map[string]any{"failed": len(failed), "error": err.Error()})
		return replays
	}
	for _, k := range failed {
		if i := pending[k]; i < len(committed) && committed[i] {
			replays[k] = true
		}
	}
	return replays
}

// committedByIndex is the committed set: every ballot in this run whose
// nullifier the chain already holds, by ballot index.
//
// The bundle side is streamed (one ballot decoded at a time, never the whole
// population) and the chain side is paged, so the only resident structure is
// the nullifier -> index map the intersection needs.
func committedByIndex(dir string, b *onChainBundle, nl nullifierLister) ([]bool, error) {
	byNullifier, err := nullifierIndex(dir, b.BallotCount)
	if err != nil {
		return nil, err
	}
	return chainCommitted(byNullifier, b, nl)
}

// chainCommitted is the chain half of the committed set: one paged walk of
// ListNullifiers against an already-built nullifier -> index map. The resume
// walks it twice (once for the plan, once to classify the window's failures),
// and the second walk must not re-stream the population.
func chainCommitted(byNullifier map[[32]byte]int, b *onChainBundle, nl nullifierLister) ([]bool, error) {
	committed := make([]bool, b.BallotCount)
	bookmark := ""
	for {
		page, err := nl.ListNullifiers(b.ElectionID, nullifierPageSize, bookmark)
		if err != nil {
			return nil, fmt.Errorf("list committed nullifiers: %w", err)
		}
		for _, h := range page.Nullifiers {
			key, ok := nullifierKey(h)
			if !ok {
				continue // not 32 bytes: it cannot be one of this run's ballots
			}
			if i, ok := byNullifier[key]; ok {
				committed[i] = true
			}
		}
		// A repeated bookmark would page forever; the empty one ends the walk.
		if page.NextBookmark == "" || page.NextBookmark == bookmark {
			return committed, nil
		}
		bookmark = page.NextBookmark
	}
}

// nullifierIndex maps each ballot's nullifier to its index in ballots.ndjson,
// decoding one ballot at a time. A ballot without a 32-byte nullifier is
// fatal: it could never be matched against the chain, so the resume would
// silently resubmit it.
func nullifierIndex(dir string, count int) (map[[32]byte]int, error) {
	byNullifier := make(map[[32]byte]int, count)
	n := 0
	err := scanBallotLines(dir, func(i int, line string) error {
		raw, err := hex.DecodeString(line)
		if err != nil {
			return fmt.Errorf("ballot %d is not hex: %w", i, err)
		}
		var b pb.Ballot
		if err := proto.Unmarshal(raw, &b); err != nil {
			return fmt.Errorf("decode ballot %d: %w", i, err)
		}
		value := b.GetCredentialPresentation().GetNullifier().GetValue()
		key, ok := nullifierKey(hex.EncodeToString(value))
		if !ok {
			return fmt.Errorf("ballot %d carries no 32-byte nullifier: it cannot be matched against the chain", i)
		}
		// Two ballots sharing a nullifier is a generator bug the chain would
		// reject as a double vote anyway; the later index wins and the earlier
		// one is treated as uncommitted (resubmitted, then rejected).
		byNullifier[key] = i
		n++
		return nil
	})
	if err != nil {
		return nil, err
	}
	if n != count {
		return nil, fmt.Errorf("bundle ballot_count is %d but %s holds %d ballots", count, BallotsFile, n)
	}
	return byNullifier, nil
}

// nullifierKey turns a hex nullifier into the fixed-size map key the
// intersection uses. Anything that is not 32 bytes is not a nullifier.
func nullifierKey(h string) ([32]byte, bool) {
	var key [32]byte
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != 32 {
		return key, false
	}
	copy(key[:], raw)
	return key, true
}

// crossCheckReceipts compares what we recorded against what the chain holds.
// Every SubmitBallot receipt whose index is not in the committed set is a
// finding (receipt_without_nullifier) — recorded, never fatal, because the
// chain is the authority and the resume still has a set to work from. A
// truncated receipts.csv is likewise a warning: a crash mid-Append is the
// expected state here.
func crossCheckReceipts(dir string, j *Journal, committed []bool) {
	events, err := readReceipts(dir)
	if errors.Is(err, ErrTruncatedReceipts) {
		_ = j.Stamp("receipts_truncated", map[string]any{"rows": len(events)})
	} else if err != nil {
		_ = j.Stamp("receipts_unreadable", map[string]any{"error": err.Error()})
		return
	}
	for _, ev := range events {
		if ev.Event != "SubmitBallot" {
			continue
		}
		i, err := strconv.Atoi(ev.Ref)
		if err != nil {
			continue
		}
		if i < 0 || i >= len(committed) || !committed[i] {
			_ = j.Stamp("receipt_without_nullifier", map[string]any{"index": i})
		}
	}
}

// resumePlan is what the journal says about an interrupted ballot window.
type resumePlan struct {
	// Segment is the segment number the resume will write. Segment 0 is the
	// original window; every resume increments.
	Segment int `json:"segment"`
	// Remaining is how many ballots the interrupted window had not dispatched,
	// as its last checkpoint saw it. The exact figure needs the chain (see
	// committedByIndex); this is the cheap number the API answers with.
	Remaining int `json:"remaining"`

	lastDone int
	stamped  bool      // interrupted_at was already recorded
	segments []Segment // every window this run has completed, from segment.end
}

// planResume decides whether a run may be resumed and, if so, with what. It
// refuses unless the run is on-chain and its journal's last ballot-window
// checkpoint left the window open (stage.ballots.start or ballots.progress
// with no stage.ballots.end after it).
func planResume(dir string, c ElectionConfig) (resumePlan, error) {
	var p resumePlan
	if c.Mode != "onchain" {
		return p, fmt.Errorf("run mode is %q: only an on-chain run has a ballot window to resume", c.Mode)
	}
	events, err := readJournalEvents(dir)
	if err != nil {
		return p, fmt.Errorf("this run has no readable journal, so there is no checkpoint to resume from: %w", err)
	}
	open := false
	n := 0
	p.Segment = 1 // journals recorded before segment.start existed still resume into a new segment
	for _, ev := range events {
		switch jstring(ev, "event") {
		case "stage.ballots.start":
			open, n = true, jint(ev, "n")
		case "ballots.progress":
			open, p.lastDone = true, jint(ev, "done")
		case "stage.ballots.interrupted":
			open = true
		case "stage.ballots.end":
			open = false
		case "segment.start":
			p.Segment = jint(ev, "index") + 1
		case "segment.end":
			p.segments = append(p.segments, segmentFromEvent(ev))
		case "interrupted_at":
			p.stamped = true
		}
	}
	if !open {
		return resumePlan{}, errors.New("this run's ballot window is not interrupted: there is nothing to resume")
	}
	if p.Segment < 1 {
		p.Segment = 1
	}
	if p.Remaining = n - p.lastDone; p.Remaining < 0 {
		p.Remaining = 0
	}
	return p, nil
}

// readJournalEvents decodes journal.ndjson into one map per event. A torn last
// line (a crash mid-write) is skipped rather than failing the read — surviving
// exactly that is what the journal is for.
func readJournalEvents(dir string) ([]map[string]any, error) {
	f, err := os.Open(filepath.Join(dir, JournalFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxBallotLine)
	var out []map[string]any
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			out = append(out, m)
		}
	}
	return out, sc.Err()
}

func jstring(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func jfloat(m map[string]any, k string) float64 { f, _ := m[k].(float64); return f }
func jint(m map[string]any, k string) int       { return int(jfloat(m, k)) }

// stampWindowEnd closes a ballot window in the journal. An interrupted window
// is stamped stage.ballots.interrupted, NOT stage.ballots.end: the difference
// is what tells a later resume the window is still open.
func stampWindowEnd(j *Journal, fields map[string]any, interrupted bool) {
	event := "stage.ballots.end"
	if interrupted {
		event = "stage.ballots.interrupted"
	}
	_ = j.Stamp(event, fields)
}

// segmentOf is one window's Segment record. committed is passed in because a
// resumed segment counts replays (ballots the chain already had) as landed.
func segmentOf(index int, res bench.RunResult, committed int) Segment {
	stats := bench.Summary(res.Latencies)
	return Segment{
		Index: index, Committed: committed, WindowMs: res.Window.Milliseconds(),
		TPS:              bench.ThroughputTPS(committed, res.Window),
		P50Ms:            float64(stats.Median.Microseconds()) / 1000.0,
		DriverCeilingTPS: res.DriverCeilingTPS(),
	}
}

func stampSegmentEnd(j *Journal, s Segment) {
	_ = j.Stamp("segment.end", map[string]any{
		"index": s.Index, "committed": s.Committed, "window_ms": s.WindowMs,
		"tps": s.TPS, "p50_ms": s.P50Ms, "driver_ceiling_tps": s.DriverCeilingTPS,
	})
}

// rollUpSubmitMetrics updates the run-level counters in submit-metrics.json
// after a resumed window, so the Verify phase judges the WHOLE run rather than
// the interrupted first window (which, on its own, reads as "dropped 500").
// The window and latency measurements stay as the first window recorded them:
// they measure one window, and a resumed run is not a sustained measurement.
func rollUpSubmitMetrics(dir string, alreadyCommitted int, res bench.RunResult, onChain, dropped int) error {
	path := filepath.Join(dir, submitMetricsFile)
	var sm submitMetrics
	if err := readJSON(path, &sm); err != nil {
		return err
	}
	sm.Submitted = alreadyCommitted + res.Submitted
	sm.Committed = alreadyCommitted + onChain
	sm.Dropped = dropped
	sm.Stopped = res.Stopped
	return writeJSON(path, sm)
}

// segmentsFromJournal reads back every window this run completed, in order.
func segmentsFromJournal(dir string) []Segment {
	events, err := readJournalEvents(dir)
	if err != nil {
		return nil
	}
	var segs []Segment
	for _, ev := range events {
		if jstring(ev, "event") == "segment.end" {
			segs = append(segs, segmentFromEvent(ev))
		}
	}
	return segs
}

// segmentFromEvent reads a segment.end event back into its Segment.
func segmentFromEvent(m map[string]any) Segment {
	return Segment{
		Index: jint(m, "index"), Committed: jint(m, "committed"),
		WindowMs: int64(jfloat(m, "window_ms")), TPS: jfloat(m, "tps"),
		P50Ms: jfloat(m, "p50_ms"), DriverCeilingTPS: jfloat(m, "driver_ceiling_tps"),
	}
}

// --- T3: verify without resuming --------------------------------------------

// reconcileReader is the chain half of a verify-only pass: the committed-ballot
// count the chaincode reports, and the nullifier pages the committed set is
// intersected against.
type reconcileReader interface {
	nullifierLister
	CountCommittedBallots(electionID string) (int, error)
}

var _ reconcileReader = (*clientsdk.BulletinClient)(nil)

// VerifyOnly is the T3 (peer-restart) audit: after the network came back, ask
// the chain what it holds for this run and reconcile it against the run's own
// committed set, then walk the chain over the blocks this run's receipts name.
//
// It submits NOTHING. A resume would paper over the interruption by filling the
// gap; T3's question is what the gap actually was, so the run is marked
// interrupted and the two counts are recorded side by side.
func (e *Executor) VerifyOnly(ctx context.Context, runID string, c ElectionConfig) error {
	conn, err := e.fabric.Connect()
	if err != nil {
		e.publish(runID, "verify", "error", "connect to Fabric: "+err.Error())
		return err
	}
	defer conn.Close()
	return e.verifyOnly(runID, conn.Bulletin, conn.Ledger())
}

// verifyOnly is VerifyOnly's body with the chain injected, so the reconciliation
// is testable without a network.
func (e *Executor) verifyOnly(runID string, rr reconcileReader, led clientsdk.Ledger) error {
	dir, err := e.store.Dir(runID)
	if err != nil {
		return err
	}
	j := e.journalFor(runID)
	defer j.Close()

	// The interruption is stamped first: whatever the reconciliation finds, the
	// fact that this window was interrupted must survive a crash in the middle
	// of finding it.
	_ = j.Stamp("interrupted_at", map[string]any{"phase": "verify-only"})

	bundlePath, err := e.bundlePath(runID)
	if err != nil {
		return err
	}
	b, err := loadBundle(bundlePath)
	if err != nil {
		return err
	}

	chainCount, countErr := rr.CountCommittedBallots(b.ElectionID)
	committed, setErr := committedByIndex(dir, b, rr)
	local := 0
	for _, ok := range committed {
		if ok {
			local++
		}
	}
	fields := map[string]any{
		"election_id": b.ElectionID,
		"expected":    b.BallotCount,
	}
	switch {
	case countErr != nil:
		fields["chain_count_error"] = countErr.Error()
	case setErr != nil:
		fields["committed_set_error"] = setErr.Error()
	default:
		fields["chain_count"] = chainCount
		fields["committed_local"] = local
		fields["reconciled"] = chainCount == local
		fields["missing"] = b.BallotCount - local
	}
	_ = j.Stamp("verify_only.reconcile", fields)
	if setErr == nil {
		crossCheckReceipts(dir, j, committed)
	}

	e.verifyOnlyChain(j, dir, led)

	// The message never invents a number it does not have: a chain that could
	// not answer is reported as not having answered.
	msg := fmt.Sprintf("verify-only: the chain holds %d of this run's %d ballots", local, b.BallotCount)
	switch {
	case countErr != nil:
		msg = fmt.Sprintf("verify-only: the chain could not report its committed count: %v", countErr)
	case setErr != nil:
		msg = fmt.Sprintf("verify-only: the chain reports %d committed; this run's committed set could not be built: %v",
			chainCount, setErr)
	default:
		msg += fmt.Sprintf(" (the chaincode reports %d committed for this election)", chainCount)
	}
	e.publish(runID, "verify", "done", msg)
	if countErr != nil {
		return countErr
	}
	return setErr
}

// verifyOnlyChain walks the blocks this run's receipts landed in and spot-checks
// each receipt against the block the peer serves now. No receipts means no
// range to walk — stamped as not run rather than as a pass.
func (e *Executor) verifyOnlyChain(j *Journal, dir string, led clientsdk.Ledger) {
	events, err := readReceipts(dir)
	if err != nil && !errors.Is(err, ErrTruncatedReceipts) {
		_ = j.Stamp("verify_only.chain", map[string]any{"status": "not run", "error": err.Error()})
		return
	}
	sample := make([]clientsdk.Receipt, 0, len(events))
	var from, to uint64
	for _, ev := range events {
		n := ev.Receipt.BlockNumber
		if len(sample) == 0 || n < from {
			from = n
		}
		if n > to {
			to = n
		}
		sample = append(sample, ev.Receipt)
	}
	if len(sample) == 0 {
		_ = j.Stamp("verify_only.chain", map[string]any{"status": "not run", "error": "no receipts to sample"})
		return
	}
	report, err := led.VerifyChain(from, to, sample)
	if err != nil {
		_ = j.Stamp("verify_only.chain", map[string]any{"status": "not run", "error": err.Error()})
		return
	}
	_ = j.Stamp("verify_only.chain", map[string]any{
		"status": report.Status, "from": from, "to": to,
		"blocks": report.Blocks, "linked": report.Linked, "sampled": len(sample),
	})
}
