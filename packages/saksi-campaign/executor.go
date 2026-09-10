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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	"github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk/bench"
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
func (e *Executor) Verify(ctx context.Context, runID string, c ElectionConfig) (StreamAudit, error) {
	dir, err := e.store.Dir(runID)
	if err != nil {
		return StreamAudit{}, err
	}
	j := e.journalFor(runID)
	defer j.Close()
	_ = j.Stamp("stage.verify.start", nil)

	e.publish(runID, "verify", "info", "auditing run…")
	out, runErr := e.run(ctx, e.demoBin, "audit-stream", dir, "--json")

	var sa StreamAudit
	if jsonErr := json.Unmarshal(out, &sa); jsonErr != nil {
		// Unparseable stdout means the binary crashed / drifted — a real error,
		// never silently read as "audit fail".
		e.publish(runID, "verify", "error", "audit-stream produced no valid result")
		crashErr := fmt.Errorf("audit-stream crashed: %v (output: %s)", runErr, truncate(out, 200))
		_ = j.Stamp("stage.verify.end", stageEnd(crashErr))
		e.finalise(j, dir, runID, c, sa, crashErr)
		return StreamAudit{}, crashErr
	}
	// timings.json is the auditor's own in-process stage timing, kept as a
	// standalone artifact so perf.csv's *_inproc_ms columns have a source a
	// reader can check.
	_ = writeJSON(filepath.Join(dir, TimingsFile), sa.TimingsMs)

	dkgHash, tallyHash, ballotsHash := runDigests(dir)
	if err := writeCorrectnessCSV(filepath.Join(dir, CorrectnessFile), sa, dkgHash, tallyHash, ballotsHash); err != nil {
		_ = j.Stamp("stage.verify.end", stageEnd(err))
		e.finalise(j, dir, runID, c, sa, err)
		return sa, err
	}
	if sa.Overall == "pass" {
		e.publish(runID, "verify", "done", "audit PASS (E=0 on every contest)")
	} else {
		e.publish(runID, "verify", "error", "audit FAIL (see correctness.csv)")
	}
	_ = j.Stamp("stage.verify.end", map[string]any{"ok": true, "overall": sa.Overall})
	e.finalise(j, dir, runID, c, sa, nil)
	return sa, nil
}

// finalise closes the run out: the run.end verdict, then the perf.csv row it
// carries. Instrumentation failures are reported, never fatal — the audit
// result the caller asked for has already been decided.
func (e *Executor) finalise(j *Journal, dir, runID string, c ElectionConfig, sa StreamAudit, stageErr error) {
	fin := Finalise(j, finaliseInput(dir, c, sa, stageErr))
	if err := writePerfRow(dir, runID, c, fin); err != nil {
		e.publish(runID, "verify", "info", "perf.csv not written: "+err.Error())
	}
}

// finaliseInput assembles the run-failed predicate's inputs. Without a
// submission window (offline runs) there is nothing to reconcile and no
// segment, so only the audit's per-contest E decides the verdict.
func finaliseInput(dir string, c ElectionConfig, sa StreamAudit, stageErr error) FinaliseInput {
	in := FinaliseInput{
		Voters: c.Voters, Positions: c.Positions,
		ReconcileOK: true, StageErr: stageErr,
		EByContest: make(map[string]int64, len(sa.Contests)),
	}
	for _, ct := range sa.Contests {
		in.EByContest[ct.Contest] = ct.E
	}
	var sm submitMetrics
	if readJSON(filepath.Join(dir, submitMetricsFile), &sm) != nil {
		return in
	}
	in.Dropped = sm.Dropped
	// bench.Reconcile is the single definition of "every ballot landed", and
	// its message names which half of that failed.
	in.ReconcileErr = bench.Reconcile(sm.Submitted, sm.Committed, sm.Expected)
	in.ReconcileOK = in.ReconcileErr == nil
	in.Interrupted = sm.Stopped
	in.Segments = []Segment{{
		Index: 0, Committed: sm.Committed, WindowMs: sm.WindowMs,
		TPS: sm.CommittedTPS, P50Ms: sm.LatencyP50Ms,
		DriverCeilingTPS: sm.DriverCeilingTPS,
	}}
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
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read bundle: %w", err)
	}
	var b onChainBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, nil, fmt.Errorf("parse bundle: %w", err)
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
	return &b, step, nil
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
		OnProgress: func(done int) {
			_ = j.Stamp("ballots.progress", map[string]any{"done": done})
		},
	})
	samples := stopSampler()

	endBytes, haveEndBytes := e.ledgerBytes()
	end := map[string]any{
		"submitted": res.Submitted, "committed": res.Committed, "dropped": res.Dropped,
		"window_ms": res.Window.Milliseconds(), "stopped": res.Stopped,
	}
	if haveEndBytes {
		end["ledger_bytes"] = endBytes
	}
	_ = j.Stamp("stage.ballots.end", end)

	if readErr != nil {
		return readErr
	}
	e.collectReceipts(runID, j, w, led, landed)
	if err := writeLatenciesCSV(dir, res, 0); err != nil {
		return err
	}
	if err := e.writeSubmitMetrics(dir, c, res, samples, count, startBytes, endBytes, haveBytes && haveEndBytes); err != nil {
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

// writeSubmitMetrics hands the ballot window's measurements to Verify, which
// runs as a separate phase and cannot see them any other way.
func (e *Executor) writeSubmitMetrics(dir string, c ElectionConfig, res bench.RunResult, samples Samples, expected int, startBytes, endBytes int64, haveBytes bool) error {
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
