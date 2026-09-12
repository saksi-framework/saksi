package campaign

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The run journal, ledger-size probe, and finaliser.
//
// Today nothing records the environment a run executed in, nothing samples
// resources while it runs, and nothing defines when a run has failed.
// journal.ndjson is an append-only, one-JSON-object-per-line event log per
// run folder (fsynced at checkpoint events so a crash loses at most the
// events since the last checkpoint, never a torn line); LedgerBytes reports
// on-disk ledger size; Finalise decides pass/fail and the scaling-limit
// verdict at run.end. The environment snapshot (CollectEnv) is in env.go and
// the docker-stats sampler is in sampler.go — both feed this journal.
//
// ONE exception to "fsynced at checkpoint events", and it costs durability:
// ballots.progress is fsynced by a writer goroutine rather than by the
// goroutine that stamped it (see stampProgress — the synchronous fsync used to
// stall ballot submission). A progress event is therefore durable shortly
// after it is stamped, not at the moment it is stamped, so a hard kill can
// lose up to progressQueue of them — 64 events, i.e. 64,000 ballots. Every
// OTHER event, including every event that closes a window, is fsynced before
// its Stamp returns exactly as before, and a closing event is written only
// after every progress line handed over before it.
//
// What that costs a reader: the last ballots.progress on disk is a LOWER BOUND
// on what the window had dispatched, so interrupted_at{last_done} and the
// resume API's Remaining are bounds too — a resume may re-offer ballots the
// chain already holds. That is already the resume path's contract (the chain's
// nullifier set, not the journal, decides what is committed), so this widens
// the over-estimate rather than introducing a new failure mode.
//
// Later tasks wire this into the executor; this file only provides the API
// and tests it.

// JournalFile is the run-folder-relative name of the event journal.
const JournalFile = "journal.ndjson"

// journalFile is what Journal needs from its underlying file. *os.File
// satisfies it; tests inject a fake to exercise the Sync-error path without
// touching disk.
type journalFile interface {
	io.Writer
	Sync() error
	Close() error
}

// progressEvent is the one event stamped from INSIDE the measured submission
// window, and so the only one written asynchronously — see stampProgress.
const progressEvent = "ballots.progress"

// progressQueue is how many progress events the writer goroutine may fall
// behind before stampProgress starts coalescing. One event per 1,000 ballots
// means 64 is 64,000 ballots of slack.
const progressQueue = 64

// barrier is a "everything handed over before me is on disk" marker for the
// progress writer. stop tells the writer this is the last thing it will serve.
//
// Barriers ride their OWN channel, never the line queue: stampProgress drops
// the head of the line queue when it is full, and dropping a barrier would
// leave its waiter parked forever.
type barrier struct {
	done chan struct{}
	stop bool
}

// Journal is an append-only, one-JSON-object-per-line event log for a single
// run folder. Every Stamp call but ballots.progress takes the mutex and issues
// exactly one Write; checkpoint events (run.start, stage.*, rep.*,
// ballots.progress, segment.*, run.end) additionally fsync.
//
// ballots.progress is written by a private writer goroutine instead, because
// it is the only event stamped from inside the measured submission window —
// see stampProgress. Its line, fields and fsync are unchanged; only the
// goroutine that performs them moved. Every other Stamp drains that queue
// before writing, so the log's order is the order the events happened in.
type Journal struct {
	mu     sync.Mutex
	f      journalFile
	path   string
	opened time.Time
	failed error

	progress  chan map[string]any // progress lines awaiting their write
	barriers  chan barrier        // unbuffered: ordering markers and the stop signal
	done      chan struct{}       // closed once the progress writer has retired
	coalesced atomic.Int64
}

// OpenJournal creates <runDir>/journal.ndjson and writes the environment
// snapshot as line 1: {"event":"env", ...env, "ts": RFC3339}, fsynced
// immediately.
func OpenJournal(runDir string, env map[string]any) (*Journal, error) {
	path := filepath.Join(runDir, JournalFile)
	f, err := openJournalFile(path)
	if err != nil {
		return nil, fmt.Errorf("open journal: %w", err)
	}
	j := newJournal(f, time.Now())
	j.path = path

	line := make(map[string]any, len(env)+2)
	for k, v := range env {
		line[k] = v
	}
	line["event"] = "env"
	line["ts"] = time.Now().UTC().Format(time.RFC3339)
	if err := j.writeLine(line, true); err != nil {
		_ = j.Close()
		return nil, err
	}
	return j, nil
}

// newJournal builds a Journal over an already-open journalFile. Unexported:
// production code always goes through OpenJournal; tests use this to inject
// a fake file and a fixed opened time.
func newJournal(f journalFile, opened time.Time) *Journal {
	j := &Journal{
		f: f, opened: opened,
		progress: make(chan map[string]any, progressQueue),
		barriers: make(chan barrier),
		done:     make(chan struct{}),
	}
	go j.writeProgress()
	return j
}

// openJournalFile opens a journal's underlying file. A var, and the single
// place the flags live, so a test can substitute a file whose writes stall or
// fail without a real disk that does either.
var openJournalFile = func(path string) (journalFile, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Stamp appends {"event":event,"ts":...,"mono_ms":<since open>,...fields} and
// fsyncs if event is a checkpoint. A prior Sync error is returned on every
// later call, without writing — except for ballots.progress, which is handed
// to the writer goroutine and always returns nil; Err() is where its errors
// surface.
//
// A nil Journal accepts and discards every Stamp: a run folder whose journal
// could not be opened still runs, it just goes unrecorded. Instrumentation
// must never be the thing that fails a phase.
func (j *Journal) Stamp(event string, fields map[string]any) error {
	if j == nil {
		return nil
	}
	line := make(map[string]any, len(fields)+3)
	for k, v := range fields {
		line[k] = v
	}
	line["event"] = event
	line["ts"] = time.Now().UTC().Format(time.RFC3339)
	line["mono_ms"] = time.Since(j.opened).Milliseconds()
	if event == progressEvent {
		j.stampProgress(line)
		// Always nil, and deliberately so: reading failed would take the
		// journal mutex, which the writer goroutine holds across its fsync
		// — the exact stall this path exists to avoid. A progress write's
		// error lands in failed and surfaces at Err() (and so at the next
		// synchronous Stamp), off the submission path.
		return nil
	}
	// Ordering barrier: everything the progress writer has been handed is on
	// disk before this line is written, so segment.end / stage.ballots.end /
	// run.end still follow the progress they close.
	j.flushProgress()
	return j.writeLine(line, isCheckpoint(event))
}

// stampProgress hands line to the writer goroutine WITHOUT ever waiting on it.
//
// This is the whole point of the split. bench.Run calls OnProgress on its
// dispatcher goroutine, so the fsync a checkpoint costs used to stall ballot
// submission itself: measured on the desktop 2026-09-12 as 12 of 62 reps
// losing 69 s of submission time (~3 % of the total), visible as multi-second
// gaps with no ballot in flight. Every committed_tps the campaign reported was
// understated by it.
//
// Policy when the queue is full: coalesce towards the LATEST progress, never
// block. Progress is a monotone dispatched-count, so a newer event subsumes an
// older one, and dropping from the head keeps the sequence ordered while
// keeping the number a reader actually needs; blocking would put the write
// back on the submission path, which is the defect this removes. Every send
// here is non-blocking, so the newest line is the one kept in the ordinary
// case and not a guarantee — whichever line is coalesced away is counted, and
// the running total rides on the next line written ("coalesced_total"), so a
// reader sees that counts were skipped rather than a silent gap. At
// progressQueue events of slack it takes the writer falling 64,000 ballots
// behind to reach this at all.
func (j *Journal) stampProgress(line map[string]any) {
	select {
	case <-j.done:
		return // journal closed: there is nothing left to write to
	default:
	}
	if n := j.coalesced.Load(); n > 0 {
		line["coalesced_total"] = n
	}
	select {
	case j.progress <- line:
		return
	default:
	}
	// Full: drop the oldest queued line to make room for this one. Only a
	// LINE can be popped here — barriers ride j.barriers precisely so this
	// cannot strand one.
	select {
	case <-j.progress:
		line["coalesced_total"] = j.coalesced.Add(1)
	default:
	}
	select {
	case j.progress <- line:
	default:
		// Room was taken between the pop and this send, so this line is the
		// one coalesced away. With the single dispatcher goroutine bench.Run
		// documents this cannot happen, but it is counted rather than
		// assumed away: the count is cumulative and rides the next line.
		j.coalesced.Add(1)
	}
}

// writeProgress is the journal's progress writer. It writes each queued line
// exactly as a synchronous Stamp would — same fields, same fsync — and records
// any error in failed, where Err() finds it.
func (j *Journal) writeProgress() {
	defer close(j.done)
	for {
		// Lines first, always. A barrier means "every line handed over before
		// me is written and fsynced", so it is only served once the line
		// queue has drained — that is the whole ordering guarantee.
		select {
		case line := <-j.progress:
			_ = j.writeLine(line, true) // the error sticks in failed
			continue
		default:
		}
		select {
		case line := <-j.progress:
			_ = j.writeLine(line, true)
		case b := <-j.barriers:
			close(b.done)
			if b.stop {
				return
			}
		}
	}
}

// await queues it and blocks until the writer goroutine has passed it. Callers
// are never on the submission path: flushProgress runs on whichever goroutine
// stamped a non-progress event, and Close runs at the end of a stage.
//
// Both waits also give up on done, so a Stamp that races a Close can never
// wedge on a writer that has already retired.
func (j *Journal) await(stop bool) {
	if j.barriers == nil {
		return
	}
	b := barrier{done: make(chan struct{}), stop: stop}
	select {
	case j.barriers <- b:
	case <-j.done:
		return
	}
	select {
	case <-b.done:
	case <-j.done:
	}
}

// flushProgress blocks until every progress event handed over so far is
// written and fsynced.
func (j *Journal) flushProgress() { j.await(false) }

// Err reports the first write or Sync error the journal hit, including one hit
// on the progress writer goroutine, where there was no Stamp call left to
// return it to. Nil-safe, like Stamp.
func (j *Journal) Err() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.failed
}

func (j *Journal) writeLine(line map[string]any, checkpoint bool) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed != nil {
		return j.failed
	}
	b, err := json.Marshal(line)
	if err != nil {
		return fmt.Errorf("marshal journal line: %w", err)
	}
	b = append(b, '\n')
	if _, err := j.f.Write(b); err != nil {
		j.failed = fmt.Errorf("write journal line: %w", err)
		return j.failed
	}
	if checkpoint {
		if err := j.f.Sync(); err != nil {
			j.failed = fmt.Errorf("sync journal: %w", err)
			return j.failed
		}
	}
	return nil
}

// Close closes the underlying journal file. Nil-safe, like Stamp.
func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	j.await(true) // drain and retire the progress writer
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.f.Close()
}

// isCheckpoint reports whether event is one of the checkpoint events that
// fsync: run.start, stage.*, rep.*, ballots.progress, segment.*, run.end.
func isCheckpoint(event string) bool {
	switch event {
	case "run.start", "run.end", "ballots.progress":
		return true
	}
	return strings.HasPrefix(event, "stage.") ||
		strings.HasPrefix(event, "rep.") ||
		strings.HasPrefix(event, "segment.")
}

// ---- Disk: ledger bytes ----------------------------------------------------

// LedgerBytes reports the on-disk size of the Fabric ledger under
// peerVolume: `du -sb` on the volume path, falling back to a rough sum of
// `docker system df -v`'s local-volume sizes if `du` is unavailable. On
// Windows (no du) it sums file sizes under peerVolume directly — the same
// result `Get-ChildItem -Recurse | Measure-Object Length -Sum` would give,
// without spawning PowerShell.
func LedgerBytes(peerVolume string) (int64, error) {
	if runtime.GOOS == "windows" {
		return ledgerBytesWalk(peerVolume)
	}
	ctx, cancel := context.WithTimeout(context.Background(), envProbeTimeout)
	defer cancel()
	if out, err := cmdRunner(ctx, "du", "-sb", peerVolume); err == nil {
		if n, ok := parseDuOutput(string(out)); ok {
			return n, nil
		}
	}
	return ledgerBytesFromDockerDF(peerVolume)
}

func parseDuOutput(out string) (int64, bool) {
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ledgerBytesFromDockerDF sums every local volume's SIZE column.
//
// ponytail: not scoped to peerVolume — it's a fallback for when du itself is
// missing, so a precise per-volume number isn't available anyway. Upgrade to
// `docker volume inspect --format '{{.Mountpoint}}'` matched against
// peerVolume if a tighter number is ever needed.
func ledgerBytesFromDockerDF(peerVolume string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), envProbeTimeout)
	defer cancel()
	out, err := cmdRunner(ctx, "docker", "system", "df", "-v")
	if err != nil {
		return 0, fmt.Errorf("ledger bytes for %s: du and docker system df both failed: %w", peerVolume, err)
	}
	var total int64
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if n, ok := parseByteSize(fields[len(fields)-1]); ok {
			total += n
		}
	}
	return total, nil
}

func ledgerBytesWalk(peerVolume string) (int64, error) {
	var total int64
	err := filepath.WalkDir(peerVolume, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("ledger bytes for %s: %w", peerVolume, err)
	}
	return total, nil
}

// ---- Finaliser --------------------------------------------------------------

// Segment is one sustained/ramp measurement window.
type Segment struct {
	Index            int
	Committed        int
	WindowMs         int64
	TPS              float64
	P50Ms            float64
	DriverCeilingTPS float64
}

// FinaliseInput is everything Finalise needs to decide pass/fail and the
// scaling-limit verdict.
type FinaliseInput struct {
	Voters, Positions int
	Segments          []Segment
	Dropped           int
	ReconcileOK       bool
	// ReconcileErr is bench.Reconcile's own diagnosis when ReconcileOK is
	// false. Optional: it only sharpens the reason, it does not decide it.
	ReconcileErr error
	EByContest   map[string]int64
	StageErr     error
	Interrupted  bool
	// Bounded reports that the ballot window closed because it reached its own
	// time bound (bench.RunOpts.MaxDuration), not because anything went wrong:
	// a sweep step is a fixed slice of wall clock at a fixed offered rate, and
	// it ends when the clock says so.
	//
	// A bounded window is still not SUSTAINED (Interrupted stays set, so the
	// scaling verdict stays per-segment and inconclusive), but it did not
	// FAIL: it ended as instructed, and every ballot it dispatched committed.
	// Without this, every sweep step would be recorded as a failed run and the
	// campaign's failure rate would measure the sweep rather than the network.
	Bounded bool
	// Resumed reports that this finalisation closes a RESUMED window: the run
	// was interrupted once, and what is being finalised is the remainder.
	//
	// A resumed run can look single-segment from the journal alone — a hard
	// kill leaves no segment.end for the window it killed, so the only segment
	// on record is the resume's own. Its window and TPS describe the remainder,
	// never the population, so publishing them as a whole-run sustained figure
	// would report the tail of a run as the run. Sustained therefore requires
	// !Resumed, which is what drops SustainedTPS and leaves the scaling verdict
	// inconclusive.
	Resumed bool
	// LedgerAudit is the on-chain cross-audit's fate: "" when there was no
	// chain to audit, "ok" when the chain's own record was dumped and audited,
	// "not run" when that could not be completed.
	LedgerAudit string
	// LedgerMatchesLocal is whether the chain's record and the console's agree.
	// Set only when LedgerAudit is "ok"; a mismatch is a finding, NOT a
	// failed run — it is a result the instrument exists to report.
	LedgerMatchesLocal *bool
}

// FinaliseResult is the run.end verdict.
type FinaliseResult struct {
	Failed       bool
	Reason       string
	SustainedTPS *float64
	ArrivalTPS   float64
	ScalingLimit string // "true" | "false" | "inconclusive"
	Sustained    bool
}

// runFailed implements the failed-run predicate: stage error, or any ballot
// dropped, or a reconcile mismatch, or a nonzero E for any contest, or the
// run was interrupted. Reason is the first clause that fired, in that order.
//
// A BOUNDED window is the one stop that is not an interruption — see
// FinaliseInput.Bounded. Its reconcile clause is decided by the caller
// (finaliseInput compares committed against submitted rather than against the
// planned population), so only the interruption clause is relaxed here.
func runFailed(f FinaliseInput) (bool, string) {
	if f.StageErr != nil {
		return true, "stage_error: " + f.StageErr.Error()
	}
	if f.Dropped > 0 {
		return true, fmt.Sprintf("dropped: %d", f.Dropped)
	}
	if !f.ReconcileOK {
		if f.ReconcileErr != nil {
			return true, "reconcile_mismatch: " + f.ReconcileErr.Error()
		}
		return true, "reconcile_mismatch"
	}
	contests := make([]string, 0, len(f.EByContest))
	for c := range f.EByContest {
		contests = append(contests, c)
	}
	sort.Strings(contests)
	for _, c := range contests {
		if e := f.EByContest[c]; e != 0 {
			return true, fmt.Sprintf("e_nonzero: %s=%d", c, e)
		}
	}
	if f.Interrupted && !f.Bounded {
		return true, "interrupted"
	}
	return false, ""
}

// Finalise decides the run.end verdict and stamps it.
func Finalise(j *Journal, f FinaliseInput) FinaliseResult {
	failed, reason := runFailed(f)
	res := FinaliseResult{
		Failed:     failed,
		Reason:     reason,
		ArrivalTPS: float64(f.Voters) / 36000,
		Sustained:  len(f.Segments) == 1 && !f.Interrupted && !f.Resumed,
	}

	res.ScalingLimit = "inconclusive"
	if res.Sustained {
		seg := f.Segments[0]
		if seg.WindowMs != 0 { // zero window: TPS stays nil, never divide by zero
			tps := seg.TPS
			res.SustainedTPS = &tps
			switch {
			case seg.TPS >= 0.8*seg.DriverCeilingTPS: // driver was the ceiling
				res.ScalingLimit = "inconclusive"
			case seg.TPS < res.ArrivalTPS:
				res.ScalingLimit = "true"
			default:
				res.ScalingLimit = "false"
			}
		}
	}

	if j != nil {
		var sustainedTPS any
		if res.SustainedTPS != nil {
			sustainedTPS = *res.SustainedTPS
		}
		end := map[string]any{
			"failed":        res.Failed,
			"reason":        res.Reason,
			"sustained_tps": sustainedTPS,
			"arrival_tps":   res.ArrivalTPS,
			"scaling_limit": res.ScalingLimit,
			"sustained":     res.Sustained,
		}
		// Absent, not false: a run whose window was never time-bounded should
		// not carry a field claiming it was considered and ruled out.
		if f.Bounded {
			end["bounded"] = true
		}
		// Same rule, and the reason sustained is false and there is no
		// whole-run TPS: a reader must be able to tell a resumed run from one
		// that simply did not sustain.
		if f.Resumed {
			end["resumed"] = true
		}
		// Absent, not false: an offline run has no chain to disagree with, and
		// a reader must be able to tell that from a chain that disagreed.
		if f.LedgerAudit != "" {
			end["ledger_audit"] = f.LedgerAudit
		}
		if f.LedgerMatchesLocal != nil {
			end["ledger_matches_local"] = *f.LedgerMatchesLocal
		}
		_ = j.Stamp("run.end", end)
	}
	return res
}
