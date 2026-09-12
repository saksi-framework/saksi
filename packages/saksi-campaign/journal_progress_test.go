package campaign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk/bench"
)

// The run journal used to fsync ballots.progress on the goroutine that stamped
// it, and bench.Run stamps it from its dispatcher — so every progress
// checkpoint stalled ballot submission. These tests hold the fix in place:
// the stamp must not block the dispatcher, the lines must still land in the
// journal in order ahead of the event that closes the window, and a write or
// Sync error on one must still fail the run.

// slowSyncFile is a real journal file whose fsync takes `delay`. It is the
// seam the no-blocking test needs: a disk that is slow in exactly the way the
// desktop's NVMe volume was under load.
type slowSyncFile struct {
	*os.File
	delay time.Duration
}

func (s *slowSyncFile) Sync() error {
	time.Sleep(s.delay)
	return s.File.Sync()
}

// useSlowJournalFile points openJournalFile at slowSyncFile for one test.
func useSlowJournalFile(t *testing.T, delay time.Duration) {
	t.Helper()
	prev := openJournalFile
	openJournalFile = func(path string) (journalFile, error) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		return &slowSyncFile{File: f, delay: delay}, nil
	}
	t.Cleanup(func() { openJournalFile = prev })
}

// journalLines reads <dir>/journal.ndjson back as parsed events.
func journalLines(t *testing.T, dir string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, JournalFile))
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	var out []map[string]any
	for _, raw := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("journal line %q is not valid JSON: %v", raw, err)
		}
		out = append(out, m)
	}
	return out
}

// (a) The progress stamp must not block bench.Run's dispatcher.
//
// Each progress fsync is made to cost 200 ms, and 5,000 ballots produce five
// of them: synchronously that is a full second of stalled dispatch bolted onto
// a window that otherwise takes microseconds. The dispatch loop must finish in
// a small fraction of that, and every progress line must still land, in order.
func TestProgressStampDoesNotBlockTheDispatcher(t *testing.T) {
	const (
		ballots  = 5000
		syncCost = 200 * time.Millisecond
		// Five progress events cost 1 s synchronously. Half a second is a
		// generous ceiling for a no-op window that should cost ~nothing,
		// and still nowhere near the synchronous cost.
		budget = 500 * time.Millisecond
	)
	useSlowJournalFile(t, syncCost)
	dir := t.TempDir()
	j, err := OpenJournal(dir, map[string]any{"go_os": "test"})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() }) // Windows will not remove an open file

	start := time.Now()
	bench.Run(context.Background(), ballots, func(int) error { return nil }, bench.RunOpts{
		Concurrency: 8,
		OnProgress:  func(done int) { _ = j.Stamp(progressEvent, map[string]any{"done": done}) },
	})
	dispatch := time.Since(start)
	t.Logf("dispatch loop: %s for %d ballots against %d progress fsyncs of %s each",
		dispatch.Round(time.Millisecond), ballots, ballots/1000, syncCost)
	if dispatch > budget {
		t.Fatalf("dispatch loop took %s: the progress stamp is still on the submission path "+
			"(%d progress fsyncs at %s each = %s of stalled dispatch)",
			dispatch.Round(time.Millisecond), ballots/1000, syncCost, time.Duration(ballots/1000)*syncCost)
	}

	if err := j.Stamp("stage.ballots.end", map[string]any{"submitted": ballots}); err != nil {
		t.Fatalf("Stamp(stage.ballots.end): %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var done []float64
	for _, ev := range journalLines(t, dir) {
		if ev["event"] == progressEvent {
			done = append(done, ev["done"].(float64))
		}
	}
	want := []float64{1000, 2000, 3000, 4000, 5000}
	if len(done) != len(want) {
		t.Fatalf("progress lines = %v, want %v", done, want)
	}
	for i := range want {
		if done[i] != want[i] {
			t.Fatalf("progress lines = %v, want %v (out of order or missing)", done, want)
		}
	}
}

// (c) Every progress line must precede the event that closes the window, even
// with a second goroutine stamping through the same journal. The asynchronous
// writer is only correct if the closing stamp waits for it.
//
// Note what is NOT asserted: a progress line may interleave with the sampler's
// `sample` lines in either order — two goroutines stamping concurrently have
// no defined order between them, and mono_ms is the ordering of record. What
// must hold is the barrier: nothing the writer was handed may land after the
// event that closes the window.
func TestProgressLinesPrecedeTheClosingEvent(t *testing.T) {
	useSlowJournalFile(t, 50*time.Millisecond)
	dir := t.TempDir()
	j, err := OpenJournal(dir, map[string]any{"go_os": "test"})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() }) // Windows will not remove an open file

	// The production shape: the docker-stats sampler stamps `sample` on its
	// own goroutine throughout the window, so the closing stamp is not the
	// only synchronous writer competing with the progress queue.
	stopSampler := make(chan struct{})
	samplerDone := make(chan struct{})
	go func() {
		defer close(samplerDone)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stopSampler:
				return
			case <-tick.C:
				_ = j.Stamp("sample", map[string]any{"container": "peer0"})
			}
		}
	}()

	for done := 1000; done <= 3000; done += 1000 {
		_ = j.Stamp(progressEvent, map[string]any{"done": done})
	}
	close(stopSampler)
	<-samplerDone
	// Stamped while the progress writer is still slow fsyncs behind: it must
	// not overtake them.
	if err := j.Stamp("segment.end", map[string]any{"index": 0}); err != nil {
		t.Fatalf("Stamp(segment.end): %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	events := journalLines(t, dir)
	closing := -1
	progress := 0
	for i, ev := range events {
		switch ev["event"] {
		case "segment.end":
			closing = i
		case progressEvent:
			progress++
			if closing != -1 {
				t.Fatalf("progress line at %d follows segment.end at %d: %v", i, closing, events)
			}
		}
	}
	if progress != 3 {
		t.Fatalf("want 3 progress lines before segment.end, got %d: %v", progress, events)
	}
	if closing == -1 {
		t.Fatalf("no segment.end in journal: %v", events)
	}
}

// progressSyncFailFile is a real journal file whose fsync fails for a
// ballots.progress line and nothing else, so a run-failure test exercises the
// asynchronous writer's error path specifically. Real, not in-memory, because
// planResume and segmentsFromJournal read journal.ndjson back off disk.
type progressSyncFailFile struct {
	*os.File
	mu    sync.Mutex
	last  []byte
	err   error
	armed *atomic.Bool // lets a test choose WHICH window the journal breaks in
}

func (f *progressSyncFailFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	f.last = append(f.last[:0], p...)
	f.mu.Unlock()
	return f.File.Write(p)
}

func (f *progressSyncFailFile) Sync() error {
	f.mu.Lock()
	isProgress := bytes.Contains(f.last, []byte(`"event":"`+progressEvent+`"`))
	f.mu.Unlock()
	if isProgress && f.armed.Load() {
		return f.err
	}
	return f.File.Sync()
}

// useProgressFailJournalFile makes every journal opened during this test fail
// its fsync on a ballots.progress line. The returned flag arms and disarms
// that, so a two-window test can break the journal in the window it means to:
// bench.Run's dispatcher races the cancellation that ends the first window, so
// "the first window stops before 1,000 dispatches" is not something a test can
// rely on.
func useProgressFailJournalFile(t *testing.T, failure error) *atomic.Bool {
	t.Helper()
	armed := &atomic.Bool{}
	armed.Store(true)
	prev := openJournalFile
	openJournalFile = func(path string) (journalFile, error) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		return &progressSyncFailFile{File: f, err: failure, armed: armed}, nil
	}
	t.Cleanup(func() { openJournalFile = prev })
	return armed
}

// (b) A Sync error on a progress event still fails the run, with the journal's
// own reason. Moving the write off the stamping goroutine must not turn a
// broken journal into a silently successful run.
func TestProgressSyncErrorFailsTheRun(t *testing.T) {
	wantErr := errors.New("disk full")
	useProgressFailJournalFile(t, wantErr)

	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeBallotStream(t, runDir, 1500) // >= 1 progress event

	err := e.submitOnChain(context.Background(), "run-1",
		ElectionConfig{Concurrency: 8}, &fakeLedger{blockSize: 10}, path)
	if err == nil {
		t.Fatal("want the run to fail when a progress event cannot be fsynced")
	}
	if !strings.Contains(err.Error(), wantErr.Error()) {
		t.Fatalf("run failed without the journal's reason: %v", err)
	}
}

// The journal's own error must survive the hand-off to the writer goroutine:
// once flushed, Err reports it and a later synchronous Stamp still returns it.
func TestProgressWriteErrorSurfacesThroughErr(t *testing.T) {
	wantErr := errors.New("disk full")
	useProgressFailJournalFile(t, wantErr)
	j, err := OpenJournal(t.TempDir(), map[string]any{"go_os": "test"})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })

	if err := j.Stamp(progressEvent, map[string]any{"done": 1000}); err != nil {
		t.Fatalf("the stamp itself must not wait for the write: %v", err)
	}
	err = j.Stamp("segment.end", nil) // flushes the queue first
	if !errors.Is(err, wantErr) {
		t.Fatalf("Stamp after a failed progress write: want %v, got %v", wantErr, err)
	}
	if !errors.Is(j.Err(), wantErr) {
		t.Fatalf("Err() = %v, want %v", j.Err(), wantErr)
	}
}

// (C1 regression) The coalescing drop must never be able to pop a barrier.
//
// Barriers used to ride the same channel as progress lines, so a full queue
// let stampProgress pop one — leaving its waiter parked until j.done, which
// never closes on a live journal. The production shape is exactly this: the
// docker-stats sampler stamps `sample` (a barrier) every 5 s during the
// window while the dispatcher feeds progress, and a stalling disk lets the
// queue fill behind it. Stranding that barrier wedges the sampler, and then
// submitBallots hangs forever in stopSampler's own wait after the window.
//
// So: queue a barrier and then flood the line queue far past progressQueue
// while the writer is deliberately slow. Without the split channels the
// stamping goroutine never returns.
func TestProgressCoalescingNeverStrandsABarrier(t *testing.T) {
	useSlowJournalFile(t, 5*time.Millisecond)
	dir := t.TempDir()
	j, err := OpenJournal(dir, map[string]any{"go_os": "test"})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })

	stamped := make(chan error, 1)
	go func() { stamped <- j.Stamp("sample", map[string]any{"container": "peer0"}) }()

	// One event per millisecond against a 5 ms fsync: the queue is full within
	// ~64 stamps and stays full, so the drop branch runs on nearly every one.
	for i := 1; i <= 1000; i++ {
		_ = j.Stamp(progressEvent, map[string]any{"done": i * 1000})
		time.Sleep(time.Millisecond)
	}

	select {
	case err := <-stamped:
		if err != nil {
			t.Fatalf("Stamp(sample): %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("a non-progress Stamp never returned: the coalescing drop stranded its barrier, " +
			"which in a real run wedges the docker-stats sampler and then the ballot window")
	}
}

// (coalescing) A full queue coalesces rather than blocking, keeps the newest
// count, and says so: the next line written carries coalesced_total, so a
// reader sees a skipped count instead of a silent gap.
func TestProgressCoalescesRatherThanBlocking(t *testing.T) {
	useSlowJournalFile(t, 5*time.Millisecond)
	dir := t.TempDir()
	j, err := OpenJournal(dir, map[string]any{"go_os": "test"})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })

	const events = 500 // >> progressQueue, stamped back to back
	start := time.Now()
	for i := 1; i <= events; i++ {
		_ = j.Stamp(progressEvent, map[string]any{"done": i * 1000})
	}
	// 500 events at a 5 ms fsync would be 2.5 s if the sender waited.
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("stamping %d progress events took %s: the sender waited on the writer",
			events, waited.Round(time.Millisecond))
	}
	if err := j.Stamp("segment.end", map[string]any{"index": 0}); err != nil {
		t.Fatalf("Stamp(segment.end): %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var written, coalesced int
	var lastDone float64
	for _, ev := range journalLines(t, dir) {
		if ev["event"] != progressEvent {
			continue
		}
		written++
		lastDone = ev["done"].(float64)
		if _, ok := ev["coalesced_total"]; ok {
			coalesced++
		}
	}
	if written >= events {
		t.Fatalf("%d of %d progress lines written: the queue never filled, so nothing was coalesced", written, events)
	}
	if coalesced == 0 {
		t.Fatalf("%d progress lines dropped but none carries coalesced_total: the gap is silent", events-written)
	}
	if lastDone != float64(events*1000) {
		t.Fatalf("last progress line is done=%v, want the newest (%d): coalescing kept the wrong end",
			lastDone, events*1000)
	}
}

// verifyPerfCells runs Verify over a finished run and returns its perf.csv row.
func verifyPerfCells(t *testing.T, e *Executor, runID, runDir string, c ElectionConfig) map[string]string {
	t.Helper()
	e.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(auditJSON), nil
	}
	if _, err := e.Verify(context.Background(), runID, c); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return perfCells(t, runDir)
}

// (I1, fresh window) The operator gets the reason as the stage's error, but
// the ARTIFACT must carry it too: the repeat driver verifies even after a
// failed submit, so a run whose journal broke inside the window must not end
// recorded as failed:false.
func TestJournalFailureInTheFreshWindowEndsTheRunFailed(t *testing.T) {
	wantErr := errors.New("disk full")
	useProgressFailJournalFile(t, wantErr)

	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeBallotStream(t, runDir, 1500) // >= 1 progress event
	c := ElectionConfig{Mode: "onchain", Voters: 1500, Positions: 1, Candidates: 2, Concurrency: 8}

	if err := e.submitOnChain(context.Background(), "run-1", c, &fakeLedger{blockSize: 10}, path); err == nil {
		t.Fatal("want the window to fail when a progress event cannot be fsynced")
	}

	cells := verifyPerfCells(t, e, "run-1", runDir, c)
	if cells["failed"] != "true" {
		t.Fatalf("perf.csv failed = %q, want true", cells["failed"])
	}
	if !strings.Contains(cells["fail_reason"], wantErr.Error()) {
		t.Fatalf("perf.csv fail_reason = %q, want the journal's own reason", cells["fail_reason"])
	}
}

// (I1 / I3c, resumed window) The same for the second window: resumeBallots'
// own Finalise must carry the reason, and so must the perf row Verify writes
// afterwards. executor.go's second journalWindowErr call site was untested.
func TestJournalFailureInTheResumedWindowEndsTheRunFailed(t *testing.T) {
	wantErr := errors.New("disk full")
	armed := useProgressFailJournalFile(t, wantErr)
	armed.Store(false) // the first window's journal is healthy

	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeRealBallotStream(t, runDir, 2000)
	c := ElectionConfig{Mode: "onchain", Voters: 2000, Positions: 1, Candidates: 2, Concurrency: 8}

	// The first window is killed at 500 and fails on the ledger, leaving a
	// window to resume. Its journal is healthy, so nothing it records can be
	// mistaken for what the resumed window's journal does.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	led := &fakeLedger{blockSize: 10, FailAt: 500, cancel: cancel}
	if err := e.submitOnChain(ctx, "run-1", c, led, path); err == nil {
		t.Fatal("want an error from the ledger failing at ballot 500")
	}
	led.FailAt = 0 // the "restart": the ledger is healthy again
	if jerr := submitMetricsJournalError(t, runDir); jerr != "" {
		t.Fatalf("the first window recorded a journal error (%q): this test must isolate the resumed one", jerr)
	}
	armed.Store(true) // from here on the journal cannot fsync a progress event

	// The resumed window has ~1,500 to submit, so it DOES stamp progress —
	// and that is what the journal chokes on.
	err := e.resumeBallots(context.Background(), "run-1", c, led, led, path)
	if err == nil {
		t.Fatal("want the resumed window to fail when a progress event cannot be fsynced")
	}
	if !strings.Contains(err.Error(), wantErr.Error()) {
		t.Fatalf("resume failed without the journal's reason: %v", err)
	}

	cells := verifyPerfCells(t, e, "run-1", runDir, c)
	if cells["failed"] != "true" {
		t.Fatalf("perf.csv failed = %q, want true", cells["failed"])
	}
	if !strings.Contains(cells["fail_reason"], wantErr.Error()) {
		t.Fatalf("perf.csv fail_reason = %q, want the journal's own reason", cells["fail_reason"])
	}
}

// (I3d) The other half of the rule, and the one that must NOT change: a
// journal that cannot be OPENED leaves the run unrecorded, it does not fail
// it. Instrumentation that is simply absent must never be the thing that fails
// a phase — only a journal that broke mid-window does.
func TestUnopenableJournalDoesNotFailTheRun(t *testing.T) {
	prev := openJournalFile
	openJournalFile = func(string) (journalFile, error) {
		return nil, errors.New("permission denied")
	}
	t.Cleanup(func() { openJournalFile = prev })

	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeBallotStream(t, runDir, 1500)

	if err := e.submitOnChain(context.Background(), "run-1",
		ElectionConfig{Concurrency: 8}, &fakeLedger{blockSize: 10}, path); err != nil {
		t.Fatalf("a run whose journal could not be opened must still run: %v", err)
	}
}

// submitMetricsJournalError reads back the window's recorded journal failure.
func submitMetricsJournalError(t *testing.T, runDir string) string {
	t.Helper()
	var sm submitMetrics
	if err := readJSON(filepath.Join(runDir, submitMetricsFile), &sm); err != nil {
		t.Fatalf("read %s: %v", submitMetricsFile, err)
	}
	return sm.JournalError
}
