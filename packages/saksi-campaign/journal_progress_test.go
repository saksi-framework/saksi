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

// (c) Every progress line must precede the event that closes the window. The
// asynchronous writer is only correct if the closing stamp waits for it.
func TestProgressLinesPrecedeTheClosingEvent(t *testing.T) {
	useSlowJournalFile(t, 50*time.Millisecond)
	dir := t.TempDir()
	j, err := OpenJournal(dir, map[string]any{"go_os": "test"})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() }) // Windows will not remove an open file
	for done := 1000; done <= 3000; done += 1000 {
		_ = j.Stamp(progressEvent, map[string]any{"done": done})
	}
	// Stamped immediately, while the progress writer is still three slow
	// fsyncs behind: it must not overtake them.
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

// progressSyncFailFile fails fsync for a ballots.progress line and nothing
// else, so the run-failure test exercises the asynchronous writer's error path
// specifically.
type progressSyncFailFile struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	last []byte
	err  error
}

func (f *progressSyncFailFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = append(f.last[:0], p...)
	return f.buf.Write(p)
}

func (f *progressSyncFailFile) Sync() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if bytes.Contains(f.last, []byte(`"event":"`+progressEvent+`"`)) {
		return f.err
	}
	return nil
}

func (f *progressSyncFailFile) Close() error { return nil }

// (b) A Sync error on a progress event still fails the run, with the journal's
// own reason. Moving the write off the stamping goroutine must not turn a
// broken journal into a silently successful run.
func TestProgressSyncErrorFailsTheRun(t *testing.T) {
	wantErr := errors.New("disk full")
	prev := openJournalFile
	openJournalFile = func(string) (journalFile, error) {
		return &progressSyncFailFile{err: wantErr}, nil
	}
	t.Cleanup(func() { openJournalFile = prev })

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
	f := &progressSyncFailFile{err: wantErr}
	j := newJournal(f, time.Now())
	defer j.Close()

	if err := j.Stamp(progressEvent, map[string]any{"done": 1000}); err != nil {
		t.Fatalf("the stamp itself must not wait for the write: %v", err)
	}
	err := j.Stamp("segment.end", nil) // flushes the queue first
	if !errors.Is(err, wantErr) {
		t.Fatalf("Stamp after a failed progress write: want %v, got %v", wantErr, err)
	}
	if !errors.Is(j.Err(), wantErr) {
		t.Fatalf("Err() = %v, want %v", j.Err(), wantErr)
	}
}
