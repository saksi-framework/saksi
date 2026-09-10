package campaign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// fakeJournalFile is an in-memory journalFile that records Sync calls and can
// be told to fail its next Sync, for exercising the checkpoint/Sync-error
// paths without touching disk.
type fakeJournalFile struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	syncCalls int
	syncErr   error
	closed    bool
}

func (f *fakeJournalFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buf.Write(p)
}

func (f *fakeJournalFile) Sync() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncCalls++
	return f.syncErr
}

func (f *fakeJournalFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeJournalFile) len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buf.Len()
}

// (1) Line 1 of a fresh journal is the env event with every documented key
// present (null allowed).
func TestOpenJournalWritesEnvAsLine1(t *testing.T) {
	dir := t.TempDir()
	env := map[string]any{
		"go_os": "linux", "go_arch": "amd64", "go_version": "go1.26",
		"saksi_demo_version": nil, "git_head_saksi": nil, "git_head_console": nil,
		"docker_version": nil, "docker_info": nil, "containers": []map[string]any{},
		"uname": nil, "cpu_model": nil, "null_probes": []string{"docker_version"},
	}
	j, err := OpenJournal(dir, env)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	defer j.Close()

	data, err := os.ReadFile(filepath.Join(dir, JournalFile))
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	if len(lines) != 1 {
		t.Fatalf("want exactly 1 line after OpenJournal, got %d", len(lines))
	}
	var got map[string]any
	if err := json.Unmarshal(lines[0], &got); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v", err)
	}
	if got["event"] != "env" {
		t.Fatalf(`want event:"env", got %v`, got["event"])
	}
	if _, ok := got["ts"]; !ok {
		t.Fatal("line 1 missing ts")
	}
	for k := range env {
		if _, ok := got[k]; !ok {
			t.Errorf("line 1 missing key %q", k)
		}
	}
}

// (2) Checkpoint events call Sync; non-checkpoint events do not.
func TestStampSyncsOnlyOnCheckpoints(t *testing.T) {
	f := &fakeJournalFile{}
	j := newJournal(f, time.Now())

	if err := j.Stamp("sample", map[string]any{"container": "peer0"}); err != nil {
		t.Fatalf("Stamp(sample): %v", err)
	}
	if f.syncCalls != 0 {
		t.Fatalf("non-checkpoint event synced: syncCalls=%d", f.syncCalls)
	}

	if err := j.Stamp("stage.generate", nil); err != nil {
		t.Fatalf("Stamp(stage.generate): %v", err)
	}
	if f.syncCalls != 1 {
		t.Fatalf("checkpoint event did not sync: syncCalls=%d", f.syncCalls)
	}

	if err := j.Stamp("run.end", nil); err != nil {
		t.Fatalf("Stamp(run.end): %v", err)
	}
	if f.syncCalls != 2 {
		t.Fatalf("want 2 syncs after 2 checkpoints, got %d", f.syncCalls)
	}
}

// (3) An injected Sync error is returned, failed is set, and a subsequent
// Stamp returns the same error and writes nothing further.
func TestStampSyncErrorFailsJournal(t *testing.T) {
	wantErr := errors.New("disk full")
	f := &fakeJournalFile{syncErr: wantErr}
	j := newJournal(f, time.Now())

	err := j.Stamp("run.start", nil) // checkpoint: triggers the failing Sync
	if err == nil {
		t.Fatal("want error from Stamp when Sync fails")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("want wrapped %v, got %v", wantErr, err)
	}
	lenAfterFailure := f.len()

	err2 := j.Stamp("run.end", map[string]any{"failed": false})
	if !errors.Is(err2, err) {
		t.Fatalf("subsequent Stamp: want same error, got %v", err2)
	}
	if f.len() != lenAfterFailure {
		t.Fatalf("subsequent Stamp wrote data: file grew from %d to %d bytes", lenAfterFailure, f.len())
	}
}

// (4) 8 goroutines x 1000 Stamp calls produce exactly 8000 parseable lines.
func TestStampConcurrent(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenJournal(dir, map[string]any{"go_os": "linux"})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	defer j.Close()

	const goroutines, perGoroutine = 8, 1000
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				if err := j.Stamp("sample", map[string]any{"g": g, "i": i}); err != nil {
					t.Errorf("Stamp: %v", err)
				}
			}
		}(g)
	}
	wg.Wait()

	data, err := os.ReadFile(filepath.Join(dir, JournalFile))
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	// line 1 is the env event.
	stampLines := lines[1:]
	if len(stampLines) != goroutines*perGoroutine {
		t.Fatalf("want %d stamped lines, got %d", goroutines*perGoroutine, len(stampLines))
	}
	for i, line := range stampLines {
		var v map[string]any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("line %d not parseable: %v (%q)", i+2, err, line)
		}
	}
}

// (5) Sampler parses a fixture of three docker-stats lines including one
// malformed -> two samples, Malformed == 1.
func TestParseDockerStatsLines(t *testing.T) {
	fixture := `{"Name":"peer0.org1","CPUPerc":"12.34%","MemUsage":"123.4MiB / 31.2GiB","NetIO":"1.2kB / 3.4MB","BlockIO":"5.6MB / 7.8MB"}
not json at all
{"Name":"orderer.example.com","CPUPerc":"0.50%","MemUsage":"50MiB / 8GiB","NetIO":"100B / 200B","BlockIO":"0B / 0B"}
{"Name":"unrelated","CPUPerc":"1.00%","MemUsage":"10MiB / 1GiB","NetIO":"0B / 0B","BlockIO":"0B / 0B"}`

	lines, malformed := parseDockerStatsLines([]byte(fixture), []string{"peer0.org1", "orderer.example.com"})
	if malformed != 1 {
		t.Fatalf("want 1 malformed line, got %d", malformed)
	}
	if len(lines) != 2 {
		t.Fatalf("want 2 kept samples, got %d", len(lines))
	}
	if lines[0].Name != "peer0.org1" || !lines[0].HasCPU || lines[0].CPUPct != 12.34 {
		t.Fatalf("bad peer0 line: %+v", lines[0])
	}
	if lines[0].MemBytes == 0 {
		t.Fatal("peer0 mem_bytes not parsed")
	}
	if lines[0].NetInBytes == 0 || lines[0].NetOutBytes == 0 {
		t.Fatalf("peer0 net io not parsed: %+v", lines[0])
	}
	if lines[1].Name != "orderer.example.com" {
		t.Fatalf("bad orderer line: %+v", lines[1])
	}
}

// (6) runFailed table: one row per clause, plus the all-clear row.
func TestRunFailed(t *testing.T) {
	base := func() FinaliseInput {
		return FinaliseInput{Voters: 100, Segments: []Segment{{TPS: 5}}, ReconcileOK: true}
	}
	cases := []struct {
		name       string
		mutate     func(FinaliseInput) FinaliseInput
		wantFailed bool
		wantReason string
	}{
		{"all clear", func(f FinaliseInput) FinaliseInput { return f }, false, ""},
		{"stage error", func(f FinaliseInput) FinaliseInput {
			f.StageErr = fmt.Errorf("generator crashed")
			return f
		}, true, "stage_error: generator crashed"},
		{"dropped", func(f FinaliseInput) FinaliseInput {
			f.Dropped = 3
			return f
		}, true, "dropped: 3"},
		{"reconcile mismatch", func(f FinaliseInput) FinaliseInput {
			f.ReconcileOK = false
			return f
		}, true, "reconcile_mismatch"},
		{"E nonzero", func(f FinaliseInput) FinaliseInput {
			f.EByContest = map[string]int64{"mayor": 0, "senate": 2}
			return f
		}, true, "e_nonzero: senate=2"},
		{"interrupted", func(f FinaliseInput) FinaliseInput {
			f.Interrupted = true
			return f
		}, true, "interrupted"},
		{"bounded stop is not an interruption", func(f FinaliseInput) FinaliseInput {
			f.Interrupted, f.Bounded = true, true
			return f
		}, false, ""},
		{"bounded does not forgive a drop", func(f FinaliseInput) FinaliseInput {
			f.Interrupted, f.Bounded = true, true
			f.Dropped = 2
			return f
		}, true, "dropped: 2"},
		{"bounded does not forgive a reconcile mismatch", func(f FinaliseInput) FinaliseInput {
			f.Interrupted, f.Bounded = true, true
			f.ReconcileOK = false
			return f
		}, true, "reconcile_mismatch"},
		{"bounded does not forgive a nonzero E", func(f FinaliseInput) FinaliseInput {
			f.Interrupted, f.Bounded = true, true
			f.EByContest = map[string]int64{"mayor": 1}
			return f
		}, true, "e_nonzero: mayor=1"},
		{"stage error wins over everything else", func(f FinaliseInput) FinaliseInput {
			f.StageErr = errors.New("boom")
			f.Dropped = 1
			f.ReconcileOK = false
			f.Interrupted = true
			return f
		}, true, "stage_error: boom"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			failed, reason := runFailed(c.mutate(base()))
			if failed != c.wantFailed || reason != c.wantReason {
				t.Fatalf("got (%v, %q), want (%v, %q)", failed, reason, c.wantFailed, c.wantReason)
			}
		})
	}
}

// (7) Finalise table: sustained / driver-bound / scaling-limit true/false /
// zero-window / interrupted.
func TestFinalise(t *testing.T) {
	cases := []struct {
		name             string
		in               FinaliseInput
		wantSustained    bool
		wantSustainedTPS *float64
		wantScalingLimit string
	}{
		{
			name: "sustained, below arrival tps -> scaling limit true",
			in: FinaliseInput{
				Voters: 36000, ReconcileOK: true,
				Segments: []Segment{{WindowMs: 10000, TPS: 0.5, DriverCeilingTPS: 10}},
			},
			wantSustained: true, wantSustainedTPS: f64p(0.5), wantScalingLimit: "true",
		},
		{
			name: "sustained, at/above arrival tps -> scaling limit false",
			in: FinaliseInput{
				Voters: 3600, ReconcileOK: true,
				Segments: []Segment{{WindowMs: 10000, TPS: 5, DriverCeilingTPS: 10}},
			},
			wantSustained: true, wantSustainedTPS: f64p(5), wantScalingLimit: "false",
		},
		{
			name: "driver was the ceiling -> inconclusive despite TPS < arrival",
			in: FinaliseInput{
				Voters: 36000, ReconcileOK: true,
				Segments: []Segment{{WindowMs: 10000, TPS: 9, DriverCeilingTPS: 10}}, // 9 >= 0.8*10
			},
			wantSustained: true, wantSustainedTPS: f64p(9), wantScalingLimit: "inconclusive",
		},
		{
			name: "zero window -> TPS nil, scaling limit inconclusive",
			in: FinaliseInput{
				Voters: 36000, ReconcileOK: true,
				Segments: []Segment{{WindowMs: 0, TPS: 0, DriverCeilingTPS: 10}},
			},
			wantSustained: true, wantSustainedTPS: nil, wantScalingLimit: "inconclusive",
		},
		{
			name: "interrupted -> not sustained, inconclusive",
			in: FinaliseInput{
				Voters: 36000, ReconcileOK: true, Interrupted: true,
				Segments: []Segment{{WindowMs: 10000, TPS: 1, DriverCeilingTPS: 10}},
			},
			wantSustained: false, wantSustainedTPS: nil, wantScalingLimit: "inconclusive",
		},
		{
			name: "multiple segments -> not sustained, inconclusive",
			in: FinaliseInput{
				Voters: 36000, ReconcileOK: true,
				Segments: []Segment{{WindowMs: 10000, TPS: 1}, {WindowMs: 10000, TPS: 2}},
			},
			wantSustained: false, wantSustainedTPS: nil, wantScalingLimit: "inconclusive",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := Finalise(nil, c.in)
			if res.Sustained != c.wantSustained {
				t.Errorf("Sustained = %v, want %v", res.Sustained, c.wantSustained)
			}
			if res.ScalingLimit != c.wantScalingLimit {
				t.Errorf("ScalingLimit = %q, want %q", res.ScalingLimit, c.wantScalingLimit)
			}
			if (res.SustainedTPS == nil) != (c.wantSustainedTPS == nil) {
				t.Fatalf("SustainedTPS = %v, want %v", res.SustainedTPS, c.wantSustainedTPS)
			}
			if res.SustainedTPS != nil && *res.SustainedTPS != *c.wantSustainedTPS {
				t.Errorf("SustainedTPS = %v, want %v", *res.SustainedTPS, *c.wantSustainedTPS)
			}
			wantArrival := float64(c.in.Voters) / 36000
			if res.ArrivalTPS != wantArrival {
				t.Errorf("ArrivalTPS = %v, want %v", res.ArrivalTPS, wantArrival)
			}
		})
	}
}

func f64p(v float64) *float64 { return &v }

// Finalise stamps run.end with the result fields.
func TestFinaliseStampsRunEnd(t *testing.T) {
	f := &fakeJournalFile{}
	j := newJournal(f, time.Now())
	Finalise(j, FinaliseInput{Voters: 100, ReconcileOK: true, Segments: []Segment{{WindowMs: 1000, TPS: 1, DriverCeilingTPS: 100}}})

	data := f.buf.Bytes()
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	var last map[string]any
	if err := json.Unmarshal(lines[len(lines)-1], &last); err != nil {
		t.Fatalf("run.end not valid JSON: %v", err)
	}
	if last["event"] != "run.end" {
		t.Fatalf("want event run.end, got %v", last["event"])
	}
	if f.syncCalls == 0 {
		t.Fatal("run.end must be synced (it's a checkpoint event)")
	}
}

// LedgerBytes on Windows sums file sizes under peerVolume (no du available).
func TestLedgerBytesWindowsWalk(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only path")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("world!"), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := LedgerBytes(dir)
	if err != nil {
		t.Fatalf("LedgerBytes: %v", err)
	}
	if want := int64(len("hello") + len("world!")); n != want {
		t.Fatalf("LedgerBytes = %d, want %d", n, want)
	}
}

// clientCPUPct: first sample has nothing to delta against (null); the second
// sample reports 100 * (delta CPU seconds / delta wall seconds).
func TestSampleAggClientCPUPercent(t *testing.T) {
	agg := newSampleAgg()
	t0 := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	seq := []float64{10, 12} // fake accumulated CPU seconds
	i := 0
	fake := func() (float64, bool) {
		v := seq[i]
		i++
		return v, true
	}

	if _, ok := agg.clientCPUPct(t0, fake); ok {
		t.Fatal("first sample should have no CPU%: nothing to delta against")
	}

	// 2 CPU-seconds consumed over a 4-second wall gap -> 50%.
	pct, ok := agg.clientCPUPct(t0.Add(4*time.Second), fake)
	if !ok {
		t.Fatal("second sample should report a CPU%")
	}
	if pct != 50 {
		t.Fatalf("cpu_pct = %v, want 50", pct)
	}
}

// clientCPUPct: a failed CPU-time read reports null and doesn't wedge the
// delta state (a later successful pair still works).
func TestSampleAggClientCPUPercentUnavailable(t *testing.T) {
	agg := newSampleAgg()
	t0 := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	fail := func() (float64, bool) { return 0, false }
	if _, ok := agg.clientCPUPct(t0, fail); ok {
		t.Fatal("unavailable CPU-time read should report null")
	}
}

// sampleClient reads CPU time through the cpuSecondsFn package var, so
// clearing it (unavailable) must surface as a null cpu_pct in the stamped
// event.
func TestSampleClientCPUUnavailableIsNull(t *testing.T) {
	orig := cpuSecondsFn
	cpuSecondsFn = func() (float64, bool) { return 0, false }
	defer func() { cpuSecondsFn = orig }()

	f := &fakeJournalFile{}
	j := newJournal(f, time.Now())
	sampleClient(j, newSampleAgg())

	var got map[string]any
	if err := json.Unmarshal(bytes.TrimRight(f.buf.Bytes(), "\n"), &got); err != nil {
		t.Fatalf("stamped line not valid JSON: %v", err)
	}
	if got["cpu_pct"] != nil {
		t.Fatalf("cpu_pct = %v, want null", got["cpu_pct"])
	}
}

// (8) CollectEnv with a fake demoBin path and every probe made to fail
// (simulating a cleared PATH) returns a map with null_probes listing the
// docker/git keys and no error (CollectEnv has no error return at all).
func TestCollectEnvAllProbesUnavailable(t *testing.T) {
	orig := cmdRunner
	cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("simulated: command not found")
	}
	defer func() { cmdRunner = orig }()

	env := CollectEnv(filepath.Join(t.TempDir(), "no-such-saksi-demo"))

	if env["go_os"] == nil || env["go_arch"] == nil || env["go_version"] == nil {
		t.Fatalf("go_* fields should never be null: %+v", env)
	}
	nullProbes, ok := env["null_probes"].([]string)
	if !ok {
		t.Fatalf("null_probes missing or wrong type: %+v", env["null_probes"])
	}
	want := []string{"docker_version", "docker_info", "containers", "git_head_saksi", "git_head_console"}
	for _, k := range want {
		found := false
		for _, np := range nullProbes {
			if np == k {
				found = true
			}
		}
		if !found {
			t.Errorf("null_probes missing %q; got %v", k, nullProbes)
		}
		if env[k] != nil {
			t.Errorf("env[%q] = %v, want null", k, env[k])
		}
	}
}
