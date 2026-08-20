package campaign

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// newRun creates a store + a run and returns the executor, run id, and dir.
func newRun(t *testing.T, mode string) (*Executor, string, string) {
	t.Helper()
	store := NewRunStore(t.TempDir())
	c := good()
	c.Mode = mode
	runID, dir, err := store.Create(c, time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	e := NewExecutor(store, NewHub(), "saksi-demo", "")
	return e, runID, dir
}

func TestGenerateWritesStreamFiles(t *testing.T) {
	e, runID, dir := newRun(t, "offline")
	var gotArgs []string
	e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		gotArgs = args
		d := argAfter(args, "--stream")
		_ = os.WriteFile(filepath.Join(d, "header.json"), []byte(`{"n":1}`), 0o644)
		_ = os.WriteFile(filepath.Join(d, "ballots.ndjson"), []byte("00\n"), 0o644)
		return nil, nil
	}

	if err := e.Generate(context.Background(), runID, good()); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, f := range []string{"header.json", "ballots.ndjson"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("%s not written: %v", f, err)
		}
	}
	// The config was mapped to the expected flags.
	joined := strings.Join(gotArgs, " ")
	for _, want := range []string{"gen", "--stream", "--trustees 3", "--threshold 2", "--election-id " + runID} {
		if !strings.Contains(joined, want) {
			t.Fatalf("gen args missing %q: %s", want, joined)
		}
	}
}

func TestVerifyWritesCorrectnessCSV(t *testing.T) {
	e, runID, dir := newRun(t, "offline")
	e.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(`{"overall":"pass","contests":[
			{"contest":"president/cand0","ground_truth":3,"decoded":3,"E":0,"pass":true},
			{"contest":"president/cand1","ground_truth":3,"decoded":3,"E":0,"pass":true}]}`), nil
	}

	sa, err := e.Verify(context.Background(), runID)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sa.Overall != "pass" || len(sa.Contests) != 2 {
		t.Fatalf("unexpected audit: %+v", sa)
	}
	data, err := os.ReadFile(filepath.Join(dir, CorrectnessFile))
	if err != nil {
		t.Fatalf("correctness.csv not written: %v", err)
	}
	got := string(data)
	if !strings.HasPrefix(got, "contest,ground_truth,decoded,E,pass\n") {
		t.Fatalf("bad csv header: %q", got)
	}
	if !strings.Contains(got, "president/cand0,3,3,0,true") {
		t.Fatalf("csv missing expected row: %q", got)
	}
}

func TestVerifyReportsAuditFailWithoutErroring(t *testing.T) {
	// A valid audit that FOUND tampering (overall=fail) is a success of the
	// tool, returned as a result — not a Go error (codex #12).
	e, runID, _ := newRun(t, "offline")
	e.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		// Non-zero exit AND valid JSON: audit-stream exits 1 on a fail.
		return []byte(`{"overall":"fail","contests":[{"contest":"c","ground_truth":3,"decoded":4,"E":1,"pass":false}]}`),
			fmt.Errorf("exit status 1")
	}
	sa, err := e.Verify(context.Background(), runID)
	if err != nil {
		t.Fatalf("a valid audit-fail must not be a Go error: %v", err)
	}
	if sa.Overall != "fail" || sa.Contests[0].Pass {
		t.Fatalf("expected a failing audit result: %+v", sa)
	}
}

func TestVerifyErrorsOnUnparseableOutput(t *testing.T) {
	// A genuine crash (no valid JSON) IS a Go error.
	e, runID, _ := newRun(t, "offline")
	e.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("panic: segfault"), fmt.Errorf("exit status 139")
	}
	if _, err := e.Verify(context.Background(), runID); err == nil {
		t.Fatal("an unparseable audit-stream output must be a Go error")
	}
}

func TestSubmitOfflineIsNoOp(t *testing.T) {
	e, runID, _ := newRun(t, "offline")
	called := false
	e.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		called = true
		return nil, nil
	}
	c := good()
	c.Mode = "offline"
	if err := e.Submit(context.Background(), runID, c); err != nil {
		t.Fatalf("offline Submit should be a no-op: %v", err)
	}
	if called {
		t.Fatal("offline Submit must not shell any command")
	}
}

func TestSubmitOnchainDrivesTheDriver(t *testing.T) {
	store := NewRunStore(t.TempDir())
	c := good()
	c.Mode = "onchain"
	c.Voters = 5
	runID, dir, err := store.Create(c, time.Now())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	e := NewExecutor(store, NewHub(), "saksi-demo", "console-driver")
	var gotName string
	var gotArgs []string
	e.run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		gotName, gotArgs = name, args
		return nil, nil
	}
	if err := e.Submit(context.Background(), runID, c); err != nil {
		t.Fatalf("onchain Submit: %v", err)
	}
	if gotName != "console-driver" || len(gotArgs) < 2 || gotArgs[0] != "submit" || gotArgs[1] != dir {
		t.Fatalf("driver not called with submit <dir>: %s %v", gotName, gotArgs)
	}
}

func TestSubmitOnchainWithoutDriverErrors(t *testing.T) {
	e, runID, _ := newRun(t, "onchain") // consBin == ""
	c := good()
	c.Mode = "onchain"
	c.Voters = 5
	if err := e.Submit(context.Background(), runID, c); err == nil {
		t.Fatal("onchain Submit without a driver must return a clear error, not hang")
	}
}
