package campaign

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T, allowHosts []string) (*Server, http.Handler, *Executor) {
	t.Helper()
	store := NewRunStore(t.TempDir())
	hub := NewHub()
	exec := NewExecutor(store, hub, "saksi-demo", "", FabricConfig{})
	// Default fake runner: succeed, writing nothing.
	exec.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	s := NewServer(store, exec, hub, FabricConfig{}, allowHosts, time.Minute)
	return s, s, exec
}

func postJSON(path string, v any) *http.Request {
	b, _ := json.Marshal(v)
	return httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
}

func TestGenerateReturns202AndRunID(t *testing.T) {
	_, h, _ := testServer(t, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postJSON("/generate", good()))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		RunID string `json:"run_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.RunID == "" {
		t.Fatal("no run_id returned")
	}
}

func TestGenerateRejectsInvalidConfig(t *testing.T) {
	_, h, _ := testServer(t, nil)
	bad := good()
	bad.Threshold = 99
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postJSON("/generate", bad))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestOfflineBoundRejectedAt400(t *testing.T) {
	_, h, _ := testServer(t, nil)
	big := good()
	big.Voters = OfflineRecordCeiling + 1 // offline, 1 position
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postJSON("/generate", big))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("offline over-ceiling should be 400, got %d", rec.Code)
	}
}

func TestExportRejectsUnknownArtifactAndBadID(t *testing.T) {
	_, h, _ := testServer(t, nil)
	// Reaches the handler; rejected on artifact allowlist / run-id gate.
	for _, p := range []string{"/export/some-run/secret", "/export/Bad_Id/run.json"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s should be 400, got %d", p, rec.Code)
		}
	}
	// A `..` segment is normalized away by the mux (307) — never serves the file.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/export/../run.json", nil))
	if rec.Code == http.StatusOK {
		t.Fatalf("traversal path must not be served, got %d", rec.Code)
	}
}

func TestRunsListsCreatedRun(t *testing.T) {
	s, h, _ := testServer(t, nil)
	_, _, _ = s.store.Create(good(), time.Now())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/runs", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "midterm") {
		t.Fatalf("runs did not list the created run: %d %s", rec.Code, rec.Body)
	}
}

func TestRunsReportsPresentArtifacts(t *testing.T) {
	s, h, _ := testServer(t, nil)
	_, dir, err := s.store.Create(good(), time.Now())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Simulate a completed Verify (correctness.csv present) — a fresh run has none.
	if err := os.WriteFile(filepath.Join(dir, CorrectnessFile),
		[]byte("contest,ground_truth,decoded,E,pass\n"), 0o644); err != nil {
		t.Fatalf("write csv: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/runs", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `"artifacts"`) || !strings.Contains(body, CorrectnessFile) {
		t.Fatalf("/runs should report the present correctness.csv: %s", body)
	}
	// run.json always exists; ballots.ndjson does not (never generated here).
	if strings.Contains(body, "ballots.ndjson") {
		t.Fatalf("/runs should not list absent artifacts: %s", body)
	}
}

func TestSingleRunLockReturns409(t *testing.T) {
	s, h, exec := testServer(t, nil)
	runID, _, err := s.store.Create(good(), time.Now())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	exec.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		close(started)
		<-release
		return []byte(`{"overall":"pass","contests":[]}`), nil
	}

	// Watch the run's events so we can wait for the phase to finish before the
	// test's TempDir is cleaned (the phase writes correctness.csv).
	events, cancelSub := s.hub.Subscribe(runID)
	defer cancelSub()

	// First verify holds the lock (its runner blocks).
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, postJSON("/verify", map[string]string{"run_id": runID}))
	if rec1.Code != http.StatusAccepted {
		t.Fatalf("first verify want 202, got %d", rec1.Code)
	}
	<-started // ensure the phase goroutine has the lock

	// Second verify on the same run must be rejected.
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, postJSON("/verify", map[string]string{"run_id": runID}))
	if rec2.Code != http.StatusConflict {
		t.Fatalf("second verify want 409, got %d", rec2.Code)
	}

	// Let the phase complete and wait for it to finish writing.
	close(release)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Phase == "verify" && (e.Level == "done" || e.Level == "error") {
				return
			}
		case <-deadline:
			t.Fatal("phase did not finish in time")
		}
	}
}

func TestCrossOriginPostRejected(t *testing.T) {
	_, h, _ := testServer(t, nil)
	req := postJSON("/generate", good())
	req.Header.Set("Origin", "http://evil.example") // != req.Host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST should be 403, got %d", rec.Code)
	}
}

func TestForbiddenHostRejected(t *testing.T) {
	_, h, _ := testServer(t, []string{"127.0.0.1:8090"})
	req := postJSON("/generate", good())
	req.Host = "attacker.example" // not in allowlist
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("forbidden host should be 403, got %d", rec.Code)
	}
}

// A ground-truth run has no encrypted ballots, so Verify and Scenarios must
// refuse it with an explanation rather than failing later on a missing
// ballots.ndjson.
func TestBallotPhasesRefuseGroundTruthRuns(t *testing.T) {
	s, h, _ := testServer(t, nil)
	c := good()
	c.Mode = ModeGroundTruth
	c.Voters = 3_524_078 // capstone tier: also proves the ceiling does not fire
	runID, _, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatalf("ground-truth run must be creatable at capstone scale: %v", err)
	}

	for _, tc := range []struct {
		name, path string
		body       any
	}{
		{"verify", "/verify", map[string]string{"run_id": runID}},
		{"scenarios", "/scenarios", map[string]any{"run_id": runID, "list": []string{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, postJSON(tc.path, tc.body))
			if w.Code != http.StatusConflict {
				t.Fatalf("%s on a ground-truth run: got %d, want %d", tc.name, w.Code, http.StatusConflict)
			}
			if !strings.Contains(w.Body.String(), ModeGroundTruth) {
				t.Fatalf("refusal should name the mode, got %q", w.Body.String())
			}
		})
	}
}

// Ground-truth mode shells gen-ground-truth, not gen --stream, and must not
// try to derive ballots.csv/election.csv from ciphertexts that do not exist.
func TestGenerateGroundTruthShellsTheRightSubcommand(t *testing.T) {
	s, _, exec := testServer(t, nil)
	var got []string
	exec.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		got = args
		return nil, nil
	}
	c := good()
	c.Mode = ModeGroundTruth
	runID, _, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Generate(context.Background(), runID, c); err != nil {
		t.Fatalf("ground-truth generate failed: %v", err)
	}
	if len(got) == 0 || got[0] != "gen-ground-truth" {
		t.Fatalf("want gen-ground-truth subcommand, got %v", got)
	}
	for _, forbidden := range []string{"--stream", "--trustees", "--threshold"} {
		for _, a := range got {
			if a == forbidden {
				t.Fatalf("%s must not be passed on the ground-truth path: %v", forbidden, got)
			}
		}
	}
}

// TestExportServesTheLedgerDump: the chain's own copy of a run is downloadable,
// so a reader can re-audit the LEDGER dump and not only the console's record of
// it. The subdirectory is addressable because handleExport cuts the run id off
// the first slash and allowlists the whole remainder.
func TestExportServesTheLedgerDump(t *testing.T) {
	s, h, _ := testServer(t, nil)
	runID, dir, err := s.store.Create(good(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, LedgerDir), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{headerFile: `{"n":1}`, BallotsFile: "aa\n"} {
		if err := os.WriteFile(filepath.Join(dir, LedgerDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{headerFile, BallotsFile} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/export/"+runID+"/"+LedgerDir+"/"+name, nil))
		if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
			t.Fatalf("ledger/%s: got %d %q", name, rec.Code, rec.Body)
		}
	}
	// And it is listed as an available artifact.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/runs", nil))
	for _, want := range []string{LedgerDir + "/" + headerFile, LedgerDir + "/" + BallotsFile} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("/runs does not list %q:\n%s", want, rec.Body)
		}
	}
}

// The wizard's runs list offers Resume and Verify-only only on a run whose
// ballot window is interrupted, and the peer-restart fault only on an idle run
// whose window has not opened. /runs carries those facts, read from each run's
// journal with the resume route's own check, so the page never guesses.
func TestRunsListReportsWhereEachRunStands(t *testing.T) {
	s, h, _ := testServer(t, nil)
	create := func(mode string, lines ...string) string {
		c := good()
		c.Mode = mode
		id, dir, err := s.store.Create(c, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if len(lines) > 0 {
			writeJournalLines(t, dir, lines...)
		}
		return id
	}
	fresh := create("offline")
	generated := create("offline", `{"event":"run.start"}`)
	failed := create("offline", `{"event":"run.start"}`, `{"event":"run.end","failed":true,"reason":"verify failed"}`)
	ended := create("offline", `{"event":"run.start"}`, `{"event":"run.end","failed":false}`)
	interrupted := create("onchain", `{"event":"run.start"}`, `{"event":"stage.ballots.start","n":10}`,
		`{"event":"ballots.progress","done":4}`, `{"event":"stage.ballots.interrupted"}`)
	closed := create("onchain", `{"event":"run.start"}`, `{"event":"stage.ballots.start","n":10}`,
		`{"event":"stage.ballots.end"}`)
	// A T3 run after its resume: the window was interrupted, a second segment
	// found 4946 ballots pending and closed it, and verify-only reconciled.
	resumed := create("onchain", `{"event":"stage.ballots.start","n":10}`, `{"event":"stage.ballots.interrupted"}`,
		`{"event":"segment.start","index":1,"pending":4946}`, `{"event":"stage.ballots.end","segment":1}`,
		`{"event":"interrupted_at","phase":"verify-only"}`, `{"event":"verify_only.reconcile","reconciled":true}`)
	// The resume closed the election: its ceremony record is on disk.
	resumedDir, _ := s.store.Dir(resumed)
	writeFile(t, resumedDir, CeremonyFile, "{}")
	// Every ballot landed through the resume but the close failed: the resume
	// route takes it again as a close-only retry.
	closePending := create("onchain", `{"event":"stage.ballots.start","n":10}`, `{"event":"stage.ballots.interrupted"}`,
		`{"event":"segment.start","index":1,"pending":6}`, `{"event":"stage.ballots.end","segment":1,"dropped":0}`)
	s.mu.Lock()
	s.busy[generated] = func() {}
	s.mu.Unlock()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/runs", nil))
	var views []runView
	if err := json.Unmarshal(rec.Body.Bytes(), &views); err != nil {
		t.Fatalf("decode /runs: %v: %s", err, rec.Body)
	}
	got := map[string]runView{}
	for _, v := range views {
		got[v.RunID] = v
	}
	for _, want := range []struct {
		id, status, reason                                   string
		busy, started, resumable, wasInterrupted, reconciled bool
		pending                                              int
	}{
		{fresh, "new", "", false, false, false, false, false, -1},
		{generated, "open", "", true, false, false, false, false, -1},
		{failed, "failed", "verify failed", false, false, false, false, false, -1},
		{ended, "ended", "", false, false, false, false, false, -1},
		{interrupted, "interrupted", "", false, true, true, true, false, -1},
		{closed, "open", "", false, true, false, false, false, -1},
		{resumed, "open", "", false, true, false, true, true, 4946},
		{closePending, "close-pending", "", false, true, true, true, false, 6},
	} {
		v := got[want.id]
		pending := -1
		if v.ResumePending != nil {
			pending = *v.ResumePending
		}
		if v.Status != want.status || v.Reason != want.reason || v.Busy != want.busy ||
			v.BallotsStarted != want.started || v.Resumable != want.resumable ||
			v.WasInterrupted != want.wasInterrupted || v.Reconciled != want.reconciled || pending != want.pending {
			t.Errorf("%s: got status=%q reason=%q busy=%v started=%v resumable=%v interrupted=%v reconciled=%v pending=%d, want %+v",
				want.id, v.Status, v.Reason, v.Busy, v.BallotsStarted, v.Resumable, v.WasInterrupted, v.Reconciled, pending, want)
		}
	}
}
