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

func TestOfflineCeilingRejectedAt400(t *testing.T) {
	_, h, _ := testServer(t, nil)
	big := good()
	big.Voters = OfflineVoterCeiling + 1 // offline
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
