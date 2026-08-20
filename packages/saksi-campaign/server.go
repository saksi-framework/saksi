package campaign

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed web/index.html
var webFS embed.FS

// exportOrder is the downloadable run artifacts, in display order. exportAllowlist
// is derived from it — no arbitrary path is ever served via /export.
var exportOrder = []string{
	RunFile,
	"header.json",
	"ballots.ndjson",
	CorrectnessFile,
	NegativeTestsFile,
	"perf.csv",
}

var exportAllowlist = func() map[string]bool {
	m := make(map[string]bool, len(exportOrder))
	for _, a := range exportOrder {
		m[a] = true
	}
	return m
}()

// Server owns the HTTP surface. All business logic lives in the executor/store;
// handlers only decode, validate, dispatch, and enforce the single-run lock +
// origin guard.
type Server struct {
	store      *RunStore
	exec       *Executor
	hub        *Hub
	timeout    time.Duration
	allowHosts map[string]bool

	mu   sync.Mutex
	busy map[string]context.CancelFunc // run id -> cancel of its running phase
}

// NewServer returns the console HTTP handler. allowHosts is the set of Host
// header values accepted (DNS-rebinding defense); timeout bounds each phase.
func NewServer(store *RunStore, exec *Executor, hub *Hub, allowHosts []string, timeout time.Duration) http.Handler {
	s := &Server{
		store:      store,
		exec:       exec,
		hub:        hub,
		timeout:    timeout,
		allowHosts: make(map[string]bool),
		busy:       make(map[string]context.CancelFunc),
	}
	for _, h := range allowHosts {
		s.allowHosts[h] = true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/generate", s.handleGenerate)
	mux.HandleFunc("/submit", s.handleSubmit)
	mux.HandleFunc("/verify", s.handleVerify)
	mux.HandleFunc("/scenarios", s.handleScenarios)
	mux.HandleFunc("/run-all", s.handleRunAll)
	mux.HandleFunc("/cancel", s.handleCancel)
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/runs", s.handleRuns)
	mux.HandleFunc("/export/", s.handleExport)
	return s.guard(mux)
}

// guard enforces the DNS-rebinding + cross-origin-POST defenses. A bare
// loopback bind does NOT stop a malicious web page from POSTing to
// 127.0.0.1:<port>, so we check Host against an allowlist and require any
// browser Origin to be same-origin.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.allowHosts) > 0 && !s.allowHosts[r.Host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			if o := r.Header.Get("Origin"); o != "" {
				u, err := url.Parse(o)
				if err != nil || u.Host != r.Host {
					http.Error(w, "cross-origin request rejected", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// tryStart claims the single-run lock for runID and stores its cancel func.
// Returns false if a phase is already running on that run.
func (s *Server) tryStart(runID string, cancel context.CancelFunc) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, running := s.busy[runID]; running {
		return false
	}
	s.busy[runID] = cancel
	return true
}

func (s *Server) finish(runID string) {
	s.mu.Lock()
	delete(s.busy, runID)
	s.mu.Unlock()
}

// dispatch runs fn as the run's single active phase under a timeout context,
// releasing the lock when done. Returns 409 if the run is already busy.
func (s *Server) dispatch(w http.ResponseWriter, runID string, fn func(context.Context)) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	if !s.tryStart(runID, cancel) {
		cancel()
		http.Error(w, "a phase is already running on this run", http.StatusConflict)
		return
	}
	go func() {
		defer cancel()
		defer s.finish(runID)
		fn(ctx)
	}()
	writeJSONResp(w, http.StatusAccepted, map[string]string{"run_id": runID})
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	c, ok := decodeConfig(w, r)
	if !ok {
		return
	}
	runID, _, err := s.store.Create(c, time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.dispatch(w, runID, func(ctx context.Context) { _ = s.exec.Generate(ctx, runID, c) })
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	runID, ok := s.runIDFromBody(w, r)
	if !ok {
		return
	}
	s.dispatch(w, runID, func(ctx context.Context) { _, _ = s.exec.Verify(ctx, runID) })
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	runID, ok := s.runIDFromBody(w, r)
	if !ok {
		return
	}
	rec, err := s.record(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.dispatch(w, runID, func(ctx context.Context) { _ = s.exec.Submit(ctx, runID, rec.Config) })
}

func (s *Server) handleRunAll(w http.ResponseWriter, r *http.Request) {
	c, ok := decodeConfig(w, r)
	if !ok {
		return
	}
	runID, _, err := s.store.Create(c, time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.dispatch(w, runID, func(ctx context.Context) {
		if err := s.exec.Generate(ctx, runID, c); err != nil {
			return
		}
		if err := s.exec.Submit(ctx, runID, c); err != nil {
			return
		}
		_, _ = s.exec.Verify(ctx, runID)
	})
}

func (s *Server) handleScenarios(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RunID string   `json:"run_id"`
		List  []string `json:"list"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	runID, err := validRun(s, body.RunID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.dispatch(w, runID, func(ctx context.Context) {
		_ = s.exec.RunScenarios(ctx, runID, body.List)
	})
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	runID, ok := s.runIDFromBody(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	cancel := s.busy[runID]
	s.mu.Unlock()
	if cancel == nil {
		http.Error(w, "no phase running on this run", http.StatusConflict)
		return
	}
	cancel()
	s.hub.Publish(runID, Event{Phase: "cancel", Level: "info", Msg: "cancellation requested"})
	writeJSONResp(w, http.StatusOK, map[string]string{"run_id": runID})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		http.Error(w, "missing run", http.StatusBadRequest)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, cancel := s.hub.Subscribe(run)
	defer cancel()
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case e, open := <-ch:
			if !open {
				return
			}
			data, _ := json.Marshal(e)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// runView is a run record enriched with the downloadable artifacts that
// currently exist for it, so the History UI can offer per-run CSV downloads
// (correctness / negative-tests) and mark which rows have results to load.
type runView struct {
	RunRecord
	Artifacts []string `json:"artifacts"`
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	recs, err := s.store.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	views := make([]runView, 0, len(recs))
	for _, rec := range recs {
		dir, err := s.store.Dir(rec.RunID)
		if err != nil {
			continue
		}
		var arts []string
		for _, name := range exportOrder { // exportOrder = stable display order
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				arts = append(arts, name)
			}
		}
		views = append(views, runView{RunRecord: rec, Artifacts: arts})
	}
	writeJSONResp(w, http.StatusOK, views)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/export/")
	id, artifact, found := strings.Cut(rest, "/")
	if !found || !exportAllowlist[artifact] {
		http.Error(w, "unknown artifact", http.StatusBadRequest)
		return
	}
	dir, err := s.store.Dir(id)
	if err != nil {
		http.Error(w, "invalid run id", http.StatusBadRequest)
		return
	}
	http.ServeFile(w, r, path.Join(dir, artifact))
}

// --- helpers ---------------------------------------------------------------

func (s *Server) record(runID string) (RunRecord, error) {
	id, err := validRun(s, runID)
	if err != nil {
		return RunRecord{}, err
	}
	dir, _ := s.store.Dir(id)
	var rec RunRecord
	if err := readJSON(path.Join(dir, RunFile), &rec); err != nil {
		return RunRecord{}, fmt.Errorf("unknown run %q", runID)
	}
	return rec, nil
}

func (s *Server) runIDFromBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	var body struct {
		RunID string `json:"run_id"`
	}
	if !decodeJSON(w, r, &body) {
		return "", false
	}
	id, err := validRun(s, body.RunID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return "", false
	}
	return id, true
}

func validRun(s *Server, runID string) (string, error) {
	if _, err := s.store.Dir(runID); err != nil {
		return "", err
	}
	return runID, nil
}

func decodeConfig(w http.ResponseWriter, r *http.Request) (ElectionConfig, bool) {
	var c ElectionConfig
	if !decodeJSON(w, r, &c) {
		return c, false
	}
	if err := c.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return c, false
	}
	return c, true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSONResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
