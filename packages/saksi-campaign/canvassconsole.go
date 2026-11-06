package campaign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/saksi-framework/saksi/packages/saksi-campaign/canvass"
)

// CanvassRunID is the SSE channel the canvass console publishes on:
// GET /events?run=canvass. Real run ids always end in a timestamp and a
// counter (RunStore.Create), so no election run can share it.
const CanvassRunID = "canvass"

// CanvassConfig places the offline canvass console: Dir holds the fixture
// (<Dir>/fixture) and the attempts (<Dir>/attempts/<n>-<id>/), Tools is the
// balotachain tools/security/canvass folder, Demo the saksi-demo binary.
type CanvassConfig struct {
	Dir   string
	Tools string
	Demo  string
}

// canvassConsole is the canvass attack console's state: its own single-flight
// slot, separate from the election runs' claim(). An attempt is offline (a
// copy of a generated election, no Fabric), so it neither needs the network
// nor disturbs it: a network reset or a peer-restart fault does not block it,
// and it does not block an election run.
type canvassConsole struct {
	cfg CanvassConfig

	mu   sync.Mutex
	busy string // "" when idle, else what is running ("fixture", "attempt 3 (T9)")
	// running is the attempt number in flight, 0 when none, and
	// runningScenario its scenario ID.
	running         int
	runningScenario string

	// Injected by tests so they need neither saksi-demo nor the tools.
	check func(CanvassConfig) error
	build func(ctx context.Context, cfg CanvassConfig, log io.Writer) error
	run   func(ctx context.Context, cfg CanvassConfig, scenario string, emit func(canvass.Event)) (*canvass.AttemptResult, error)
	valid func(fixtureDir string) bool
}

func newCanvassConsole() *canvassConsole {
	return &canvassConsole{
		check: checkCanvass,
		build: func(ctx context.Context, cfg CanvassConfig, log io.Writer) error {
			return canvass.BuildFixture(ctx, cfg.fixtureDir(), cfg.Demo, cfg.Tools, log)
		},
		run: func(ctx context.Context, cfg CanvassConfig, scenario string, emit func(canvass.Event)) (*canvass.AttemptResult, error) {
			return canvass.RunAttempt(ctx, cfg.fixtureDir(), cfg.attemptsDir(), cfg.Demo, cfg.Tools, scenario, emit)
		},
		valid: canvass.FixtureValid,
	}
}

func (c CanvassConfig) fixtureDir() string  { return filepath.Join(c.Dir, "fixture") }
func (c CanvassConfig) attemptsDir() string { return filepath.Join(c.Dir, "attempts") }

// checkCanvass says why this console cannot build or replay, or nil.
func checkCanvass(c CanvassConfig) error {
	if c.Dir == "" {
		return errors.New("no canvass folder (--canvass-dir)")
	}
	if err := canvass.CheckTools(c.Tools); err != nil {
		return err
	}
	if c.Demo == "" {
		return errors.New("no saksi-demo binary (--demo)")
	}
	if _, err := exec.LookPath(c.Demo); err != nil {
		return fmt.Errorf("saksi-demo: %w", err)
	}
	return nil
}

// SetCanvass configures the canvass console. Without it the canvass routes
// answer 503.
func (s *Server) SetCanvass(c CanvassConfig) {
	s.cv.mu.Lock()
	s.cv.cfg = c
	s.cv.mu.Unlock()
}

// claim takes the canvass slot for what, or returns why it is taken.
func (cv *canvassConsole) claim(what string) string {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	if cv.busy != "" {
		return "the canvass console is busy: " + cv.busy + " is running"
	}
	cv.busy = what
	return ""
}

func (cv *canvassConsole) release() {
	cv.mu.Lock()
	cv.busy, cv.running, cv.runningScenario = "", 0, ""
	cv.mu.Unlock()
}

func (cv *canvassConsole) state() (cfg CanvassConfig, busy string, running int) {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	return cv.cfg, cv.busy, cv.running
}

// canvassReady returns the configuration, or writes 503 when it cannot be used.
func (s *Server) canvassReady(w http.ResponseWriter) (CanvassConfig, bool) {
	cfg, _, _ := s.cv.state()
	if err := s.cv.check(cfg); err != nil {
		http.Error(w, "canvass console unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return cfg, false
	}
	return cfg, true
}

// publishCanvass sends one engine event on the canvass SSE channel. The
// engine event rides whole in Event.Canvass; Phase/Level/Msg summarise it for
// the generic log view.
func (s *Server) publishCanvass(e canvass.Event) {
	level, msg := "info", e.Type
	switch e.Type {
	case canvass.EventStart:
		msg = fmt.Sprintf("attempt %d (%s) started", e.Attempt, e.Scenario)
	case canvass.EventArrival:
		msg = fmt.Sprintf("arrival %d: %s", e.Seq, e.Precinct)
		if e.Delivered != nil && !*e.Delivered {
			msg += " (not delivered)"
		}
	case canvass.EventNational:
		msg = "national hook ran"
	case canvass.EventFinal:
		level = "done"
		if e.Final != nil {
			msg = "verdict " + e.Final.Verdict
		}
	case canvass.EventError:
		level, msg = "error", e.Error
	}
	ev := e
	s.hub.Publish(CanvassRunID, Event{Phase: "canvass." + e.Type, Level: level, Msg: msg, Canvass: &ev})
}

// hubLines is an io.Writer publishing each complete line as a fixture log
// event, so the fixture build streams over SSE.
type hubLines struct {
	s   *Server
	buf bytes.Buffer
}

func (h *hubLines) Write(p []byte) (int, error) {
	h.buf.Write(p)
	for {
		line, err := h.buf.ReadString('\n')
		if err != nil {
			h.buf.WriteString(line) // partial line: keep for the next write
			return len(p), nil
		}
		if line = strings.TrimRight(line, "\r\n"); line != "" {
			h.s.hub.Publish(CanvassRunID, Event{Phase: "canvass.fixture", Level: "info", Msg: line})
		}
	}
}

// buildCanvassFixture builds (or reuses) the fixture, streaming its log.
func (s *Server) buildCanvassFixture(ctx context.Context, cfg CanvassConfig) error {
	err := s.cv.build(ctx, cfg, &hubLines{s: s})
	if err != nil {
		s.hub.Publish(CanvassRunID, Event{Phase: "canvass.fixture", Level: "error", Msg: "fixture refused: " + err.Error()})
		return err
	}
	s.hub.Publish(CanvassRunID, Event{Phase: "canvass.fixture", Level: "done", Msg: "fixture ready"})
	return nil
}

// handleCanvassPage serves the canvass console page.
func (s *Server) handleCanvassPage(w http.ResponseWriter, r *http.Request) {
	data, err := webFS.ReadFile("web/canvass.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// canvassScenarios is GET /api/canvass/scenarios: the scenario table (live
// and recorded) plus what the page needs to restore itself after a reload.
type canvassScenarios struct {
	Scenarios []canvass.Scenario `json:"scenarios"`
	// Fixture is true when a valid fixture is built and an attempt can start
	// without building one first.
	Fixture bool `json:"fixture"`
	// Busy names what holds the canvass slot, "" when idle.
	Busy string `json:"busy,omitempty"`
	// Running is the attempt in flight, 0 when none.
	Running int `json:"running,omitempty"`
	// LastAttempt is the highest attempt number on disk, 0 when none.
	LastAttempt int `json:"last_attempt"`
	// Unavailable says why this console cannot build or replay ("" = it can).
	Unavailable string `json:"unavailable,omitempty"`
	RunID       string `json:"run_id"`
}

func (s *Server) handleCanvassScenarios(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, busy, running := s.cv.state()
	out := canvassScenarios{Scenarios: canvass.Scenarios(), Busy: busy, Running: running, RunID: CanvassRunID}
	if err := s.cv.check(cfg); err != nil {
		out.Unavailable = err.Error()
	}
	if cfg.Dir != "" {
		out.Fixture = s.cv.valid(cfg.fixtureDir())
		if n, err := canvass.NextAttempt(cfg.attemptsDir()); err == nil {
			out.LastAttempt = n - 1
		}
	}
	writeJSONResp(w, http.StatusOK, out)
}

// handleCanvassFixture is POST /api/canvass/fixture: build the fixture (or
// confirm the cached one) in the background; progress on the canvass SSE run.
func (s *Server) handleCanvassFixture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, ok := s.canvassReady(w)
	if !ok {
		return
	}
	if why := s.cv.claim("fixture build"); why != "" {
		http.Error(w, why, http.StatusConflict)
		return
	}
	go func() {
		defer s.cv.release()
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()
		_ = s.buildCanvassFixture(ctx, cfg)
	}()
	writeJSONResp(w, http.StatusAccepted, map[string]string{"run_id": CanvassRunID})
}

// handleCanvassAttack is POST /api/canvass/attack {"scenario": "<id>"}: replay
// one live scenario. The fixture is built first when none is valid. 400 for an
// unknown or recorded-only scenario, 409 while an attempt or a build runs.
func (s *Server) handleCanvassAttack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Scenario string `json:"scenario"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	sc, found := canvass.LookupScenario(body.Scenario)
	if !found {
		http.Error(w, fmt.Sprintf("unknown scenario %q", body.Scenario), http.StatusBadRequest)
		return
	}
	if !sc.Live {
		http.Error(w, fmt.Sprintf("scenario %s needs Fabric and is shown as recorded only (%s)", sc.ID, canvass.RecordedNote), http.StatusBadRequest)
		return
	}
	cfg, ok := s.canvassReady(w)
	if !ok {
		return
	}
	if why := s.cv.claim("attempt"); why != "" {
		http.Error(w, why, http.StatusConflict)
		return
	}
	// The slot is held, so no other attempt can take this number before
	// RunAttempt numbers its folder the same way.
	n, err := canvass.NextAttempt(cfg.attemptsDir())
	if err != nil {
		s.cv.release()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.cv.mu.Lock()
	s.cv.busy, s.cv.running, s.cv.runningScenario = fmt.Sprintf("attempt %d (%s)", n, sc.ID), n, sc.ID
	s.cv.mu.Unlock()
	go func() {
		defer s.cv.release()
		ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()
		if !s.cv.valid(cfg.fixtureDir()) {
			if err := s.buildCanvassFixture(ctx, cfg); err != nil {
				s.publishCanvass(canvass.Event{Type: canvass.EventError, Attempt: n, Scenario: sc.ID, Error: "fixture: " + err.Error()})
				return
			}
		}
		// RunAttempt emits its own error event once the attempt folder
		// exists; a refusal before that (no result) is published here.
		if res, err := s.cv.run(ctx, cfg, sc.ID, s.publishCanvass); err != nil && res == nil {
			s.publishCanvass(canvass.Event{Type: canvass.EventError, Attempt: n, Scenario: sc.ID, Error: err.Error()})
		}
	}()
	writeJSONResp(w, http.StatusAccepted, struct {
		RunID    string `json:"run_id"`
		Attempt  int    `json:"attempt"`
		Scenario string `json:"scenario"`
	}{CanvassRunID, n, sc.ID})
}

// canvassAttempt is GET /api/canvass/attempt/<n>: a finished attempt's
// attempt.json as Result, or, while it runs, Running with the events so far,
// so a reloaded page can rebuild its tiles either way.
type canvassAttempt struct {
	N        int                    `json:"n"`
	Scenario string                 `json:"scenario"`
	Running  bool                   `json:"running"`
	Result   *canvass.AttemptResult `json:"result,omitempty"`
	Events   []canvass.Event        `json:"events"`
}

// handleCanvassAttempt serves one attempt by number, or "latest". The suffix
// only selects which attempt to read; it never selects an action.
func (s *Server) handleCanvassAttempt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, _, running := s.cv.state()
	if cfg.Dir == "" {
		http.Error(w, "canvass console unavailable: no canvass folder (--canvass-dir)", http.StatusServiceUnavailable)
		return
	}
	arg := strings.TrimPrefix(r.URL.Path, "/api/canvass/attempt/")
	var n int
	if arg == "latest" {
		next, err := canvass.NextAttempt(cfg.attemptsDir())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		n = next - 1
		if n < 1 {
			http.Error(w, "no attempt yet", http.StatusNotFound)
			return
		}
	} else {
		v, err := strconv.Atoi(arg)
		if err != nil || v < 1 || strconv.Itoa(v) != arg {
			http.Error(w, "attempt must be a positive number or latest", http.StatusBadRequest)
			return
		}
		n = v
	}
	dir, scenario, err := findAttempt(cfg.attemptsDir(), n)
	if err != nil {
		// The POST has numbered this attempt, but its folder does not exist
		// until a missing fixture is built and RunAttempt starts. Answer it as
		// running so a client that polls right after the POST does not see a
		// 404. Once the slot is released (an attempt refused before its folder
		// existed), it is 404 again.
		s.cv.mu.Lock()
		pending, pendingScenario := s.cv.running == n, s.cv.runningScenario
		s.cv.mu.Unlock()
		if pending {
			writeJSONResp(w, http.StatusOK, canvassAttempt{N: n, Scenario: pendingScenario, Running: true, Events: []canvass.Event{}})
			return
		}
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	out := canvassAttempt{N: n, Scenario: scenario, Events: []canvass.Event{}}
	var res canvass.AttemptResult
	if raw, err := os.ReadFile(filepath.Join(dir, canvass.AttemptFile)); err == nil && json.Unmarshal(raw, &res) == nil {
		out.Result = &res
	} else {
		out.Running = running == n
	}
	out.Events = readCanvassEvents(filepath.Join(dir, canvass.EventsFile))
	writeJSONResp(w, http.StatusOK, out)
}

// findAttempt locates attemptsDir/<n>-<scenario>/.
func findAttempt(attemptsDir string, n int) (dir, scenario string, err error) {
	entries, err := os.ReadDir(attemptsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return "", "", fmt.Errorf("attempt %d not found", n)
	}
	if err != nil {
		return "", "", err
	}
	prefix := strconv.Itoa(n) + "-"
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			return filepath.Join(attemptsDir, e.Name()), strings.TrimPrefix(e.Name(), prefix), nil
		}
	}
	return "", "", fmt.Errorf("attempt %d not found", n)
}

// readCanvassEvents reads an attempt's events.ndjson, skipping a torn last
// line (the attempt may still be writing it).
func readCanvassEvents(path string) []canvass.Event {
	out := []canvass.Event{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e canvass.Event
		if json.Unmarshal(line, &e) == nil {
			out = append(out, e)
		}
	}
	return out
}
