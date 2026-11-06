package campaign

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saksi-framework/saksi/packages/saksi-campaign/canvass"
)

// canvassStub replaces the engine so the handlers run without saksi-demo or
// the balotachain tools. An attempt writes its folder the way RunAttempt
// does, emits start, then waits on gate before writing attempt.json and the
// final event.
type canvassStub struct {
	gate    chan struct{} // closed or sent on to let the running attempt finish
	started chan int      // receives the attempt number once its folder exists
	builds  chan struct{}
	valid   bool
}

func canvassServer(t *testing.T) (*Server, http.Handler, *canvassStub, CanvassConfig) {
	t.Helper()
	s, h, _ := testServer(t, nil)
	cfg := CanvassConfig{Dir: t.TempDir(), Tools: "tools", Demo: "saksi-demo"}
	s.SetCanvass(cfg)
	st := &canvassStub{gate: make(chan struct{}), started: make(chan int, 4), builds: make(chan struct{}, 4), valid: true}
	s.cv.check = func(CanvassConfig) error { return nil }
	s.cv.valid = func(string) bool { return st.valid }
	s.cv.build = func(ctx context.Context, _ CanvassConfig, log io.Writer) error {
		fmt.Fprintln(log, "fixture: stub build")
		st.builds <- struct{}{}
		<-st.gate
		return nil
	}
	s.cv.run = func(ctx context.Context, c CanvassConfig, scenario string, emit func(canvass.Event)) (*canvass.AttemptResult, error) {
		n, err := canvass.NextAttempt(c.attemptsDir())
		if err != nil {
			return nil, err
		}
		dir := filepath.Join(c.attemptsDir(), fmt.Sprintf("%d-%s", n, scenario))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		ev, _ := os.Create(filepath.Join(dir, canvass.EventsFile))
		defer ev.Close()
		send := func(e canvass.Event) {
			e.Attempt, e.Scenario = n, scenario
			raw, _ := json.Marshal(e)
			ev.Write(append(raw, '\n'))
			emit(e)
		}
		send(canvass.Event{Type: canvass.EventStart, Tiles: []canvass.Tile{{Precinct: "p01", State: "waiting"}}})
		st.started <- n
		<-st.gate
		final := &canvass.Final{Verdict: "PASS", Pass: true, Expected: []string{}, Got: []string{}}
		res := &canvass.AttemptResult{N: n, Scenario: scenario, Dir: dir, Final: final}
		raw, _ := json.Marshal(res)
		if err := os.WriteFile(filepath.Join(dir, canvass.AttemptFile), raw, 0o644); err != nil {
			return nil, err
		}
		send(canvass.Event{Type: canvass.EventFinal, Final: final})
		return res, nil
	}
	return s, h, st, cfg
}

func attack(h http.Handler, scenario string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postJSON("/api/canvass/attack", map[string]string{"scenario": scenario}))
	return rec
}

func cvGet(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// waitIdle polls until the canvass slot is free.
func waitIdle(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, busy, _ := s.cv.state(); busy == "" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("canvass console never went idle")
}

func TestCanvassAttackBusyIs409(t *testing.T) {
	s, h, st, _ := canvassServer(t)
	rec := attack(h, "T9")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("first attack: want 202, got %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		RunID    string `json:"run_id"`
		Attempt  int    `json:"attempt"`
		Scenario string `json:"scenario"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.RunID != "canvass" || body.Attempt != 1 || body.Scenario != "T9" {
		t.Fatalf("202 body = %+v, want run canvass, attempt 1, T9", body)
	}
	<-st.started

	if rec := attack(h, "clean"); rec.Code != http.StatusConflict {
		t.Errorf("attack while an attempt runs: want 409, got %d: %s", rec.Code, rec.Body)
	}
	fx := httptest.NewRecorder()
	h.ServeHTTP(fx, postJSON("/api/canvass/fixture", nil))
	if fx.Code != http.StatusConflict {
		t.Errorf("fixture build while an attempt runs: want 409, got %d: %s", fx.Code, fx.Body)
	}

	// An election run is not held up by the canvass slot.
	if gen := httptest.NewRecorder(); true {
		h.ServeHTTP(gen, postJSON("/generate", good()))
		if gen.Code != http.StatusAccepted {
			t.Errorf("/generate while a canvass attempt runs: want 202, got %d: %s", gen.Code, gen.Body)
		}
	}

	close(st.gate)
	waitIdle(t, s)
	if rec := attack(h, "clean"); rec.Code != http.StatusAccepted {
		t.Fatalf("attack after the first finished: want 202, got %d: %s", rec.Code, rec.Body)
	}
	if n := <-st.started; n != 2 {
		t.Errorf("second attempt numbered %d, want 2", n)
	}
	waitIdle(t, s)
}

func TestCanvassFixtureBuildBlocksAttack(t *testing.T) {
	s, h, st, _ := canvassServer(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postJSON("/api/canvass/fixture", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("fixture: want 202, got %d: %s", rec.Code, rec.Body)
	}
	<-st.builds
	if rec := attack(h, "T9"); rec.Code != http.StatusConflict {
		t.Errorf("attack during a fixture build: want 409, got %d: %s", rec.Code, rec.Body)
	}
	close(st.gate)
	waitIdle(t, s)
}

// With no valid fixture, an attack builds one first and then replays.
func TestCanvassAttackBuildsMissingFixture(t *testing.T) {
	s, h, st, _ := canvassServer(t)
	st.valid = false
	if rec := attack(h, "T13"); rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d: %s", rec.Code, rec.Body)
	}
	<-st.builds
	// While the fixture builds the attempt has no folder yet, but the number
	// the POST returned already answers as running, not 404.
	var mid canvassAttempt
	rec := cvGet(h, "/api/canvass/attempt/1")
	if rec.Code != http.StatusOK {
		t.Fatalf("attempt 1 during the fixture build: want 200, got %d: %s", rec.Code, rec.Body)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &mid)
	if !mid.Running || mid.Result != nil || mid.N != 1 || mid.Scenario != "T13" || len(mid.Events) != 0 {
		t.Errorf("attempt 1 during the fixture build = %+v", mid)
	}
	if rec := cvGet(h, "/api/canvass/attempt/2"); rec.Code != http.StatusNotFound {
		t.Errorf("attempt 2 during the build: want 404, got %d", rec.Code)
	}
	close(st.gate)
	<-st.started
	waitIdle(t, s)
}

func TestCanvassAttackRejectsBadScenario(t *testing.T) {
	_, h, _, _ := canvassServer(t)
	for _, sc := range []string{"T99", "", "t9", "T19", "T20"} {
		if rec := attack(h, sc); rec.Code != http.StatusBadRequest {
			t.Errorf("scenario %q: want 400, got %d: %s", sc, rec.Code, rec.Body)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/canvass/attack", strings.NewReader("{")))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("malformed body: want 400, got %d", rec.Code)
	}
	if rec := cvGet(h, "/api/canvass/attack"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET attack: want 405, got %d", rec.Code)
	}
}

func TestCanvassUnconfiguredIs503(t *testing.T) {
	_, h, _ := testServer(t, nil)
	if rec := attack(h, "T9"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("attack: want 503, got %d: %s", rec.Code, rec.Body)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postJSON("/api/canvass/fixture", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("fixture: want 503, got %d: %s", rec.Code, rec.Body)
	}
	// The listing still answers, saying why the console cannot replay.
	rec = cvGet(h, "/api/canvass/scenarios")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"unavailable"`) {
		t.Errorf("scenarios unconfigured: got %d %s", rec.Code, rec.Body)
	}
}

func TestCanvassScenariosListing(t *testing.T) {
	_, h, _, _ := canvassServer(t)
	rec := cvGet(h, "/api/canvass/scenarios")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	var out canvassScenarios
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.RunID != "canvass" || !out.Fixture || out.Busy != "" || out.LastAttempt != 0 || out.Unavailable != "" {
		t.Errorf("state = %+v", out)
	}
	byID := map[string]canvass.Scenario{}
	var ids []string
	for _, sc := range out.Scenarios {
		byID[sc.ID] = sc
		ids = append(ids, sc.ID)
	}
	want := []string{"clean", "T9", "T10", "T11", "T12", "T13", "T14a", "T14b", "T15", "T16", "T21", "T24"}
	for _, id := range want {
		sc, ok := byID[id]
		if !ok || !sc.Live || sc.Label == "" || (id != "clean" && sc.Where == "") {
			t.Errorf("live scenario %s missing or incomplete: %+v (ids %v)", id, sc, ids)
		}
	}
	for _, id := range []string{"T19", "T20"} {
		sc, ok := byID[id]
		if !ok || sc.Live || sc.Recorded == nil || sc.Recorded.Verdict == "" {
			t.Errorf("recorded scenario %s: want disabled with a recorded outcome, got %+v", id, sc)
		}
	}
	if len(out.Scenarios) != len(want)+2 {
		t.Errorf("%d scenarios listed, want %d: %v", len(out.Scenarios), len(want)+2, ids)
	}
	if rec := httptest.NewRecorder(); true {
		h.ServeHTTP(rec, postJSON("/api/canvass/scenarios", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST scenarios: want 405, got %d", rec.Code)
		}
	}
}

func TestCanvassAttemptState(t *testing.T) {
	s, h, st, _ := canvassServer(t)
	if rec := cvGet(h, "/api/canvass/attempt/latest"); rec.Code != http.StatusNotFound {
		t.Errorf("latest with no attempt: want 404, got %d", rec.Code)
	}
	if rec := attack(h, "T16"); rec.Code != http.StatusAccepted {
		t.Fatalf("attack: %d %s", rec.Code, rec.Body)
	}
	<-st.started

	// Mid-run: no attempt.json yet; running, with the events so far.
	var mid canvassAttempt
	rec := cvGet(h, "/api/canvass/attempt/1")
	if rec.Code != http.StatusOK {
		t.Fatalf("attempt 1 mid-run: %d %s", rec.Code, rec.Body)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &mid)
	if !mid.Running || mid.Result != nil || mid.Scenario != "T16" || len(mid.Events) != 1 || mid.Events[0].Type != canvass.EventStart {
		t.Errorf("mid-run state = %+v", mid)
	}
	var sc canvassScenarios
	_ = json.Unmarshal(cvGet(h, "/api/canvass/scenarios").Body.Bytes(), &sc)
	if sc.Running != 1 || sc.Busy == "" || sc.LastAttempt != 1 {
		t.Errorf("scenarios mid-run = running %d busy %q last %d", sc.Running, sc.Busy, sc.LastAttempt)
	}

	close(st.gate)
	waitIdle(t, s)
	for _, p := range []string{"/api/canvass/attempt/1", "/api/canvass/attempt/latest"} {
		var done canvassAttempt
		rec := cvGet(h, p)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", p, rec.Code, rec.Body)
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &done)
		if done.Running || done.Result == nil || done.Result.Final == nil || done.Result.Final.Verdict != "PASS" || done.N != 1 || len(done.Events) != 2 {
			t.Errorf("%s finished state = %+v", p, done)
		}
	}
	for path, want := range map[string]int{
		"/api/canvass/attempt/2":   http.StatusNotFound,
		"/api/canvass/attempt/0":   http.StatusBadRequest,
		"/api/canvass/attempt/01":  http.StatusBadRequest,
		"/api/canvass/attempt/abc": http.StatusBadRequest,
		"/api/canvass/attempt/":    http.StatusBadRequest,
	} {
		if rec := cvGet(h, path); rec.Code != want {
			t.Errorf("%s: want %d, got %d", path, want, rec.Code)
		}
	}
}

// Progress goes out on the existing SSE hub under run "canvass", with the
// whole engine event attached.
func TestCanvassEventsOnSSE(t *testing.T) {
	s, h, st, _ := canvassServer(t)
	ch, cancel := s.hub.Subscribe(CanvassRunID)
	defer cancel()
	if rec := attack(h, "T9"); rec.Code != http.StatusAccepted {
		t.Fatalf("attack: %d %s", rec.Code, rec.Body)
	}
	<-st.started
	close(st.gate)
	var phases []string
	timeout := time.After(5 * time.Second)
	for {
		select {
		case e := <-ch:
			phases = append(phases, e.Phase)
			if e.Canvass == nil || e.Canvass.Scenario != "T9" || e.Canvass.Attempt != 1 {
				t.Errorf("event %s carries canvass %+v", e.Phase, e.Canvass)
			}
			if e.Phase == "canvass.final" {
				if e.Level != "done" || e.Msg != "verdict PASS" {
					t.Errorf("final event = %+v", e)
				}
				waitIdle(t, s)
				return
			}
		case <-timeout:
			t.Fatalf("no final event; got %v", phases)
		}
	}
}

func TestCanvassPageServed(t *testing.T) {
	_, h, _ := testServer(t, nil)
	rec := cvGet(h, "/canvass")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("/canvass: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	footer := "Offline replay: one generated election; the ledger read-back is the generated ballots in ledger order; no Fabric. Live runs: Appendix E."
	if !strings.Contains(rec.Body.String(), footer) {
		t.Error("/canvass lost the verbatim footer")
	}
}

// With auth on, the page is public and every canvass API route is admin-only.
func TestCanvassRoutesNeedAdmin(t *testing.T) {
	_, h := authServer(t)
	if rec := cvGet(h, "/canvass"); rec.Code != http.StatusOK {
		t.Errorf("/canvass signed out: want 200, got %d", rec.Code)
	}
	for _, p := range []string{"/api/canvass/scenarios", "/api/canvass/attempt/1"} {
		if rec := cvGet(h, p); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s signed out: want 401, got %d", p, rec.Code)
		}
	}
	for _, p := range []string{"/api/canvass/fixture", "/api/canvass/attack"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, postJSON(p, map[string]string{"scenario": "T9"}))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("POST %s signed out: want 401, got %d", p, rec.Code)
		}
	}
}
