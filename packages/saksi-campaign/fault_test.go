package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func onchainConfig() ElectionConfig {
	c := good()
	c.Mode = "onchain"
	c.Voters = 100
	return c
}

var goodFault = map[string]any{"kind": "peer-restart", "at": 0.5, "down_s": 20, "confirm": "RESTART"}

// faultRun creates a generated (journal present, window not opened) run on s.
func faultRun(t *testing.T, s *Server, c ElectionConfig) (string, string) {
	t.Helper()
	runID, dir, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeJournalLines(t, dir, `{"event":"run.start"}`, `{"event":"stage.generate.end","ok":true}`)
	return runID, dir
}

func postFault(t *testing.T, s *Server, runID string, body any, remote, user string) *httptest.ResponseRecorder {
	t.Helper()
	req := signIn(t, s, user, postJSON("/api/runs/"+runID+"/fault", body))
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func withFault(over map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range goodFault {
		out[k] = v
	}
	for k, v := range over {
		if v == nil {
			delete(out, k)
		} else {
			out[k] = v
		}
	}
	return out
}

func TestFaultRouteRefusals(t *testing.T) {
	s, _ := gateServer(t, enabledFabric(), "abc", 1<<62)
	runID, dir := faultRun(t, s, onchainConfig())

	cases := []struct {
		name   string
		body   any
		remote string
		want   int
		says   string
	}{
		{"non-loopback", goodFault, "192.0.2.7:4000", http.StatusForbidden, "loopback"},
		{"missing confirm", withFault(map[string]any{"confirm": nil}), loopback, http.StatusBadRequest, "exactly \\\"RESTART"},
		{"wrong confirm", withFault(map[string]any{"confirm": "RESET"}), loopback, http.StatusBadRequest, "exactly \\\"RESTART"},
		{"kind", withFault(map[string]any{"kind": "orderer-restart"}), loopback, http.StatusBadRequest, "kind"},
		{"at 0", withFault(map[string]any{"at": 0}), loopback, http.StatusBadRequest, "at must"},
		{"at 1", withFault(map[string]any{"at": 1}), loopback, http.StatusBadRequest, "at must"},
		{"at negative", withFault(map[string]any{"at": -0.2}), loopback, http.StatusBadRequest, "at must"},
		{"at rounds to no ballot", withFault(map[string]any{"at": 0.001}), loopback, http.StatusBadRequest, "at least one ballot"},
		{"down_s short", withFault(map[string]any{"down_s": 4}), loopback, http.StatusBadRequest, "down_s"},
		{"down_s long", withFault(map[string]any{"down_s": 121}), loopback, http.StatusBadRequest, "down_s"},
		{"unknown field", withFault(map[string]any{"container": "orderer.example.com"}), loopback, http.StatusBadRequest, "container"},
		{"case-folded confirm", json.RawMessage(`{"kind":"peer-restart","at":0.5,"down_s":20,"confirm":"nope","Confirm":"RESTART"}`), loopback, http.StatusBadRequest, "Confirm"},
		{"case-folded kind", json.RawMessage(`{"KIND":"peer-restart","at":0.5,"down_s":20,"confirm":"RESTART"}`), loopback, http.StatusBadRequest, "KIND"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postFault(t, s, runID, tc.body, tc.remote, "")
			if rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.says) {
				t.Fatalf("want %d naming %s, got %d %s", tc.want, tc.says, rec.Code, rec.Body)
			}
		})
	}
	get := httptest.NewRequest(http.MethodGet, "/api/runs/"+runID+"/fault", nil)
	get.RemoteAddr = loopback
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, get)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: want 405, got %d", rec.Code)
	}

	// Only an on-chain single election with no attack plan.
	offline := good()
	offline.Voters = 100
	rep := onchainConfig()
	rep.Rep = &RepTag{Index: 1, Kind: "measured"}
	attacked := onchainConfig()
	attacked.AttackPlan = &AttackPlan{Stages: []string{StageClose}}
	for _, tc := range []struct {
		name string
		c    ElectionConfig
		says string
	}{{"offline", offline, "on-chain"}, {"campaign repetition", rep, "campaign repetition"}, {"attack plan", attacked, "attack plan"}} {
		id, _ := faultRun(t, s, tc.c)
		if rec := postFault(t, s, id, goodFault, loopback, ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), tc.says) {
			t.Errorf("%s run: want 409 naming %q, got %d %s", tc.name, tc.says, rec.Code, rec.Body)
		}
	}

	off, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	offID, _ := faultRun(t, off, onchainConfig())
	if rec := postFault(t, off, offID, goodFault, loopback, ""); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Fabric") {
		t.Fatalf("no Fabric: want 400, got %d %s", rec.Code, rec.Body)
	}

	// Not while a phase runs, not once the window has opened, not before generation.
	if why := s.claim(runID, func() {}); why != "" {
		t.Fatal(why)
	}
	if rec := postFault(t, s, runID, goodFault, loopback, ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "already running") {
		t.Fatalf("busy run: want 409, got %d %s", rec.Code, rec.Body)
	}
	s.finish(runID)
	started, startedDir := faultRun(t, s, onchainConfig())
	writeJournalLines(t, startedDir, `{"event":"run.start"}`, `{"event":"stage.ballots.start","n":100}`)
	if rec := postFault(t, s, started, goodFault, loopback, ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "already started") {
		t.Fatalf("window opened: want 409, got %d %s", rec.Code, rec.Body)
	}
	fresh, freshDir, err := s.store.Create(onchainConfig(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec := postFault(t, s, fresh, goodFault, loopback, ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "generate it first") {
		t.Fatalf("no journal: want 409, got %d %s", rec.Code, rec.Body)
	}
	for _, d := range []string{dir, freshDir} {
		var r RunRecord
		if err := readJSON(filepath.Join(d, RunFile), &r); err != nil || r.Config.FaultPlan != nil {
			t.Fatalf("a refused fault was armed in %s: %+v %v", d, r.Config.FaultPlan, err)
		}
	}
}

func TestFaultArmsAGeneratedRun(t *testing.T) {
	s, _ := gateServer(t, enabledFabric(), "abc", 1<<62)
	enableTestAuth(t, s)
	runID, dir := faultRun(t, s, onchainConfig())

	for _, tc := range []struct {
		user, remote string
		want         int
	}{{"", loopback, http.StatusUnauthorized}, {"t1", loopback, http.StatusForbidden}, {"admin", "192.0.2.7:4000", http.StatusForbidden}} {
		if rec := postFault(t, s, runID, goodFault, tc.remote, tc.user); rec.Code != tc.want {
			t.Errorf("%q from %s: want %d, got %d %s", tc.user, tc.remote, tc.want, rec.Code, rec.Body)
		}
	}
	rec := postFault(t, s, runID, goodFault, loopback, "admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("arm: want 200, got %d %s", rec.Code, rec.Body)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["at_index"] != float64(50) || body["container"] != faultPeerContainer {
		t.Fatalf("response = %v", body)
	}
	var r RunRecord
	if err := readJSON(filepath.Join(dir, RunFile), &r); err != nil {
		t.Fatal(err)
	}
	if r.Config.FaultPlan == nil || *r.Config.FaultPlan != (FaultPlan{Kind: FaultPeerRestart, At: 0.5, DownS: 20}) {
		t.Fatalf("run.json fault_plan = %+v", r.Config.FaultPlan)
	}
	if !r.Config.securityRun() {
		t.Fatal("a run with a fault is a security run")
	}
	if armed := journalEventsOfType(t, dir, "fault.armed"); len(armed) != 1 || jint(armed[0], "at_index") != 50 {
		t.Fatalf("fault.armed = %v", armed)
	}

	// A config never carries a fault: /generate, /run-all and campaigns lack
	// this route's loopback and confirmation guards.
	withPlan := onchainConfig()
	withPlan.FaultPlan = &FaultPlan{Kind: FaultPeerRestart, At: 0.5, DownS: 20}
	if err := withPlan.Validate(); err == nil || !strings.Contains(err.Error(), "/fault") {
		t.Fatalf("Validate with fault_plan: %v", err)
	}
	gen := signIn(t, s, "admin", postJSON("/generate", withPlan))
	gen.RemoteAddr = loopback
	grec := httptest.NewRecorder()
	s.ServeHTTP(grec, gen)
	if grec.Code != http.StatusBadRequest {
		t.Fatalf("/generate with fault_plan: want 400, got %d %s", grec.Code, grec.Body)
	}
}

// dockerRecorder is an Executor runner that records every command and plays
// the stopped peer on led.
func dockerRecorder(led *fakeLedger) (Runner, func() [][]string) {
	var mu sync.Mutex
	var calls [][]string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		mu.Lock()
		calls = append(calls, append([]string{name}, args...))
		mu.Unlock()
		if name == "docker" && len(args) == 2 {
			led.mu.Lock()
			led.peerDown = args[0] == "stop"
			led.mu.Unlock()
		}
		return nil, nil
	}
	return run, func() [][]string {
		mu.Lock()
		defer mu.Unlock()
		return append([][]string(nil), calls...)
	}
}

// fastFault makes the outage end as soon as the window has tried every ballot,
// and records the down time it was asked for.
func fastFault(t *testing.T, led *fakeLedger, n int) *time.Duration {
	t.Helper()
	oldSleep, oldPoll := faultSleep, peerReadyPoll
	t.Cleanup(func() { faultSleep, peerReadyPoll = oldSleep, oldPoll })
	peerReadyPoll = time.Millisecond
	asked := new(time.Duration)
	faultSleep = func(ctx context.Context, d time.Duration) {
		*asked = d
		deadline := time.Now().Add(time.Minute)
		for time.Now().Before(deadline) {
			led.mu.Lock()
			tried := led.ballots
			led.mu.Unlock()
			if tried >= n {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}
	return asked
}

// The fault stops exactly peer0.org1.example.com when ballot at x N is
// dispatched, the rest of the window fails and is recorded as drops, the peer
// comes back, and Resume then commits the rest and closes the election.
func TestPeerRestartFaultFiresAtItsBallotAndResumeFinishesTheRun(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	const n = 100
	path := writeRealBallotStream(t, runDir, n)
	c := ElectionConfig{Mode: "onchain", Voters: n, Positions: 1, Candidates: 2, Concurrency: 1,
		FaultPlan: &FaultPlan{Kind: FaultPeerRestart, At: 0.3, DownS: 20}}
	led := &fakeLedger{RejectDuplicates: true}
	run, calls := dockerRecorder(led)
	e.run = run
	asked := fastFault(t, led, n)

	err := e.submitOnChain(context.Background(), "run-1", c, led, path)
	if err == nil || !strings.Contains(err.Error(), "70 of 100 ballots did not commit") {
		t.Fatalf("submit: %v, want the 70 ballots sent while the peer was down as drops", err)
	}
	want := [][]string{{"docker", "stop", "peer0.org1.example.com"}, {"docker", "start", "peer0.org1.example.com"}}
	if got := calls(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("commands = %v, want exactly %v", got, want)
	}
	if *asked != 20*time.Second {
		t.Fatalf("down time = %s, want 20s", *asked)
	}
	accepted := led.acceptedIndices()
	if len(accepted) != 30 {
		t.Fatalf("chain holds %d ballots, want the 30 sent before the stop", len(accepted))
	}
	for i := 0; i < 30; i++ {
		if !accepted[i] {
			t.Fatalf("ballot %d, sent before the fault, did not commit", i)
		}
	}

	events, err := readJournalEvents(runDir)
	if err != nil {
		t.Fatal(err)
	}
	order := map[string]int{}
	for i, ev := range events {
		if _, seen := order[jstring(ev, "event")]; !seen {
			order[jstring(ev, "event")] = i
		}
	}
	start := journalEventsOfType(t, runDir, "fault.start")
	end := journalEventsOfType(t, runDir, "fault.end")
	ready := journalEventsOfType(t, runDir, "fault.peer_ready")
	if len(start) != 1 || len(end) != 1 || len(ready) != 1 {
		t.Fatalf("fault events: start %v end %v ready %v", start, end, ready)
	}
	if jint(start[0], "at_index") != 30 || jint(start[0], "ballots_committed") != 30 || start[0]["ok"] != true ||
		start[0]["block_height"] == nil || jstring(start[0], "container") != faultPeerContainer {
		t.Fatalf("fault.start = %v", start[0])
	}
	if end[0]["ok"] != true || ready[0]["ok"] != true || ready[0]["block_height"] == nil || ready[0]["window_conn_ready"] != true {
		t.Fatalf("fault.end = %v, fault.peer_ready = %v", end[0], ready[0])
	}
	if !(order["fault.window"] < order["fault.start"] && order["fault.start"] < order["fault.end"] && order["fault.end"] < order["fault.peer_ready"]) {
		t.Fatalf("fault events out of order: %v", order)
	}
	interrupted := journalEventsOfType(t, runDir, "stage.ballots.interrupted")
	if len(interrupted) != 1 || jint(interrupted[0], "dropped") != 70 || jstring(interrupted[0], "fault") != FaultPeerRestart {
		t.Fatalf("the faulted window must end interrupted with its drops: %v", interrupted)
	}
	if ends := journalEventsOfType(t, runDir, "stage.ballots.end"); len(ends) != 0 {
		t.Fatalf("the faulted window must not be stamped ended (Resume would refuse it): %v", ends)
	}
	for _, name := range led.callNames() {
		if name == "CloseElection" {
			t.Fatal("an election whose window dropped ballots must not be closed")
		}
	}

	// The operator's next steps: verify-only, then resume.
	plan, err := planResume(runDir, c)
	if err != nil {
		t.Fatalf("a faulted run must be resumable: %v", err)
	}
	if plan.Remaining != 70 {
		t.Fatalf("resume estimate = %d pending, want the 70 the window did not commit", plan.Remaining)
	}
	if err := e.verifyOnly("run-1", countingLedger{fakeLedger: led, count: 30}, led); err != nil {
		t.Fatalf("verify-only: %v", err)
	}
	if rec := journalEventsOfType(t, runDir, "verify_only.reconcile"); len(rec) != 1 || rec[0]["reconciled"] != true {
		t.Fatalf("verify_only.reconcile = %v", rec)
	}
	if err := e.resumeAndClose(context.Background(), "run-1", c, led, led, path); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := len(led.acceptedIndices()); got != n {
		t.Fatalf("chain holds %d ballots after the resume, want %d", got, n)
	}
	names := led.callNames()
	if names[len(names)-1] != "CloseElection" {
		t.Fatalf("resume must close the election last, calls end %v", names[len(names)-3:])
	}
	if _, err := os.Stat(filepath.Join(runDir, CeremonyFile)); err != nil {
		t.Fatalf("resume must open the ceremony: %v", err)
	}
	if runEnd := readRunEnd(t, runDir); runEnd["security_run"] != true || runEnd["resumed"] != true {
		t.Fatalf("run.end = %v, want a resumed security run", runEnd)
	}
	if got := calls(); len(got) != 2 {
		t.Fatalf("resume ran commands %v", got[2:])
	}
}

// Stopping the peer under a campaign, the ladder, a reset or another run's
// phase would wreck it: the fault is refused at the moment it would fire, and
// docker is never run. The fault run's own phase does not count.
func TestPeerRestartFaultRefusedWhileAnythingElseUsesTheNetwork(t *testing.T) {
	for _, tc := range []struct {
		name    string
		occupy  func(s *Server) func()
		refused string // "" = the fault fires
	}{
		{"a campaign job", func(s *Server) func() {
			j, _ := s.jobs.start("campaign")
			return func() { s.jobs.run(j, func() (json.RawMessage, error) { return nil, nil }, nil) }
		}, "campaign-"},
		{"another run's phase", func(s *Server) func() {
			if why := s.claim("other-run", func() {}); why != "" {
				t.Fatal(why)
			}
			return func() { s.finish("other-run") }
		}, "other-run"},
		{"only its own phase", func(*Server) func() { return func() {} }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, root := gateServer(t, FabricConfig{}, "abc", 1<<62)
			e := s.exec
			runDir := filepath.Join(root, "run-1")
			if err := os.MkdirAll(runDir, 0o755); err != nil {
				t.Fatal(err)
			}
			const n = 20
			path := writeRealBallotStream(t, runDir, n)
			c := ElectionConfig{Mode: "onchain", Voters: n, Positions: 1, Candidates: 2, Concurrency: 1,
				FaultPlan: &FaultPlan{Kind: FaultPeerRestart, At: 0.5, DownS: 20}}
			led := &fakeLedger{}
			run, calls := dockerRecorder(led)
			e.run = run
			fastFault(t, led, n)
			// The fault run's own phase holds its lock, as a dispatched phase does.
			if why := s.claim("run-1", func() {}); why != "" {
				t.Fatal(why)
			}
			defer s.finish("run-1")
			release := tc.occupy(s)
			defer release()

			err := e.submitOnChain(context.Background(), "run-1", c, led, path)
			refused := journalEventsOfType(t, runDir, "fault.refused")
			if tc.refused == "" {
				if len(calls()) != 2 || len(refused) != 0 || err == nil {
					t.Fatalf("with only its own phase the fault must fire: docker %v, refused %v, err %v", calls(), refused, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("an unfired fault must not fail the run: %v", err)
			}
			if got := calls(); len(got) != 0 {
				t.Fatalf("docker ran while the network was in use: %v", got)
			}
			if len(refused) != 1 || !strings.Contains(jstring(refused[0], "reason"), tc.refused) {
				t.Fatalf("fault.refused = %v, want it to name %q", refused, tc.refused)
			}
		})
	}
}

// Arming is refused while anything else uses the network, and on a
// time-bounded window.
func TestFaultArmingRefusedWhileTheNetworkIsInUse(t *testing.T) {
	s, _ := gateServer(t, enabledFabric(), "abc", 1<<62)
	runID, dir := faultRun(t, s, onchainConfig())

	if why := s.claim("other-run", func() {}); why != "" {
		t.Fatal(why)
	}
	if rec := postFault(t, s, runID, goodFault, loopback, ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "other-run") {
		t.Fatalf("another run busy: want 409 naming it, got %d %s", rec.Code, rec.Body)
	}
	s.finish("other-run")

	j, _ := s.jobs.start("campaign")
	if rec := postFault(t, s, runID, goodFault, loopback, ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), j.ID) {
		t.Fatalf("a campaign running: want 409 naming it, got %d %s", rec.Code, rec.Body)
	}
	s.jobs.run(j, func() (json.RawMessage, error) { return nil, nil }, nil)

	bounded := onchainConfig()
	bounded.WindowS = 60
	boundedID, _ := faultRun(t, s, bounded)
	if rec := postFault(t, s, boundedID, goodFault, loopback, ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "window_s") {
		t.Fatalf("a bounded window: want 409, got %d %s", rec.Code, rec.Body)
	}

	var r RunRecord
	if err := readJSON(filepath.Join(dir, RunFile), &r); err != nil || r.Config.FaultPlan != nil {
		t.Fatalf("a refused arm wrote a plan: %+v %v", r.Config.FaultPlan, err)
	}
	if rec := postFault(t, s, runID, goodFault, loopback, ""); rec.Code != http.StatusOK {
		t.Fatalf("with the network free the fault arms: %d %s", rec.Code, rec.Body)
	}
	if why := s.claim(runID, func() {}); why != "" {
		t.Fatalf("arming must release the run: %s", why)
	}
}

// A console stopping mid-fault, or a panic in the restart, must not leave the
// peer down.
func TestPeerIsStartedAgainOnShutdownAndPanic(t *testing.T) {
	newFault := func(t *testing.T) (*Executor, *peerFault, func() [][]string, string) {
		dir := t.TempDir()
		e := newTestExecutor(t, dir)
		led := &fakeLedger{}
		run, calls := dockerRecorder(led)
		e.run = run
		old := peerReadyPoll
		t.Cleanup(func() { peerReadyPoll = old })
		peerReadyPoll = time.Millisecond
		j := e.journalFor("run-1")
		t.Cleanup(func() { j.Close() })
		f := e.newPeerFault(context.Background(), "run-1", j, led,
			&FaultPlan{Kind: FaultPeerRestart, At: 0.5, DownS: 20}, 10, func() int { return 0 })
		return e, f, calls, filepath.Join(dir, "run-1")
	}

	t.Run("shutdown", func(t *testing.T) {
		e, f, calls, _ := newFault(t)
		if restored, _ := e.RestorePeer(); restored {
			t.Fatal("no fault is active: nothing to restore")
		}
		oldSleep := faultSleep
		t.Cleanup(func() { faultSleep = oldSleep })
		held, release := make(chan struct{}), make(chan struct{})
		faultSleep = func(context.Context, time.Duration) { close(held); <-release }
		f.dispatched(5)
		<-held
		restored, err := e.RestorePeer()
		if !restored || err != nil {
			t.Fatalf("mid-fault shutdown: restored %v err %v", restored, err)
		}
		if got := calls(); fmt.Sprint(got[len(got)-1]) != "[docker start peer0.org1.example.com]" {
			t.Fatalf("RestorePeer ran %v", got)
		}
		close(release)
		f.wait()
		if restored, _ := e.RestorePeer(); restored {
			t.Fatal("after the fault ended nothing is down")
		}
	})

	t.Run("panic", func(t *testing.T) {
		e, f, calls, runDir := newFault(t)
		oldSleep := faultSleep
		t.Cleanup(func() { faultSleep = oldSleep })
		faultSleep = func(context.Context, time.Duration) { panic("boom in the restart") }
		f.dispatched(5)
		f.wait()
		want := "[[docker stop peer0.org1.example.com] [docker start peer0.org1.example.com]]"
		if got := fmt.Sprint(calls()); got != want {
			t.Fatalf("docker = %s, want %s", got, want)
		}
		if p := journalEventsOfType(t, runDir, "fault.panic"); len(p) != 1 || !strings.Contains(jstring(p[0], "error"), "boom") {
			t.Fatalf("fault.panic = %v", p)
		}
		if restored, _ := e.RestorePeer(); restored {
			t.Fatal("the recovered fault left a peer counted as down")
		}
	})
}

// The restarted peer answering is not enough: fault.peer_ready is ok only when
// the window's own connection answers too.
func TestPeerReadyNeedsTheWindowConnection(t *testing.T) {
	old, oldPoll := peerReadyTimeout, peerReadyPoll
	t.Cleanup(func() { peerReadyTimeout, peerReadyPoll = old, oldPoll })
	peerReadyTimeout, peerReadyPoll = 50*time.Millisecond, time.Millisecond

	e := newTestExecutor(t, t.TempDir())
	down := &fakeLedger{peerDown: true}
	f := &peerFault{e: e, led: down}
	_, h, windowReady, err := f.waitReady(func() (uint64, error) { return 7, nil })
	if err != nil || h == nil || *h != 7 || windowReady {
		t.Fatalf("fresh probe ok, window connection down: height %v windowReady %v err %v", h, windowReady, err)
	}
	down.peerDown = false
	if _, _, windowReady, err = f.waitReady(func() (uint64, error) { return 7, nil }); err != nil || !windowReady {
		t.Fatalf("both answering: windowReady %v err %v", windowReady, err)
	}
	if _, _, _, err = f.waitReady(func() (uint64, error) { return 0, errors.New("refused") }); err == nil {
		t.Fatal("a peer that never answers must be an error")
	}
}

// A resume stopped part-way leaves ballots unsent and must not close; the next
// resume sends them and closes.
func TestResumeStoppedPartWayDoesNotClose(t *testing.T) {
	e, led, c, runDir, path := crashedRun(t, 40, 20)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := e.resumeAndClose(ctx, "run-1", c, led, led, path)
	if err == nil || !strings.Contains(err.Error(), "stays open") {
		t.Fatalf("a stopped resume: %v", err)
	}
	for _, name := range led.callNames() {
		if name == "CloseElection" {
			t.Fatal("a stopped resume closed the election")
		}
	}
	if _, err := os.Stat(filepath.Join(runDir, CeremonyFile)); err == nil {
		t.Fatal("a stopped resume opened the ceremony")
	}
	if err := e.resumeAndClose(context.Background(), "run-1", c, led, led, path); err != nil {
		t.Fatalf("resume again: %v", err)
	}
	if got := len(led.acceptedIndices()); got != 40 {
		t.Fatalf("chain holds %d, want 40", got)
	}
	if names := led.callNames(); names[len(names)-1] != "CloseElection" {
		t.Fatalf("the second resume must close, calls end %v", names[len(names)-2:])
	}
}

// Every ballot landed but the close failed: the run is not stuck. A second
// resume is planned close-only; a close the chain already holds counts as done;
// once closed there is nothing left to resume.
func TestResumeCloseIsRetryable(t *testing.T) {
	for _, tc := range []struct {
		name, retryFail string
	}{{"close succeeds on retry", ""}, {"close already on chain", `election "run-1" is already closed`}} {
		t.Run(tc.name, func(t *testing.T) {
			e, led, c, runDir, path := crashedRun(t, 20, 10)
			led.failOn = "CloseElection"
			err := e.resumeAndClose(context.Background(), "run-1", c, led, led, path)
			if err == nil || !strings.Contains(err.Error(), "resume again to retry the close") {
				t.Fatalf("a failed close: %v", err)
			}
			if got := len(led.acceptedIndices()); got != 20 {
				t.Fatalf("chain holds %d, want 20", got)
			}

			plan, err := planResume(runDir, c)
			if err != nil || !plan.CloseOnly {
				t.Fatalf("after a failed close: plan %+v err %v, want close-only", plan, err)
			}
			led.failOn, led.failText = "", ""
			if tc.retryFail != "" {
				led.failOn, led.failText = "CloseElection", tc.retryFail
			}
			ballotsBefore := len(led.acceptedIndices())
			if err := e.resumeAndClose(context.Background(), "run-1", c, led, led, path); err != nil {
				t.Fatalf("close-only resume: %v", err)
			}
			if len(led.acceptedIndices()) != ballotsBefore {
				t.Fatal("a close-only resume submitted ballots")
			}
			if _, err := os.Stat(filepath.Join(runDir, CeremonyFile)); err != nil {
				t.Fatalf("the close-only resume must open the ceremony: %v", err)
			}
			closes := journalEventsOfType(t, runDir, "resume.close")
			last := closes[len(closes)-1]
			if last["ok"] != true || last["close_only"] != true || last["already_closed"] != (tc.retryFail != "") {
				t.Fatalf("resume.close = %v", last)
			}
			if _, err := planResume(runDir, c); err == nil {
				t.Fatal("a closed election has nothing left to resume")
			}
		})
	}
}

func TestPeerRestartFaultNotReachedIsStamped(t *testing.T) {
	dir := t.TempDir()
	e := newTestExecutor(t, dir)
	j := e.journalFor("run-1")
	f := e.newPeerFault(context.Background(), "run-1", j, &fakeLedger{}, &FaultPlan{Kind: FaultPeerRestart, At: 0.5, DownS: 5}, 10,
		func() int { return 0 })
	f.dispatched(4)
	f.wait()
	j.Close()
	if got := journalEventsOfType(t, filepath.Join(dir, "run-1"), "fault.not_fired"); len(got) != 1 || jint(got[0], "at_index") != 5 {
		t.Fatalf("fault.not_fired = %v", got)
	}
	var none *peerFault
	none.dispatched(9)
	none.wait()
	if none.hasFired() {
		t.Fatal("no fault never fired")
	}
}

// A window reads the plan from run.json when it opens, so a fault armed after
// the phase's record was read still fires.
func TestArmedFaultIsReadWhenTheWindowOpens(t *testing.T) {
	s, _ := gateServer(t, enabledFabric(), "abc", 1<<62)
	stale, err := func() (RunRecord, error) {
		id, _ := faultRun(t, s, onchainConfig())
		return s.record(id)
	}()
	if err != nil {
		t.Fatal(err)
	}
	if rec := postFault(t, s, stale.RunID, goodFault, loopback, ""); rec.Code != http.StatusOK {
		t.Fatalf("arm: %d %s", rec.Code, rec.Body)
	}
	if stale.Config.FaultPlan != nil {
		t.Fatal("test setup: the stale record must predate the plan")
	}
	if got := s.exec.armedFault(stale.RunID, stale.Config); got == nil || got.At != 0.5 {
		t.Fatalf("armedFault = %+v", got)
	}
}
