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
	if end[0]["ok"] != true || ready[0]["ok"] != true || ready[0]["block_height"] == nil {
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

	// The operator's next step: Resume.
	if _, err := planResume(runDir, c); err != nil {
		t.Fatalf("a faulted run must be resumable: %v", err)
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

// Stopping the peer under a campaign, the ladder or a reset would wreck it:
// the fault is refused at the moment it would fire, and docker is never run.
func TestPeerRestartFaultRefusedWhileAJobRuns(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeRealBallotStream(t, runDir, 20)
	c := ElectionConfig{Mode: "onchain", Voters: 20, Positions: 1, Candidates: 2, Concurrency: 2,
		FaultPlan: &FaultPlan{Kind: FaultPeerRestart, At: 0.5, DownS: 20}}
	led := &fakeLedger{}
	run, calls := dockerRecorder(led)
	e.run = run
	e.faultGate = func() error { return errors.New("campaign campaign-1 is running on this network") }

	if err := e.submitOnChain(context.Background(), "run-1", c, led, path); err != nil {
		t.Fatalf("an unfired fault must not fail the run: %v", err)
	}
	if got := calls(); len(got) != 0 {
		t.Fatalf("docker ran while a job held the network: %v", got)
	}
	refused := journalEventsOfType(t, runDir, "fault.refused")
	if len(refused) != 1 || !strings.Contains(jstring(refused[0], "reason"), "campaign-1") {
		t.Fatalf("fault.refused = %v", refused)
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
