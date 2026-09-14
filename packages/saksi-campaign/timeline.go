package campaign

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"sync"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	"github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk/bench"
)

// The attack timeline.
//
// A security run (ElectionConfig.AttackPlan) pauses its lifecycle at each stage
// the plan lists and mounts that stage's attacks there, at the moment they
// belong to, before continuing:
//
//	dkg       after CreateElection, before the real PublishDKGTranscript
//	ballots   ballots_at x N ballots dispatched and committed, the rest not yet sent
//	close     after CloseElection
//	ceremony  the ceremony is open, the tally not yet published
//
// Mounting at the real moment is what makes a verdict about the gate it names.
// Mounted after the lifecycle, every ballot attack meets a closed election and
// is refused by the closed-election gate before the gate it was meant to test.
//
// An attack goes to the live election only when an on-chain gate exists to
// refuse it and a refused submission leaves nothing behind (LiveCapable); every
// other attack is simulated against a copy of the run, and its row says so.
// Offline runs pause at the same stages and simulate every attack.
//
// While paused the lifecycle waits for the operator (POST /api/runs/<id>/pause:
// run one attack, run them all, or skip). When the wait runs out, every attack
// at the stage not yet run is run and the lifecycle continues — the plan is the
// operator's intent, and an unattended run still carries it out.

// StageUnstaged is the mounted_stage of an attack mounted outside any pause:
// the full catalogue after the count, or one attack run on its own.
const StageUnstaged = "unstaged"

// MountContext is the state of the election when an attack was mounted.
// A field with no producer (no ledger offline) is empty, never a made-up zero.
type MountContext struct {
	Stage            string  `json:"mounted_stage"`
	ElectionStatus   string  `json:"election_status,omitempty"`
	BallotsCommitted *int    `json:"ballots_committed,omitempty"`
	BlockHeight      *uint64 `json:"block_height,omitempty"`
}

func (p *AttackPlan) has(stage string) bool {
	return p != nil && slices.Contains(p.Stages, stage)
}

func (p *AttackPlan) timeout() time.Duration {
	if p == nil || p.TimeoutS <= 0 {
		return DefaultPauseTimeout
	}
	return time.Duration(p.TimeoutS * float64(time.Second))
}

// pauseIndex is how many of n ballots the window dispatches before the ballots
// stage pauses: ballots_at x n, held inside [1, n-1] so there is always a cast
// ballot whose nullifier can be reused and an uncast one to tamper with. 0
// means the window does not pause.
func (p *AttackPlan) pauseIndex(n int) int {
	if !p.has(StageBallots) || n < 2 {
		return 0
	}
	at := p.BallotsAt
	if at == 0 {
		at = DefaultBallotsAt
	}
	return min(max(int(at*float64(n)), 1), n-1)
}

// PauseView is GET /api/runs/<id>/pause: where the lifecycle is holding, if
// anywhere, and what the operator is being asked to decide.
type PauseView struct {
	Paused    bool         `json:"paused"`
	Stage     string       `json:"stage,omitempty"`
	Scenarios []string     `json:"scenarios,omitempty"`
	Mount     MountContext `json:"mount"`
	// Live reports that this pause is on a ledger: attacks with an on-chain
	// gate are submitted to the running election.
	Live     bool       `json:"live"`
	Deadline *time.Time `json:"deadline,omitempty"`
	// Running names the attack being mounted right now.
	Running string `json:"running,omitempty"`
}

type stagePause struct {
	mu     sync.Mutex
	view   PauseView
	decide chan pauseDecision
}

type pauseDecision struct{ action, scenario string }

func (p *stagePause) snapshot() PauseView {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.view
}

func (p *stagePause) update(fn func(v *PauseView)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fn(&p.view)
}

// errNoPause is DecidePause on a run that is not holding at a stage.
var errNoPause = errors.New("this run is not paused at an attack stage")

// PauseStatus reports where a run's lifecycle is paused, if it is.
func (e *Executor) PauseStatus(runID string) PauseView {
	e.pauseMu.Lock()
	p := e.pauses[runID]
	e.pauseMu.Unlock()
	if p == nil {
		return PauseView{}
	}
	return p.snapshot()
}

// DecidePause hands the operator's decision to a paused lifecycle: "run" one
// scenario of the paused stage, "run-all" of them and continue, or "skip" the
// rest and continue.
func (e *Executor) DecidePause(runID, action, scenario string) error {
	e.pauseMu.Lock()
	p := e.pauses[runID]
	e.pauseMu.Unlock()
	if p == nil {
		return errNoPause
	}
	v := p.snapshot()
	switch action {
	case "run":
		if !slices.Contains(v.Scenarios, scenario) {
			return fmt.Errorf("scenario %q is not an attack of the %s stage", scenario, v.Stage)
		}
	case "run-all", "skip":
	default:
		return fmt.Errorf("unknown pause action %q (want run, run-all or skip)", action)
	}
	select {
	case p.decide <- pauseDecision{action: action, scenario: scenario}:
		return nil
	default:
		return fmt.Errorf("the %s stage is still working through earlier decisions", v.Stage)
	}
}

func (e *Executor) setPause(runID string, p *stagePause) {
	e.pauseMu.Lock()
	defer e.pauseMu.Unlock()
	if e.pauses == nil {
		e.pauses = make(map[string]*stagePause)
	}
	if p == nil {
		delete(e.pauses, runID)
		return
	}
	e.pauses[runID] = p
}

// pauseForAttacks holds the lifecycle at stage, if the run's plan lists it,
// until the operator has run or skipped the stage's attacks. mount mounts one
// of them in this stage's context; the result's mount context is stamped here.
//
// A cancelled context ends the pause at once without running anything more:
// the caller's next lifecycle step then fails on the same cancellation.
func (e *Executor) pauseForAttacks(ctx context.Context, runID string, c ElectionConfig, stage string,
	mc MountContext, live bool, mount func(Scenario) ScenarioResult) {
	if !c.AttackPlan.has(stage) {
		return
	}
	dir, err := e.store.Dir(runID)
	if err != nil {
		return
	}
	scs := ScenariosForStage(stage)
	ids := make([]string, len(scs))
	for i, sc := range scs {
		ids[i] = sc.ID
	}
	mc.Stage = stage
	timeout := c.AttackPlan.timeout()
	deadline := time.Now().Add(timeout)
	p := &stagePause{
		decide: make(chan pauseDecision, 8),
		view:   PauseView{Paused: true, Stage: stage, Scenarios: ids, Mount: mc, Live: live, Deadline: &deadline},
	}
	e.setPause(runID, p)
	defer e.setPause(runID, nil)

	j := e.journalFor(runID)
	defer j.Close()
	start := time.Now()
	_ = j.Stamp("attack.pause", mountFields(mc, map[string]any{"scenarios": ids, "live": live}))
	e.publish(runID, "attack", "pause", fmt.Sprintf(
		"paused at %s: %d attack(s) wait for Run or Skip (they all run at %s if nobody decides)",
		stage, len(ids), deadline.Format(time.TimeOnly)))

	ran := make(map[string]bool, len(scs))
	runOne := func(sc Scenario) {
		p.update(func(v *PauseView) { v.Running = sc.ID })
		res := mount(sc)
		res.Mount = mc
		ran[sc.ID] = true
		_ = j.Stamp("attack.result", mountFields(mc, map[string]any{
			"scenario": sc.ID, "verdict": res.Verdict, "live": res.OnChain,
			"gate_expected": res.GateExpected, "gate_observed": res.GateObserved,
		}))
		if err := e.saveScenarioResult(runID, dir, res); err != nil {
			e.publish(runID, "attack", "error", sc.ID+": verdict not saved: "+err.Error())
		}
		p.update(func(v *PauseView) { v.Running = "" })
	}
	runRest := func() {
		for _, sc := range scs {
			if !ran[sc.ID] && ctx.Err() == nil {
				runOne(sc)
			}
		}
	}
	resume := func(reason string) {
		_ = j.Stamp("attack.resume", map[string]any{
			"stage": stage, "reason": reason, "paused_ms": time.Since(start).Milliseconds(),
		})
		e.publish(runID, "attack", "info", fmt.Sprintf("%s stage: continuing (%s)", stage, reason))
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			resume("cancelled")
			return
		case <-timer.C:
			runRest()
			resume("timeout")
			return
		case d := <-p.decide:
			switch d.action {
			case "run-all":
				runRest()
				resume("run-all")
				return
			case "skip":
				resume("skip")
				return
			case "run":
				for _, sc := range scs {
					if sc.ID == d.scenario {
						runOne(sc)
					}
				}
				// The wait restarts after every decision: the operator is here.
				deadline = time.Now().Add(timeout)
				p.update(func(v *PauseView) { v.Deadline = &deadline })
				timer.Reset(timeout)
			}
		}
	}
}

// mountFields is a journal payload carrying the mount context.
func mountFields(mc MountContext, extra map[string]any) map[string]any {
	extra["stage"] = mc.Stage
	if mc.ElectionStatus != "" {
		extra["election_status"] = mc.ElectionStatus
	}
	if mc.BallotsCommitted != nil {
		extra["ballots_committed"] = *mc.BallotsCommitted
	}
	if mc.BlockHeight != nil {
		extra["block_height"] = *mc.BlockHeight
	}
	return extra
}

// simulatedMount mounts every attack at a pause as a simulation.
func (e *Executor) simulatedMount(ctx context.Context, runID string, onChain bool) func(Scenario) ScenarioResult {
	return func(sc Scenario) ScenarioResult {
		dir, err := e.store.Dir(runID)
		if err != nil {
			return ScenarioResult{Scenario: sc.ID, Stage: sc.Stage, Verdict: "INCONCLUSIVE", Actual: "not mounted: " + err.Error()}
		}
		return e.simulateStaged(ctx, runID, dir, sc, onChain)
	}
}

// chainHeight is the ledger's height now, or nil when it cannot be read.
func chainHeight(led clientsdk.Ledger) *uint64 {
	h, _, err := led.ChainInfo()
	if err != nil {
		return nil
	}
	return &h
}

// committedFromMetrics is how many ballots the run's ballot window committed,
// or nil before a window has run.
func committedFromMetrics(dir string) *int {
	var sm submitMetrics
	if readJSON(filepath.Join(dir, submitMetricsFile), &sm) != nil {
		return nil
	}
	return &sm.Committed
}

// runBench is the ballot window's dispatcher. A variable only so a test can
// prove a run without an attack plan dispatches exactly as it always has.
var runBench = bench.Run

// pausedWindow is the ballot window of a security run whose plan pauses mid-
// submission. It dispatches ballots [0, at), lets every one of them finish,
// mounts the ballots stage against the open election, then dispatches [at, n).
//
// The two halves are ONE window: the result is stitched back together by
// index, and its duration is the sum of the halves, so neither the pause nor
// the attacks mounted in it are counted as submission time. Throughput from a
// security run is still perturbed (the orderer and peers saw the attacks), and
// perf.csv marks it so.
func (e *Executor) pausedWindow(ctx context.Context, runID string, c ElectionConfig, led clientsdk.Ledger,
	n, at int, submit bench.SubmitFunc, opts bench.RunOpts) bench.RunResult {
	first := runBench(ctx, at, submit, opts)
	if first.Stopped || ctx.Err() != nil {
		return joinWindows(n, at, first, bench.RunResult{LastIndex: -1, Stopped: true})
	}

	// The target of every tampering attack is ballot `at`, the first one not
	// dispatched: its nullifier is unspent, so it passes every gate before the
	// one under test. The donor of a reused nullifier is the first ballot that
	// committed.
	donor := slices.Index(first.OK[:at], true)
	committed := first.Committed
	mc := MountContext{ElectionStatus: "open", BallotsCommitted: &committed, BlockHeight: chainHeight(led)}
	simulate := e.simulatedMount(ctx, runID, true)
	e.pauseForAttacks(ctx, runID, c, StageBallots, mc, true, func(sc Scenario) ScenarioResult {
		if !sc.LiveCapable() || sc.MutateBallot == nil {
			return simulate(sc)
		}
		return e.mountBallotLive(runID, sc, at, donor, func(h string) error {
			_, _, err := led.Submit("SubmitBallot", h)
			return err
		})
	})

	rest := opts
	if opts.MaxDuration > 0 {
		if rest.MaxDuration = opts.MaxDuration - first.Window; rest.MaxDuration <= 0 {
			return joinWindows(n, at, first, bench.RunResult{LastIndex: -1, Stopped: true})
		}
	}
	if opts.OnProgress != nil {
		rest.OnProgress = func(done int) { opts.OnProgress(at + done) }
	}
	second := runBench(ctx, n-at, func(k int) error { return submit(at + k) }, rest)
	return joinWindows(n, at, first, second)
}

// joinWindows stitches the two halves of a paused window into the window they
// measure: counts and latencies add, per-index records keep absolute indices,
// and the duration is the sum of the halves.
func joinWindows(n, at int, a, b bench.RunResult) bench.RunResult {
	res := bench.RunResult{
		Submitted:   a.Submitted + b.Submitted,
		Committed:   a.Committed + b.Committed,
		Dropped:     a.Dropped + b.Dropped,
		Latencies:   append(append([]time.Duration(nil), a.Latencies...), b.Latencies...),
		Window:      a.Window + b.Window,
		Stopped:     a.Stopped || b.Stopped,
		LastIndex:   a.LastIndex,
		ByIndex:     make([]time.Duration, n),
		OK:          make([]bool, n),
		Concurrency: a.Concurrency,
	}
	copy(res.ByIndex, a.ByIndex)
	copy(res.OK, a.OK)
	copy(res.ByIndex[at:], b.ByIndex)
	copy(res.OK[at:], b.OK)
	if b.LastIndex >= 0 {
		res.LastIndex = at + b.LastIndex
	}
	return res
}

// mountBallotLive submits sc's tampered ballot to the open election at the
// ballots pause. target is a ballot the window has not sent; donor one that
// committed (-1 if none did). A refused ballot leaves no state, and the real
// target ballot is submitted normally when the window resumes.
func (e *Executor) mountBallotLive(runID string, sc Scenario, target, donor int, submit func(string) error) ScenarioResult {
	res := newLiveResult(sc)
	dir, err := e.store.Dir(runID)
	if err != nil {
		res.Verdict, res.Actual = "INCONCLUSIVE", "not mounted: "+err.Error()
		return res
	}
	lines, err := ballotLinesAt(dir, target, donor)
	if err != nil {
		res.Verdict, res.Actual = "INCONCLUSIVE", "not mounted: "+err.Error()
		return res
	}
	tampered, err := sc.MutateBallot(lines[target], lines[donor])
	if err != nil {
		res.Verdict, res.Actual = "INCONCLUSIVE", "not mounted: "+err.Error()
		return res
	}
	e.publish(runID, "attack", "info", fmt.Sprintf(
		"%s: submitting a tampered copy of ballot %d to the open election…", sc.ID, target))
	classifyLive(&res, sc, submit(tampered))
	e.publish(runID, "attack", "info", sc.ID+": "+res.Verdict+" — "+res.Actual)
	return res
}

// ballotLinesAt reads just the wanted ballot lines (negative indices are
// ignored), stopping once it has them.
func ballotLinesAt(dir string, want ...int) (map[int]string, error) {
	out := make(map[int]string, len(want))
	need := 0
	for _, i := range want {
		if i >= 0 {
			need++
		}
	}
	errDone := errors.New("done")
	err := scanBallotLines(dir, func(i int, line string) error {
		if slices.Contains(want, i) {
			out[i] = line
			if len(out) == need {
				return errDone
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, errDone) {
		return nil, err
	}
	if len(out) != need {
		return nil, fmt.Errorf("%s has no ballot at %v", BallotsFile, want)
	}
	return out, nil
}

// handlePause serves /api/runs/{id}/pause. GET reports where the run's
// lifecycle is paused (paused:false when it is not); POST decides the pause:
// {"action":"run","scenario":<id>}, {"action":"run-all"} or {"action":"skip"}.
func (s *Server) handlePause(w http.ResponseWriter, r *http.Request, id string) {
	runID, err := validRun(s, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		writeJSONResp(w, http.StatusOK, s.exec.PauseStatus(runID))
		return
	}
	var body struct {
		Action   string `json:"action"`
		Scenario string `json:"scenario"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := s.exec.DecidePause(runID, body.Action, body.Scenario); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errNoPause) {
			code = http.StatusConflict
		}
		http.Error(w, err.Error(), code)
		return
	}
	writeJSONResp(w, http.StatusAccepted, s.exec.PauseStatus(runID))
}
