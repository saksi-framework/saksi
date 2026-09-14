package campaign

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

// The peer-restart fault: T3 (tools/t3-restart.sh) from the console.
//
// POST /api/runs/<id>/fault arms it on a generated on-chain run whose ballot
// window has not started. When the window has dispatched at x N ballots, the
// worker holding ballot at x N stops peer0.org1.example.com and every other
// worker keeps dispatching: ballots sent while the peer is down fail and are
// recorded as drops, never hidden. After down_s the peer is started again and
// the window waits until it answers. Each step is stamped in the run journal.
//
// The run then ends failed with those drops, its window marked interrupted, and
// the operator finishes it with POST /api/runs/<id>/resume (which submits what
// the chain does not hold and closes the election) and the ceremony and verify
// as usual.
//
// Why arming is a separate guarded route, and only before the window: the
// config routes (/generate, /run-all, campaigns) are reachable without the
// loopback and confirmation guards, internal campaign calls included, so a
// config may never carry a fault; and a window already running captured its
// config when it started.

const (
	FaultPeerRestart = "peer-restart"
	// faultConfirm is the exact string the body's confirm must carry.
	faultConfirm = "RESTART"
	// faultPeerContainer is the only container a fault ever stops or starts.
	faultPeerContainer = "peer0.org1.example.com"
	faultMinDownS      = 5
	faultMaxDownS      = 120
	// faultDockerTimeout bounds one docker stop or start.
	faultDockerTimeout = time.Minute
)

// peerReadyTimeout bounds the wait for the restarted peer to answer, and
// peerReadyPoll is the interval between probes; vars so tests are quick.
var peerReadyTimeout, peerReadyPoll = 3 * time.Minute, time.Second

// faultSleep holds the peer down; a var so tests do not wait down_s.
var faultSleep = func(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// FaultPlan is ElectionConfig.fault_plan.
type FaultPlan struct {
	Kind string `json:"kind"`
	// At is the fraction of the window's ballots dispatched before the peer stops.
	At float64 `json:"at"`
	// DownS is how long the peer stays stopped.
	DownS float64 `json:"down_s"`
}

// index is the ballot whose dispatch stops the peer.
func (p FaultPlan) index(n int) int { return int(p.At * float64(n)) }

// validate checks the plan against a window of n ballots.
func (p FaultPlan) validate(n int) error {
	switch {
	case p.Kind != FaultPeerRestart:
		return fmt.Errorf("fault kind must be %q (got %q)", FaultPeerRestart, p.Kind)
	case !(p.At > 0 && p.At < 1):
		return fmt.Errorf("at must be between 0 and 1, exclusive (got %v)", p.At)
	case p.DownS < faultMinDownS || p.DownS > faultMaxDownS:
		return fmt.Errorf("down_s must be between %d and %d seconds (got %v)", faultMinDownS, faultMaxDownS, p.DownS)
	}
	if i := p.index(n); i < 1 || i > n-1 {
		return fmt.Errorf("at %v of %d ballots stops the peer at ballot %d: at least one ballot must be sent before and after it", p.At, n, i)
	}
	return nil
}

// handleFault serves POST /api/runs/<id>/fault {kind, at, down_s, confirm}.
func (s *Server) handleFault(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	refuse := func(code int, format string, args ...any) {
		writeJSONResp(w, code, map[string]string{"error": fmt.Sprintf(format, args...)})
	}
	if !isLoopback(r.RemoteAddr) {
		refuse(http.StatusForbidden, "a fault is accepted only from the console machine itself (loopback)")
		return
	}
	runID, err := validRun(s, id)
	if err != nil {
		refuse(http.StatusBadRequest, "%v", err)
		return
	}
	var req struct {
		FaultPlan
		Confirm string `json:"confirm"`
	}
	if err := decodeExactKeys(w, r, &req, "kind", "at", "down_s", "confirm"); err != nil {
		refuse(http.StatusBadRequest, "invalid fault body: %v", err)
		return
	}
	if req.Confirm != faultConfirm {
		refuse(http.StatusBadRequest, "confirm must be exactly %q: the fault stops the Fabric peer mid-election", faultConfirm)
		return
	}
	rec, err := s.record(runID)
	if err != nil {
		refuse(http.StatusNotFound, "%v", err)
		return
	}
	c := rec.Config
	n := c.Voters * c.Positions
	if err := req.FaultPlan.validate(n); err != nil {
		refuse(http.StatusBadRequest, "%v", err)
		return
	}
	switch {
	case c.Mode != "onchain":
		refuse(http.StatusConflict, "run mode is %q: a peer-restart fault needs an on-chain run", c.Mode)
		return
	case c.Rep != nil:
		refuse(http.StatusConflict, "this run is a campaign repetition, a measurement: it never carries a fault")
		return
	case c.AttackPlan != nil:
		refuse(http.StatusConflict, "this run has an attack plan: run the fault as its own security run, "+
			"so its drops and its resume are not mixed with attack pauses")
		return
	case c.WindowS > 0:
		refuse(http.StatusConflict, "this run's ballot window is time-bounded (window_s %v): a faulted window would "+
			"become resumable, and the resume would send every remaining ballot, ignoring the bound", c.WindowS)
		return
	}
	if !s.fabric.Enabled() {
		refuse(http.StatusBadRequest, "%v", errNoFabric())
		return
	}
	// Held for the check and the write, so no phase starts in between; a phase
	// dispatched from a record read before this write still sees the plan,
	// because the window reads it from run.json when it opens.
	if why := s.claimAlone(runID); why != "" {
		refuse(http.StatusConflict, "%s", why)
		return
	}
	defer s.finish(runID)
	dir, err := s.store.Dir(runID)
	if err != nil {
		refuse(http.StatusBadRequest, "%v", err)
		return
	}
	events, err := readJournalEvents(dir)
	if err != nil {
		refuse(http.StatusConflict, "this run has no journal yet: generate it first (%v)", err)
		return
	}
	for _, ev := range events {
		if jstring(ev, "event") == "stage.ballots.start" {
			refuse(http.StatusConflict, "this run's ballot window has already started: a fault is armed only before "+
				"/ceremony/start or /submit opens it")
			return
		}
	}
	plan := req.FaultPlan
	rec.Config.FaultPlan = &plan
	if err := writeJSON(filepath.Join(dir, RunFile), rec); err != nil {
		refuse(http.StatusInternalServerError, "fault not armed: %v", err)
		return
	}
	fields := map[string]any{"kind": plan.Kind, "at": plan.At, "down_s": plan.DownS,
		"at_index": plan.index(n), "ballots": n, "container": faultPeerContainer, "from": r.RemoteAddr}
	j := s.exec.journalFor(runID)
	_ = j.Stamp("fault.armed", fields)
	j.Close()
	delete(fields, "from")
	fields["run_id"] = runID
	writeJSONResp(w, http.StatusOK, fields)
}

// claimAlone takes runID's lock only when nothing else is using the network:
// no job and no phase on any other run. It returns why not. The window checks
// the same again when the fault fires (faultGate).
func (s *Server) claimAlone(runID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, running := s.busy[runID]; running {
		return "a phase is already running on this run"
	}
	if j := s.jobs.running(); j != nil {
		return fmt.Sprintf("%s %s is running on this network: arm the fault once it has finished", j.Kind, j.ID)
	}
	if others := s.busyRunsLocked(runID); len(others) > 0 {
		return fmt.Sprintf("a phase is running on %v, which shares this network: arm the fault once it has finished", others)
	}
	s.busy[runID] = func() {}
	return ""
}

// faultGate refuses to fire runID's fault while anything else uses the
// network: a job (campaign, ladder, reset) or a phase on another run.
func (s *Server) faultGate(runID string) error {
	if j := s.jobs.running(); j != nil {
		return fmt.Errorf("%s %s is running on this network", j.Kind, j.ID)
	}
	s.mu.Lock()
	others := s.busyRunsLocked(runID)
	s.mu.Unlock()
	if len(others) > 0 {
		return fmt.Errorf("a phase is running on %v, which shares this network", others)
	}
	return nil
}

// RestorePeer starts the peer again when a fault has it stopped, for a console
// that is shutting down mid-fault; it reports whether one was down.
func (e *Executor) RestorePeer() (bool, error) {
	e.stopMu.Lock() // a docker stop still in flight finishes first
	defer e.stopMu.Unlock()
	if e.peersDown.Load() == 0 {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), faultDockerTimeout)
	defer cancel()
	_, err := e.run(ctx, "docker", "start", faultPeerContainer)
	return true, err
}

// setFaulting marks runID's fault active (from firing until the peer answers)
// or over.
func (e *Executor) setFaulting(runID string, active bool) {
	e.faultMu.Lock()
	defer e.faultMu.Unlock()
	if !active {
		delete(e.faulting, runID)
		return
	}
	if e.faulting == nil {
		e.faulting = make(map[string]bool)
	}
	e.faulting[runID] = true
}

// faultingRun names a run whose fault has the peer stopped or recovering, or "".
func (e *Executor) faultingRun() string {
	e.faultMu.Lock()
	defer e.faultMu.Unlock()
	for id := range e.faulting {
		return id
	}
	return ""
}

// armedFault is the fault plan the window runs with: run.json's, read when the
// window opens, else the config the phase was dispatched with.
func (e *Executor) armedFault(runID string, c ElectionConfig) *FaultPlan {
	dir, err := e.store.Dir(runID)
	if err != nil {
		return c.FaultPlan
	}
	var rec RunRecord
	if readJSON(filepath.Join(dir, RunFile), &rec) == nil && rec.Config.FaultPlan != nil {
		return rec.Config.FaultPlan
	}
	return c.FaultPlan
}

// peerFault is one armed fault inside one ballot window. nil is a window with
// no fault; every method is nil-safe.
type peerFault struct {
	e         *Executor
	ctx       context.Context
	runID     string
	j         *Journal
	led       clientsdk.Ledger
	plan      FaultPlan
	at        int
	committed func() int // ballots the window has committed so far

	triggered atomic.Bool // the fault was decided: fired, refused, or never reached
	fired     atomic.Bool // the peer was stopped
	started   atomic.Bool // the peer's restart was attempted
	done      chan struct{}
}

func (e *Executor) newPeerFault(ctx context.Context, runID string, j *Journal, led clientsdk.Ledger,
	plan *FaultPlan, n int, committed func() int) *peerFault {
	if plan == nil {
		return nil
	}
	f := &peerFault{e: e, ctx: ctx, runID: runID, j: j, led: led, plan: *plan,
		at: plan.index(n), committed: committed, done: make(chan struct{})}
	_ = j.Stamp("fault.window", map[string]any{"kind": plan.Kind, "at_index": f.at, "down_s": plan.DownS})
	return f
}

// dispatched is called as each ballot is handed to a worker. The first ballot
// at or past the fault index stops the peer before it is sent; every other
// worker carries on.
func (f *peerFault) dispatched(i int) {
	if f == nil || i < f.at || !f.triggered.CompareAndSwap(false, true) {
		return
	}
	if f.e.faultGate != nil {
		if err := f.e.faultGate(f.runID); err != nil {
			_ = f.j.Stamp("fault.refused", map[string]any{"at_index": f.at, "reason": err.Error()})
			f.e.publish(f.runID, "fault", "error", "peer-restart fault not fired: "+err.Error())
			close(f.done)
			return
		}
	}
	f.fired.Store(true)
	f.e.setFaulting(f.runID, true) // cleared when restore ends
	f.e.peersDown.Add(1)           // counted before the stop: a shutdown during it restores too
	func() {
		// A panic after the stop must not leave the peer down.
		defer func() {
			if p := recover(); p != nil {
				_ = f.start()
				panic(p)
			}
		}()
		f.stop()
	}()
	go f.restore()
}

// hasFired reports that the peer was stopped during this window.
func (f *peerFault) hasFired() bool { return f != nil && f.fired.Load() }

// wait blocks until the fault is over: the peer is back and answering, or the
// fault never fired, which is stamped.
func (f *peerFault) wait() {
	if f == nil {
		return
	}
	if f.triggered.CompareAndSwap(false, true) {
		_ = f.j.Stamp("fault.not_fired", map[string]any{"at_index": f.at,
			"reason": fmt.Sprintf("the window ended before ballot %d was dispatched", f.at)})
		close(f.done)
	}
	<-f.done
}

func (f *peerFault) docker(action string) error {
	ctx, cancel := context.WithTimeout(context.Background(), faultDockerTimeout)
	defer cancel()
	_, err := f.e.run(ctx, "docker", action, faultPeerContainer)
	return err
}

// start starts the peer again, once; a later call does nothing.
func (f *peerFault) start() error {
	if !f.started.CompareAndSwap(false, true) {
		return nil
	}
	defer f.e.peersDown.Add(-1)
	return f.docker("start")
}

// stop stops the peer and stamps fault.start with the chain as it was then.
func (f *peerFault) stop() {
	committed, height := f.committed(), chainHeight(f.led)
	t0 := time.Now()
	f.e.stopMu.Lock()
	err := f.docker("stop")
	f.e.stopMu.Unlock()
	fields := map[string]any{"kind": f.plan.Kind, "container": faultPeerContainer, "at_index": f.at,
		"ballots_committed": committed, "stop_ms": time.Since(t0).Milliseconds(), "ok": err == nil}
	if height != nil {
		fields["block_height"] = *height
	}
	if err != nil {
		fields["error"] = err.Error()
	}
	_ = f.j.Stamp("fault.start", fields)
	f.e.publish(f.runID, "fault", "info", fmt.Sprintf(
		"stopped %s at ballot %d (%d committed); down for %gs", faultPeerContainer, f.at, committed, f.plan.DownS))
}

// restore holds the peer down, starts it again whatever happened meanwhile (a
// cancelled window, a panic), and waits until it answers.
func (f *peerFault) restore() {
	defer close(f.done)
	defer f.e.setFaulting(f.runID, false)
	defer func() {
		if p := recover(); p != nil {
			fields := map[string]any{"container": faultPeerContainer, "error": fmt.Sprint(p)}
			if err := f.start(); err != nil {
				fields["start_error"] = err.Error()
			}
			_ = f.j.Stamp("fault.panic", fields)
			f.e.publish(f.runID, "fault", "error", fmt.Sprintf("peer-restart fault panicked (%v); %s started again", p, faultPeerContainer))
		}
	}()
	downAt := time.Now()
	faultSleep(f.ctx, time.Duration(f.plan.DownS*float64(time.Second)))
	err := f.start()
	fields := map[string]any{"container": faultPeerContainer, "down_ms": time.Since(downAt).Milliseconds(),
		"ballots_committed": f.committed(), "ok": err == nil}
	if err != nil {
		fields["error"] = err.Error()
	}
	_ = f.j.Stamp("fault.end", fields)

	waited, height, windowReady, err := f.waitReady(f.peerProbe())
	ready := map[string]any{"ok": err == nil && windowReady, "wait_ms": waited.Milliseconds(),
		"window_conn_ready": windowReady, "ballots_committed": f.committed()}
	if height != nil {
		ready["block_height"] = *height
	}
	if err != nil {
		ready["error"] = err.Error()
	}
	_ = f.j.Stamp("fault.peer_ready", ready)
	f.e.publish(f.runID, "fault", "info", fmt.Sprintf("%s answering again after %s", faultPeerContainer, waited.Round(time.Millisecond)))
}

// peerProbe reads the channel height on a fresh connection when a network is
// configured, and on the window's ledger otherwise (tests).
func (f *peerFault) peerProbe() func() (uint64, error) {
	if !f.e.fabric.Enabled() {
		return func() (uint64, error) { h, _, err := f.led.ChainInfo(); return h, err }
	}
	return func() (uint64, error) {
		conn, err := f.e.fabric.Connect()
		if err != nil {
			return 0, err
		}
		defer conn.Close()
		h, _, err := conn.Ledger().ChainInfo()
		return h, err
	}
}

// waitReady polls the peer until it answers a ledger query. On a live network
// each probe opens a fresh connection, so the wait measures the peer and not the
// window connection's reconnect backoff; that connection is then waited for
// too, since the window collects its receipts over it next; windowReady says
// whether that connection answered before the deadline.
func (f *peerFault) waitReady(probe func() (uint64, error)) (time.Duration, *uint64, bool, error) {
	start := time.Now()
	deadline := start.Add(peerReadyTimeout)
	for {
		h, err := probe()
		if err == nil {
			waited := time.Since(start)
			windowReady := chainHeight(f.led) != nil
			for !windowReady && time.Now().Before(deadline) {
				time.Sleep(peerReadyPoll)
				windowReady = chainHeight(f.led) != nil
			}
			return waited, &h, windowReady, nil
		}
		if time.Now().After(deadline) {
			return time.Since(start), nil, false, fmt.Errorf("the peer did not answer within %s: %w", peerReadyTimeout, err)
		}
		time.Sleep(peerReadyPoll)
	}
}
