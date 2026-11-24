package campaign

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

// The live console is its precinct's registered machine: setup records
// CreateElection, then RegisterPrecinctMachine naming the console's ballot
// certificate, before any ballot can be cast.
func TestLiveSetupRegistersTheConsoleAsMachine(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveCeremony)
	if got, err := fx.chain.GetPrecinctMachine(runID); err != nil || got != oracleMachineFP {
		t.Fatalf("registered machine = %q, %v; want %s", got, err, oracleMachineFP)
	}
	fx.chain.oracleChain.mu.Lock()
	submits := slices.Clone(fx.chain.oracleChain.submits)
	fx.chain.oracleChain.mu.Unlock()
	create, reg := slices.Index(submits, "CreateElection"), slices.Index(submits, "RegisterPrecinctMachine")
	if create < 0 || reg != create+1 {
		t.Fatalf("submits %v: want RegisterPrecinctMachine right after CreateElection", submits)
	}
	if tx := c.s.live.st.Lifecycle["RegisterPrecinctMachine"]; tx.TxID == "" {
		t.Fatalf("live state has no RegisterPrecinctMachine transaction: %+v", c.s.live.st.Lifecycle)
	}
}

// A registration that committed while its receipt was lost leaves the run in
// setup; the restart finds this console's machine already registered and
// carries on.
func TestLiveRestartTakesARegisteredMachineFromTheChain(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	fx.chain.lose.Store("RegisterPrecinctMachine")
	if code, _ := c.do(http.MethodPost, "/api/live/elections", "admin", listBody(map[string]any{"title": "x", "positions": livePositions, "trustees": 3, "threshold": 2})); code != http.StatusBadGateway {
		t.Fatalf("setup with the registration receipt lost: %d", code)
	}
	if c.state() != LiveSetup {
		t.Fatalf("state %s, want setup", c.state())
	}
	fx.chain.lose.Store("")
	c2 := fx.console()
	if c2.state() != LiveCeremony {
		t.Fatalf("after restart: %s", c2.state())
	}
}

// An election already bound to another machine is not taken over: every
// ballot this console sent would be refused at the caller gate.
func TestLiveSetupRefusesAnElectionBoundToAnotherMachine(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	other := strings.Repeat("ee", 32)
	hook := func(fn string) {
		if fn != "RegisterPrecinctMachine" {
			return
		}
		o := fx.chain.oracleChain
		o.mu.Lock()
		for id := range o.params {
			if _, ok := o.machine[id]; !ok {
				o.machine[id] = other
			}
		}
		o.mu.Unlock()
	}
	fx.chain.before.Store(&hook)
	code, out := c.do(http.MethodPost, "/api/live/elections", "admin", listBody(map[string]any{"title": "x", "positions": livePositions, "trustees": 3, "threshold": 2}))
	if code != http.StatusConflict || !strings.Contains(out["error"].(string), other) {
		t.Fatalf("setup onto another machine's election: %d %v", code, out)
	}
	if c.state() != LiveSetup {
		t.Fatalf("state %s, want setup", c.state())
	}
}
