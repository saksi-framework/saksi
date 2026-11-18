package campaign

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// The console verifies by itself once the tally is published (live_tally.go):
// the same run POST /api/live/verify makes, with no press.

// publishTally drives a fresh election to the threshold-th signature, which
// publishes the tally.
func (c *liveConsole) publishTally() string {
	c.t.Helper()
	runID := c.toState(LiveClosed)
	c.partials(1, liveContests)
	c.partials(2, liveContests)
	c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(1), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(1)})
	out := c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(2), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(2)})
	if out["published"] != true {
		c.t.Fatalf("not published at threshold: %v", out)
	}
	return runID
}

// autoVerify is the election view's auto_verify, or nil.
func (c *liveConsole) autoVerify() map[string]any {
	c.t.Helper()
	el := c.ok(http.MethodGet, "/api/live/election", "", nil)
	a, _ := el["auto_verify"].(map[string]any)
	return a
}

// A published tally is verified with no press: verified on a pass, exactly
// as after a press, with one verify-live run.
func TestLiveVerifiesByItselfAfterPublication(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.publishTally()
	c.s.live.waitBackground()
	if c.state() != LiveVerified {
		t.Fatalf("state %s after publication, want verified with no press", c.state())
	}
	if n := fx.ops.verifyCalls(); n != 1 {
		t.Fatalf("verify-live ran %d times, want 1", n)
	}
	el := c.ok(http.MethodGet, "/api/live/election", "", nil)
	a, _ := el["auto_verify"].(map[string]any)
	if el["verify_overall"] != "pass" || a == nil || a["state"] != autoVerifyDone || a["error"] != nil {
		t.Fatalf("view after the automatic run: verify_overall %v auto_verify %v", el["verify_overall"], el["auto_verify"])
	}
	board := c.ok(http.MethodGet, "/api/board/"+runID, "", nil)
	if board["verified"] != true {
		t.Fatalf("board after the automatic run: %v", board["verified"])
	}
	// The press still works, and re-verifies.
	if out := c.ok(http.MethodPost, "/api/live/verify", "admin", nil); out["state"] != LiveVerified || fx.ops.verifyCalls() != 2 {
		t.Fatalf("press after the automatic run: %v, %d runs", out, fx.ops.verifyCalls())
	}
}

// A failed verdict leaves the election tallied with the failure recorded as
// a failed press records it; the press is the retry.
func TestLiveAutomaticVerifyFailureStaysTallied(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	fx.ops.setVerify("fail")
	runID := c.publishTally()
	c.s.live.waitBackground()
	if c.state() != LiveTallied {
		t.Fatalf("state %s after a failed automatic verify, want tallied", c.state())
	}
	el := c.ok(http.MethodGet, "/api/live/election", "", nil)
	if el["verify_overall"] != "fail" || el["auto_verify"].(map[string]any)["state"] != autoVerifyDone {
		t.Fatalf("view: %v %v", el["verify_overall"], el["auto_verify"])
	}
	board := c.ok(http.MethodGet, "/api/board/"+runID, "", nil)
	if board["verified"] != false || board["live"].(map[string]any)["failed_checks"].([]any)[0] != "tally.homomorphic_sum" {
		t.Fatalf("board after a failed automatic verify: %v", board["live"])
	}
	// The press retries.
	fx.ops.setVerify("")
	if out := c.ok(http.MethodPost, "/api/live/verify", "admin", nil); out["state"] != LiveVerified || c.state() != LiveVerified {
		t.Fatalf("retry press: %v", out)
	}

	// A run that gives no verdict (the op fails) records nothing but the
	// error in auto_verify; the state stays tallied and the press retries.
	fx2 := newLiveFixture(t)
	d := fx2.console()
	fx2.ops.setVerify("error")
	d.publishTally()
	d.s.live.waitBackground()
	el = d.ok(http.MethodGet, "/api/live/election", "", nil)
	a := el["auto_verify"].(map[string]any)
	if d.state() != LiveTallied || el["verify_overall"] != nil || a["state"] != autoVerifyError || a["error"] == "" {
		t.Fatalf("after an automatic run with no verdict: %s %v %v", d.state(), el["verify_overall"], a)
	}
	fx2.ops.setVerify("")
	if out := d.ok(http.MethodPost, "/api/live/verify", "admin", nil); out["state"] != LiveVerified {
		t.Fatalf("retry press: %v", out)
	}
}

// A press that arrives while the automatic run is in flight waits for it and
// answers its result: verify-live runs once.
func TestLiveVerifyPressDuringTheAutomaticRunRunsOnce(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	gate := make(chan struct{})
	fx.ops.mu.Lock()
	fx.ops.verifyGate = gate
	fx.ops.mu.Unlock()
	c.publishTally()
	deadline := time.Now().Add(5 * time.Second)
	for fx.ops.verifyCalls() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if a := c.autoVerify(); a == nil || a["state"] != autoVerifyRunning {
		t.Fatalf("auto_verify while in flight: %v", a)
	}
	var wg sync.WaitGroup
	var out map[string]any
	var code int
	wg.Add(1)
	go func() {
		defer wg.Done()
		code, out = c.do(http.MethodPost, "/api/live/verify", "admin", nil)
	}()
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	c.s.live.waitBackground()
	if code != http.StatusOK || out["state"] != LiveVerified || out["overall"] != "pass" {
		t.Fatalf("press during the automatic run: %d %v", code, out)
	}
	if n := fx.ops.verifyCalls(); n != 1 {
		t.Fatalf("verify-live ran %d times, want 1", n)
	}
}

// A console restart at tallied with no verification result starts it again,
// once; one with a result does not.
func TestLiveRestartAtTalliedVerifiesOnce(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	fx.ops.setVerify("error")
	c.publishTally()
	c.s.live.waitBackground()
	if c.state() != LiveTallied || fx.ops.verifyCalls() != 1 {
		t.Fatalf("before the restart: %s, %d runs", c.state(), fx.ops.verifyCalls())
	}
	fx.ops.setVerify("")
	c2 := fx.console()
	c2.s.live.waitBackground()
	if c2.state() != LiveVerified || fx.ops.verifyCalls() != 2 {
		t.Fatalf("after the restart: %s, %d runs", c2.state(), fx.ops.verifyCalls())
	}
	// Verified: a restart runs nothing.
	c3 := fx.console()
	c3.s.live.waitBackground()
	if c3.state() != LiveVerified || fx.ops.verifyCalls() != 2 || c3.autoVerify() != nil {
		t.Fatalf("restart when verified: %s, %d runs", c3.state(), fx.ops.verifyCalls())
	}

	// Tallied with a failed verdict: a restart runs nothing either.
	fx2 := newLiveFixture(t)
	d := fx2.console()
	fx2.ops.setVerify("fail")
	d.publishTally()
	d.s.live.waitBackground()
	d2 := fx2.console()
	d2.s.live.waitBackground()
	if d2.state() != LiveTallied || fx2.ops.verifyCalls() != 1 {
		t.Fatalf("restart at tallied with a failed verdict: %s, %d runs", d2.state(), fx2.ops.verifyCalls())
	}

	// The chain has the tally the console missed (its receipt was lost and
	// the console stopped): the restart takes the tally and verifies it.
	fx3 := newLiveFixture(t)
	e := fx3.console()
	e.toState(LiveClosed)
	e.partials(1, liveContests)
	e.partials(2, liveContests)
	e.ok(http.MethodPost, "/api/live/tally-sig", e.tok(1), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(1)})
	fx3.chain.lose.Store("PublishTally")
	e.ok(http.MethodPost, "/api/live/tally-sig", e.tok(2), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(2)})
	fx3.chain.lose.Store("")
	if e.state() != LiveClosed {
		t.Fatalf("state %s with a lost receipt", e.state())
	}
	e2 := fx3.console()
	e2.s.live.waitBackground()
	if e2.state() != LiveVerified || fx3.ops.verifyCalls() != 1 {
		t.Fatalf("restart with the tally on the chain: %s, %d runs", e2.state(), fx3.ops.verifyCalls())
	}
}

// The presenter's threshold demonstration (POST /api/live/tally/publish) now
// that the trustees sign by themselves: from closed, before any partial
// combines and with no signature held, the console sends a tally no trustee
// signed (zero for every contest), and the chain refuses it at the threshold
// gate. Nothing changes; the chain holds no tally.
func TestLivePublishBeforeAnyTotalsIsRefusedAtThreshold(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveClosed)
	c.partials(1, liveContests) // one of two: nothing combines
	fx.ops.mu.Lock()
	fx.ops.combineFail = true
	fx.ops.mu.Unlock()
	before, _ := os.ReadFile(filepath.Join(fx.runs, runID, liveStateFile))
	receiptsBefore, _ := os.ReadFile(filepath.Join(fx.runs, runID, "receipts.csv"))
	submits := len(fx.chain.oracleChain.submits)
	code, out := c.do(http.MethodPost, "/api/live/tally/publish", "admin", nil)
	if code != http.StatusUnprocessableEntity || out["gate"] != "threshold" {
		t.Fatalf("publish before any totals: %d %v", code, out)
	}
	after, _ := os.ReadFile(filepath.Join(fx.runs, runID, liveStateFile))
	receiptsAfter, _ := os.ReadFile(filepath.Join(fx.runs, runID, "receipts.csv"))
	if !bytes.Equal(before, after) || !bytes.Equal(receiptsBefore, receiptsAfter) || c.state() != LiveClosed {
		t.Fatal("a refused publish changed the run")
	}
	// What was sent: one PublishTally, no signature, a zero for each contest.
	ch := fx.chain.oracleChain
	ch.mu.Lock()
	sent := ch.submits[submits:]
	_, onChain := ch.tally[runID]
	ch.mu.Unlock()
	if len(sent) != 1 || sent[0] != "PublishTally" || onChain {
		t.Fatalf("submits %v, tally on the chain %v", sent, onChain)
	}
	if last := fx.chain.lastTally(); len(last.Signatures) != 0 || !slices.Equal(last.Totals, []uint64{0, 0, 0, 0}) || last.ElectionId != runID {
		t.Fatalf("the tally sent: %+v", last)
	}
	// With a signature held, the demonstration sends it (as before).
	fx.ops.mu.Lock()
	fx.ops.combineFail = false
	fx.ops.mu.Unlock()
	c.partials(2, liveContests)
	c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(1), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(1)})
	if code, out := c.do(http.MethodPost, "/api/live/tally/publish", "admin", nil); code != http.StatusUnprocessableEntity || out["gate"] != "threshold" {
		t.Fatalf("publish with 1 of 2 signatures: %d %v", code, out)
	}
	if last := fx.chain.lastTally(); len(last.Signatures) != 1 {
		t.Fatalf("the tally sent with one signature held: %+v", last)
	}
	// After publication the route is refused in its state, never sent.
	c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(2), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(2)})
	c.s.live.waitBackground()
	submits = len(fx.chain.oracleChain.submits)
	if code, _ := c.do(http.MethodPost, "/api/live/tally/publish", "admin", nil); code != http.StatusConflict || len(fx.chain.oracleChain.submits) != submits {
		t.Fatalf("publish after publication: %d", code)
	}
}

// A chain that accepted the unsigned demonstration tally: the console says
// so, records nothing, and stays closed.
func TestLiveUnsignedPublishAcceptedIsNeverTheResult(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveClosed)
	fx.ops.mu.Lock()
	fx.ops.combineFail = true
	fx.ops.mu.Unlock()
	fx.chain.acceptTally.Store(true)
	before, _ := os.ReadFile(filepath.Join(fx.runs, runID, liveStateFile))
	code, out := c.do(http.MethodPost, "/api/live/tally/publish", "admin", nil)
	if code != http.StatusInternalServerError || out["code"] != "accepted-unsigned" {
		t.Fatalf("an accepted unsigned tally: %d %v", code, out)
	}
	after, _ := os.ReadFile(filepath.Join(fx.runs, runID, liveStateFile))
	if !bytes.Equal(before, after) || c.state() != LiveClosed {
		t.Fatal("an accepted unsigned tally was recorded")
	}
	if el := c.ok(http.MethodGet, "/api/live/election", "", nil); el["totals"] != nil || el["auto_verify"] != nil {
		t.Fatalf("view after an accepted unsigned tally: %v %v", el["totals"], el["auto_verify"])
	}
}

// A tally on the chain with fewer than threshold signatures (a chain without
// the threshold gate took the unsigned demonstration tally) is never adopted
// at a restart: the election stays closed and nothing is verified. A tally
// with threshold signatures still is.
func TestLiveRestartIgnoresAnUnderSignedTallyOnTheChain(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveClosed)
	fx.ops.mu.Lock()
	fx.ops.combineFail = true
	fx.ops.mu.Unlock()
	// The chain records whatever it is given (no gate).
	under := &pb.TallyResult{Version: 1, ElectionId: runID, Totals: []uint64{0, 0, 0, 0},
		Signatures: []*pb.TrusteeSignature{{TrusteeId: "1"}}}
	raw, _ := proto.Marshal(under)
	ch := fx.chain.oracleChain
	ch.mu.Lock()
	ch.tally[runID] = hex.EncodeToString(raw)
	ch.mu.Unlock()
	c2 := fx.console()
	c2.s.live.waitBackground()
	if c2.state() != LiveClosed || fx.ops.verifyCalls() != 0 {
		t.Fatalf("restart with an under-signed tally on the chain: %s, %d verify runs", c2.state(), fx.ops.verifyCalls())
	}
	if el := c2.ok(http.MethodGet, "/api/live/election", "", nil); el["totals"] != nil {
		t.Fatalf("the under-signed tally's totals are shown: %v", el["totals"])
	}
	// The trustees' signatures then meet it as a tally not taken.
	fx.ops.mu.Lock()
	fx.ops.combineFail = false
	fx.ops.mu.Unlock()
	c2.partials(1, liveContests)
	c2.partials(2, liveContests)
	c2.ok(http.MethodPost, "/api/live/tally-sig", c2.tok(1), map[string]any{"totals": []int{0, 0, 0, 0}, "signature": sig(1)})
	out := c2.ok(http.MethodPost, "/api/live/tally-sig", c2.tok(2), map[string]any{"totals": []int{0, 0, 0, 0}, "signature": sig(2)})
	if out["published"] != false || c2.state() != LiveClosed {
		t.Fatalf("signatures over the under-signed tally's totals: %v, state %s", out, c2.state())
	}
}
