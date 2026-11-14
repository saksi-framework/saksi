package campaign

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// Tests added by the task 3 review's fix round (S1 to S6, M2, M4, M8 and the
// /vote/ mount). The fixtures are live_test.go's.

// rawGET is a request the pollers can make from any goroutine: it touches
// none of liveConsole's own bookkeeping.
func rawGET(s *Server, path string) int {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "192.0.2.9:52000"
	s.ServeHTTP(rec, req)
	return rec.Code
}

// S1: the board and the election view are read while trustees post partials
// and signatures. Before the snapshot, the board iterated the live maps after
// releasing mu, which the race detector (and, on a bad day, the runtime)
// reports as a concurrent map read and write. Run with -race.
func TestLiveBoardAndViewReadWhileTrusteesPost(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveClosed)

	stop := make(chan struct{})
	var polls atomic.Int64
	var bad atomic.Value
	var wg sync.WaitGroup
	for _, path := range []string{"/api/board/" + runID, "/api/live/election", "/api/board/" + runID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if code := rawGET(c.s, path); code != http.StatusOK {
					bad.Store(fmt.Sprintf("%s: %d", path, code))
				}
				polls.Add(1)
			}
		}()
	}
	for id := 1; id <= 3; id++ {
		c.partials(id, liveContests)
	}
	c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(1), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(1)})
	c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(2), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(2)})
	close(stop)
	wg.Wait()
	if v := bad.Load(); v != nil {
		t.Fatalf("a poll failed: %v", v)
	}
	if polls.Load() == 0 {
		t.Fatal("the pollers never ran")
	}
	if c.state() != LiveTallied {
		t.Fatalf("state %s, want tallied", c.state())
	}
	board := c.ok(http.MethodGet, "/api/board/"+runID, "", nil)
	dec := board["live"].(map[string]any)["decryption"].(map[string]any)
	if dec["trustees_decrypted"].(float64) != 3 || len(dec["tally_signatures"].([]any)) != 2 {
		t.Fatalf("board decryption after the posts: %v", dec)
	}
}

// S6: the board and the election view answer while a transition holds mu
// (as one does across a stalled chain submit).
func TestLiveBoardAndViewDoNotWaitOnTheStateLock(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveOpen)
	c.s.live.mu.Lock()
	done := make(chan []int)
	go func() {
		done <- []int{rawGET(c.s, "/api/board/"+runID), rawGET(c.s, "/api/live/election")}
	}()
	codes := <-done // would deadlock (and time out) if either waited on mu
	c.s.live.mu.Unlock()
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK {
		t.Fatalf("board and view while mu is held: %v", codes)
	}
}

// S2: private/issued.json is a set of account names with no time in it, and
// an issuance does not move live.json's updated_at.
func TestLiveIssuedRecordHoldsNoTime(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveCeremony)
	c.ceremony(runID)
	before := c.s.live.snapshot().UpdatedAt
	c.issue("voter1")
	c.issue("voter2")
	data, err := os.ReadFile(filepath.Join(fx.runs, runID, livePrivateDir, liveIssuedFile))
	if err != nil {
		t.Fatal(err)
	}
	var set map[string]bool
	if err := json.Unmarshal(data, &set); err != nil {
		t.Fatalf("issued.json is not a set of names: %v\n%s", err, data)
	}
	if len(set) != 2 || !set["voter1"] || !set["voter2"] {
		t.Fatalf("issued.json: %s", data)
	}
	timeLike := regexp.MustCompile(`\d{4}-\d{2}-\d{2}|\d{2}:\d{2}|\d{9,}`)
	if timeLike.Match(data) {
		t.Fatalf("issued.json holds a time-like value: %s", data)
	}
	if after := c.s.live.snapshot().UpdatedAt; !after.Equal(before) {
		t.Fatalf("an issuance moved updated_at from %v to %v", before, after)
	}
	var st liveState
	if err := readJSON(filepath.Join(fx.runs, runID, liveStateFile), &st); err != nil || st.Issued != 2 || !st.UpdatedAt.Equal(before) {
		t.Fatalf("live.json after two issuances: issued %d, updated_at %v (want %v), %v", st.Issued, st.UpdatedAt, before, err)
	}
}

// S3: a partial whose commit the console never learned of. The trustee's
// retry meets the chain's partial-duplicate gate; a byte-equal partial on the
// chain is recorded and answered 200, a different one is 409.
func TestLivePartialAlreadyOnTheChain(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveClosed)

	// Trustee 1: every commit lands, every receipt is lost.
	fx.chain.lose.Store("SubmitPartialDecryption")
	var ps []map[string]string
	for _, ct := range liveContests {
		ps = append(ps, map[string]string{"contest_id": ct, "partial": fakePartial("1", ct)})
	}
	if code, out := c.do(http.MethodPost, "/api/live/partial", c.tok(1), map[string]any{"partials": ps}); code != http.StatusBadGateway {
		t.Fatalf("partials with lost receipts: %d %v", code, out)
	}
	fx.chain.lose.Store("")
	if n := len(c.s.live.snapshot().Decrypted); n != 0 {
		t.Fatalf("decrypted before the retry: %d", n)
	}
	out := c.ok(http.MethodPost, "/api/live/partial", c.tok(1), map[string]any{"partials": ps})
	for _, r := range out["recorded"].([]any) {
		if r.(map[string]any)["already_on_chain"] != true {
			t.Fatalf("retry: %v", out)
		}
	}
	if out["trustees_decrypted"].(float64) != 1 {
		t.Fatalf("retry counted %v trustees", out["trustees_decrypted"])
	}

	// Trustee 2: the chain holds a different partial for one contest.
	other := fakePartial("2", liveContests[0])
	raw, _ := hex.DecodeString(other)
	raw = append(raw, 0xa0, 0x06, 0x01) // an unknown field: same trustee and contest, other bytes
	if _, err := fx.chain.oracleChain.Submit("SubmitPartialDecryption", runID, hex.EncodeToString(raw)); err != nil {
		t.Fatal(err)
	}
	code, res := c.do(http.MethodPost, "/api/live/partial", c.tok(2), map[string]any{"partials": []map[string]string{
		{"contest_id": liveContests[0], "partial": other}}})
	if code != http.StatusConflict || !strings.Contains(res["error"].(string), "different partial") || !strings.Contains(res["error"].(string), liveContests[0]) {
		t.Fatalf("a different partial on the chain: %d %v", code, res)
	}
}

// S3: a restart from closed onward takes the chain's partials into the count.
func TestLiveRestartFillsPartialsFromTheChain(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveClosed)
	for _, ct := range liveContests {
		if _, err := fx.chain.oracleChain.Submit("SubmitPartialDecryption", runID, fakePartial("2", ct)); err != nil {
			t.Fatal(err)
		}
	}
	c2 := fx.console()
	if got := c2.s.live.snapshot().Decrypted; len(got) != 1 || got[0] != 2 {
		t.Fatalf("decrypted after restart: %v", got)
	}
	board := c2.ok(http.MethodGet, "/api/board/"+runID, "", nil)
	if board["live"].(map[string]any)["decryption"].(map[string]any)["trustees_decrypted"].(float64) != 1 {
		t.Fatalf("board after restart: %v", board["live"])
	}
	// The trustee's own retry is then answered from the record.
	var ps []map[string]string
	for _, ct := range liveContests {
		ps = append(ps, map[string]string{"contest_id": ct, "partial": fakePartial("2", ct)})
	}
	c2.ok(http.MethodPost, "/api/live/partial", c2.tok(2), map[string]any{"partials": ps})
}

// S3, the same failure shape for the tally: PublishTally committed but its
// receipt was lost. The next publication meets "already published" and adopts
// the chain's tally when its totals are the ones held; other totals are 409.
func TestLiveTallyAlreadyOnTheChain(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	c.toState(LiveClosed)
	c.partials(1, liveContests)
	c.partials(2, liveContests)
	c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(1), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(1)})
	fx.chain.lose.Store("PublishTally")
	out := c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(2), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(2)})
	fx.chain.lose.Store("")
	if out["published"] != false || c.state() != LiveClosed {
		t.Fatalf("auto-publish with a lost receipt: %v, state %s", out, c.state())
	}
	pub := c.ok(http.MethodPost, "/api/live/tally/publish", "admin", nil)
	if pub["already_on_chain"] != true || c.state() != LiveTallied {
		t.Fatalf("publish after a lost receipt: %v, state %s", pub, c.state())
	}

	// Other totals on the chain than the signatures carry.
	fx2 := newLiveFixture(t)
	d := fx2.console()
	runID := d.toState(LiveClosed)
	d.partials(1, liveContests)
	d.partials(2, liveContests)
	d.ok(http.MethodPost, "/api/live/tally-sig", d.tok(1), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(1)})
	foreign := &pb.TallyResult{Version: 1, ElectionId: runID, Totals: []uint64{9, 9, 9, 9},
		Signatures: []*pb.TrusteeSignature{{TrusteeId: "1"}, {TrusteeId: "2"}}}
	raw, _ := proto.Marshal(foreign)
	if _, err := fx2.chain.oracleChain.Submit("PublishTally", hex.EncodeToString(raw)); err != nil {
		t.Fatal(err)
	}
	code, res := d.do(http.MethodPost, "/api/live/tally/publish", "admin", nil)
	if code != http.StatusConflict || !strings.Contains(res["error"].(string), "different tally") || d.state() != LiveClosed {
		t.Fatalf("other totals on the chain: %d %v, state %s", code, res, d.state())
	}
}

// S4: a ballot naming another election is refused with a stable code before
// it reaches the chain, and nothing is filed. A record that does not decode
// is still relayed unchanged, so the chain's own gate answers it.
func TestLiveBallotForAnotherElectionIsNotRelayed(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveOpen)
	// Another open election on the same channel.
	other, _ := proto.Marshal(&pb.ElectionParameters{Version: 1, ElectionId: "study-other"})
	if _, err := fx.chain.oracleChain.Submit("CreateElection", hex.EncodeToString(other)); err != nil {
		t.Fatal(err)
	}
	submits := len(fx.chain.oracleChain.submits)
	csvBefore, _ := os.ReadFile(filepath.Join(fx.runs, runID, BallotsCSV))
	code, out := c.do(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": fakeBallot("study-other", "president", 7, nil)})
	if code != http.StatusBadRequest || out["code"] != "wrong-election" {
		t.Fatalf("a ballot for another election: %d %v", code, out)
	}
	if len(fx.chain.oracleChain.submits) != submits {
		t.Fatal("a ballot for another election was submitted")
	}
	csvAfter, _ := os.ReadFile(filepath.Join(fx.runs, runID, BallotsCSV))
	if !bytes.Equal(csvBefore, csvAfter) || c.s.live.snapshot().Ballots != 1 {
		t.Fatal("a ballot for another election was filed in this run")
	}

	// Bytes that are not a Ballot go to the chain exactly as posted.
	junk := "ffff"
	code, out = c.do(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": junk})
	if code != http.StatusUnprocessableEntity || out["gate"] != "decode" {
		t.Fatalf("an undecodable record: %d %v", code, out)
	}
	last := fx.chain.oracleChain.bytesIn[len(fx.chain.oracleChain.bytesIn)-1]
	if hex.EncodeToString(last) != junk {
		t.Fatalf("the chain got %x, not the posted bytes", last)
	}
}
