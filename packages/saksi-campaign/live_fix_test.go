package campaign

import (
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"time"

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

// S2: private/checkin.json, the issuance record, holds no time, and neither
// a check-in nor an issuance moves live.json's updated_at.
func TestLiveIssuedRecordHoldsNoTime(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveCeremony)
	c.ceremony(runID)
	before := c.s.live.snapshot().UpdatedAt
	c.issue("voter1")
	c.issue("voter2")
	data, err := os.ReadFile(filepath.Join(fx.runs, runID, livePrivateDir, liveCheckinFile))
	if err != nil {
		t.Fatal(err)
	}
	var rec checkinRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("checkin.json: %v\n%s", err, data)
	}
	issued := 0
	for i, e := range rec.Entries {
		if e.State == CheckinIssued {
			issued++
			if i+1 != testSeqs["voter1"] && i+1 != testSeqs["voter2"] {
				t.Fatalf("entry %d issued: %s", i+1, data)
			}
		}
	}
	if issued != 2 {
		t.Fatalf("checkin.json: %d issued, want 2", issued)
	}
	// Cookie hashes are random hex; the rest must hold no date, clock time or
	// long number.
	scrub := regexp.MustCompile(`"[0-9a-f]{64}"`).ReplaceAll(data, []byte(`"h"`))
	timeLike := regexp.MustCompile(`\d{4}-\d{2}-\d{2}|\d{2}:\d{2}|\d{9,}`)
	if timeLike.Match(scrub) {
		t.Fatalf("checkin.json holds a time-like value: %s", data)
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

// S5: POST elections while the election is still in setup retries its
// CreateElection instead of answering 409.
func TestLiveCreateRetriesAStuckSetup(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	req := listBody(map[string]any{"title": "x", "positions": livePositions, "trustees": 3, "threshold": 2})
	fx.chain.down.Store(true)
	if code, _ := c.do(http.MethodPost, "/api/live/elections", "admin", req); code != http.StatusBadGateway {
		t.Fatalf("setup with the chain down: %d", code)
	}
	runID := c.s.live.snapshot().RunID
	if code, _ := c.do(http.MethodPost, "/api/live/elections", "admin", req); code != http.StatusBadGateway || c.state() != LiveSetup {
		t.Fatalf("retry with the chain still down: %d %s", code, c.state())
	}
	fx.chain.down.Store(false)
	code, out := c.do(http.MethodPost, "/api/live/elections", "admin", req)
	if code != http.StatusOK || out["run_id"] != runID || out["state"] != LiveCeremony {
		t.Fatalf("retry with the chain up: %d %v (want 200, %s, ceremony)", code, out, runID)
	}
	// Now a POST elections is the usual 409.
	if code, _ := c.do(http.MethodPost, "/api/live/elections", "admin", req); code != http.StatusConflict {
		t.Fatalf("POST elections in ceremony: %d", code)
	}
}

// S5: abandon is allowed in setup and ceremony only, is terminal and
// durable, never shows as tallied or verified, and lets a new election start
// on the same runs folder.
func TestLiveAbandon(t *testing.T) {
	// Refused before any setup and in every state from open on.
	fx := newLiveFixture(t)
	c := fx.console()
	if code, _ := c.do(http.MethodPost, "/api/live/abandon", "admin", nil); code != http.StatusNotFound {
		t.Fatalf("abandon with no election: %d", code)
	}
	for _, st := range []string{LiveOpen, LiveClosed, LiveTallied, LiveVerified} {
		fx := newLiveFixture(t)
		c := fx.console()
		c.toState(st)
		if code, _ := c.do(http.MethodPost, "/api/live/abandon", "admin", nil); code != http.StatusConflict || c.state() != st {
			t.Fatalf("abandon in %s: %d, state %s", st, code, c.state())
		}
	}
	// Admin only.
	fx = newLiveFixture(t)
	c = fx.console()
	c.toState(LiveCeremony)
	for _, who := range []string{"", "voter1", "t1", c.tok(1)} {
		if code, _ := c.do(http.MethodPost, "/api/live/abandon", who, nil); code != http.StatusUnauthorized && code != http.StatusForbidden {
			t.Fatalf("abandon as %q: %d", who, code)
		}
	}

	// In ceremony, part-way through: then trustee routes are 409 and the
	// roster names the state.
	runID := c.s.live.snapshot().RunID
	c.ok(http.MethodPost, "/api/live/dkg/receive-key", c.tok(1), map[string]any{"trustee_id": 1, "receive_public_key": pt(0x71)})
	out := c.ok(http.MethodPost, "/api/live/abandon", "admin", nil)
	if out["state"] != LiveAbandoned || c.state() != LiveAbandoned {
		t.Fatalf("abandon in ceremony: %v", out)
	}
	var disk liveState
	if err := readJSON(filepath.Join(fx.runs, runID, liveStateFile), &disk); err != nil || disk.State != LiveAbandoned {
		t.Fatalf("live.json after abandon: %s %v", disk.State, err)
	}
	if code, _ := c.do(http.MethodPost, "/api/live/dkg/receive-key", c.tok(2), map[string]any{"trustee_id": 2, "receive_public_key": pt(0x72)}); code != http.StatusConflict {
		t.Fatalf("receive-key after abandon: %d", code)
	}
	if r := c.ok(http.MethodGet, "/api/live/dkg/roster", c.tok(1), nil); r["state"] != LiveAbandoned {
		t.Fatalf("roster after abandon: %v", r)
	}
	if code, _ := c.do(http.MethodPost, "/api/live/abandon", "admin", nil); code != http.StatusConflict {
		t.Fatalf("abandon twice: %d", code)
	}
	board := c.ok(http.MethodGet, "/api/board/"+runID, "", nil)
	if board["verified"] != false || board["sealed"] != true || board["status"] != LiveAbandoned || len(board["files"].([]any)) != 0 {
		t.Fatalf("board of an abandoned run: verified %v sealed %v status %v files %v", board["verified"], board["sealed"], board["status"], board["files"])
	}

	// A restart while abandoned stays abandoned and touches no chain.
	submits := len(fx.chain.oracleChain.submits)
	c2 := fx.console()
	if c2.state() != LiveAbandoned || len(fx.chain.oracleChain.submits) != submits {
		t.Fatalf("restart while abandoned: %s, %d new submits", c2.state(), len(fx.chain.oracleChain.submits)-submits)
	}

	// A new election on the same runs folder, run to the end.
	next := c2.toState(LiveVerified)
	if next == runID || c2.state() != LiveVerified {
		t.Fatalf("new election after abandon: %s %s", next, c2.state())
	}
	// The abandoned run keeps its own board, still never verified.
	board = c2.ok(http.MethodGet, "/api/board/"+runID, "", nil)
	if board["verified"] != false || board["status"] != LiveAbandoned {
		t.Fatalf("abandoned run's board after the next election: %v %v", board["verified"], board["status"])
	}

	// Abandon in setup (CreateElection never went through).
	fx3 := newLiveFixture(t)
	c3 := fx3.console()
	fx3.chain.down.Store(true)
	c3.do(http.MethodPost, "/api/live/elections", "admin", listBody(map[string]any{"title": "x", "positions": livePositions, "trustees": 3, "threshold": 2}))
	c3.ok(http.MethodPost, "/api/live/abandon", "admin", nil)
	fx3.chain.down.Store(false)
	if c3.fx.console().state() != LiveAbandoned {
		t.Fatal("an election abandoned in setup was resumed on restart")
	}
}

// M2: a re-verify that fails while verified steps the state back to tallied,
// with the failed checks recorded; the board then shows no verified mark.
func TestLiveFailedReverifyStepsBackToTallied(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveVerified)
	fx.ops.mu.Lock()
	fx.ops.verify = "fail"
	fx.ops.mu.Unlock()
	out := c.ok(http.MethodPost, "/api/live/verify", "admin", nil)
	if out["overall"] != "fail" || out["state"] != LiveTallied || c.state() != LiveTallied {
		t.Fatalf("failed re-verify: %v, state %s", out, c.state())
	}
	board := c.ok(http.MethodGet, "/api/board/"+runID, "", nil)
	live := board["live"].(map[string]any)
	if board["verified"] != false || live["verify_overall"] != "fail" || live["failed_checks"].([]any)[0] != "tally.homomorphic_sum" {
		t.Fatalf("board after a failed re-verify: verified %v, %v", board["verified"], live)
	}
	// A passing verify brings it back.
	fx.ops.mu.Lock()
	fx.ops.verify = ""
	fx.ops.mu.Unlock()
	if out := c.ok(http.MethodPost, "/api/live/verify", "admin", nil); out["state"] != LiveVerified {
		t.Fatalf("verify after the fix: %v", out)
	}
}

// M4 and M8: if the check-in record cannot be written, the signature is
// withheld, the 500 names no path, and the entry may try again.
func TestLiveIssuedWriteFailureWithholdsTheSignature(t *testing.T) {
	logs := captureLog(t)
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveCeremony)
	c.ceremony(runID)
	priv := filepath.Join(fx.runs, runID, livePrivateDir)
	c.checkIn("voter1")
	c.ok(http.MethodPost, "/api/live/issue/presign", "phone:voter1", map[string]string{"blinded_commitment": pt(0x10)})
	if err := os.Chmod(priv, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(priv, 0o700) })
	code, out := c.do(http.MethodPost, "/api/live/issue/sign", "phone:voter1", map[string]string{"e_prime": pt(0x11)})
	os.Chmod(priv, 0o700)
	body := c.bodies[len(c.bodies)-1]
	if code != http.StatusInternalServerError || out["s_iss"] != nil || strings.Contains(body, pt(0x55)) {
		t.Fatalf("sign with checkin.json unwritable: %d %s", code, body)
	}
	if out["error"] != liveInternalError || strings.Contains(body, fx.runs) || strings.Contains(body, "private") {
		t.Fatalf("the 500 is not generic: %s", body)
	}
	for _, needle := range []string{"sessions/", "voter1", "Halimbawa", "Uno", "1990-01-01", "checkin.json"} {
		if strings.Contains(logs.String(), needle) {
			t.Fatalf("the log names %q: %s", needle, logs.String())
		}
	}
	if c.s.live.snapshot().Issued != 0 {
		t.Fatal("a withheld signature was counted")
	}
	if out := c.ok(http.MethodGet, "/api/live/checkin", "phone:voter1", nil); out["state"] != CheckinSigned {
		t.Fatalf("after the withheld signature: %v", out)
	}
	// Nothing was recorded, so the entry starts again.
	c.presignSign("voter1")
	data, _ := os.ReadFile(filepath.Join(priv, liveCheckinFile))
	var rec checkinRecord
	if json.Unmarshal(data, &rec) != nil || rec.Entries[testSeqs["voter1"]-1].State != CheckinIssued || c.s.live.snapshot().Issued != 1 {
		t.Fatalf("checkin.json after the retry: %s", data)
	}
}

// M4: at most liveMaxSessions open sessions (429), and a session older than
// liveSessionTTL is gone: it no longer counts, and sign over it is refused.
func TestLiveSessionCapAndTTL(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveCeremony)
	c.ceremony(runID)
	sessions := filepath.Join(fx.runs, runID, livePrivateDir, liveSessionsDir)
	var others []string
	for i := 0; i < liveMaxSessions; i++ {
		p := filepath.Join(sessions, fmt.Sprintf("%032x.json", i+1))
		if err := os.WriteFile(p, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		others = append(others, p)
	}
	c.checkIn("voter1")
	code, out := c.do(http.MethodPost, "/api/live/issue/presign", "phone:voter1", map[string]string{"blinded_commitment": pt(0x10)})
	if code != http.StatusTooManyRequests {
		t.Fatalf("presign with %d sessions open: %d %v", liveMaxSessions, code, out)
	}
	// Age them past the TTL: they stop counting and are removed.
	old := time.Now().Add(-liveSessionTTL - time.Minute)
	for _, p := range others {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	c.ok(http.MethodPost, "/api/live/issue/presign", "phone:voter1", map[string]string{"blinded_commitment": pt(0x10)})
	for _, p := range others {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a stale session file was kept: %s", filepath.Base(p))
		}
	}
	// voter1's own session expires before sign.
	c.s.live.now = func() time.Time { return time.Now().Add(liveSessionTTL + time.Minute) }
	code, out = c.do(http.MethodPost, "/api/live/issue/sign", "phone:voter1", map[string]string{"e_prime": pt(0x11)})
	c.s.live.now = time.Now
	if code != http.StatusConflict || !strings.Contains(out["error"].(string), "expired") {
		t.Fatalf("sign over an expired session: %d %v", code, out)
	}
	if c.s.live.snapshot().Issued != 0 {
		t.Fatal("an expired session was signed")
	}
	c.presignSign("voter1") // a fresh presign then works
}

// M4: the Go transcript check refuses the identity as the joint key or as
// any verification key, whatever the CLI said.
func TestLiveTranscriptCheckRefusesTheIdentity(t *testing.T) {
	st := &liveState{ElectionID: "e", Trustees: 2, Acks: map[string]liveAck{
		"1": {VerificationKey: pt(0xc1), JointPublicKey: pt(0xb1)},
		"2": {VerificationKey: pt(0xc2), JointPublicKey: pt(0xb1)},
	}}
	tr := func(joint, vk1, vk2 string) liveTranscript {
		var t liveTranscript
		t.ElectionID, t.JointPublicKey = "e", joint
		t.VerificationKeys = append(t.VerificationKeys,
			struct {
				TrusteeID       string `json:"trustee_id"`
				VerificationKey string `json:"verification_key"`
				Fingerprint     string `json:"fingerprint"`
			}{TrusteeID: "1", VerificationKey: vk1},
			struct {
				TrusteeID       string `json:"trustee_id"`
				VerificationKey string `json:"verification_key"`
				Fingerprint     string `json:"fingerprint"`
			}{TrusteeID: "2", VerificationKey: vk2})
		return t
	}
	if why := checkTranscript(st, tr(pt(0xb1), pt(0xc1), pt(0xc2))); why != "" {
		t.Fatalf("a good transcript was refused: %s", why)
	}
	if why := checkTranscript(st, tr(identityPoint, pt(0xc1), pt(0xc2))); !strings.Contains(why, "joint public key is the identity") {
		t.Fatalf("identity joint key: %q", why)
	}
	st.Acks["2"] = liveAck{VerificationKey: identityPoint, JointPublicKey: pt(0xb1)}
	if why := checkTranscript(st, tr(pt(0xb1), pt(0xc1), identityPoint)); !strings.Contains(why, "trustee 2's verification key is the identity") {
		t.Fatalf("identity verification key: %q", why)
	}
}

// M4: the phone's ballot POST, same-origin with no cookie, passes guard; a
// cross-origin one and a Host off the allowlist (including the right name
// without its port) do not.
func TestLiveBallotPostThroughGuard(t *testing.T) {
	fx := newLiveFixture(t)
	fx.allowHosts = []string{"example.com", "vote.example:8443"} // example.com: the helpers' own requests
	c := fx.console()
	runID := c.toState(LiveCeremony)
	c.ceremony(runID)
	c.issue("voter1")
	post := func(host, origin string, n byte) (int, string) {
		body, _ := json.Marshal(map[string]string{"ballot": fakeBallot(runID, "president", n, nil)})
		req := httptest.NewRequest(http.MethodPost, "/api/live/ballot", bytes.NewReader(body))
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		c.s.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, body := post("vote.example:8443", "https://vote.example:8443", 1); code != http.StatusOK {
		t.Fatalf("same-origin ballot with no cookie: %d %s", code, body)
	}
	if code, body := post("vote.example:8443", "https://evil.example", 2); code != http.StatusForbidden || !strings.Contains(body, "cross-origin") {
		t.Fatalf("cross-origin ballot: %d %s", code, body)
	}
	if code, body := post("vote.example", "https://vote.example", 3); code != http.StatusForbidden || !strings.Contains(body, "forbidden host") {
		t.Fatalf("Host without its port: %d %s", code, body)
	}
	if n := c.s.live.snapshot().Ballots; n != 1 {
		t.Fatalf("ballots recorded: %d, want 1", n)
	}
}

// The phone app is served from the console's own origin at /vote/, from
// <web-dir>/vote: public, behind the same guard, with .wasm as
// application/wasm.
func TestVoteAppIsServedFromTheWebDir(t *testing.T) {
	web := t.TempDir()
	vote := filepath.Join(web, "vote")
	if err := os.MkdirAll(filepath.Join(vote, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(vote, "index.html"), []byte("<title>vote</title>"), 0o644)
	wasm := []byte("\x00asm\x01\x00\x00\x00")
	os.WriteFile(filepath.Join(vote, "pkg", "saksi_live_bg.wasm"), wasm, 0o644)
	t.Setenv("SAKSI_WEB_DIR", web)
	fx := newLiveFixture(t)
	fx.allowHosts = []string{"vote.example:8443"}
	c := fx.console()
	get := func(host, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = host
		rec := httptest.NewRecorder()
		c.s.ServeHTTP(rec, req)
		return rec
	}
	if rec := get("vote.example:8443", "/vote/"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>vote</title>") {
		t.Fatalf("/vote/ with no session: %d %s", rec.Code, rec.Body)
	}
	rec := get("vote.example:8443", "/vote/pkg/saksi_live_bg.wasm")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/wasm" || !bytes.Equal(rec.Body.Bytes(), wasm) {
		t.Fatalf("wasm: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec := get("vote.example:8443", "/vote?x=1"); rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/vote/?x=1" {
		t.Fatalf("/vote: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get("evil.example", "/vote/"); rec.Code != http.StatusForbidden {
		t.Fatalf("/vote/ on a Host off the allowlist: %d", rec.Code)
	}
	if routeAccess["/vote/"] != accessPublic || routeAccess["/vote"] != accessPublic {
		t.Fatal("/vote/ is not public in routeAccess")
	}
}

// Final review 4, finding 1: the presenter presses Close while a phone's
// final issuance step is in flight. The entry is credential_issued on disk
// before the reply, so the reply must not wait on mu, which Close holds
// across a chain submit that can stall: a phone that timed out there could
// never be issued again. The count still reaches live.json, through Close's
// own save.
func TestLiveSignDoesNotWaitOnAStalledClose(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveOpen)
	c.checkIn("voter2") // voter1 was issued on the way to open
	c.ok(http.MethodPost, "/api/live/issue/presign", "phone:voter2", map[string]string{"blinded_commitment": pt(0x10)})

	entered, release := make(chan struct{}), make(chan struct{})
	hold := func(fn string) {
		if fn == "CloseElection" {
			close(entered)
			<-release
		}
	}
	fx.chain.before.Store(&hold)
	closed := make(chan error, 1)
	go func() {
		_, err := c.s.live.close()
		closed <- err
	}()
	<-entered // Close now holds mu across its submit

	signed := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		data, _ := json.Marshal(map[string]string{"e_prime": pt(0x11)})
		req := httptest.NewRequest(http.MethodPost, "/api/live/issue/sign", bytes.NewReader(data))
		req.AddCookie(&http.Cookie{Name: checkinCookie, Value: fx.phones["voter2"]})
		rec := httptest.NewRecorder()
		c.s.ServeHTTP(rec, req)
		signed <- rec
	}()
	var rec *httptest.ResponseRecorder
	select {
	case rec = <-signed:
	case <-time.After(5 * time.Second):
		close(release)
		<-closed
		t.Fatal("issue/sign waited on the state lock a stalled Close holds")
	}
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "s_iss") {
		t.Fatalf("sign during Close: %d %s", rec.Code, rec.Body)
	}
	// The public count shows the issuance while Close still holds mu.
	vrec := httptest.NewRecorder()
	c.s.ServeHTTP(vrec, httptest.NewRequest(http.MethodGet, "/api/live/election", nil))
	if !strings.Contains(vrec.Body.String(), `"credentials_issued":2`) {
		close(release)
		<-closed
		t.Fatalf("election view during Close: %s", vrec.Body)
	}
	close(release)
	if err := <-closed; err != nil {
		t.Fatalf("close: %v", err)
	}
	if c.state() != LiveClosed || c.s.live.snapshot().Issued != 2 {
		t.Fatalf("after close: %s, issued %d", c.state(), c.s.live.snapshot().Issued)
	}
	var st liveState
	if err := readJSON(filepath.Join(fx.runs, runID, liveStateFile), &st); err != nil || st.Issued != 2 {
		t.Fatalf("live.json after close: issued %d, %v", st.Issued, err)
	}
}

// Final review 4, finding 2: the election view and the board are public and
// polled. The chain count they show is read at most once per
// liveChainCountTTL, not once per GET, and it still comes from the chain.
func TestLiveChainCountIsCachedBriefly(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveOpen)
	now := time.Now()
	c.s.live.counts.mu.Lock()
	c.s.live.counts.now = func() time.Time { return now }
	c.s.live.counts.at = time.Time{} // start with no count cached
	c.s.live.counts.mu.Unlock()
	view := func() map[string]any {
		return c.ok(http.MethodGet, "/api/live/election", "", nil)["counts"].(map[string]any)
	}
	before := fx.chain.lists.Load()
	first := view()
	if first["ballot_records_source"] != "chain" {
		t.Fatalf("the count is not the chain's: %v", first)
	}
	for i := 0; i < 5; i++ {
		view()
		if code := rawGET(c.s, "/api/board/"+runID); code != http.StatusOK {
			t.Fatalf("board: %d", code)
		}
	}
	if n := fx.chain.lists.Load() - before; n != 1 {
		t.Fatalf("%d chain listings for 11 reads inside the cache window, want 1", n)
	}
	// A ballot lands; inside the window the old count stands, after it the
	// chain's new count shows.
	c.ok(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": fakeBallot(runID, "secretary", 9, nil)})
	if got := view()["ballot_records"]; got != first["ballot_records"] {
		t.Fatalf("inside the window: %v, want the cached %v", got, first["ballot_records"])
	}
	now = now.Add(liveChainCountTTL)
	if got := view()["ballot_records"].(float64); got != first["ballot_records"].(float64)+1 {
		t.Fatalf("after the window: %v, want %v + 1", got, first["ballot_records"])
	}
	if n := fx.chain.lists.Load() - before; n != 2 {
		t.Fatalf("%d chain listings, want 2", n)
	}
}

// Final review 4, finding 2 (and fix round 1, minor 1): GET /api/live/ledger
// reads every ballot and partial from the chain, so it is rate limited, by a
// bucket of its own: an empty ledger bucket leaves the ballots' alone.
func TestLiveLedgerIsRateLimited(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveOpen)
	now := time.Now()
	l := newRateLimiter(5, 2)
	l.now = func() time.Time { return now }
	c.s.live.ledgerLimit = l
	ballots := newRateLimiter(5, 1)
	ballots.now = func() time.Time { return now }
	c.s.live.limit = ballots
	for i := 0; i < 2; i++ {
		if code := rawGET(c.s, "/api/live/ledger"); code != http.StatusOK {
			t.Fatalf("ledger read %d: %d", i+1, code)
		}
	}
	if code := rawGET(c.s, "/api/live/ledger"); code != http.StatusTooManyRequests {
		t.Fatalf("ledger read past the burst: %d, want 429", code)
	}
	// The ledger's bucket is empty; the ballots' one token is still there.
	c.ok(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": fakeBallot(runID, "secretary", 9, nil)})
	now = now.Add(time.Second)
	if code := rawGET(c.s, "/api/live/ledger"); code != http.StatusOK {
		t.Fatalf("ledger read after a second: %d", code)
	}
}

// Final review 4, finding 4: if the CSV row cannot be written after the
// ndjson line was, the line is cut back, so the next ballot's index names the
// same line in both files.
func TestLiveBallotFilesStayInStepAfterAFailedWrite(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveOpen)
	dir := filepath.Join(fx.runs, runID)
	csvPath := filepath.Join(dir, BallotsCSV)
	if err := os.Chmod(csvPath, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(csvPath, 0o644) })
	if code, _ := c.do(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": fakeBallot(runID, "secretary", 7, nil)}); code == http.StatusOK {
		t.Fatal("the ballot was recorded with ballots.csv unwritable")
	}
	if err := os.Chmod(csvPath, 0o644); err != nil {
		t.Fatal(err)
	}
	c.ok(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": fakeBallot(runID, "secretary", 8, nil)})

	nd, err := os.ReadFile(filepath.Join(dir, BallotsFile))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(nd), "\n"), "\n")
	cf, err := os.Open(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(cf).ReadAll()
	cf.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows)-1 != len(lines) {
		t.Fatalf("%d ndjson lines, %d CSV rows", len(lines), len(rows)-1)
	}
	idx := columnIndex(rows[0])
	for i, r := range rows[1:] {
		raw, _ := hex.DecodeString(lines[i])
		if field(r, idx, "index") != fmt.Sprint(i) || field(r, idx, "ballot_sha256") != sha256Hex(raw) {
			t.Fatalf("row %d (index %s) does not match ndjson line %d", i, field(r, idx, "index"), i)
		}
	}
	if st := c.s.live.snapshot(); st.Ballots != len(lines) {
		t.Fatalf("live count %d, %d lines", st.Ballots, len(lines))
	}
}

// Final review 4, finding 5: the live console and the trustee processes get
// read and idle timeouts; no write timeout (it would cut /events); a study
// serve keeps Go's defaults, as before.
func TestLiveServerTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    ServeOptions
		live bool
	}{
		{"study", ServeOptions{Addr: "127.0.0.1:8090"}, false},
		{"study with auth", ServeOptions{Addr: "127.0.0.1:8090", AuthFile: "u"}, false},
		{"live", ServeOptions{Addr: "127.0.0.1:8090", Live: true, AuthFile: "u"}, true},
		{"trustee", ServeOptions{Addr: "127.0.0.1:9001", Trustee: true}, true},
	} {
		srv := serverFor(tc.o, http.NotFoundHandler())
		if srv.WriteTimeout != 0 || srv.ReadHeaderTimeout != 10*time.Second {
			t.Fatalf("%s: write %v, header %v", tc.name, srv.WriteTimeout, srv.ReadHeaderTimeout)
		}
		read, idle := time.Duration(0), time.Duration(0)
		if tc.live {
			read, idle = 30*time.Second, 120*time.Second
		}
		if srv.ReadTimeout != read || srv.IdleTimeout != idle {
			t.Fatalf("%s: read %v idle %v, want %v %v", tc.name, srv.ReadTimeout, srv.IdleTimeout, read, idle)
		}
	}
}

// Final review 4, deferred: the console runs verify-live itself, so the
// board's check does not call it independent.
func TestLiveBoardVerifierCheckIsNotCalledIndependent(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveVerified)
	board := c.ok(http.MethodGet, "/api/board/"+runID, "", nil)
	found := false
	for _, x := range board["checks"].([]any) {
		name := x.(map[string]any)["name"].(string)
		if strings.Contains(name, "independent") {
			t.Fatalf("board check %q", name)
		}
		if name == "The verifier (verify-live) passed the on-chain record" {
			found = x.(map[string]any)["pass"] == true
		}
	}
	if !found {
		t.Fatalf("no passing verify-live check: %v", board["checks"])
	}
}

// Fix round 1, Important 1: a chain read that stalls (a partitioned peer)
// must not queue the public reads behind it. Callers that find a read in
// flight return at once: -1 (the console's count) before any read finished,
// the last count after one; only one read is in flight at a time.
func TestLiveChainCountNeverWaitsOnAStalledRead(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveOpen)
	now := time.Now()
	var clockMu sync.Mutex
	clock := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }
	advance := func() { clockMu.Lock(); now = now.Add(liveChainCountTTL); clockMu.Unlock() }
	c.s.live.counts.mu.Lock()
	c.s.live.counts.now = clock
	c.s.live.counts.at = time.Time{}
	c.s.live.counts.mu.Unlock()
	electionID := c.s.live.snapshot().ElectionID

	stall := func(want int) {
		t.Helper()
		gate := make(chan struct{})
		fx.chain.listGate.Store(&gate)
		first := make(chan int, 1)
		go func() { first <- c.s.live.chainCount(electionID) }()
		deadline := time.Now().Add(5 * time.Second)
		for fx.chain.listing.Load() != 1 {
			if time.Now().After(deadline) {
				t.Fatal("the first read never reached the chain")
			}
			time.Sleep(5 * time.Millisecond)
		}
		const callers = 8
		got := make(chan int, callers)
		start := time.Now()
		var wg sync.WaitGroup
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got <- c.s.live.chainCount(electionID)
			}()
		}
		// The public routes too: a view and a board answer while it stalls.
		wg.Add(1)
		go func() {
			defer wg.Done()
			if code := rawGET(c.s, "/api/live/election"); code != http.StatusOK {
				t.Errorf("election view during a stalled read: %d", code)
			}
			if code := rawGET(c.s, "/api/board/"+runID); code != http.StatusOK {
				t.Errorf("board during a stalled read: %d", code)
			}
		}()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			fx.chain.listGate.Store(nil)
			close(gate)
			<-done
			t.Fatalf("callers waited %v on a stalled read", time.Since(start))
		}
		close(got)
		for n := range got {
			if n != want {
				t.Fatalf("a caller during the stalled read got %d, want %d", n, want)
			}
		}
		if n := fx.chain.listing.Load(); n != 1 {
			t.Fatalf("%d chain reads in flight, want 1", n)
		}
		fx.chain.listGate.Store(nil)
		close(gate)
		if n := <-first; n < 0 {
			t.Fatalf("the stalled read, once released: %d", n)
		}
	}

	stall(-1) // no count yet: the views fall back to the console's count
	c.s.live.counts.mu.Lock()
	last, at := c.s.live.counts.n, c.s.live.counts.at
	c.s.live.counts.mu.Unlock()
	if !at.Equal(clock()) {
		t.Fatalf("stamped %v, want the finish time %v", at, clock())
	}
	advance() // the count expires; the next read stalls again
	stall(last)
}
