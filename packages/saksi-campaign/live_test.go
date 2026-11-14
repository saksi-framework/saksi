package campaign

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// Unit tests of live mode with a fake `saksi-demo live` runner and the
// in-memory stand-in chain (live_e2e_test.go). The real-binary and
// real-Fabric runs are in live_e2e_test.go.

const fakeIssuerSecret = "5ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e75ec7e700"

// fakeOps is a fake LiveRunner: canned outputs shaped as the wire format's,
// key and session files written and claimed as the CLI does.
type fakeOps struct {
	mu          sync.Mutex
	calls       []string
	inFlight    int
	maxInFlight map[string]int
	slow        time.Duration // each issuance op sleeps this long
	signed      []string      // the nonce each issue-sign consumed
	nonce       int
	verify      string // verify-live overall; "" = pass
}

func newFakeOps() *fakeOps { return &fakeOps{maxInFlight: map[string]int{}} }

func pt(i int) string { return fmt.Sprintf("%064x", i) }

func (f *fakeOps) run(_ context.Context, op string, input []byte) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, op)
	f.inFlight++
	if f.inFlight > f.maxInFlight["all"] {
		f.maxInFlight["all"] = f.inFlight
	}
	slow := f.slow
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.inFlight--; f.mu.Unlock() }()

	var in map[string]any
	_ = json.Unmarshal(input, &in)
	out := map[string]any{}
	switch op {
	case "issuer-keygen":
		data, _ := json.Marshal(map[string]string{"kind": "saksi-live-issuer-key-v1", "secret": fakeIssuerSecret, "public_key": pt(0xa1)})
		fh, err := os.OpenFile(in["key_file"].(string), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, &liveOpError{op, err.Error()}
		}
		fh.Write(data)
		fh.Close()
		out["public_key"] = pt(0xa1)
	case "election-params":
		var contests []string
		for _, p := range in["positions"].([]any) {
			pm := p.(map[string]any)
			for _, c := range pm["candidates"].([]any) {
				contests = append(contests, pm["id"].(string)+"/"+c.(string))
			}
		}
		if len(contests) == 0 {
			return nil, &liveOpError{op, "the election has no positions"}
		}
		n := int(in["trustees"].(float64))
		var ids []string
		for i := 1; i <= n; i++ {
			ids = append(ids, fmt.Sprint(i))
		}
		ik, _ := hex.DecodeString(in["issuer_public_key"].(string))
		raw, _ := proto.Marshal(&pb.ElectionParameters{Version: 1, ElectionId: in["election_id"].(string),
			ContestIds: contests, TrusteeIds: ids, Threshold: uint32(in["threshold"].(float64)), IssuerPublicKey: ik})
		out = map[string]any{"params": hex.EncodeToString(raw), "election_id": in["election_id"], "contest_ids": contests,
			"trustee_ids": ids, "threshold": in["threshold"]}
	case "dkg-roster":
		seen := map[string]bool{}
		for _, p := range in["peers"].([]any) {
			k := p.(map[string]any)["receive_public_key"].(string)
			if seen[k] {
				return nil, &liveOpError{op, "peer receive_public_key repeats another trustee's key"}
			}
			seen[k] = true
		}
		out = map[string]any{"peers": in["peers"], "roster_digest": pt(0xd1), "roster_fingerprint": "D1D1-D1D1-D1D1-D1D1-D1D1-D1D1-D1D1-D1D1"}
	case "dkg-transcript":
		var vks []map[string]string
		for i := range in["dealers"].([]any) {
			vks = append(vks, map[string]string{"trustee_id": fmt.Sprint(i + 1), "verification_key": pt(0xc0 + i + 1), "fingerprint": "F"})
		}
		raw, _ := proto.Marshal(&pb.DKGTranscript{Version: 1, ElectionId: electionOfParams(in["params"].(string))})
		out = map[string]any{"dkg": hex.EncodeToString(raw), "election_id": electionOfParams(in["params"].(string)),
			"joint_public_key": pt(0xb1), "joint_key_fingerprint": "B1B1-B1B1-B1B1-B1B1-B1B1-B1B1-B1B1-B1B1", "verification_keys": vks}
	case "issue-presign":
		time.Sleep(slow)
		f.mu.Lock()
		f.nonce++
		n := f.nonce
		f.mu.Unlock()
		fh, err := os.OpenFile(in["session_file"].(string), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, &liveOpError{op, "session file already exists; refusing to overwrite a secret file"}
		}
		fmt.Fprintf(fh, `{"k":"nonce-%d"}`, n)
		fh.Close()
		out["r"] = pt(0xe0 + n)
	case "issue-sign":
		time.Sleep(slow)
		path := in["session_file"].(string)
		claimed := path + ".claimed.0123"
		if err := os.Rename(path, claimed); err != nil {
			return nil, &liveOpError{op, "session is already used or missing; not signing"}
		}
		data, _ := os.ReadFile(claimed)
		os.Remove(claimed)
		f.mu.Lock()
		f.signed = append(f.signed, string(data))
		f.mu.Unlock()
		out["s_iss"] = pt(0x55)
	case "combine":
		out["totals"] = []uint64{1, 0, 0, 1}
	case "tally-assemble":
		for _, sg := range in["signatures"].([]any) {
			if sg.(map[string]any)["signature"] == strings.Repeat("ba", 64) {
				return nil, &liveOpError{op, "tally signature from trustee does not verify"}
			}
		}
		totals := []uint64{}
		for _, t := range in["totals"].([]any) {
			totals = append(totals, uint64(t.(float64)))
		}
		tr := &pb.TallyResult{Version: 1, ElectionId: electionOfParams(in["params"].(string)), Totals: totals}
		for _, sg := range in["signatures"].([]any) {
			tr.Signatures = append(tr.Signatures, &pb.TrusteeSignature{TrusteeId: sg.(map[string]any)["trustee_id"].(string)})
		}
		raw, _ := proto.Marshal(tr)
		out = map[string]any{"tally": hex.EncodeToString(raw), "totals": totals, "signatures": len(tr.Signatures)}
	case "verify-live":
		f.mu.Lock()
		v := f.verify
		f.mu.Unlock()
		if v == "" {
			v = "pass"
		}
		out = map[string]any{"overall": v, "failed_checks": []any{}}
		if v != "pass" {
			out["failed_checks"] = []any{map[string]string{"check": "tally.homomorphic_sum", "detail": "x"}}
		}
	default:
		return nil, &liveOpError{op, "the fake has no such op"}
	}
	return json.Marshal(out)
}

func electionOfParams(h string) string {
	raw, _ := hex.DecodeString(h)
	var p pb.ElectionParameters
	_ = proto.Unmarshal(raw, &p)
	return p.ElectionId
}

// flakyChain is a chain that can be taken down, or made to lose the receipt
// of a transaction that did commit (a commit-status wait that times out).
type flakyChain struct {
	*oracleChain
	down atomic.Bool
	lose atomic.Value // fn whose receipts are lost after the commit
}

func (c *flakyChain) Submit(fn string, args ...string) (clientsdk.Receipt, error) {
	if c.down.Load() {
		return clientsdk.Receipt{}, errors.New("dial tcp: connection refused")
	}
	rc, err := c.oracleChain.Submit(fn, args...)
	if lost, _ := c.lose.Load().(string); err == nil && lost == fn {
		return clientsdk.Receipt{}, errors.New("rpc error: code = DeadlineExceeded desc = waiting for the commit status timed out")
	}
	return rc, err
}

// liveFixture is the files and fakes a live console runs over, kept across
// restarts.
type liveFixture struct {
	t       *testing.T
	runs    string
	users   string
	tokFile string
	tokens  []string
	ops     *fakeOps
	chain   *flakyChain
	// allowHosts is the console's --allow-host list (none: guard skips Host).
	allowHosts []string
}

func newLiveFixture(t *testing.T) *liveFixture {
	t.Helper()
	fx := &liveFixture{t: t, runs: t.TempDir(), ops: newFakeOps(),
		chain: &flakyChain{oracleChain: newOracleChain(t, "")}}
	dir := t.TempDir()
	h := fixtureHashes()["admin-pw"]
	users := []User{
		{Username: "admin", Role: RoleAdmin, PasswordBcrypt: h},
		{Username: "t1", Role: RoleTrustee, TrusteeID: "1", PasswordBcrypt: h},
		{Username: "voter1", Role: RoleVoter, PasswordBcrypt: h},
		{Username: "voter2", Role: RoleVoter, PasswordBcrypt: h},
		{Username: "voter3", Role: RoleVoter, PasswordBcrypt: h},
	}
	data, _ := json.Marshal(users)
	fx.users = filepath.Join(dir, "users.json")
	os.WriteFile(fx.users, data, 0o600)
	var entries []TrusteeToken
	for i := 1; i <= 3; i++ {
		tok, _ := NewTrusteeToken()
		fx.tokens = append(fx.tokens, tok)
		sum, _ := HashTrusteeToken(strings.NewReader(tok))
		entries = append(entries, TrusteeToken{TrusteeID: fmt.Sprint(i), TokenSHA256: sum})
	}
	data, _ = json.Marshal(entries)
	fx.tokFile = filepath.Join(dir, "tokens.json")
	os.WriteFile(fx.tokFile, data, 0o600)
	return fx
}

// console starts a console over the fixture: a restart is a second call.
func (fx *liveFixture) console() *liveConsole {
	fx.t.Helper()
	store := NewRunStore(fx.runs)
	hub := NewHub()
	exec := NewExecutor(store, hub, "saksi-demo", "", FabricConfig{})
	s := NewServer(store, exec, hub, FabricConfig{}, fx.allowHosts, time.Minute)
	if err := s.EnableAuth(fx.users); err != nil {
		fx.t.Fatal(err)
	}
	if err := s.EnableLive(LiveOptions{TrusteeTokens: fx.tokFile, Runner: fx.ops.run,
		Dial: func() (liveChain, error) { return fx.chain, nil }}); err != nil {
		fx.t.Fatal(err)
	}
	return &liveConsole{t: fx.t, s: s, fx: fx, sessions: map[string]string{}}
}

type liveConsole struct {
	t        *testing.T
	s        *Server
	fx       *liveFixture
	sessions map[string]string
	bodies   []string
}

// do sends a request as who ("" = anonymous, "tN" bearer = trustee token N).
func (c *liveConsole) do(method, path, who string, body any) (int, map[string]any) {
	c.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		switch b := body.(type) {
		case []byte:
			rd = bytes.NewReader(b)
		default:
			data, _ := json.Marshal(body)
			rd = bytes.NewReader(data)
		}
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "192.0.2.7:51000"
	switch {
	case strings.HasPrefix(who, "bearer:"):
		req.Header.Set("Authorization", "Bearer "+strings.TrimPrefix(who, "bearer:"))
	case who != "":
		tok, ok := c.sessions[who]
		if !ok {
			var err error
			if tok, err = c.s.auth.create(c.s.auth.users[who]); err != nil {
				c.t.Fatal(err)
			}
			c.sessions[who] = tok
		}
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	}
	rec := httptest.NewRecorder()
	c.s.ServeHTTP(rec, req)
	c.bodies = append(c.bodies, rec.Body.String())
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (c *liveConsole) ok(method, path, who string, body any) map[string]any {
	c.t.Helper()
	code, out := c.do(method, path, who, body)
	if code/100 != 2 {
		c.t.Fatalf("%s %s as %q: %d %v", method, path, who, code, out)
	}
	return out
}

func (c *liveConsole) tok(id int) string { return "bearer:" + c.fx.tokens[id-1] }

func (c *liveConsole) state() string {
	c.s.live.mu.Lock()
	defer c.s.live.mu.Unlock()
	if c.s.live.st == nil {
		return ""
	}
	return c.s.live.st.State
}

var livePositions = []map[string]any{
	{"id": "president", "candidates": []string{"alice", "bob"}},
	{"id": "secretary", "candidates": []string{"dan", "eve"}},
}

func (c *liveConsole) setup() string {
	out := c.ok(http.MethodPost, "/api/live/elections", "admin", map[string]any{
		"title": "Test", "positions": livePositions, "trustees": 3, "threshold": 2})
	return out["run_id"].(string)
}

func fakeDeal(electionID string, id, n int) map[string]any {
	var shares []map[string]any
	for k := 1; k <= n; k++ {
		shares = append(shares, map[string]any{"dealer_id": id, "recipient_id": k,
			"nonce": pt(id*100 + k), "ciphertext": pt(id*1000 + k), "tag": pt(id*10000 + k)})
	}
	return map[string]any{"election_id": electionID, "dealer_id": id,
		"commitments": []string{pt(id*10 + 1), pt(id*10 + 2)}, "masked_shares": shares,
		"roster_digest": pt(0xd1), "roster_fingerprint": "x"}
}

func fakeAck(electionID string, id int) map[string]any {
	return map[string]any{"election_id": electionID, "trustee_id": id,
		"verification_key": pt(0xc0 + id), "fingerprint": "F", "joint_public_key": pt(0xb1),
		"joint_key_fingerprint": "B1", "roster_digest": pt(0xd1), "roster_fingerprint": "x"}
}

func (c *liveConsole) ceremony(electionID string) {
	for id := 1; id <= 3; id++ {
		c.ok(http.MethodPost, "/api/live/dkg/receive-key", c.tok(id), map[string]any{"trustee_id": id, "receive_public_key": pt(0x70 + id)})
	}
	for id := 1; id <= 3; id++ {
		c.ok(http.MethodPost, "/api/live/dkg/deal", c.tok(id), fakeDeal(electionID, id, 3))
	}
	for id := 1; id <= 3; id++ {
		c.ok(http.MethodPost, "/api/live/dkg/ack", c.tok(id), fakeAck(electionID, id))
	}
}

func (c *liveConsole) issue(voter string) {
	c.ok(http.MethodPost, "/api/live/issue/presign", voter, map[string]string{"blinded_commitment": pt(0x10)})
	c.ok(http.MethodPost, "/api/live/issue/sign", voter, map[string]string{"e_prime": pt(0x11)})
}

func fakeBallot(electionID, position string, n byte, extra []byte) string {
	nul := bytes.Repeat([]byte{n}, 32)
	raw, _ := proto.Marshal(&pb.Ballot{Version: 1, ElectionId: electionID, PositionId: position,
		CredentialPresentation: &pb.CredentialPresentation{Nullifier: &pb.Nullifier{Value: nul}}})
	return hex.EncodeToString(append(raw, extra...))
}

func fakePartial(trustee, contest string) string {
	raw, _ := proto.Marshal(&pb.PartialDecryption{Version: 1, TrusteeId: trustee, ContestId: contest})
	return hex.EncodeToString(raw)
}

func (c *liveConsole) partials(id int, contests []string) {
	var ps []map[string]string
	for _, ct := range contests {
		ps = append(ps, map[string]string{"contest_id": ct, "partial": fakePartial(fmt.Sprint(id), ct)})
	}
	c.ok(http.MethodPost, "/api/live/partial", c.tok(id), map[string]any{"partials": ps})
}

var liveContests = []string{"president/alice", "president/bob", "secretary/dan", "secretary/eve"}

func sig(i int) string { return strings.Repeat(fmt.Sprintf("%02x", i), 64) }

// toState drives a fresh election to want.
func (c *liveConsole) toState(want string) string {
	runID := c.setup()
	if want == LiveCeremony {
		return runID
	}
	c.ceremony(runID)
	c.issue("voter1")
	c.ok(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": fakeBallot(runID, "president", 1, nil)})
	if want == LiveOpen {
		return runID
	}
	c.ok(http.MethodPost, "/api/live/close", "admin", nil)
	if want == LiveClosed {
		return runID
	}
	c.partials(1, liveContests)
	c.partials(2, liveContests)
	c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(1), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(1)})
	c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(2), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(2)})
	if want == LiveTallied {
		return runID
	}
	c.ok(http.MethodPost, "/api/live/verify", "admin", nil)
	return runID
}

// --- tests -------------------------------------------------------------------------

func TestLiveRoutesAre404WhenLiveIsOff(t *testing.T) {
	_, h := authServer(t)
	for p, acc := range routeAccess {
		if !strings.HasPrefix(p, "/api/live/") || acc != accessPublic && acc != accessAnonymous {
			continue
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s with live off: %d", p, rec.Code)
		}
	}
}

func TestLiveRoleAccess(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	cases := []struct {
		method, path, who string
		want              int
	}{
		{http.MethodPost, "/api/live/elections", "", 401},
		{http.MethodPost, "/api/live/elections", "voter1", 403},
		{http.MethodPost, "/api/live/elections", "t1", 403},
		{http.MethodPost, "/api/live/close", "voter1", 403},
		{http.MethodPost, "/api/live/verify", c.tok(1), 401}, // a token is not a session
		{http.MethodPost, "/api/live/issue/presign", "", 401},
		{http.MethodPost, "/api/live/issue/presign", "admin", 403},
		{http.MethodPost, "/api/live/issue/sign", "t1", 403},
		{http.MethodGet, "/api/live/dkg/roster", "", 401},
		{http.MethodGet, "/api/live/dkg/roster", "t1", 401}, // a trustee login is not a token
		{http.MethodGet, "/api/live/dkg/roster", "admin", 401},
		{http.MethodGet, "/api/live/dkg/roster", "bearer:" + strings.Repeat("0", 64), 401},
		{http.MethodPost, "/api/live/partial", "voter1", 401},
		{http.MethodGet, "/api/live/election", "", 404}, // public; no election yet
		{http.MethodGet, "/api/live/ledger", "", 404},
		{http.MethodPost, "/api/live/ballot", "", 404},
		// A voter may not use the study's signed-in routes.
		{http.MethodPost, "/ceremony/publish", "voter1", 403},
		{http.MethodGet, "/events", "voter1", 403},
	}
	for _, tc := range cases {
		if code, out := c.do(tc.method, tc.path, tc.who, map[string]any{}); code != tc.want {
			t.Errorf("%s %s as %q: %d %v, want %d", tc.method, tc.path, tc.who, code, out, tc.want)
		}
	}
}

func TestLiveHappyPathAndWrongStates(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()

	// Nothing but setup works before setup.
	if code, _ := c.do(http.MethodPost, "/api/live/close", "admin", nil); code != http.StatusNotFound {
		t.Fatalf("close before setup: %d", code)
	}
	runID := c.setup()
	if c.state() != LiveCeremony {
		t.Fatalf("after setup: %s", c.state())
	}
	if code, _ := c.do(http.MethodPost, "/api/live/elections", "admin", map[string]any{"title": "x", "positions": livePositions}); code != http.StatusConflict {
		t.Fatalf("second election while one is running: %d", code)
	}
	// Wrong state: issuance, ballots, close, partials and signatures wait.
	for _, p := range []struct {
		path, who string
		body      any
	}{
		{"/api/live/issue/presign", "voter1", map[string]any{"blinded_commitment": pt(1)}},
		{"/api/live/close", "admin", nil},
		{"/api/live/partial", c.tok(1), map[string]any{"partials": []any{map[string]string{"contest_id": "x", "partial": "00"}}}},
		{"/api/live/tally-sig", c.tok(1), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(1)}},
		{"/api/live/tally/publish", "admin", nil}, {"/api/live/verify", "admin", nil},
	} {
		if code, out := c.do(http.MethodPost, p.path, p.who, p.body); code != http.StatusConflict {
			t.Errorf("%s in ceremony: %d %v", p.path, code, out)
		}
	}
	if code, out := c.do(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": fakeBallot(runID, "president", 1, nil)}); code != http.StatusConflict {
		t.Fatalf("ballot in ceremony: %d %v", code, out)
	}

	// The ceremony relay: the roster waits for every key; a deal waits for
	// the roster; an inbox waits for every deal.
	c.ok(http.MethodPost, "/api/live/dkg/receive-key", c.tok(1), map[string]any{"receive_public_key": pt(0x71)})
	if out := c.ok(http.MethodGet, "/api/live/dkg/roster", c.tok(1), nil); out["complete"] != false {
		t.Fatalf("roster with one key: %v", out)
	}
	if code, _ := c.do(http.MethodPost, "/api/live/dkg/deal", c.tok(1), fakeDeal(runID, 1, 3)); code != http.StatusConflict {
		t.Fatalf("deal before the roster: %d", code)
	}
	c.ok(http.MethodPost, "/api/live/dkg/receive-key", c.tok(2), map[string]any{"receive_public_key": pt(0x72)})
	// A repeated key is refused by dkg-roster, and that key is not kept.
	if code, out := c.do(http.MethodPost, "/api/live/dkg/receive-key", c.tok(3), map[string]any{"receive_public_key": pt(0x72)}); code != http.StatusConflict {
		t.Fatalf("repeated key: %d %v", code, out)
	}
	c.ok(http.MethodPost, "/api/live/dkg/receive-key", c.tok(3), map[string]any{"receive_public_key": pt(0x73)})
	roster := c.ok(http.MethodGet, "/api/live/dkg/roster", c.tok(2), nil)
	if roster["complete"] != true || roster["roster_digest"] != pt(0xd1) || len(roster["peers"].([]any)) != 3 {
		t.Fatalf("roster: %v", roster)
	}
	if code, _ := c.do(http.MethodPost, "/api/live/dkg/receive-key", c.tok(3), map[string]any{"receive_public_key": pt(0x74)}); code != http.StatusConflict {
		t.Fatal("a receive key changed after the roster froze")
	}
	// A deal over another roster is refused.
	bad := fakeDeal(runID, 1, 3)
	bad["roster_digest"] = pt(0xee)
	if code, _ := c.do(http.MethodPost, "/api/live/dkg/deal", c.tok(1), bad); code != http.StatusConflict {
		t.Fatalf("deal over another roster: %d", code)
	}
	deals := map[int]map[string]any{}
	for id := 1; id <= 3; id++ {
		deals[id] = fakeDeal(runID, id, 3)
		c.ok(http.MethodPost, "/api/live/dkg/deal", c.tok(id), deals[id])
		if id == 1 {
			if out := c.ok(http.MethodGet, "/api/live/dkg/inbox", c.tok(2), nil); out["complete"] != false {
				t.Fatalf("inbox with one deal: %v", out)
			}
		}
	}
	redeal := fakeDeal(runID, 1, 3)
	redeal["commitments"] = []string{pt(9), pt(8)}
	if code, _ := c.do(http.MethodPost, "/api/live/dkg/deal", c.tok(1), redeal); code != http.StatusConflict {
		t.Fatal("a second, different deal was accepted")
	}
	// Each inbox holds, from every dealer, exactly the share it posted for
	// this recipient.
	for id := 1; id <= 3; id++ {
		in := c.ok(http.MethodGet, "/api/live/dkg/inbox", c.tok(id), nil)
		for k, d := range in["dealers"].([]any) {
			got, _ := json.Marshal(d.(map[string]any)["masked_share"])
			want, _ := json.Marshal(deals[k+1]["masked_shares"].([]map[string]any)[id-1])
			if !bytes.Equal(got, want) {
				t.Fatalf("trustee %d's share from dealer %d: %s, want %s", id, k+1, got, want)
			}
		}
	}
	for id := 1; id <= 2; id++ {
		if out := c.ok(http.MethodPost, "/api/live/dkg/ack", c.tok(id), fakeAck(runID, id)); out["published"] != false {
			t.Fatal("published before every acknowledgement")
		}
	}
	// A trustee that saw other commitments: its key share does not match the
	// transcript, and nothing is published.
	wrong := fakeAck(runID, 3)
	wrong["verification_key"] = pt(0xfe)
	if code, out := c.do(http.MethodPost, "/api/live/dkg/ack", c.tok(3), wrong); code != http.StatusConflict || !strings.Contains(out["error"].(string), "does not match") {
		t.Fatalf("mismatched ack: %d %v", code, out)
	}
	if c.state() != LiveCeremony {
		t.Fatal("a mismatched transcript was published")
	}
	c.s.live.mu.Lock()
	delete(c.s.live.st.Acks, "3")
	c.s.live.mu.Unlock()
	if out := c.ok(http.MethodPost, "/api/live/dkg/ack", c.tok(3), fakeAck(runID, 3)); out["published"] != true {
		t.Fatalf("last ack: %v", out)
	}
	if c.state() != LiveOpen {
		t.Fatalf("after the ceremony: %s", c.state())
	}
	el := c.ok(http.MethodGet, "/api/live/election", "", nil)
	if el["joint_public_key"] != pt(0xb1) || el["dkg"] == "" || el["issuer_public_key"] != pt(0xa1) || el["counts"].(map[string]any)["voters_on_roll"] != 3.0 {
		t.Fatalf("election view: %v", el)
	}

	// Ballots: relayed byte for byte, even a non-canonical encoding (an
	// unknown field appended), and fingerprinted from the stored bytes.
	c.issue("voter1")
	odd := fakeBallot(runID, "president", 1, []byte{0x78, 0x01}) // unknown field 15, varint 1
	rc := c.ok(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": odd})
	raw, _ := hex.DecodeString(odd)
	if rc["ballot_fingerprint"] != ballotFingerprint(raw) || rc["recorded_bytes_match"] != true || rc["tracking_code"] != "BC-0101-0101" {
		t.Fatalf("receipt: %v", rc)
	}
	if got := fx.chain.bytesIn[len(fx.chain.bytesIn)-1]; !bytes.Equal(got, raw) {
		t.Fatal("the bytes on the chain are not the bytes the phone sent")
	}
	code, out := c.do(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": odd})
	if code != http.StatusUnprocessableEntity || out["gate"] != "nullifier" || !strings.Contains(out["reason"].(string), "already spent") {
		t.Fatalf("replay: %d %v", code, out)
	}
	c.ok(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": fakeBallot(runID, "secretary", 2, nil)})
	led := c.ok(http.MethodGet, "/api/live/ledger", "", nil)
	if led["nullifier_count"] != 2.0 || led["ballots"].([]any)[0].(map[string]any)["ballot"] != odd {
		t.Fatalf("ledger: %v", led)
	}

	c.ok(http.MethodPost, "/api/live/close", "admin", nil)
	if code, _ := c.do(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": fakeBallot(runID, "secretary", 3, nil)}); code != http.StatusConflict {
		t.Fatal("a ballot was relayed after close")
	}
	if code, _ := c.do(http.MethodPost, "/api/live/issue/presign", "voter2", map[string]string{"blinded_commitment": pt(1)}); code != http.StatusConflict {
		t.Fatal("issuance stayed open after close")
	}
	c.partials(1, liveContests)
	c.partials(1, liveContests) // a retry is answered from the record
	c.partials(2, liveContests)
	if led := c.ok(http.MethodGet, "/api/live/ledger", "", nil); len(led["partials"].([]any)) != 8 {
		t.Fatalf("ledger partials: %d", len(led["partials"].([]any)))
	}
	// A signature that does not verify is refused and not kept.
	if code, _ := c.do(http.MethodPost, "/api/live/tally-sig", c.tok(1), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": strings.Repeat("ba", 64)}); code != http.StatusBadRequest {
		t.Fatalf("bad signature: %d", code)
	}
	out = c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(1), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(1)})
	if out["published"] != false {
		t.Fatal("published below threshold")
	}
	if code, _ := c.do(http.MethodPost, "/api/live/tally-sig", c.tok(1), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(9)}); code != http.StatusConflict {
		t.Fatal("a second signature from one trustee was accepted")
	}
	out = c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(2), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(2)})
	if out["published"] != true || c.state() != LiveTallied {
		t.Fatalf("at threshold: %v (%s)", out, c.state())
	}
	ver := c.ok(http.MethodPost, "/api/live/verify", "admin", nil)
	if ver["overall"] != "pass" || c.state() != LiveVerified {
		t.Fatalf("verify: %v", ver)
	}
	// The verifier was given the chain's nullifier count.
	board := c.ok(http.MethodGet, "/api/board/"+runID, "", nil)
	lb := board["live"].(map[string]any)
	if board["verified"] != true || lb["state"] != LiveVerified || len(lb["ballots"].([]any)) != 2 ||
		lb["decryption"].(map[string]any)["trusteesDecrypted"] != nil ||
		lb["decryption"].(map[string]any)["trustees_decrypted"] != 2.0 {
		t.Fatalf("board: %v", board)
	}
	first := lb["ballots"].([]any)[0].(map[string]any)
	if first["ballot_fingerprint"] != ballotFingerprint(raw) || first["tx_id"] == "" {
		t.Fatalf("board ballot: %v", first)
	}
	vc := c.ok(http.MethodGet, "/api/verify-code/"+runID+"/BC-0101-0101", "", nil)
	if vc["found"] != true || vc["ballot_fingerprint"] != ballotFingerprint(raw) || vc["committed_on_chain"] != true {
		t.Fatalf("verify-code: %v", vc)
	}
	// The public files are served once tallied; live.json and private/ never.
	if code, _ := c.do(http.MethodGet, "/api/board/"+runID+"/files/ballots.ndjson", "", nil); code != http.StatusOK {
		t.Fatalf("public ballots: %d", code)
	}
	for _, f := range []string{"live.json", "private/issuer.key", "private/issued.json"} {
		if code, _ := c.do(http.MethodGet, "/api/board/"+runID+"/files/"+f, "", nil); code != http.StatusNotFound {
			t.Errorf("%s served: %d", f, code)
		}
	}
	// A new election may start once this one is verified.
	if code, out := c.do(http.MethodPost, "/api/live/elections", "admin", map[string]any{"title": "Next", "positions": livePositions, "trustees": 3, "threshold": 2}); code != http.StatusCreated {
		t.Fatalf("next election: %d %v", code, out)
	}
}

func TestLiveTrusteeTokenActsOnlyAsItsTrustee(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.setup()
	if code, _ := c.do(http.MethodPost, "/api/live/dkg/receive-key", c.tok(2), map[string]any{"trustee_id": 3, "receive_public_key": pt(1)}); code != http.StatusForbidden {
		t.Fatalf("trustee 2 posting trustee 3's key: %d", code)
	}
	c.ceremony(runID)
	c.issue("voter1")
	c.ok(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": fakeBallot(runID, "president", 1, nil)})
	c.ok(http.MethodPost, "/api/live/close", "admin", nil)
	// Trustee 2's token with trustee 3's partial.
	body := map[string]any{"partials": []map[string]string{{"contest_id": liveContests[0], "partial": fakePartial("3", liveContests[0])}}}
	if code, _ := c.do(http.MethodPost, "/api/live/partial", c.tok(2), body); code != http.StatusForbidden {
		t.Fatalf("trustee 2 submitting trustee 3's partial: %d", code)
	}
	if code, _ := c.do(http.MethodPost, "/api/live/tally-sig", c.tok(2), map[string]any{"trustee_id": "3", "totals": []int{1, 0, 0, 1}, "signature": sig(3)}); code != http.StatusForbidden {
		t.Fatalf("trustee 2 signing as 3: %d", code)
	}
	// A token beyond the election's trustees acts as nobody.
	fx2 := newLiveFixture(t)
	c2 := fx2.console()
	c2.ok(http.MethodPost, "/api/live/elections", "admin", map[string]any{"title": "Two", "positions": livePositions, "trustees": 2, "threshold": 2})
	if code, _ := c2.do(http.MethodPost, "/api/live/dkg/receive-key", c2.tok(3), map[string]any{"receive_public_key": pt(1)}); code != http.StatusForbidden {
		t.Fatalf("trustee 3 of a 2-trustee election: %d", code)
	}
}

func TestLiveIssuanceOncePerAccountEvenAcrossRestart(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	c.toState(LiveOpen) // voter1 has its credential
	if code, out := c.do(http.MethodPost, "/api/live/issue/presign", "voter1", map[string]string{"blinded_commitment": pt(1)}); code != http.StatusConflict {
		t.Fatalf("second presign: %d %v", code, out)
	}
	// Restart: the issued record is on disk.
	c2 := fx.console()
	if code, _ := c2.do(http.MethodPost, "/api/live/issue/presign", "voter1", map[string]string{"blinded_commitment": pt(1)}); code != http.StatusConflict {
		t.Fatal("a restart let voter1 be issued again")
	}
	if code, _ := c2.do(http.MethodPost, "/api/live/issue/sign", "voter1", map[string]string{"e_prime": pt(1)}); code != http.StatusConflict {
		t.Fatal("a restart let voter1 be signed again")
	}
	c2.issue("voter2")
	if n := len(fx.ops.signed); n != 2 {
		t.Fatalf("%d signatures made, want 2", n)
	}
	el := c2.ok(http.MethodGet, "/api/live/election", "", nil)
	if el["counts"].(map[string]any)["credentials_issued"] != 2.0 {
		t.Fatalf("counts: %v", el["counts"])
	}
}

func TestLiveSecondPresignReplacesTheFirst(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	c.toState(LiveCeremony)
	c.ceremony(c.s.live.st.ElectionID)
	c.ok(http.MethodPost, "/api/live/issue/presign", "voter2", map[string]string{"blinded_commitment": pt(1)})
	c.ok(http.MethodPost, "/api/live/issue/presign", "voter2", map[string]string{"blinded_commitment": pt(2)})
	entries, _ := os.ReadDir(c.s.live.sessionsDir())
	if len(entries) != 1 {
		t.Fatalf("%d session files for one account, want 1", len(entries))
	}
	c.ok(http.MethodPost, "/api/live/issue/sign", "voter2", map[string]string{"e_prime": pt(3)})
	if got := fx.ops.signed[len(fx.ops.signed)-1]; !strings.Contains(got, "nonce-2") {
		t.Fatalf("signed with %s, want the second session", got)
	}
	// A sign with no session open is refused.
	if code, _ := c.do(http.MethodPost, "/api/live/issue/sign", "voter3", map[string]string{"e_prime": pt(3)}); code != http.StatusConflict {
		t.Fatalf("sign without presign: %d", code)
	}
}

func TestLiveIssuanceIsSerialized(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	c.toState(LiveCeremony)
	c.ceremony(c.s.live.st.ElectionID)
	fx.ops.mu.Lock()
	fx.ops.slow = 30 * time.Millisecond
	fx.ops.maxInFlight["all"] = 0
	fx.ops.mu.Unlock()
	var wg sync.WaitGroup
	for _, v := range []string{"voter1", "voter2", "voter3"} {
		c.do(http.MethodGet, "/api/live/election", v, nil) // mint the session first, not concurrently
	}
	for _, v := range []string{"voter1", "voter2", "voter3"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.issueConcurrent(v)
		}()
	}
	wg.Wait()
	if m := fx.ops.maxInFlight["all"]; m != 1 {
		t.Fatalf("%d issuance ops ran at once, want 1", m)
	}
	if len(fx.ops.signed) != 3 {
		t.Fatalf("%d signatures, want 3", len(fx.ops.signed))
	}
}

// issueConcurrent is issue without the shared test bookkeeping.
func (c *liveConsole) issueConcurrent(voter string) {
	for _, step := range []struct{ path, key string }{{"/api/live/issue/presign", "blinded_commitment"}, {"/api/live/issue/sign", "e_prime"}} {
		data, _ := json.Marshal(map[string]string{step.key: pt(7)})
		req := httptest.NewRequest(http.MethodPost, step.path, bytes.NewReader(data))
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.sessions[voter]})
		rec := httptest.NewRecorder()
		c.s.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			c.t.Errorf("%s %s: %d %s", voter, step.path, rec.Code, rec.Body)
		}
	}
}

func TestLiveRestartResumesInEveryState(t *testing.T) {
	for _, want := range []string{LiveCeremony, LiveOpen, LiveClosed, LiveTallied, LiveVerified} {
		t.Run(want, func(t *testing.T) {
			fx := newLiveFixture(t)
			c := fx.console()
			runID := c.toState(want)
			c2 := fx.console()
			if c2.state() != want || c2.s.live.st.RunID != runID {
				t.Fatalf("after restart: %s %s, want %s %s", c2.state(), c2.s.live.st.RunID, want, runID)
			}
			if want == LiveCeremony {
				c2.ceremony(runID) // the ceremony carries on after the restart
				if c2.state() != LiveOpen {
					t.Fatalf("ceremony after restart: %s", c2.state())
				}
			}
			if want == LiveOpen {
				c2.issue("voter2")
				c2.ok(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": fakeBallot(runID, "president", 2, nil)})
				if c2.s.live.st.Ballots != 2 {
					t.Fatalf("ballots after restart: %d", c2.s.live.st.Ballots)
				}
			}
		})
	}
}

func TestLiveRestartFinishesWhatTheChainAlreadyHas(t *testing.T) {
	// Setup cut off by the chain: the run stays in setup, and the next start
	// records CreateElection.
	fx := newLiveFixture(t)
	c := fx.console()
	fx.chain.down.Store(true)
	if code, _ := c.do(http.MethodPost, "/api/live/elections", "admin", map[string]any{"title": "x", "positions": livePositions, "trustees": 3, "threshold": 2}); code != http.StatusBadGateway {
		t.Fatalf("setup with the chain down: %d", code)
	}
	if c.state() != LiveSetup {
		t.Fatalf("state %s, want setup", c.state())
	}
	fx.chain.down.Store(false)
	c2 := fx.console()
	if c2.state() != LiveCeremony {
		t.Fatalf("after restart: %s", c2.state())
	}

	// A close and a ballot the chain recorded but the console did not: the
	// restart takes both from the chain.
	runID := c2.s.live.st.ElectionID
	c2.ceremony(runID)
	b := fakeBallot(runID, "president", 4, nil)
	fx.chain.oracleChain.Submit("SubmitBallot", b)
	fx.chain.oracleChain.Submit("CloseElection", runID)
	c3 := fx.console()
	if c3.state() != LiveClosed || c3.s.live.st.Ballots != 1 {
		t.Fatalf("after restart: %s with %d ballots", c3.state(), c3.s.live.st.Ballots)
	}
	board := c3.ok(http.MethodGet, "/api/board/"+runID, "", nil)
	if n := len(board["live"].(map[string]any)["ballots"].([]any)); n != 1 {
		t.Fatalf("board ballots after resume: %d", n)
	}
}

func TestLiveRefusedPublishChangesNothing(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveClosed)
	c.partials(1, liveContests)
	c.partials(2, liveContests)
	c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(1), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(1)})
	before, _ := os.ReadFile(filepath.Join(fx.runs, runID, liveStateFile))
	receiptsBefore, _ := os.ReadFile(filepath.Join(fx.runs, runID, "receipts.csv"))
	code, out := c.do(http.MethodPost, "/api/live/tally/publish", "admin", nil)
	if code != http.StatusUnprocessableEntity || out["gate"] != "threshold" || !strings.Contains(out["reason"].(string), "threshold is 2") {
		t.Fatalf("1-of-2 publish: %d %v", code, out)
	}
	after, _ := os.ReadFile(filepath.Join(fx.runs, runID, liveStateFile))
	receiptsAfter, _ := os.ReadFile(filepath.Join(fx.runs, runID, "receipts.csv"))
	if !bytes.Equal(before, after) || !bytes.Equal(receiptsBefore, receiptsAfter) || c.state() != LiveClosed {
		t.Fatal("a refused publish changed the run")
	}
	// The verifier failing leaves the election tallied, not verified.
	c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(2), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(2)})
	fx.ops.verify = "fail"
	ver := c.ok(http.MethodPost, "/api/live/verify", "admin", nil)
	if ver["overall"] != "fail" || c.state() != LiveTallied {
		t.Fatalf("failed verify: %v %s", ver["overall"], c.state())
	}
	board := c.ok(http.MethodGet, "/api/board/"+runID, "", nil)
	if board["verified"] != false || board["live"].(map[string]any)["failed_checks"].([]any)[0] != "tally.homomorphic_sum" {
		t.Fatalf("board after a failed verify: %v", board["live"])
	}
}

func TestLiveSecretsNeverInResponsesOrLogs(t *testing.T) {
	logs := captureLog(t)
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveVerified)
	c.do(http.MethodGet, "/api/board/"+runID, "", nil)
	c.do(http.MethodGet, "/api/live/election", "", nil)
	c.do(http.MethodGet, "/api/live/ledger", "", nil)
	c.do(http.MethodGet, "/export/"+runID+"/run.json", "admin", nil)
	for _, b := range c.bodies {
		if strings.Contains(b, fakeIssuerSecret) || strings.Contains(b, "nonce-") {
			t.Fatalf("a secret appeared in a response: %.200s", b)
		}
	}
	if strings.Contains(logs.String(), fakeIssuerSecret) || strings.Contains(logs.String(), "nonce-") {
		t.Fatal("a secret appeared in the log")
	}
	priv := filepath.Join(fx.runs, runID, livePrivateDir)
	for _, p := range []string{priv, filepath.Join(priv, liveSessionsDir)} {
		if info, err := os.Stat(p); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", p, err, info.Mode())
		}
	}
	for _, f := range []string{liveIssuerKey, liveIssuedFile} {
		if info, err := os.Stat(filepath.Join(priv, f)); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v", f, err)
		}
	}
}

func TestLiveBallotHandlerWritesNothingThatNamesAnAccount(t *testing.T) {
	logs := captureLog(t)
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveOpen)
	c.issue("voter2")
	// The phone's own session cookie rides along, from a distinctive address.
	c.ok(http.MethodPost, "/api/live/ballot", "voter2", map[string]string{"ballot": fakeBallot(runID, "president", 9, nil)})
	c.ok(http.MethodPost, "/api/live/ballot", "voter2", map[string]string{"ballot": fakeBallot(runID, "secretary", 8, nil)})
	dir := filepath.Join(fx.runs, runID)
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if rel, _ := filepath.Rel(dir, p); strings.HasPrefix(rel, livePrivateDir) {
			return nil // the issued record names accounts, and links none to a ballot
		}
		data, _ := os.ReadFile(p)
		for _, needle := range []string{"voter1", "voter2", "voter3", "192.0.2.7", c.sessions["voter2"]} {
			if bytes.Contains(data, []byte(needle)) {
				t.Errorf("%s contains %q", p, needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"voter2", "192.0.2.7"} {
		if strings.Contains(logs.String(), needle) {
			t.Errorf("the log contains %q", needle)
		}
	}
	// authorize strips the cookie before the handler: a probe on the same
	// route pattern sees no session.
	s := c.s
	var sawCookie, sawSession bool
	mux := &routeMux{mux: http.NewServeMux()}
	mux.HandleFunc("/api/live/ballot", func(w http.ResponseWriter, r *http.Request) {
		sawCookie = r.Header.Get("Cookie") != ""
		sawSession = sessionFrom(r) != nil
	})
	req := httptest.NewRequest(http.MethodPost, "/api/live/ballot", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.sessions["voter2"]})
	s.authorize(mux).ServeHTTP(httptest.NewRecorder(), req)
	if sawCookie || sawSession {
		t.Fatalf("the ballot handler saw cookie=%v session=%v", sawCookie, sawSession)
	}
}

func TestLiveBallotBodyCapAndRateLimit(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveOpen)
	big := []byte(`{"ballot":"` + strings.Repeat("ab", liveMaxBallotBody) + `"}`)
	if code, _ := c.do(http.MethodPost, "/api/live/ballot", "", big); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized ballot: %d", code)
	}
	for _, bad := range []string{"", "abc", "zz", "AB CD"} {
		if code, _ := c.do(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": bad}); code != http.StatusBadRequest {
			t.Errorf("ballot %q: %d", bad, code)
		}
	}
	if code, _ := c.do(http.MethodPost, "/api/live/ballot", "", map[string]any{"ballot": "00", "account": "voter1"}); code != http.StatusBadRequest {
		t.Error("an unknown field was accepted")
	}
	c.s.live.limit = newRateLimiter(0, 2)
	codes := []int{}
	for i := 0; i < 3; i++ {
		code, _ := c.do(http.MethodPost, "/api/live/ballot", "", map[string]string{"ballot": fakeBallot(runID, "secretary", byte(40+i), nil)})
		codes = append(codes, code)
	}
	if codes[2] != http.StatusTooManyRequests {
		t.Fatalf("rate limit: %v", codes)
	}
}

func TestLiveSetupRefusals(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	for name, body := range map[string]map[string]any{
		"no title":           {"title": " ", "positions": livePositions},
		"threshold too high": {"title": "x", "positions": livePositions, "trustees": 3, "threshold": 4},
		"trustee 4 no token": {"title": "x", "positions": livePositions, "trustees": 4, "threshold": 2},
		"no positions":       {"title": "x", "positions": []any{}, "trustees": 3, "threshold": 2},
	} {
		if code, out := c.do(http.MethodPost, "/api/live/elections", "admin", body); code != http.StatusBadRequest {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	if c.state() != "" {
		t.Fatalf("a refused setup left state %s", c.state())
	}
}

func TestTrusteeTokensFile(t *testing.T) {
	h := strings.Repeat("ab", 32)
	for name, data := range map[string]string{
		"empty":     `[]`,
		"bad id":    `[{"trustee_id":"01","token_sha256":"` + h + `"}]`,
		"dup id":    `[{"trustee_id":"1","token_sha256":"` + h + `"},{"trustee_id":"1","token_sha256":"` + strings.Repeat("cd", 32) + `"}]`,
		"dup hash":  `[{"trustee_id":"1","token_sha256":"` + h + `"},{"trustee_id":"2","token_sha256":"` + h + `"}]`,
		"short":     `[{"trustee_id":"1","token_sha256":"abcd"}]`,
		"extra key": `[{"trustee_id":"1","token_sha256":"` + h + `","token":"x"}]`,
	} {
		if _, err := parseTrusteeTokens([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	a, _ := NewTrusteeToken()
	b, _ := NewTrusteeToken()
	ha, _ := HashTrusteeToken(strings.NewReader(a))
	hb, _ := HashTrusteeToken(strings.NewReader(b + "\n"))
	tt, err := parseTrusteeTokens([]byte(`[{"trustee_id":"1","token_sha256":"` + ha + `"},{"trustee_id":"2","token_sha256":"` + hb + `"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := tt.match(b); !ok || id != "2" {
		t.Fatalf("token b matched %q %v", id, ok)
	}
	if _, ok := tt.match(a + "x"); ok {
		t.Fatal("a wrong token matched")
	}
	if _, err := HashTrusteeToken(strings.NewReader("short\n")); err == nil {
		t.Fatal("a short token was hashed")
	}
}

func TestVoterRoleInUsersFile(t *testing.T) {
	h := fixtureHashes()["admin-pw"]
	if _, err := parseUsers([]byte(`[{"username":"v","role":"voter","password_bcrypt":"` + h + `"}]`)); err != nil {
		t.Fatal(err)
	}
	if _, err := parseUsers([]byte(`[{"username":"v","role":"voter","trustee_id":"1","password_bcrypt":"` + h + `"}]`)); err == nil {
		t.Fatal("a voter with a trustee id was accepted")
	}
}

func TestServeOptions(t *testing.T) {
	for _, tc := range []struct {
		o       ServeOptions
		err     bool
		warning bool
	}{
		{ServeOptions{Addr: "0.0.0.0:8443"}, false, false},
		{ServeOptions{Addr: "0.0.0.0:8443", TLSCert: "c"}, true, false},
		{ServeOptions{Addr: "127.0.0.1:8090", Live: true}, true, false}, // no auth file
		{ServeOptions{Addr: "0.0.0.0:8443", Live: true, AuthFile: "u"}, true, false},
		{ServeOptions{Addr: "192.168.1.5:8443", Live: true, AuthFile: "u"}, true, false},
		{ServeOptions{Addr: "127.0.0.1:8090", Live: true, AuthFile: "u"}, false, true},
		{ServeOptions{Addr: "localhost:8090", Live: true, AuthFile: "u"}, false, true},
		{ServeOptions{Addr: "[::1]:8090", Live: true, AuthFile: "u"}, false, true},
		{ServeOptions{Addr: "0.0.0.0:8443", Live: true, AuthFile: "u", TLSCert: "c", TLSKey: "k"}, false, false},
	} {
		w, err := CheckServeOptions(tc.o)
		if (err != nil) != tc.err || (w != "") != tc.warning {
			t.Errorf("%+v: warning %q err %v", tc.o, w, err)
		}
	}
}

// writeTestCert writes a self-signed certificate for 127.0.0.1.
func writeTestCert(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	kder, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

func TestTLSServesHTTPSWithASecureCookie(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	certFile, keyFile, pool := writeTestCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	opts := ServeOptions{Addr: ln.Addr().String(), TLSCert: certFile, TLSKey: keyFile, Live: true, AuthFile: fx.users}
	go Serve(ln, opts, c.s)
	t.Cleanup(func() { ln.Close() })
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := client.Post("https://"+ln.Addr().String()+"/api/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"admin-pw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("login over TLS: %d %v", resp.StatusCode, resp.TLS)
	}
	var secure bool
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie {
			secure = ck.Secure
		}
	}
	if !secure {
		t.Fatal("the session cookie is not Secure over TLS")
	}
	// TLS 1.1 is refused.
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MaxVersion: tls.VersionTLS11}}}
	if _, err := old.Get("https://" + ln.Addr().String() + "/api/live/election"); err == nil {
		t.Fatal("a TLS 1.1 client was served")
	}
}
