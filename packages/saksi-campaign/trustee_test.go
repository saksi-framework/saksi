package campaign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// The trustee process (trustee.go) against the console's live server running
// in process, with the real saksi-demo binary for every op. The chain is the
// in-memory oracleChain (live_e2e_test.go), or a wrapper of it that lies to
// one trustee where a test needs the chain read faked.

// --- the fleet: five trustee processes ------------------------------------------------

type trusteeProc struct {
	id      int
	opts    TrusteeOptions
	srvOpts TrusteeServerOptions
	T       *TrusteeService
	handler atomic.Pointer[TrusteeServer]
	srv     *httptest.Server
	client  *http.Client
}

type trusteeFleet struct {
	t     *testing.T
	h     *liveE2E
	procs []*trusteeProc
	// bodies is every trustee API response body the test saw.
	bodyMu sync.Mutex
	bodies []string
}

// fleetOptions tunes one trustee for a test.
type fleetOptions struct {
	// consoleFor: the console URL trustee id uses ("" = the real console).
	consoleFor func(id int) string
	// chainFor wraps the chain trustee id reads.
	chainFor func(id int, c trusteeChain) trusteeChain
	// peerFor: the URL trustee id uses for peer ("" = peer's real URL).
	peerFor func(id, peer int) string
	// minBallots per trustee (0 = default).
	minBallots func(id int) int
	// crash hook per trustee.
	crash func(id int, point string) bool
}

const trusteeTestPassword = "trustee-pw"

// newTrusteeFleet starts five trustee processes against h's console, each
// reading the chain dial gives it.
func newTrusteeFleet(t *testing.T, h *liveE2E, dial func(id int) func() (trusteeChain, error), fo fleetOptions) *trusteeFleet {
	t.Helper()
	f := &trusteeFleet{t: t, h: h}
	hash := hashFor(t, trusteeTestPassword)
	for id := 1; id <= 5; id++ {
		p := &trusteeProc{id: id}
		p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hd := p.handler.Load(); hd != nil {
				hd.ServeHTTP(w, r)
				return
			}
			http.Error(w, "starting", http.StatusServiceUnavailable)
		}))
		t.Cleanup(p.srv.Close)
		f.procs = append(f.procs, p)
	}
	for _, p := range f.procs {
		id := p.id
		dir := filepath.Join(h.work, fmt.Sprintf("trustee-%d", id))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		users, _ := json.Marshal([]User{{Username: fmt.Sprintf("trustee%d", id), Role: RoleTrustee, TrusteeID: fmt.Sprint(id), PasswordBcrypt: hash}})
		authFile := filepath.Join(dir, "accounts.json")
		tokFile := filepath.Join(dir, "token")
		if err := os.WriteFile(authFile, users, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tokFile, []byte(h.tokens[id-1]+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		tok, err := LoadTrusteeTokenFile(tokFile)
		if err != nil {
			t.Fatal(err)
		}
		peers := map[int]string{}
		for _, q := range f.procs {
			peers[q.id] = q.srv.URL
			if fo.peerFor != nil {
				if u := fo.peerFor(id, q.id); u != "" {
					peers[q.id] = u
				}
			}
		}
		console := h.srv.URL
		if fo.consoleFor != nil {
			if u := fo.consoleFor(id); u != "" {
				console = u
			}
		}
		chainDial := dial(id)
		if fo.chainFor != nil {
			inner := chainDial
			chainDial = func() (trusteeChain, error) {
				c, err := inner()
				if err != nil {
					return nil, err
				}
				return fo.chainFor(id, c), nil
			}
		}
		p.opts = TrusteeOptions{
			ID: id, ConsoleURL: console, ConsoleCA: h.caFile, Token: tok,
			StateDir: filepath.Join(dir, "state"), Peers: peers,
			Runner: execLiveRunner(h.demo), Dial: chainDial, Poll: 25 * time.Millisecond,
		}
		if fo.minBallots != nil {
			p.opts.MinBallots = fo.minBallots(id)
		}
		if fo.crash != nil {
			p.opts.crash = func(point string) bool { return fo.crash(id, point) }
		}
		p.srvOpts = TrusteeServerOptions{AuthFile: authFile}
		f.start(p)
	}
	h.tr = f
	return f
}

// start (re)starts trustee p's process over its state folder and signs in.
func (f *trusteeFleet) start(p *trusteeProc) {
	f.t.Helper()
	T, err := NewTrusteeService(p.opts)
	if err != nil {
		f.t.Fatalf("trustee %d: %v", p.id, err)
	}
	ts, err := NewTrusteeServer(T, p.srvOpts)
	if err != nil {
		f.t.Fatalf("trustee %d: %v", p.id, err)
	}
	p.T = T
	p.handler.Store(ts)
	T.Start()
	f.t.Cleanup(T.Close)
	jar, _ := cookiejar.New(nil)
	p.client = &http.Client{Jar: jar, Transport: p.srv.Client().Transport}
	code, out := f.call(p, http.MethodPost, "/api/login", map[string]string{"username": fmt.Sprintf("trustee%d", p.id), "password": trusteeTestPassword})
	if code != http.StatusNoContent {
		f.t.Fatalf("trustee %d login: %d %v", p.id, code, out)
	}
}

// restart kills trustee id's process (its driver stops, sessions are lost)
// and starts a new one over the same state folder.
func (f *trusteeFleet) restart(id int) {
	p := f.procs[id-1]
	p.T.Close()
	p.handler.Store(nil)
	f.start(p)
}

func (f *trusteeFleet) call(p *trusteeProc, method, path string, body any) (int, map[string]any) {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		rd = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, p.srv.URL+path, rd)
	resp, err := p.client.Do(req)
	if err != nil {
		f.t.Fatalf("trustee %d %s %s: %v", p.id, method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	f.bodyMu.Lock()
	f.bodies = append(f.bodies, string(data))
	f.bodyMu.Unlock()
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func (f *trusteeFleet) status(id int) TrusteeStatus {
	f.t.Helper()
	p := f.procs[id-1]
	req, _ := http.NewRequest(http.MethodGet, p.srv.URL+"/api/trustee/status", nil)
	resp, err := p.client.Do(req)
	if err != nil {
		f.t.Fatalf("trustee %d status: %v", id, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		f.t.Fatalf("trustee %d status: %d %s", id, resp.StatusCode, data)
	}
	f.bodyMu.Lock()
	f.bodies = append(f.bodies, string(data))
	f.bodyMu.Unlock()
	var st TrusteeStatus
	if err := json.Unmarshal(data, &st); err != nil {
		f.t.Fatal(err)
	}
	return st
}

// press presses one of the three buttons and expects it to be taken.
func (f *trusteeFleet) press(id int, action string, body any) {
	f.t.Helper()
	code, out := f.call(f.procs[id-1], http.MethodPost, "/api/trustee/"+action, body)
	if code != http.StatusAccepted {
		f.t.Fatalf("trustee %d %s: %d %v", id, action, code, out)
	}
}

// waitFor polls trustee id's status until cond holds.
func (f *trusteeFleet) waitFor(id int, what string, cond func(TrusteeStatus) bool) TrusteeStatus {
	f.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var st TrusteeStatus
	for time.Now().Before(deadline) {
		st = f.status(id)
		if cond(st) {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.t.Fatalf("trustee %d: timed out waiting for %s; status %+v", id, what, st)
	return st
}

func (f *trusteeFleet) waitStep(id int, step, state string) TrusteeStatus {
	f.t.Helper()
	return f.waitFor(id, step+" "+state, func(st TrusteeStatus) bool {
		if s := st.Steps[step].State; s != state && (s == stepFailed || s == stepBlocked || s == stepRefused) {
			f.t.Fatalf("trustee %d: %s is %s (%s), want %s; alarms %v", id, step, s, st.Steps[step].Error, state, st.Alarms)
		}
		return st.Steps[step].State == state
	})
}

// ceremony presses Join on every trustee and waits until every one has
// checked the published transcript.
func (f *trusteeFleet) ceremony() {
	f.t.Helper()
	for id := 1; id <= 5; id++ {
		f.press(id, "join", nil)
	}
	var first TrusteeStatus
	for id := 1; id <= 5; id++ {
		st := f.waitStep(id, "join", stepDone)
		if st.Ceremony.TranscriptCheck != "ok" || !st.Ceremony.RosterChecked {
			f.t.Fatalf("trustee %d joined without the checks: %+v", id, st.Ceremony)
		}
		for _, e := range st.Ceremony.Roster {
			if !e.Self && e.PeerCheck != "ok" {
				f.t.Fatalf("trustee %d: peer %d check %s", id, e.TrusteeID, e.PeerCheck)
			}
		}
		if id == 1 {
			first = st
		} else if st.Fingerprints.Roster != first.Fingerprints.Roster || st.Fingerprints.JointKey != first.Fingerprints.JointKey {
			f.t.Fatalf("trustee %d shows roster %s joint key %s; trustee 1 %s %s", id,
				st.Fingerprints.Roster, st.Fingerprints.JointKey, first.Fingerprints.Roster, first.Fingerprints.JointKey)
		}
	}
	el := f.h.must(nil, http.MethodGet, "/api/live/election", "", nil)
	if el["joint_key_fingerprint"] != first.Fingerprints.JointKey || el["roster_fingerprint"] != first.Fingerprints.Roster {
		f.t.Fatalf("console shows joint key %v roster %v; trustees %s %s", el["joint_key_fingerprint"], el["roster_fingerprint"],
			first.Fingerprints.JointKey, first.Fingerprints.Roster)
	}
}

// decrypt presses Decrypt on trustee id and waits until its partial is
// recorded and read back from the chain.
func (f *trusteeFleet) decrypt(id int) TrusteeStatus {
	f.t.Helper()
	f.press(id, "decrypt", nil)
	st := f.waitStep(id, "decrypt", stepDone)
	if !st.Decryption.PartialRecorded || st.Decryption.PartialReadBack != "ok" || st.Decryption.BallotsDigest == "" {
		f.t.Fatalf("trustee %d decrypted without the checks: %+v", id, st.Decryption)
	}
	return st
}

// sign waits for trustee id's own combine, checks its totals are want,
// presses Sign tally over them and waits for the signature to be posted.
func (f *trusteeFleet) sign(id int, want []float64) map[string]any {
	f.t.Helper()
	st := f.waitFor(id, "its own combine", func(st TrusteeStatus) bool { return st.Tally.ReadyToSign })
	got := make([]float64, len(st.Tally.Totals))
	for i, x := range st.Tally.Totals {
		got[i] = float64(x)
	}
	if !slices.Equal(got, want) {
		f.t.Fatalf("trustee %d combined %v, want %v", id, got, want)
	}
	f.press(id, "sign", map[string]any{"totals": st.Tally.Totals})
	st = f.waitStep(id, "sign", stepDone)
	el := f.h.must(nil, http.MethodGet, "/api/live/election", "", nil)
	return map[string]any{"published": el["state"] == LiveTallied || el["state"] == LiveVerified, "signature_posted": st.Tally.SignaturePosted}
}

// secrets is every secret the trustees hold: share scalars, receive key
// secrets and tokens.
func (f *trusteeFleet) secrets() []string {
	var out []string
	for _, p := range f.procs {
		out = append(out, p.opts.Token)
		_ = filepath.Walk(p.opts.StateDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			base := filepath.Base(path)
			if base != trusteeReceiveKey && base != trusteeShareFile {
				return nil
			}
			var sec struct {
				Secret string `json:"secret"`
				Share  string `json:"share"`
			}
			data, _ := os.ReadFile(path)
			_ = json.Unmarshal(data, &sec)
			for _, v := range []string{sec.Secret, sec.Share} {
				if v != "" {
					out = append(out, v)
				}
			}
			return nil
		})
	}
	return out
}

// checkSecrets asserts no trustee secret is in any response the test saw
// (console and trustee APIs) or in the log, and the state folders' modes.
func (f *trusteeFleet) checkSecrets(logs string) {
	f.t.Helper()
	secrets := f.secrets()
	if len(secrets) < 5+5+5 {
		f.t.Fatalf("found only %d trustee secrets to look for", len(secrets))
	}
	f.bodyMu.Lock()
	bodies := append([]string(nil), f.bodies...)
	f.bodyMu.Unlock()
	f.h.bodyMu.Lock()
	bodies = append(bodies, f.h.bodies...)
	f.h.bodyMu.Unlock()
	for _, sec := range secrets {
		for _, b := range bodies {
			if strings.Contains(strings.ToLower(b), strings.ToLower(sec)) {
				f.t.Fatalf("a trustee secret appeared in a response")
			}
		}
		if strings.Contains(strings.ToLower(logs), strings.ToLower(sec)) {
			f.t.Fatalf("a trustee secret appeared in the log")
		}
	}
	for _, p := range f.procs {
		_ = filepath.Walk(p.opts.StateDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			switch {
			case info.IsDir() && info.Mode().Perm() != 0o700:
				f.t.Errorf("%s is mode %o, want 0700", path, info.Mode().Perm())
			case !info.IsDir() && info.Mode().Perm() != 0o600:
				f.t.Errorf("%s is mode %o, want 0600", path, info.Mode().Perm())
			}
			return nil
		})
	}
}

// --- shared steps --------------------------------------------------------------------

// trusteeTestBed is a console over the oracle chain with five trustee
// processes.
type trusteeTestBed struct {
	h     *liveE2E
	f     *trusteeFleet
	chain *oracleChain
	admin *http.Client
}

func newTrusteeTestBed(t *testing.T, fo fleetOptions) *trusteeTestBed {
	t.Helper()
	if os.Getenv("SAKSI_DEMO_BIN") == "" {
		t.Skip("set SAKSI_DEMO_BIN to the saksi-demo binary to run the trustee process tests")
	}
	demo := findDemo(t)
	b := &trusteeTestBed{}
	b.h = newLiveE2E(t, demo, func() (liveChain, error) { return b.chain, nil })
	b.chain = newOracleChain(t, demo)
	b.f = newTrusteeFleet(t, b.h, func(int) func() (trusteeChain, error) {
		return func() (trusteeChain, error) { return b.chain, nil }
	}, fo)
	b.admin = b.h.login("ban", "admin-pw")
	return b
}

func (b *trusteeTestBed) setup() string {
	el := b.h.must(b.admin, http.MethodPost, "/api/live/elections", "", map[string]any{
		"title": "Trustee test",
		"positions": []map[string]any{
			{"id": "president", "candidates": []string{"alice", "bob", "carol"}},
			{"id": "secretary", "candidates": []string{"dan", "eve", "fay"}},
		},
	})
	return el["election_id"].(string)
}

// vote enrols the three voters and casts their six ballots; the totals are
// [2,1,0, 0,1,2].
func (b *trusteeTestBed) vote() {
	h := b.h
	el := h.must(nil, http.MethodGet, "/api/live/election", "", nil)
	choices := [3][2]int{{0, 2}, {0, 1}, {1, 2}}
	for v := 0; v < 3; v++ {
		c := h.login(fmt.Sprintf("voter%d", v+1), "voter-pw")
		begin := h.cliOp("voter-begin", map[string]any{})
		pre := h.must(c, http.MethodPost, "/api/live/issue/presign", "", map[string]any{"blinded_commitment": begin["blinded_commitment"]})
		blind := h.cliOp("voter-blind", map[string]any{"state": begin["state"], "r": pre["r"], "issuer_public_key": el["issuer_public_key"]})
		sig := h.must(c, http.MethodPost, "/api/live/issue/sign", "", map[string]any{"e_prime": blind["e_prime"]})
		fin := h.cliOp("voter-finalize", map[string]any{"state": blind["state"], "s_iss": sig["s_iss"], "issuer_public_key": sig["issuer_public_key"]})
		for p, pos := range []string{"president", "secretary"} {
			bal := h.cliOp("ballot", map[string]any{"params": el["params"], "dkg": el["dkg"], "credential": fin["credential"], "position_id": pos, "choice": choices[v][p]})
			h.must(nil, http.MethodPost, "/api/live/ballot", "", map[string]any{"ballot": bal["ballot"]})
		}
	}
}

func (b *trusteeTestBed) close() { b.h.must(b.admin, http.MethodPost, "/api/live/close", "", nil) }

var wantTotals = []float64{2, 1, 0, 0, 1, 2}

// --- tests -----------------------------------------------------------------------

// The whole election through five trustee processes, with a kill and restart
// of trustee 2 at every crash point inside a step (before and after each post) and of every trustee
// between steps; no trustee secret in any response, log line or loose file.
func TestTrusteeProcessesKillAndRestart(t *testing.T) {
	logs := captureLog(t)
	var crashMu sync.Mutex
	crashed := map[string]bool{}
	b := newTrusteeTestBed(t, fleetOptions{crash: func(id int, point string) bool {
		if id != 2 {
			return false
		}
		crashMu.Lock()
		defer crashMu.Unlock()
		if crashed[point] {
			return false
		}
		crashed[point] = true
		return true
	}})
	f := b.f
	b.setup()
	for id := 1; id <= 5; id++ {
		f.press(id, "join", nil)
	}
	// Trustee 2 stops at each crash point of the ceremony; restart it each time.
	for _, point := range []string{"keygen-saved", "deal-saved", "ack-saved", "ack-posted"} {
		f.waitFor(2, "the kill at "+point, func(TrusteeStatus) bool {
			crashMu.Lock()
			defer crashMu.Unlock()
			return crashed[point]
		})
		time.Sleep(50 * time.Millisecond)
		f.restart(2)
	}
	for id := 1; id <= 5; id++ {
		f.waitStep(id, "join", stepDone)
	}
	// Between steps: every trustee killed and restarted.
	for id := 1; id <= 5; id++ {
		f.restart(id)
		if st := f.status(id); st.Steps["join"].State != stepDone || st.Ceremony.TranscriptCheck != "ok" {
			t.Fatalf("trustee %d after restart: %+v", id, st.Steps)
		}
	}
	b.vote()
	b.close()
	f.press(2, "decrypt", nil)
	f.waitFor(2, "the kill at partial-saved", func(TrusteeStatus) bool {
		crashMu.Lock()
		defer crashMu.Unlock()
		return crashed["partial-saved"]
	})
	time.Sleep(50 * time.Millisecond)
	f.restart(2)
	f.waitFor(2, "the kill at partial-posted", func(TrusteeStatus) bool {
		crashMu.Lock()
		defer crashMu.Unlock()
		return crashed["partial-posted"]
	})
	time.Sleep(50 * time.Millisecond)
	f.restart(2)
	f.waitStep(2, "decrypt", stepDone)
	f.decrypt(1)
	f.restart(1)
	f.decrypt(3)
	for id := 1; id <= 3; id++ {
		f.restart(id)
	}
	f.sign(1, wantTotals)
	f.restart(1)
	if st := f.status(1); !st.Tally.SignaturePosted || st.Steps["sign"].State != stepDone {
		t.Fatalf("trustee 1 after restart: %+v %+v", st.Tally, st.Steps["sign"])
	}
	// Trustee 2 is killed after its signature is made, before it is posted.
	st := f.waitFor(2, "its combine", func(st TrusteeStatus) bool { return st.Tally.ReadyToSign })
	f.press(2, "sign", map[string]any{"totals": st.Tally.Totals})
	f.waitFor(2, "the kill at sig-saved", func(TrusteeStatus) bool {
		crashMu.Lock()
		defer crashMu.Unlock()
		return crashed["sig-saved"]
	})
	time.Sleep(50 * time.Millisecond)
	f.restart(2)
	f.waitStep(2, "sign", stepDone)
	res := f.sign(3, wantTotals)
	if res["published"] != true {
		t.Fatalf("not published after 3 signatures")
	}
	for id := 1; id <= 5; id++ {
		st := f.waitFor(id, "the published tally", func(st TrusteeStatus) bool { return st.Tally.Published && st.Tally.Matches != nil })
		if !*st.Tally.Matches {
			t.Fatalf("trustee %d: published %v, own %v", id, st.Tally.PublishedTotals, st.Tally.Totals)
		}
	}
	f.checkSecrets(logs.String())
}

// The console swaps trustee 3's receive key in the roster it shows trustee 1
// (and recomputes the digest to match): trustee 1's check against trustee 3's
// own host catches it, and trustee 1 never deals.
func TestTrusteeRefusesASwappedRosterKey(t *testing.T) {
	var bed atomic.Pointer[trusteeTestBed]
	var evil atomic.Value
	b := newTrusteeTestBed(t, fleetOptions{consoleFor: func(id int) string {
		if id != 1 {
			return ""
		}
		proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b := bed.Load()
			if b == nil {
				http.Error(w, "starting", http.StatusServiceUnavailable)
				return
			}
			rec := httptest.NewRecorder()
			b.h.s.ServeHTTP(rec, r)
			body := rec.Body.Bytes()
			if r.URL.Path == "/api/live/dkg/roster" && rec.Code == 200 {
				var m map[string]any
				_ = json.Unmarshal(body, &m)
				if m["complete"] == true {
					peers := m["peers"].([]any)
					peers[2].(map[string]any)["receive_public_key"] = evil.Load()
					out := b.h.cliOp("dkg-roster", map[string]any{"params": m["params"], "peers": peers})
					m["roster_digest"] = out["roster_digest"]
					body, _ = json.Marshal(m)
				}
			}
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(body)
		}))
		t.Cleanup(proxy.Close)
		return proxy.URL
	}})
	k := b.h.cliOp("trustee-keygen", map[string]any{"trustee_id": 3, "key_file": filepath.Join(b.h.work, "evil.key")})
	evil.Store(k["receive_public_key"].(string))
	bed.Store(b)
	b.setup()
	for id := 1; id <= 5; id++ {
		b.f.press(id, "join", nil)
	}
	st := b.f.waitFor(1, "the roster alarm", func(st TrusteeStatus) bool { return st.Steps["join"].State == stepBlocked })
	// Trustee 3's own host states its real key: that names the swap. (Trustee
	// 1's digest also differs from every other trustee's.)
	if len(st.Alarms) == 0 || st.Alarms[0].Code != "roster-peer-3" || !strings.Contains(st.Alarms[0].Message, "trustee 3's own host") {
		t.Fatalf("alarms: %+v", st.Alarms)
	}
	for _, e := range st.Ceremony.Roster {
		if e.TrusteeID != 1 && e.PeerCheck != "mismatch" {
			t.Errorf("peer %d check %s: every peer's digest differs from the swapped roster's", e.TrusteeID, e.PeerCheck)
		}
	}
	time.Sleep(200 * time.Millisecond)
	// Nobody dealt: trustee 1 caught the swap, and every other trustee saw
	// trustee 1's digest differ from its own.
	roster := b.h.must(nil, http.MethodGet, "/api/live/dkg/roster", b.h.tokens[1], nil)
	if roster["complete"] != true || roster["dealt"] != nil {
		t.Fatalf("a trustee dealt over a roster its peers did not confirm: %v", roster["dealt"])
	}
	if code, _ := b.f.call(b.f.procs[0], http.MethodPost, "/api/trustee/join", nil); code != http.StatusConflict {
		t.Fatalf("join again after the alarm: %d", code)
	}
}

// A peer whose roster digest differs: the trustee refuses to deal.
func TestTrusteeRefusesAPeerWithAnotherDigest(t *testing.T) {
	var bed atomic.Pointer[trusteeTestBed]
	fake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := bed.Load()
		if b == nil {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		v := b.f.procs[1].T.PeerView() // trustee 2's own statement, with another digest
		if v.RosterDigest != "" {
			v.RosterDigest = strings.Repeat("ab", 32)
		}
		writeJSONResp(w, 200, v)
	}))
	t.Cleanup(fake.Close)
	b := newTrusteeTestBed(t, fleetOptions{peerFor: func(id, peer int) string {
		if id == 4 && peer == 2 {
			return fake.URL
		}
		return ""
	}})
	bed.Store(b)
	b.setup()
	for id := 1; id <= 5; id++ {
		b.f.press(id, "join", nil)
	}
	st := b.f.waitFor(4, "the digest alarm", func(st TrusteeStatus) bool { return st.Steps["join"].State == stepBlocked })
	if st.Alarms[0].Code != "roster-peer-2" || !strings.Contains(st.Alarms[0].Message, "computed roster") || st.Ceremony.Dealt {
		t.Fatalf("status: %+v %+v", st.Alarms, st.Ceremony)
	}
}

// lyingChain lies to one trustee about one read.
type lyingChain struct {
	trusteeChain
	dkg     func(string) (string, error)
	partial func(eid, contest, trustee string) (string, error)
	ballots func(eid string, ns []string) ([]string, error)
	list    func(eid string, size int, bm string) (clientsdk.NullifierPage, error)
}

func (c lyingChain) GetDKGTranscript(id string) (string, error) {
	if c.dkg != nil {
		return c.dkg(id)
	}
	return c.trusteeChain.GetDKGTranscript(id)
}

func (c lyingChain) GetPartialDecryption(id, contest, trustee string) (string, error) {
	if c.partial != nil {
		return c.partial(id, contest, trustee)
	}
	return c.trusteeChain.GetPartialDecryption(id, contest, trustee)
}

func (c lyingChain) ListNullifiers(id string, size int, bm string) (clientsdk.NullifierPage, error) {
	if c.list != nil {
		return c.list(id, size, bm)
	}
	return c.trusteeChain.ListNullifiers(id, size, bm)
}

// A transcript on the chain that is not the one the trustee's keys make: an
// alarm, and Decrypt and Sign are blocked.
func TestTrusteeAlarmsOnATranscriptThatDiffersFromItsAck(t *testing.T) {
	var bed atomic.Pointer[trusteeTestBed]
	b := newTrusteeTestBed(t, fleetOptions{chainFor: func(id int, c trusteeChain) trusteeChain {
		if id != 5 {
			return c
		}
		return lyingChain{trusteeChain: c, dkg: func(eid string) (string, error) {
			h, err := c.GetDKGTranscript(eid)
			if err != nil {
				return h, err
			}
			raw, _ := hex.DecodeString(h)
			var tr pb.DKGTranscript
			_ = proto.Unmarshal(raw, &tr)
			// Dealer 1's constant commitment replaced by another valid point.
			b := bed.Load()
			k := b.h.cliOp("trustee-keygen", map[string]any{"trustee_id": 1, "key_file": filepath.Join(b.h.work, fmt.Sprintf("x-%d.key", time.Now().UnixNano()))})
			pt, _ := hex.DecodeString(k["receive_public_key"].(string))
			tr.TrusteeCommitments[0].CoefficientCommitments[0] = pt
			out, _ := proto.Marshal(&tr)
			return hex.EncodeToString(out), nil
		}}
	}})
	bed.Store(b)
	b.setup()
	for id := 1; id <= 5; id++ {
		b.f.press(id, "join", nil)
	}
	st := b.f.waitFor(5, "the transcript alarm", func(st TrusteeStatus) bool { return st.Steps["join"].State == stepBlocked })
	if st.Ceremony.TranscriptCheck != "mismatch" || st.Alarms[0].Code != "transcript" {
		t.Fatalf("status: %+v %+v", st.Ceremony, st.Alarms)
	}
	for id := 1; id <= 4; id++ {
		b.f.waitStep(id, "join", stepDone)
	}
	b.vote()
	b.close()
	for _, action := range []string{"decrypt", "sign"} {
		code, out := b.f.call(b.f.procs[4], http.MethodPost, "/api/trustee/"+action, map[string]any{})
		if code != http.StatusConflict {
			t.Fatalf("%s after a transcript alarm: %d %v", action, code, out)
		}
	}
	// It never combines either, so there is nothing for it to sign.
	for id := 1; id <= 3; id++ {
		b.f.decrypt(id)
	}
	time.Sleep(300 * time.Millisecond)
	if st := b.f.status(5); len(st.Tally.Totals) != 0 || st.Tally.ReadyToSign {
		t.Fatalf("a blocked trustee combined: %+v", st.Tally)
	}
}

// Decrypt is refused before the chain says closed, on a position under
// --min-ballots, and over a second, different ballot set; the same set again
// gives the same partial.
func TestTrusteeDecryptRefusals(t *testing.T) {
	var hide atomic.Bool
	var crashOnce atomic.Bool
	b := newTrusteeTestBed(t, fleetOptions{
		minBallots: func(id int) int {
			if id == 4 {
				return 4 // 3 ballots per position: refused
			}
			return 0
		},
		chainFor: func(id int, c trusteeChain) trusteeChain {
			if id != 2 {
				return c
			}
			return lyingChain{trusteeChain: c, list: func(eid string, size int, bm string) (clientsdk.NullifierPage, error) {
				page, err := c.ListNullifiers(eid, size, bm)
				if err == nil && hide.Load() && len(page.Nullifiers) > 0 {
					page.Nullifiers = page.Nullifiers[1:]
				}
				return page, err
			}}
		},
		crash: func(id int, point string) bool {
			return id == 3 && point == "partial-saved" && crashOnce.CompareAndSwap(false, true)
		},
	})
	f := b.f
	b.setup()
	f.ceremony()
	b.vote()
	// Before close: refused at once, from the chain's status.
	code, out := f.call(f.procs[0], http.MethodPost, "/api/trustee/decrypt", nil)
	if code != http.StatusConflict || !strings.Contains(fmt.Sprint(out["error"]), "not closed") {
		t.Fatalf("decrypt while open: %d %v", code, out)
	}
	b.close()

	// Under --min-ballots.
	f.press(4, "decrypt", nil)
	st := f.waitFor(4, "the refusal", func(st TrusteeStatus) bool { return st.Steps["decrypt"].State == stepRefused })
	if !strings.Contains(st.Steps["decrypt"].Error, "fewer than --min-ballots 4") || st.Decryption.PartialComputed {
		t.Fatalf("min-ballots: %+v", st.Steps["decrypt"])
	}

	// Trustee 2 decrypts over the full set, then the chain shows it a set
	// with one ballot fewer: a second decryption is refused.
	st2 := f.decrypt(2)
	hide.Store(true)
	if err := f.procs[1].T.update(func(p *trusteeProgress) {
		// As if the process had recorded the set and died before the partial:
		// the next run must decrypt again, and meets another set.
		p.Partial, p.PartialPosted, p.PartialReadBack = nil, false, ""
		p.Steps["decrypt"] = stepStatus{State: stepFailed}
	}); err != nil {
		t.Fatal(err)
	}
	f.press(2, "decrypt", nil)
	st = f.waitFor(2, "the second-set refusal", func(st TrusteeStatus) bool { return st.Steps["decrypt"].State == stepRefused })
	if !strings.Contains(st.Steps["decrypt"].Error, "already used ballot set") || st.Decryption.BallotsDigest != st2.Decryption.BallotsDigest {
		t.Fatalf("second set: %+v %s", st.Steps["decrypt"], st.Decryption.BallotsDigest)
	}
	hide.Store(false)

	// Trustee 3 is killed after computing its partial and before posting it:
	// the restart posts that same partial.
	f.press(3, "decrypt", nil)
	f.waitFor(3, "the kill", func(TrusteeStatus) bool { return crashOnce.Load() })
	time.Sleep(50 * time.Millisecond)
	var saved json.RawMessage
	_ = readJSON(filepath.Join(f.procs[2].T.electionDir(b.h.must(nil, http.MethodGet, "/api/live/election", "", nil)["election_id"].(string)), trusteeProgressFile), &struct {
		Partial *json.RawMessage `json:"partial"`
	}{&saved})
	f.restart(3)
	f.waitStep(3, "decrypt", stepDone)
	var after json.RawMessage
	_ = readJSON(filepath.Join(f.procs[2].T.electionDir(st.Election.ElectionID), trusteeProgressFile), &struct {
		Partial *json.RawMessage `json:"partial"`
	}{&after})
	if len(saved) == 0 || !bytes.Equal(saved, after) {
		t.Fatal("the restarted trustee posted another partial than the one it computed")
	}
	// And pressing Decrypt again on a finished decryption changes nothing.
	f.press(3, "decrypt", nil)
	time.Sleep(100 * time.Millisecond)
	if st := f.status(3); st.Steps["decrypt"].State != stepDone {
		t.Fatalf("decrypt again: %+v", st.Steps["decrypt"])
	}
}

// The partial read back from the chain is not the one the trustee computed:
// an alarm.
func TestTrusteeAlarmsOnAPartialReadBackMismatch(t *testing.T) {
	b := newTrusteeTestBed(t, fleetOptions{chainFor: func(id int, c trusteeChain) trusteeChain {
		if id != 1 {
			return c
		}
		return lyingChain{trusteeChain: c, partial: func(eid, contest, trustee string) (string, error) {
			h, err := c.GetPartialDecryption(eid, contest, trustee)
			if err != nil || trustee != "1" {
				return h, err
			}
			raw, _ := hex.DecodeString(h)
			raw[len(raw)-1] ^= 1
			return hex.EncodeToString(raw), nil
		}}
	}})
	f := b.f
	b.setup()
	f.ceremony()
	b.vote()
	b.close()
	f.press(1, "decrypt", nil)
	st := f.waitFor(1, "the read-back alarm", func(st TrusteeStatus) bool { return st.Steps["decrypt"].State == stepBlocked })
	if st.Decryption.PartialReadBack != "mismatch" || st.Alarms[0].Code != "partial-readback" {
		t.Fatalf("status: %+v %+v", st.Decryption, st.Alarms)
	}
}

// Nothing is signed without the trustee's press, a press must name the
// totals shown, and a console that refuses the signature (its totals differ)
// raises an alarm.
func TestTrusteeSignsOnlyOnThePressAndAlarmsOnTotals(t *testing.T) {
	var bed atomic.Pointer[trusteeTestBed]
	b := newTrusteeTestBed(t, fleetOptions{consoleFor: func(id int) string {
		if id != 3 {
			return ""
		}
		proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b := bed.Load()
			if b == nil {
				http.Error(w, "starting", http.StatusServiceUnavailable)
				return
			}
			if r.URL.Path == "/api/live/tally-sig" {
				writeJSONResp(w, http.StatusBadRequest, map[string]string{"error": "the signature is refused: tally-assemble: the totals differ"})
				return
			}
			b.h.s.ServeHTTP(w, r)
		}))
		t.Cleanup(proxy.Close)
		return proxy.URL
	}})
	bed.Store(b)
	f := b.f
	b.setup()
	f.ceremony()
	b.vote()
	b.close()
	for id := 1; id <= 3; id++ {
		f.decrypt(id)
	}
	for id := 1; id <= 5; id++ {
		st := f.waitFor(id, "its combine", func(st TrusteeStatus) bool { return st.Tally.ReadyToSign })
		if st.Tally.SignaturePosted || st.Steps["sign"].State != stepWaiting {
			t.Fatalf("trustee %d signed without a press: %+v", id, st.Tally)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if el := b.h.must(nil, http.MethodGet, "/api/live/election", "", nil); el["counts"].(map[string]any)["tally_signatures"] != 0.0 {
		t.Fatalf("signatures before any press: %v", el["counts"])
	}
	// A press over other totals is refused.
	if code, _ := f.call(f.procs[0], http.MethodPost, "/api/trustee/sign", map[string]any{"totals": []int{3, 0, 0, 0, 0, 3}}); code != http.StatusConflict {
		t.Fatalf("sign over other totals: %d", code)
	}
	st := f.status(3)
	f.press(3, "sign", map[string]any{"totals": st.Tally.Totals})
	st = f.waitFor(3, "the totals alarm", func(st TrusteeStatus) bool { return st.Steps["sign"].State == stepBlocked })
	if st.Alarms[0].Code != "tally-totals" || st.Tally.SignaturePosted {
		t.Fatalf("status: %+v %+v", st.Alarms, st.Tally)
	}
}

// The console abandons the ceremony and starts a new election: each trustee
// follows it with a fresh receive key, and the old folder is left as it was.
func TestTrusteeFollowsANewElection(t *testing.T) {
	b := newTrusteeTestBed(t, fleetOptions{})
	f := b.f
	first := b.setup()
	for id := 1; id <= 4; id++ { // trustee 5 never joins: the ceremony is stuck
		f.press(id, "join", nil)
	}
	f.waitFor(1, "the roster wait", func(st TrusteeStatus) bool {
		return st.Steps["join"].State == stepWaiting && strings.Contains(st.Steps["join"].Detail, "4 of 5")
	})
	oldKeys := map[int]string{}
	oldHash := map[int]string{}
	for id := 1; id <= 4; id++ {
		oldKeys[id] = f.status(id).Fingerprints.ReceiveKey
	}
	b.h.must(b.admin, http.MethodPost, "/api/live/abandon", "", nil)
	f.waitFor(1, "the abandon", func(st TrusteeStatus) bool { return st.Steps["join"].State == stepFailed })
	time.Sleep(100 * time.Millisecond)
	for id := 1; id <= 4; id++ {
		f.procs[id-1].T.Close() // a quiet folder to hash
		oldHash[id] = hashTree(t, f.procs[id-1].T.electionDir(first))
		f.start(f.procs[id-1])
	}
	second := b.setup()
	f.press(5, "join", nil)
	for id := 1; id <= 5; id++ {
		st := f.waitStep(id, "join", stepDone)
		if st.Election.ElectionID != second || (id <= 4 && st.Fingerprints.ReceiveKey == oldKeys[id]) {
			t.Fatalf("trustee %d on %s with key %s (old %s)", id, st.Election.ElectionID, st.Fingerprints.ReceiveKey, oldKeys[id])
		}
	}
	for id := 1; id <= 4; id++ {
		if h := hashTree(t, f.procs[id-1].T.electionDir(first)); h != oldHash[id] {
			t.Fatalf("trustee %d's folder for the abandoned election changed", id)
		}
	}
}

func hashTree(t *testing.T, dir string) string {
	h := sha256.New()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		fmt.Fprintf(h, "%s %o\n", rel, info.Mode())
		if !info.IsDir() {
			data, _ := os.ReadFile(path)
			h.Write(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// --- start-up and HTTP rules (no binary needed) --------------------------------

func TestTrusteeTokenFileAndStateDirModes(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte(strings.Repeat("a", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrusteeTokenFile(tok); err == nil || !strings.Contains(err.Error(), "want 0600") {
		t.Fatalf("a 0644 token file: %v", err)
	}
	_ = os.Chmod(tok, 0o600)
	if got, err := LoadTrusteeTokenFile(tok); err != nil || got != strings.Repeat("a", 64) {
		t.Fatalf("a 0600 token file: %q %v", got, err)
	}
	if err := os.WriteFile(tok, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrusteeTokenFile(tok); err == nil {
		t.Fatal("a short token was accepted")
	}

	loose := filepath.Join(dir, "loose")
	_ = os.Mkdir(loose, 0o755)
	if err := ensurePrivateDir(loose); err == nil || !strings.Contains(err.Error(), "want 0700") {
		t.Fatalf("a 0755 state dir: %v", err)
	}
	fresh := filepath.Join(dir, "fresh", "state")
	if err := ensurePrivateDir(fresh); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(fresh); info.Mode().Perm() != 0o700 {
		t.Fatalf("a new state dir is mode %o", info.Mode().Perm())
	}

	base := TrusteeOptions{ID: 1, ConsoleURL: "https://vote.example:8443", Token: strings.Repeat("a", 64), StateDir: fresh,
		Runner: func(context.Context, string, []byte) ([]byte, error) { return nil, nil },
		Dial:   func() (trusteeChain, error) { return nil, nil }}
	for _, bad := range []func(o *TrusteeOptions){
		func(o *TrusteeOptions) { o.ConsoleURL = "http://vote.example:8443" },
		func(o *TrusteeOptions) { o.ConsoleURL = "https://vote.example:8443/api" },
		func(o *TrusteeOptions) { o.Peers = map[int]string{2: "http://t2.example:9002"} },
		func(o *TrusteeOptions) { o.ID = 0 },
		func(o *TrusteeOptions) { o.StateDir = loose },
		func(o *TrusteeOptions) { o.Dial = nil },
	} {
		o := base
		bad(&o)
		if _, err := NewTrusteeService(o); err == nil {
			t.Errorf("options %+v were accepted", o)
		}
	}
	if _, err := NewTrusteeService(base); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTrusteePeers("1=https://a:1,1=https://b:2"); err == nil {
		t.Fatal("a peer named twice was accepted")
	}
	if m, err := ParseTrusteePeers("1=https://a:1, 2=https://b:2"); err != nil || len(m) != 2 {
		t.Fatalf("peers: %v %v", m, err)
	}
	if _, err := CheckTrusteeServeOptions(ServeOptions{Addr: "0.0.0.0:9001"}); err == nil {
		t.Fatal("a non-loopback trustee without TLS was accepted")
	}
	if w, err := CheckTrusteeServeOptions(ServeOptions{Addr: "127.0.0.1:9001"}); err != nil || w == "" {
		t.Fatalf("loopback without TLS: %q %v", w, err)
	}
}

// Every route is in the access table, behind the guard; only this trustee's
// own account can act; the peer route says nothing secret.
func TestTrusteeRouteAccess(t *testing.T) {
	dir := t.TempDir()
	web := filepath.Join(dir, "web", "trustee")
	_ = os.MkdirAll(web, 0o755)
	_ = os.WriteFile(filepath.Join(web, "index.html"), []byte("<p>trustee</p>"), 0o644)
	hash := hashFor(t, "pw")
	write := func(name string, users []User) string {
		data, _ := json.Marshal(users)
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, data, 0o600)
		return p
	}
	T, err := NewTrusteeService(TrusteeOptions{ID: 2, ConsoleURL: "https://vote.example:8443", Token: strings.Repeat("b", 64),
		StateDir: filepath.Join(dir, "state"),
		Runner:   func(context.Context, string, []byte) ([]byte, error) { return nil, nil },
		Dial:     func() (trusteeChain, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]User{
		{{Username: "ban", Role: RoleAdmin, PasswordBcrypt: hash}},
		{{Username: "t3", Role: RoleTrustee, TrusteeID: "3", PasswordBcrypt: hash}},
		{{Username: "v", Role: RoleVoter, PasswordBcrypt: hash}},
	} {
		if _, err := NewTrusteeServer(T, TrusteeServerOptions{AuthFile: write("bad.json", bad)}); err == nil {
			t.Errorf("accounts %v were accepted", bad)
		}
	}
	ts, err := NewTrusteeServer(T, TrusteeServerOptions{
		AuthFile:   write("ok.json", []User{{Username: "trustee2", Role: RoleTrustee, TrusteeID: "2", PasswordBcrypt: hash}}),
		AllowHosts: []string{"t2.example:9002"}, WebDir: filepath.Join(dir, "web"),
	})
	if err != nil {
		t.Fatal(err)
	}
	registered := map[string]bool{}
	for _, p := range ts.routes {
		registered[p] = true
		if _, ok := trusteeRouteAccess[p]; !ok {
			t.Errorf("route %q has no entry in trusteeRouteAccess", p)
		}
	}
	for p := range trusteeRouteAccess {
		if !registered[p] {
			t.Errorf("trusteeRouteAccess names %q, which is not registered", p)
		}
	}
	srv := httptest.NewServer(ts)
	t.Cleanup(srv.Close)
	do := func(c *http.Client, method, path, host, origin string, body string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if c == nil {
			c = http.DefaultClient
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data)
	}
	host := "t2.example:9002"
	if code, _ := do(nil, "GET", "/api/trustee/peer", "evil.example:9002", "", ""); code != 403 {
		t.Fatalf("a Host off the allowlist: %d", code)
	}
	for _, path := range []string{"/api/trustee/status"} {
		if code, _ := do(nil, "GET", path, host, "", ""); code != 401 {
			t.Fatalf("%s without a session: %d", path, code)
		}
	}
	for _, path := range []string{"/api/trustee/join", "/api/trustee/decrypt", "/api/trustee/sign"} {
		if code, _ := do(nil, "POST", path, host, "", ""); code != 401 {
			t.Fatalf("%s without a session: %d", path, code)
		}
	}
	if code, body := do(nil, "GET", "/api/trustee/peer", host, "", ""); code != 200 || !strings.Contains(body, `"trustee_id":2`) {
		t.Fatalf("peer: %d %s", code, body)
	}
	if code, body := do(nil, "GET", "/trustee/", host, "", ""); code != 200 || !strings.Contains(body, "trustee") {
		t.Fatalf("app: %d %s", code, body)
	}
	if code, _ := do(nil, "GET", "/api/live/election", host, "", ""); code != 404 {
		t.Fatalf("an unknown path: %d", code)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	if code, _ := do(c, "POST", "/api/login", host, "https://evil.example", `{"username":"trustee2","password":"pw"}`); code != 403 {
		t.Fatalf("a cross-origin login: %d", code)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/api/login", strings.NewReader(`{"username":"trustee2","password":"pw"}`))
	req.Host = host
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("login: %v %v", err, resp)
	}
	resp.Body.Close()
	var sessionCookieSeen *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie {
			sessionCookieSeen = ck
		}
	}
	if sessionCookieSeen == nil || sessionCookieSeen.Domain != "" || !sessionCookieSeen.HttpOnly {
		t.Fatalf("session cookie: %+v", sessionCookieSeen)
	}
	// The jar keys cookies by the URL, not the Host header; carry it by hand.
	cookie := sessionCookieSeen.Name + "=" + sessionCookieSeen.Value
	get := func(path string) (int, string) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.Host = host
		req.Header.Set("Cookie", cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data)
	}
	if code, body := get("/api/me"); code != 200 || !strings.Contains(body, `"trustee_id":"2"`) {
		t.Fatalf("me: %d %s", code, body)
	}
	if code, body := get("/api/trustee/status"); code != 200 || !strings.Contains(body, `"trustee_id":2`) {
		t.Fatalf("status: %d %s", code, body)
	}
	// A session of another trustee process means nothing here.
	other := newAuthState(map[string]User{"t3": {Username: "t3", Role: RoleTrustee, TrusteeID: "3"}})
	tok, _ := other.create(User{Username: "t3", Role: RoleTrustee, TrusteeID: "3"})
	cookie = sessionCookie + "=" + tok
	if code, _ := get("/api/trustee/status"); code != 401 {
		t.Fatalf("another process's session: %d", code)
	}
}

// The process refuses to act when the console says its token is another
// trustee's.
func TestTrusteeIdentityFromTheConsole(t *testing.T) {
	b := newTrusteeTestBed(t, fleetOptions{})
	b.setup()
	p := b.f.procs[0]
	o := p.opts
	o.ID = 2 // trustee 1's token, claimed by a process with --id 2
	o.StateDir = filepath.Join(b.h.work, "mixed-up")
	T, err := NewTrusteeService(o)
	if err != nil {
		t.Fatal(err)
	}
	err = T.CheckIdentity(context.Background())
	if err == nil || !strings.Contains(err.Error(), "trustee 1's, but this process is --id 2") {
		t.Fatalf("identity: %v", err)
	}
	o.Token = strings.Repeat("c", 64)
	o.ID = 1
	T, _ = NewTrusteeService(o)
	if err := T.CheckIdentity(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("an unknown token: %v", err)
	}
}

// I1: the answer to a post is lost after the console recorded it (the process
// is killed between the 200 and saving the flag), and the restart comes only
// after the console has moved on, so the re-post is refused. Trustee 2's ack
// is re-posted after the election opened: the chain's transcript decides, and
// it goes on to decrypt and sign. Trustee 4's partial is re-posted after the
// tally was published: the byte-equal partial on the chain counts as posted.
// Trustee 5 is in the same spot as trustee 2 but the chain shows it a
// transcript whose first dealer's commitment is replaced: the encoding or
// joint-key check still ends in the alarm.
func TestTrusteeLostAnswersAfterPosting(t *testing.T) {
	var bed atomic.Pointer[trusteeTestBed]
	var crashMu sync.Mutex
	crashed := map[string]bool{}
	hit := func(id int, point string) bool {
		crashMu.Lock()
		defer crashMu.Unlock()
		return crashed[fmt.Sprint(id, point)]
	}
	b := newTrusteeTestBed(t, fleetOptions{
		crash: func(id int, point string) bool {
			want := (id == 2 || id == 5) && point == "ack-posted" || id == 4 && point == "partial-posted"
			crashMu.Lock()
			defer crashMu.Unlock()
			k := fmt.Sprint(id, point)
			if !want || crashed[k] {
				return false
			}
			crashed[k] = true
			return true
		},
		chainFor: func(id int, c trusteeChain) trusteeChain {
			if id != 5 {
				return c
			}
			return lyingChain{trusteeChain: c, dkg: func(eid string) (string, error) {
				h, err := c.GetDKGTranscript(eid)
				if err != nil {
					return h, err
				}
				raw, _ := hex.DecodeString(h)
				var tr pb.DKGTranscript
				_ = proto.Unmarshal(raw, &tr)
				b := bed.Load()
				k := b.h.cliOp("trustee-keygen", map[string]any{"trustee_id": 1, "key_file": filepath.Join(b.h.work, fmt.Sprintf("y-%d.key", time.Now().UnixNano()))})
				pt, _ := hex.DecodeString(k["receive_public_key"].(string))
				tr.TrusteeCommitments[0].CoefficientCommitments[0] = pt
				out, _ := proto.Marshal(&tr)
				return hex.EncodeToString(out), nil
			}}
		},
	})
	bed.Store(b)
	f := b.f
	b.setup()
	for id := 1; id <= 5; id++ {
		f.press(id, "join", nil)
	}
	for _, id := range []int{2, 5} {
		f.waitFor(id, "the kill after the ack", func(TrusteeStatus) bool { return hit(id, "ack-posted") })
	}
	// Both acks reached the console, so the others finish and it opens.
	for _, id := range []int{1, 3, 4} {
		f.waitStep(id, "join", stepDone)
	}
	if el := b.h.must(nil, http.MethodGet, "/api/live/election", "", nil); el["state"] != LiveOpen {
		t.Fatalf("console state %v", el["state"])
	}
	f.restart(2)
	f.restart(5)
	st := f.waitStep(2, "join", stepDone)
	if st.Ceremony.TranscriptCheck != "ok" || !st.Ceremony.Acknowledged {
		t.Fatalf("trustee 2 after the lost ack answer: %+v", st.Ceremony)
	}
	st = f.waitFor(5, "the transcript alarm", func(st TrusteeStatus) bool { return st.Steps["join"].State == stepBlocked })
	if st.Ceremony.TranscriptCheck != "mismatch" || st.Alarms[0].Code != "transcript" {
		t.Fatalf("trustee 5: %+v %+v", st.Ceremony, st.Alarms)
	}

	b.vote()
	b.close()
	f.decrypt(2) // the trustee whose ack answer was lost decrypts...
	f.press(4, "decrypt", nil)
	f.waitFor(4, "the kill after the partial", func(TrusteeStatus) bool { return hit(4, "partial-posted") })
	f.decrypt(1)
	f.sign(1, wantTotals)
	f.sign(2, wantTotals) // ...and signs
	if res := f.sign(3, wantTotals); res["published"] != true {
		t.Fatal("not published after 3 signatures")
	}
	// Trustee 4 comes back after publication: the console refuses the re-post
	// (not closed), and the chain holds its exact partial.
	f.restart(4)
	st = f.waitStep(4, "decrypt", stepDone)
	if !st.Decryption.PartialRecorded || st.Decryption.PartialReadBack != "ok" {
		t.Fatalf("trustee 4 after the lost partial answer: %+v", st.Decryption)
	}
	for _, id := range []int{1, 2, 3, 4} {
		st := f.waitFor(id, "the published tally", func(st TrusteeStatus) bool { return st.Tally.Published && st.Tally.Matches != nil })
		if !*st.Tally.Matches {
			t.Fatalf("trustee %d: published %v, own %v", id, st.Tally.PublishedTotals, st.Tally.Totals)
		}
	}
}

// M1: a peer that read another ballot set: decryption is blocked before any
// partial is computed.
func TestTrusteeRefusesAPeerWithAnotherBallotSet(t *testing.T) {
	var bed atomic.Pointer[trusteeTestBed]
	fake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := bed.Load()
		if b == nil {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		v := b.f.procs[0].T.PeerView() // trustee 1's own statement, with another ballot set
		if v.BallotsDigest != "" {
			v.BallotsDigest = strings.Repeat("cd", 32)
		}
		writeJSONResp(w, 200, v)
	}))
	t.Cleanup(fake.Close)
	b := newTrusteeTestBed(t, fleetOptions{peerFor: func(id, peer int) string {
		if id == 2 && peer == 1 {
			return fake.URL
		}
		return ""
	}})
	bed.Store(b)
	f := b.f
	b.setup()
	f.ceremony()
	b.vote()
	b.close()
	f.decrypt(1)
	f.press(2, "decrypt", nil)
	st := f.waitFor(2, "the ballot-set alarm", func(st TrusteeStatus) bool { return st.Steps["decrypt"].State == stepBlocked })
	if len(st.Alarms) == 0 || st.Alarms[0].Code != "ballots-peer-1" || st.Decryption.PartialComputed {
		t.Fatalf("status: %+v %+v", st.Alarms, st.Decryption)
	}
	el := b.h.must(nil, http.MethodGet, "/api/live/election", "", nil)
	if el["counts"].(map[string]any)["trustees_decrypted"] != 1.0 {
		t.Fatalf("trustees decrypted: %v", el["counts"])
	}
}

// M2: a --peers URL that answers as another trustee is a visible wait, not an
// alarm that ends the election, and the start-up check names it.
func TestTrusteeWrongPeerURLWaits(t *testing.T) {
	b := newTrusteeTestBed(t, fleetOptions{})
	f := b.f
	// Trustee 4's --peers sends peer 2 to trustee 3's host.
	f.procs[3].opts.Peers[2] = f.procs[2].srv.URL
	f.restart(4)
	warn := f.procs[3].T.PeerWarnings(context.Background())
	if len(warn) != 1 || !strings.Contains(warn[0], "--peers 2="+f.procs[2].srv.URL+" answers as trustee 3") {
		t.Fatalf("start-up warnings: %v", warn)
	}
	b.setup()
	for id := 1; id <= 5; id++ {
		f.press(id, "join", nil)
	}
	st := f.waitFor(4, "the wait on peer 2", func(st TrusteeStatus) bool {
		return st.Steps["join"].State == stepWaiting && strings.Contains(st.Steps["join"].Detail, "trustee(s) 2")
	})
	for _, e := range st.Ceremony.Roster {
		if e.TrusteeID == 2 && !strings.Contains(e.Detail, "answers as trustee 3") {
			t.Fatalf("peer 2 detail: %q", e.Detail)
		}
	}
	if len(st.Alarms) != 0 {
		t.Fatalf("alarms: %+v", st.Alarms)
	}
	// Fixed and restarted, it goes through.
	f.procs[3].opts.Peers[2] = f.procs[1].srv.URL
	f.restart(4)
	f.waitStep(4, "join", stepDone)
}

// I1 (rehearsal 1): a trustee's view of its peers' ballot sets is read again
// on every poll from the close on, not only at its own decrypt. A peer that
// decrypts later shows as the same ballots; a trustee that never decrypts
// still reports what each peer states; a peer that does not answer says so.
func TestTrusteePeerBallotChecksFollowLaterDecrypts(t *testing.T) {
	b := newTrusteeTestBed(t, fleetOptions{})
	f := b.f
	b.setup()
	f.ceremony()
	b.vote()
	b.close()
	peer := func(st TrusteeStatus, id int) TrusteePeerBallotCheck {
		for _, c := range st.Decryption.PeerChecks {
			if c.TrusteeID == id {
				return c
			}
		}
		return TrusteePeerBallotCheck{TrusteeID: id}
	}
	// Before anyone decrypts, a closed election already shows each peer's
	// statement: none has a ballot set yet.
	f.waitFor(4, "peers read after the close", func(st TrusteeStatus) bool {
		return peer(st, 1).State == "waiting" && peer(st, 5).State == "waiting"
	})
	// Trustee 1 decrypts first. Trustee 4, with no set of its own yet (its
	// combine waits for the threshold), reports trustee 1's set as stated.
	one := f.decrypt(1)
	st := f.waitFor(4, "peer 1 reported", func(st TrusteeStatus) bool { return peer(st, 1).State == "reported" })
	if c := peer(st, 1); !strings.Contains(c.Detail, one.Fingerprints.Ballots) {
		t.Fatalf("trustee 4 on peer 1: %+v, want ballot set %s named", c, one.Fingerprints.Ballots)
	}
	if c := peer(st, 2); c.State != "waiting" || !strings.Contains(c.Detail, "no ballot set") {
		t.Fatalf("trustee 4 on peer 2: %+v", c)
	}
	// Trustees 2 and 3 decrypt after trustee 1: trustee 1 sees them.
	f.decrypt(2)
	f.decrypt(3)
	f.waitFor(1, "peers 2 and 3 with the same ballots", func(st TrusteeStatus) bool {
		return peer(st, 2).State == "ok" && peer(st, 3).State == "ok"
	})
	// After the threshold every trustee combines over the chain's set, so
	// trustee 4, which never decrypted, ends with the same set as every peer.
	st = f.waitFor(4, "every peer with the same ballots", func(st TrusteeStatus) bool {
		for _, id := range []int{1, 2, 3, 5} {
			if peer(st, id).State != "ok" {
				return false
			}
		}
		return true
	})
	if len(st.Alarms) != 0 {
		t.Fatalf("trustee 4 alarms: %+v", st.Alarms)
	}
	// Trustee 5's process stops answering: the others say it cannot be reached.
	f.procs[4].T.Close()
	f.procs[4].handler.Store(nil)
	st = f.waitFor(1, "peer 5 unreachable", func(st TrusteeStatus) bool { return peer(st, 5).State == "unreachable" })
	if c := peer(st, 5); !strings.Contains(c.Detail, "not reachable") {
		t.Fatalf("trustee 1 on peer 5: %+v", c)
	}
}
