package campaign

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// End to end through the HTTP routes only, with the real saksi-demo binary.
// The test plays five trustee processes and three voters by calling the CLI
// for their crypto, exactly as task 4's trustee processes and the phones do.
//
// TestLiveElectionEndToEnd runs against oracleChain, an in-memory stand-in for
// the chaincode. TestLiveElectionOnFabric runs the same flow against a real
// Fabric network (SAKSI_LIVE_FABRIC=1): that one proves the chaincode, not a
// stand-in, accepts and refuses what the plan says.

// --- the stand-in chain ---------------------------------------------------------

// oracleChain is an in-memory bulletin board. It is NOT the chaincode: it
// stores bytes as the chaincode does (unchanged, keyed by nullifier) and
// applies the gates the demo shows, using the real auditor (saksi-demo live
// aggregate) as its CDS check and counting a tally's signatures without
// verifying them. Only the Fabric test proves the real gates.
type oracleChain struct {
	t    *testing.T
	demo string

	mu       sync.Mutex
	params   map[string]string
	status   map[string]string
	dkg      map[string]string
	ballots  map[string]map[string]string // election -> nullifier -> hex
	order    map[string][]string
	partials map[string]string // election/contest/trustee -> hex
	tally    map[string]string
	machine  map[string]string // election -> registered machine fingerprint
	block    uint64
	submits  []string // every function submitted, in order
	bytesIn  [][]byte // every SubmitBallot argument, decoded
}

func newOracleChain(t *testing.T, demo string) *oracleChain {
	return &oracleChain{t: t, demo: demo,
		params: map[string]string{}, status: map[string]string{}, dkg: map[string]string{},
		ballots: map[string]map[string]string{}, order: map[string][]string{},
		partials: map[string]string{}, tally: map[string]string{}, machine: map[string]string{}}
}

// oracleMachineFP is the fingerprint the oracle reports for the console's
// ballot identity: every submit reaches the oracle as that one machine.
var oracleMachineFP = strings.Repeat("cd", 32)

func (c *oracleChain) MachineFingerprint() string { return oracleMachineFP }

func (c *oracleChain) GetPrecinctMachine(id string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if fp, ok := c.machine[id]; ok {
		return fp, nil
	}
	return "", fmt.Errorf("no precinct machine registered for election %q", id)
}

type oracleRefusal struct{ msg string }

func (e oracleRefusal) Error() string { return e.msg }

func (c *oracleChain) Submit(fn string, args ...string) (clientsdk.Receipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.submits = append(c.submits, fn)
	if err := c.apply(fn, args); err != nil {
		return clientsdk.Receipt{}, err
	}
	c.block++
	return clientsdk.Receipt{TxID: fmt.Sprintf("tx-%d", c.block), BlockNumber: c.block}, nil
}

func refuse(gate, format string, args ...any) error {
	return oracleRefusal{"failed to endorse transaction; gate=" + gate + ": " + fmt.Sprintf(format, args...)}
}

func (c *oracleChain) apply(fn string, args []string) error {
	switch fn {
	case "CreateElection":
		var p pb.ElectionParameters
		raw, _ := hex.DecodeString(args[0])
		if err := proto.Unmarshal(raw, &p); err != nil {
			return refuse("decode", "%v", err)
		}
		if _, ok := c.params[p.ElectionId]; ok {
			return oracleRefusal{"election " + p.ElectionId + " already exists"}
		}
		c.params[p.ElectionId], c.status[p.ElectionId] = args[0], "open"
		c.ballots[p.ElectionId] = map[string]string{}
	case "RegisterPrecinctMachine":
		id, fp := args[0], args[1]
		if _, ok := c.params[id]; !ok {
			return refuse("election-exists", "no election found with id %q", id)
		}
		if _, ok := c.machine[id]; ok {
			return refuse("machine-duplicate", "a precinct machine is already registered for election %q", id)
		}
		if len(c.ballots[id]) > 0 || c.status[id] != "open" {
			return refuse("machine-window", "election %q: a precinct machine can only be registered before the first ballot", id)
		}
		c.machine[id] = fp
	case "PublishDKGTranscript":
		var d pb.DKGTranscript
		raw, _ := hex.DecodeString(args[0])
		if err := proto.Unmarshal(raw, &d); err != nil {
			return refuse("decode", "%v", err)
		}
		if _, ok := c.dkg[d.ElectionId]; ok {
			return refuse("dkg-duplicate", "already published")
		}
		c.dkg[d.ElectionId] = args[0]
	case "SubmitBallot":
		raw, err := hex.DecodeString(args[0])
		if err != nil {
			return refuse("decode", "ballot is not valid hex")
		}
		c.bytesIn = append(c.bytesIn, raw)
		var b pb.Ballot
		if err := proto.Unmarshal(raw, &b); err != nil {
			return refuse("decode", "decode ballot: %v", err)
		}
		id := b.ElectionId
		// The caller gate: the submitter is always oracleMachineFP.
		switch fp, ok := c.machine[id]; {
		case !ok:
			return refuse("caller", "no precinct machine is registered for election %q", id)
		case fp != oracleMachineFP:
			return refuse("caller", "caller is not this precinct's machine for election %q", id)
		}
		if c.status[id] != "open" {
			return refuse("election-open", "election %q is not open", id)
		}
		n := hex.EncodeToString(b.CredentialPresentation.GetNullifier().GetValue())
		if _, spent := c.ballots[id][n]; spent {
			return refuse("nullifier", "nullifier %s already spent", n)
		}
		if c.demo != "" { // the unit tests' fake ballots carry no proofs
			var out bytes.Buffer
			cmd := exec.Command(c.demo, "live", "aggregate")
			in, _ := json.Marshal(map[string]any{"params": c.params[id], "dkg": c.dkg[id], "ballots": []string{args[0]}})
			cmd.Stdin, cmd.Stderr = bytes.NewReader(in), &out
			if err := cmd.Run(); err != nil {
				if strings.Contains(out.String(), "cds") {
					return refuse("cds", "%s", out.String())
				}
				return refuse("shape", "%s", out.String())
			}
		}
		c.ballots[id][n] = hex.EncodeToString(raw) // stored as submitted
		c.order[id] = append(c.order[id], n)
	case "CloseElection":
		if c.status[args[0]] == "closed" {
			return oracleRefusal{"election is already closed"}
		}
		c.status[args[0]] = "closed"
	case "SubmitPartialDecryption":
		var p pb.PartialDecryption
		raw, _ := hex.DecodeString(args[1])
		if err := proto.Unmarshal(raw, &p); err != nil {
			return refuse("decode", "%v", err)
		}
		if c.status[args[0]] != "closed" {
			return refuse("election-closed", "not closed")
		}
		k := args[0] + "/" + p.ContestId + "/" + p.TrusteeId
		if _, ok := c.partials[k]; ok {
			return refuse("partial-duplicate", "duplicate")
		}
		c.partials[k] = args[1]
	case "PublishTally":
		var tr pb.TallyResult
		raw, _ := hex.DecodeString(args[0])
		if err := proto.Unmarshal(raw, &tr); err != nil {
			return oracleRefusal{"decode tally"}
		}
		if _, ok := c.tally[tr.ElectionId]; ok {
			return oracleRefusal{fmt.Sprintf("failed to endorse transaction; a tally is already published for election %q", tr.ElectionId)}
		}
		var p pb.ElectionParameters
		praw, _ := hex.DecodeString(c.params[tr.ElectionId])
		_ = proto.Unmarshal(praw, &p)
		if got := len(tr.Signatures); got < int(p.Threshold) {
			return oracleRefusal{fmt.Sprintf("failed to endorse transaction; tally has %d valid trustee signatures, threshold is %d", got, p.Threshold)}
		}
		c.tally[tr.ElectionId] = args[0]
	default:
		return fmt.Errorf("oracle: unknown function %s", fn)
	}
	return nil
}

func (c *oracleChain) get(m map[string]string, k, what string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := m[k]
	if !ok {
		return "", fmt.Errorf("no %s found for election %q", what, k)
	}
	return v, nil
}

func (c *oracleChain) GetElection(id string) (string, error) {
	return c.get(c.params, id, "election")
}
func (c *oracleChain) GetElectionStatus(id string) (string, error) {
	return c.get(c.status, id, "election")
}
func (c *oracleChain) GetDKGTranscript(id string) (string, error) {
	return c.get(c.dkg, id, "DKG transcript")
}
func (c *oracleChain) GetTally(id string) (string, error) { return c.get(c.tally, id, "tally") }
func (c *oracleChain) ListNullifiers(id string, _ int, _ string) (clientsdk.NullifierPage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return clientsdk.NullifierPage{Nullifiers: append([]string(nil), c.order[id]...)}, nil
}
func (c *oracleChain) GetBallot(id, n string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if b, ok := c.ballots[id][n]; ok {
		return b, nil
	}
	return "", fmt.Errorf("no ballot found for election %q nullifier %q", id, n)
}
func (c *oracleChain) GetBallots(id string, ns []string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = c.ballots[id][n]
	}
	return out, nil
}
func (c *oracleChain) GetPartialDecryption(id, contest, trustee string) (string, error) {
	return c.get(c.partials, id+"/"+contest+"/"+trustee, "partial decryption")
}

// --- the harness ------------------------------------------------------------------

type liveE2E struct {
	t       *testing.T
	demo    string
	srv     *httptest.Server
	s       *Server
	work    string // trustee and voter scratch, never in the run store
	tokens  []string
	bodies  []string // every response body the test saw
	bodyMu  sync.Mutex
	runsDir string
	// phoneSent is every ballot hex a phone (or the test's tamperer) built.
	phoneSent map[string]bool
	// caFile is the console's TLS certificate (httptest's), which the trustee
	// processes trust through --console-ca.
	caFile string
	// tr, when set, plays the trustees as five trustee processes driven only
	// through their own HTTP API (trustee_test.go); nil plays them with the
	// CLI directly.
	tr *trusteeFleet
}

// cliOp runs a CLI op as a trustee or voter would.
func (h *liveE2E) cliOp(op string, in any) map[string]any {
	h.t.Helper()
	out, err := h.cliTry(op, in)
	if err != nil {
		h.t.Fatalf("%s: %v", op, err)
	}
	return out
}

func (h *liveE2E) cliTry(op string, in any) (map[string]any, error) {
	data, _ := json.Marshal(in)
	cmd := exec.Command(h.demo, "live", op)
	var stdout, stderr bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(data), &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s", strings.TrimSpace(stderr.String()))
	}
	var out map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// call sends one request and decodes the JSON answer.
func (h *liveE2E) call(c *http.Client, method, path, bearer string, body any) (int, map[string]any) {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		rd = bytes.NewReader(data)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, rd)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if c == nil {
		c = h.srv.Client()
	}
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	h.bodyMu.Lock()
	h.bodies = append(h.bodies, string(data))
	h.bodyMu.Unlock()
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func (h *liveE2E) must(c *http.Client, method, path, bearer string, body any) map[string]any {
	h.t.Helper()
	code, out := h.call(c, method, path, bearer, body)
	if code/100 != 2 {
		h.t.Fatalf("%s %s: %d %v", method, path, code, out)
	}
	return out
}

func (h *liveE2E) login(user, pw string) *http.Client {
	h.t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Transport: h.srv.Client().Transport}
	code, out := h.call(c, http.MethodPost, "/api/login", "", map[string]string{"username": user, "password": pw})
	if code != http.StatusNoContent {
		h.t.Fatalf("login %s: %d %v", user, code, out)
	}
	return c
}

// phone is a new phone: its own cookie jar, no account.
func (h *liveE2E) phone() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Transport: h.srv.Client().Transport}
}

// enrol checks voter v (1..3 of testVoters) in on a phone of its own (find,
// declaration, the desk's approval, a signature), then runs the blind
// issuance over that check-in. It returns the credential and the phone.
func (h *liveE2E) enrol(admin *http.Client, v int, el map[string]any) (any, *http.Client) {
	h.t.Helper()
	name := fmt.Sprintf("voter%d", v)
	d := testVoters[name]
	ph := h.phone()
	found := h.must(ph, http.MethodPost, "/api/live/checkin/find", "", detailsBody(d, false))
	seq := found["entry"].(map[string]any)["seq"]
	if seq != float64(testSeqs[name]) {
		h.t.Fatalf("%s found as entry %v", name, seq)
	}
	h.must(ph, http.MethodPost, "/api/live/checkin/declare", "", detailsBody(d, true))
	h.must(admin, http.MethodPost, "/api/live/desk/approve", "", map[string]any{"seq": seq})
	h.must(ph, http.MethodPost, "/api/live/checkin/sign", "", map[string]any{"strokes": [][][]int{{{100, 100}, {200, 150}, {300, 120}}}})
	if st := h.must(ph, http.MethodGet, "/api/live/checkin", "", nil); st["state"] != CheckinSigned {
		h.t.Fatalf("%s's check-in: %v", name, st)
	}
	begin := h.cliOp("voter-begin", map[string]any{})
	pre := h.must(ph, http.MethodPost, "/api/live/issue/presign", "", map[string]any{"blinded_commitment": begin["blinded_commitment"]})
	blind := h.cliOp("voter-blind", map[string]any{"state": begin["state"], "r": pre["r"], "issuer_public_key": el["issuer_public_key"]})
	sig := h.must(ph, http.MethodPost, "/api/live/issue/sign", "", map[string]any{"e_prime": blind["e_prime"]})
	fin := h.cliOp("voter-finalize", map[string]any{"state": blind["state"], "s_iss": sig["s_iss"], "issuer_public_key": sig["issuer_public_key"]})
	if st := h.must(ph, http.MethodGet, "/api/live/checkin", "", nil); st["state"] != CheckinIssued {
		h.t.Fatalf("%s after issuance: %v", name, st)
	}
	return fin["credential"], ph
}

func hashFor(t *testing.T, pw string) string {
	h, err := HashPassword(strings.NewReader(pw + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// newLiveE2E builds a console with live mode on over chain, an admin, three
// old-style voter accounts (which must obtain nothing) and five trustee
// tokens. The voters are the test list's.
func newLiveE2E(t *testing.T, demo string, dial func() (liveChain, error)) *liveE2E {
	t.Helper()
	h := &liveE2E{t: t, demo: demo, work: t.TempDir(), runsDir: t.TempDir(), phoneSent: map[string]bool{}}
	store := NewRunStore(h.runsDir)
	hub := NewHub()
	exec := NewExecutor(store, hub, demo, "", FabricConfig{})
	s := NewServer(store, exec, hub, FabricConfig{}, nil, time.Minute)
	users := []User{{Username: "ban", Role: RoleAdmin, PasswordBcrypt: hashFor(t, "admin-pw")}}
	vh := hashFor(t, "voter-pw")
	for i := 1; i <= 3; i++ {
		users = append(users, User{Username: fmt.Sprintf("voter%d", i), Role: RoleVoter, PasswordBcrypt: vh})
	}
	ufile := filepath.Join(h.work, "users.json")
	data, _ := json.Marshal(users)
	if err := os.WriteFile(ufile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableAuth(ufile); err != nil {
		t.Fatal(err)
	}
	var entries []TrusteeToken
	for i := 1; i <= 5; i++ {
		tok, _ := NewTrusteeToken()
		h.tokens = append(h.tokens, tok)
		sum, _ := HashTrusteeToken(strings.NewReader(tok))
		entries = append(entries, TrusteeToken{TrusteeID: fmt.Sprint(i), TokenSHA256: sum})
	}
	tfile := filepath.Join(h.work, "tokens.json")
	data, _ = json.Marshal(entries)
	if err := os.WriteFile(tfile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableLive(LiveOptions{TrusteeTokens: tfile, Runner: execLiveRunner(demo), Dial: dial}); err != nil {
		t.Fatal(err)
	}
	h.s = s
	h.srv = httptest.NewTLSServer(s)
	t.Cleanup(h.srv.Close)
	h.caFile = filepath.Join(h.work, "console-ca.pem")
	if err := os.WriteFile(h.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *liveE2E) tdir(id int) string {
	d := filepath.Join(h.work, fmt.Sprintf("t%d", id))
	_ = os.MkdirAll(d, 0o700)
	return d
}

// runLiveElection drives the whole election and its refusals through the
// routes, returning the run id.
func runLiveElection(t *testing.T, h *liveE2E) string {
	start := time.Now()
	step := func(what string) { t.Logf("%7.2fs  %s", time.Since(start).Seconds(), what) }
	admin := h.login("ban", "admin-pw")

	// Setup.
	preview := h.must(admin, http.MethodPost, "/api/live/voter-list/preview", "", map[string]any{"csv": testVoterList})
	if preview["valid"] != true || preview["count"] != 5.0 {
		t.Fatalf("voter list preview: %v", preview)
	}
	el := h.must(admin, http.MethodPost, "/api/live/elections", "", map[string]any{
		"title": "Live demo election",
		"positions": []map[string]any{
			{"id": "president", "candidates": []string{"alice", "bob", "carol"}},
			{"id": "secretary", "candidates": []string{"dan", "eve", "fay"}},
		},
		"voter_list": testVoterList, "voter_list_fingerprint": preview["fingerprint"],
	})
	runID := el["run_id"].(string)
	if el["state"] != LiveCeremony || el["trustees"] != 5.0 || el["threshold"] != 3.0 {
		t.Fatalf("created election: %v", el)
	}
	step("setup: CreateElection recorded, state ceremony (" + runID + ")")

	// The key ceremony, five trustee processes.
	if h.tr != nil {
		h.tr.ceremony()
	} else {
		cliCeremony(t, h)
	}
	el = h.must(nil, http.MethodGet, "/api/live/election", "", nil)
	if el["state"] != LiveOpen || el["dkg"] == "" {
		t.Fatalf("after ceremony: %v", el["state"])
	}
	step("ceremony: 5 receive keys, 5 deals, 5 acks, PublishDKGTranscript recorded, state open")

	// Check-in and enrolment, three phones.
	creds := make([]any, 3)
	voters := make([]*http.Client, 3)
	for v := 0; v < 3; v++ {
		creds[v], voters[v] = h.enrol(admin, v+1, el)
	}
	// A second signature for an issued entry is refused.
	if code, out := h.call(voters[0], http.MethodPost, "/api/live/issue/presign", "", map[string]any{"blinded_commitment": strings.Repeat("e2", 32)}); code != http.StatusConflict || out["code"] != "already-issued" {
		t.Fatalf("second issuance for voter1: %d %v", code, out)
	}
	// Another phone in voter1's name is refused at the precinct.
	if code, out := h.call(h.phone(), http.MethodPost, "/api/live/checkin/declare", "", detailsBody(testVoters["voter1"], true)); code != http.StatusConflict || out["code"] != "already-checked-in" {
		t.Fatalf("impersonation of voter1: %d %v", code, out)
	}
	// An old-style voter account obtains nothing.
	if code, out := h.call(h.login("voter2", "voter-pw"), http.MethodPost, "/api/live/issue/presign", "", map[string]any{"blinded_commitment": strings.Repeat("e2", 32)}); code != http.StatusForbidden || out["code"] != "no-checkin" {
		t.Fatalf("issuance to a voter account: %d %v", code, out)
	}
	if el := h.must(nil, http.MethodGet, "/api/live/election", "", nil); el["counts"].(map[string]any)["checked_in"] != 3.0 || el["counts"].(map[string]any)["credentials_issued"] != 3.0 {
		t.Fatalf("counts after enrolment: %v", el["counts"])
	}
	step("check-in and enrolment: 3 phones checked in and issued; a second issuance, an impersonation and a voter account refused")

	// Voting: 3 voters x 2 positions; choices give totals [2,1,0, 0,1,2].
	choices := [3][2]int{{0, 2}, {0, 1}, {1, 2}}
	want := []float64{2, 1, 0, 0, 1, 2}
	var firstBallot string
	for v := 0; v < 3; v++ {
		for p, pos := range []string{"president", "secretary"} {
			b := h.cliOp("ballot", map[string]any{"params": el["params"], "dkg": el["dkg"], "credential": creds[v], "position_id": pos, "choice": choices[v][p]})
			if v == 2 && p == 1 {
				// One changed byte in a CDS response, before the genuine
				// ballot spends its nullifier.
				tampered := tamperCDS(t, b["ballot"].(string))
				h.phoneSent[tampered] = true
				code, out := h.call(nil, http.MethodPost, "/api/live/ballot", "", map[string]any{"ballot": tampered})
				if code != http.StatusUnprocessableEntity || out["gate"] != "cds" {
					t.Fatalf("tampered ballot: %d %v", code, out)
				}
				step("refusal: a ballot with one changed byte refused at gate cds: " + truncateErr(out["reason"].(string)))
			}
			h.phoneSent[b["ballot"].(string)] = true
			rc := h.must(nil, http.MethodPost, "/api/live/ballot", "", map[string]any{"ballot": b["ballot"]})
			if rc["tracking_code"] != b["tracking_code"] || rc["ballot_fingerprint"] != b["ballot_fingerprint"] || rc["recorded_bytes_match"] != true {
				t.Fatalf("ballot receipt %v vs phone %v %v", rc, b["tracking_code"], b["ballot_fingerprint"])
			}
			if v == 0 && p == 0 {
				firstBallot = b["ballot"].(string)
			}
		}
	}
	code, out := h.call(nil, http.MethodPost, "/api/live/ballot", "", map[string]any{"ballot": firstBallot})
	if code != http.StatusUnprocessableEntity || out["gate"] != "nullifier" {
		t.Fatalf("replayed ballot: %d %v", code, out)
	}
	step("refusal: a replayed ballot refused at gate nullifier: " + truncateErr(out["reason"].(string)))
	step("voting: 6 ballots recorded, each fingerprint equals the phone's")

	h.must(admin, http.MethodPost, "/api/live/close", "", nil)
	step("close: CloseElection recorded")

	// The threshold demonstration before any Decrypt: no partial combines and
	// no signature is held, so the console sends a tally no trustee signed,
	// and the chain refuses it at the threshold gate. Nothing changes.
	code, out = h.call(admin, http.MethodPost, "/api/live/tally/publish", "", nil)
	if code != http.StatusUnprocessableEntity || out["gate"] != "threshold" {
		t.Fatalf("unsigned publish: %d %v", code, out)
	}
	step("refusal: an unsigned publish before any Decrypt refused at gate threshold: " + truncateErr(out["reason"].(string)))
	if el := h.must(nil, http.MethodGet, "/api/live/election", "", nil); el["state"] != LiveClosed {
		t.Fatalf("a refused publish changed the state to %v", el["state"])
	}

	// Decryption by trustees 1-3, over the ballots read back from the chain.
	led := h.must(nil, http.MethodGet, "/api/live/ledger", "", nil)
	if led["nullifier_count"] != 6.0 {
		t.Fatalf("ledger count %v", led["nullifier_count"])
	}
	var ballots []string
	for _, b := range led["ballots"].([]any) {
		bm := b.(map[string]any)
		ballots = append(ballots, bm["ballot"].(string))
		// The bytes on the chain are the bytes a phone sent, and the
		// fingerprint is of those bytes.
		if !h.phoneSent[bm["ballot"].(string)] {
			t.Fatalf("the chain holds a ballot record no phone sent: %v", bm["tracking_code"])
		}
		raw, _ := hex.DecodeString(bm["ballot"].(string))
		if bm["ballot_fingerprint"] != ballotFingerprint(raw) {
			t.Fatalf("ledger fingerprint %v is not of the stored bytes", bm["ballot_fingerprint"])
		}
	}
	for id := 1; id <= 3; id++ {
		if h.tr != nil {
			h.tr.decrypt(id)
			continue
		}
		part := h.cliOp("partial", map[string]any{"share_file": filepath.Join(h.tdir(id), "share.json"), "params": led["params"], "dkg": led["dkg"], "ballots": ballots})
		h.must(nil, http.MethodPost, "/api/live/partial", h.tokens[id-1], part)
	}
	led = h.must(nil, http.MethodGet, "/api/live/ledger", "", nil)
	var partials []string
	for _, p := range led["partials"].([]any) {
		partials = append(partials, p.(map[string]any)["partial"].(string))
	}
	if len(partials) != 18 {
		t.Fatalf("%d partials on the chain, want 18", len(partials))
	}
	step("decrypt: 3 trustees x 6 contests SubmitPartialDecryption recorded")

	if h.tr != nil {
		// The trustee processes sign by themselves after their own Decrypt;
		// the third signature publishes.
		for id := 1; id <= 3; id++ {
			h.tr.signed(id, want)
		}
		h.tr.waitPublished()
	} else {
		sign := func(id int) map[string]any {
			comb := h.cliOp("combine", map[string]any{"params": led["params"], "dkg": led["dkg"], "ballots": ballots, "partials": partials})
			sig := h.cliOp("sign-tally", map[string]any{"share_file": filepath.Join(h.tdir(id), "share.json"), "params": led["params"], "dkg": led["dkg"], "ballots": ballots, "partials": partials, "totals": comb["totals"]})
			return h.must(nil, http.MethodPost, "/api/live/tally-sig", h.tokens[id-1], sig)
		}
		sign(1)
		sign(2)
		code, out = h.call(admin, http.MethodPost, "/api/live/tally/publish", "", nil)
		if code != http.StatusUnprocessableEntity || out["gate"] != "threshold" {
			t.Fatalf("2-signature publish: %d %v", code, out)
		}
		step("refusal: a 2-signature publish refused at gate threshold: " + truncateErr(out["reason"].(string)))
		if el := h.must(nil, http.MethodGet, "/api/live/election", "", nil); el["state"] != LiveClosed {
			t.Fatalf("a refused publish changed the state to %v", el["state"])
		}
		if res := sign(3); res["published"] != true {
			t.Fatalf("third signature did not publish: %v", res)
		}
	}
	el = h.must(nil, http.MethodGet, "/api/live/election", "", nil)
	got, _ := json.Marshal(el["totals"])
	wantJSON, _ := json.Marshal(want)
	if (el["state"] != LiveTallied && el["state"] != LiveVerified) || !bytes.Equal(got, wantJSON) {
		t.Fatalf("tallied %v totals %s, want %s", el["state"], got, wantJSON)
	}
	step("tally: PublishTally with 3 signatures, totals " + string(got) + " equal the choices")

	ver := h.must(admin, http.MethodPost, "/api/live/verify", "", nil)
	if ver["overall"] != "pass" || ver["state"] != LiveVerified || ver["expected_ballots"] != 6.0 {
		t.Fatalf("verify: %v %v %v", ver["overall"], ver["state"], ver["failed_checks"])
	}
	step("verify: verify-live over the chain record, overall pass, state verified")

	// The board and the tracking-code check.
	board := h.must(nil, http.MethodGet, "/api/board/"+runID, "", nil)
	lb := board["live"].(map[string]any)
	if board["verified"] != true || board["sealed"] != false || lb["state"] != LiveVerified || len(lb["ballots"].([]any)) != 6 {
		t.Fatalf("board: verified %v sealed %v live %v", board["verified"], board["sealed"], lb)
	}
	first := lb["ballots"].([]any)[0].(map[string]any)
	vc := h.must(nil, http.MethodGet, "/api/verify-code/"+runID+"/"+first["tracking_code"].(string), "", nil)
	if vc["found"] != true || vc["committed_on_chain"] != true || vc["ballot_fingerprint"] != first["ballot_fingerprint"] {
		t.Fatalf("verify-code: %v", vc)
	}
	step("board: verified, 6 ballots with tracking code and fingerprint; tracking-code check confirms on chain")
	return runID
}

// cliCeremony plays the five trustees' ceremony with the CLI directly.
func cliCeremony(t *testing.T, h *liveE2E) {
	for id := 1; id <= 5; id++ {
		k := h.cliOp("trustee-keygen", map[string]any{"trustee_id": id, "key_file": filepath.Join(h.tdir(id), "receive.key")})
		h.must(nil, http.MethodPost, "/api/live/dkg/receive-key", h.tokens[id-1], k)
	}
	var roster map[string]any
	deals := map[int]map[string]any{}
	for id := 1; id <= 5; id++ {
		roster = h.must(nil, http.MethodGet, "/api/live/dkg/roster", h.tokens[id-1], nil)
		if roster["complete"] != true {
			t.Fatalf("roster: %v", roster)
		}
		deal := h.cliOp("dkg-deal", map[string]any{
			"receive_key_file": filepath.Join(h.tdir(id), "receive.key"), "params": roster["params"],
			"dealer_id": id, "peers": roster["peers"],
		})
		if deal["roster_digest"] != roster["roster_digest"] {
			t.Fatalf("trustee %d: dealer digest %v, console %v", id, deal["roster_digest"], roster["roster_digest"])
		}
		deals[id] = deal
		h.must(nil, http.MethodPost, "/api/live/dkg/deal", h.tokens[id-1], deal)
	}
	var lastAck map[string]any
	for id := 1; id <= 5; id++ {
		in := h.must(nil, http.MethodGet, "/api/live/dkg/inbox", h.tokens[id-1], nil)
		// The relay returns each masked share exactly as its dealer posted it.
		for _, d := range in["dealers"].([]any) {
			dm := d.(map[string]any)
			dealer := int(dm["dealer_id"].(float64))
			want, _ := json.Marshal(deals[dealer]["masked_shares"].([]any)[id-1])
			got, _ := json.Marshal(dm["masked_share"])
			if !bytes.Equal(want, got) {
				t.Fatalf("trustee %d: dealer %d's share was altered in relay", id, dealer)
			}
		}
		rcv := h.cliOp("dkg-receive", map[string]any{
			"receive_key_file": filepath.Join(h.tdir(id), "receive.key"),
			"share_file":       filepath.Join(h.tdir(id), "share.json"),
			"params":           in["params"], "trustee_id": id,
			"peers": in["peers"], "dealers": in["dealers"],
		})
		lastAck = h.must(nil, http.MethodPost, "/api/live/dkg/ack", h.tokens[id-1], rcv)
	}
	if lastAck["published"] != true {
		t.Fatalf("last ack did not publish: %v", lastAck)
	}
}

// tamperCDS changes one byte of the first CDS proof's response.
func tamperCDS(t *testing.T, ballotHex string) string {
	raw, _ := hex.DecodeString(ballotHex)
	var b pb.Ballot
	if err := proto.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	b.WellFormednessProofs[0].Branches[0].Response[0] ^= 0x01
	out, err := proto.Marshal(&b)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(out)
}

// checkSecretsKept asserts the issuer secret is in no response and no file
// outside the private folder, no voter's name or date of birth is in a file
// outside it, no date of birth is in any response or the log, and the
// private folder's modes.
func checkSecretsKept(t *testing.T, h *liveE2E, runID string, logs string) {
	dir := filepath.Join(h.runsDir, runID)
	var key struct {
		Secret string `json:"secret"`
	}
	data, err := os.ReadFile(filepath.Join(dir, livePrivateDir, liveIssuerKey))
	if err != nil || json.Unmarshal(data, &key) != nil || key.Secret == "" {
		t.Fatalf("issuer key file: %v", err)
	}
	for _, b := range h.bodies {
		if strings.Contains(b, key.Secret) {
			t.Fatal("the issuer secret appeared in a response")
		}
	}
	if strings.Contains(logs, key.Secret) {
		t.Fatal("the issuer secret appeared in the log")
	}
	for _, d := range allDOBs {
		for _, b := range h.bodies {
			if strings.Contains(b, d) {
				t.Fatalf("a response carries a date of birth: %.200s", b)
			}
		}
		if strings.Contains(logs, d) {
			t.Fatal("the log carries a date of birth")
		}
	}
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		inPrivate := rel == livePrivateDir || strings.HasPrefix(rel, livePrivateDir+string(filepath.Separator))
		switch {
		case inPrivate && info.IsDir() && info.Mode().Perm() != 0o700:
			t.Errorf("%s is mode %o, want 0700", rel, info.Mode().Perm())
		case inPrivate && !info.IsDir() && info.Mode().Perm() != 0o600:
			t.Errorf("%s is mode %o, want 0600", rel, info.Mode().Perm())
		case !inPrivate && !info.IsDir():
			b, _ := os.ReadFile(p)
			if bytes.Contains(b, []byte(key.Secret)) {
				t.Errorf("%s holds the issuer secret", rel)
			}
			for _, v := range append([]string{"voter1", "voter2", "voter3", "Halimbawa", "Sampol", "Pagsubok"}, allDOBs...) {
				if bytes.Contains(b, []byte(v)) {
					t.Errorf("%s names %s", rel, v)
				}
			}
		}
		return nil
	})
}

func captureLog(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	var mu sync.Mutex
	w := writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return buf.Write(p) })
	prev := log.Writer()
	log.SetOutput(w)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestLiveElectionEndToEnd(t *testing.T) {
	if os.Getenv("SAKSI_DEMO_BIN") == "" {
		t.Skip("set SAKSI_DEMO_BIN to the saksi-demo binary to run the live end-to-end test")
	}
	demo := findDemo(t)
	logs := captureLog(t)
	var chain *oracleChain
	h := newLiveE2E(t, demo, func() (liveChain, error) { return chain, nil })
	chain = newOracleChain(t, demo)
	runID := runLiveElection(t, h)

	// What the console handed the chain is exactly what the phones built:
	// every SubmitBallot argument was one of the phone's (or the test's
	// tampered) records, never a re-encoding.
	for _, raw := range chain.bytesIn {
		if !h.phoneSent[hex.EncodeToString(raw)] {
			t.Fatalf("the chain received a ballot no phone built")
		}
	}
	checkSecretsKept(t, h, runID, logs.String())
	t.Logf("functions submitted: %v", chain.submits)
}

// TestLiveElectionWithTrusteeProcesses is the end-to-end flow with the five
// trustees as five trustee processes (saksi-campaign trustee), each reading
// the chain itself and driven only through its own HTTP API.
func TestLiveElectionWithTrusteeProcesses(t *testing.T) {
	if os.Getenv("SAKSI_DEMO_BIN") == "" {
		t.Skip("set SAKSI_DEMO_BIN to the saksi-demo binary to run the live end-to-end test")
	}
	demo := findDemo(t)
	logs := captureLog(t)
	var chain *oracleChain
	h := newLiveE2E(t, demo, func() (liveChain, error) { return chain, nil })
	chain = newOracleChain(t, demo)
	newTrusteeFleet(t, h, func(int) func() (trusteeChain, error) {
		return func() (trusteeChain, error) { return chain, nil }
	}, fleetOptions{})
	runID := runLiveElection(t, h)
	checkTrusteesAfterTally(t, h)
	checkSecretsKept(t, h, runID, logs.String())
	h.tr.checkSecrets(logs.String())
}

// checkTrusteesAfterTally: every trustee process read the published tally
// from the chain and it equals its own combine.
func checkTrusteesAfterTally(t *testing.T, h *liveE2E) {
	for id := 1; id <= 5; id++ {
		st := h.tr.waitFor(id, "the published tally", func(st TrusteeStatus) bool { return st.Tally.Published && st.Tally.Matches != nil })
		if !*st.Tally.Matches || len(st.Alarms) != 0 {
			t.Fatalf("trustee %d: published %v, own %v, alarms %v", id, st.Tally.PublishedTotals, st.Tally.Totals, st.Alarms)
		}
	}
	t.Logf("trustees: all 5 read the published tally from the chain; it equals each one's own combine")
}

// TestLiveElectionOnFabric is the same flow against a real Fabric network,
// with the trustees as five trustee processes reading the real chain.
// Gated by SAKSI_LIVE_FABRIC=1, with SAKSI_DEMO_BIN and the connection from
// SAKSI_FABRIC_TLS_CERT, SAKSI_FABRIC_CERT, SAKSI_FABRIC_KEY and, optionally,
// SAKSI_FABRIC_PEER (localhost:7051), SAKSI_FABRIC_GATEWAY_PEER
// (peer0.org1.example.com), SAKSI_FABRIC_MSP_ID (Org1MSP), SAKSI_FABRIC_CHANNEL
// (saksi) and SAKSI_FABRIC_CHAINCODE (saksi-bulletin). Each run makes a fresh
// election id, because the ledger persists.
func TestLiveElectionOnFabric(t *testing.T) {
	if os.Getenv("SAKSI_LIVE_FABRIC") != "1" {
		t.Skip("set SAKSI_LIVE_FABRIC=1 (and the SAKSI_FABRIC_* paths) to run against a real Fabric network")
	}
	if os.Getenv("SAKSI_DEMO_BIN") == "" {
		t.Fatal("SAKSI_LIVE_FABRIC=1 needs SAKSI_DEMO_BIN")
	}
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	cfg := FabricConfig{
		PeerEndpoint: env("SAKSI_FABRIC_PEER", "localhost:7051"),
		GatewayPeer:  env("SAKSI_FABRIC_GATEWAY_PEER", "peer0.org1.example.com"),
		TLSCert:      os.Getenv("SAKSI_FABRIC_TLS_CERT"),
		MSPID:        env("SAKSI_FABRIC_MSP_ID", "Org1MSP"),
		Cert:         os.Getenv("SAKSI_FABRIC_CERT"),
		Key:          os.Getenv("SAKSI_FABRIC_KEY"),
		Channel:      env("SAKSI_FABRIC_CHANNEL", "saksi"),
		Chaincode:    env("SAKSI_FABRIC_CHAINCODE", "saksi-bulletin"),
	}
	if !cfg.Enabled() {
		t.Fatal("SAKSI_FABRIC_TLS_CERT, SAKSI_FABRIC_CERT and SAKSI_FABRIC_KEY are required")
	}
	conn, err := cfg.Connect()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	chain := fabricLiveChain{BulletinClient: conn.Bulletin, led: conn.Ledger()}
	height0, _, err := conn.Ledger().ChainInfo()
	if err != nil {
		t.Fatalf("chain info: %v", err)
	}
	t.Logf("channel %s height %d at start", cfg.Channel, height0)
	logs := captureLog(t)
	start := time.Now()
	h := newLiveE2E(t, findDemo(t), func() (liveChain, error) { return chain, nil })
	// Five trustee processes, each with its own gateway connection, reading
	// the real chain.
	newTrusteeFleet(t, h, func(int) func() (trusteeChain, error) { return TrusteeFabricDial(cfg) }, fleetOptions{})
	runID := runLiveElection(t, h)
	checkTrusteesAfterTally(t, h)
	h.tr.checkSecrets(logs.String())

	// The bytes the chain holds are the bytes the phones sent: ballots.ndjson
	// holds what GetBallot returned, and each receipt said they matched.
	ndjson, _ := os.ReadFile(filepath.Join(h.runsDir, runID, BallotsFile))
	if n := strings.Count(string(ndjson), "\n"); n != 6 {
		t.Fatalf("ballots.ndjson has %d lines", n)
	}
	checkSecretsKept(t, h, runID, logs.String())
	height1, _, _ := conn.Ledger().ChainInfo()
	t.Logf("election %s on Fabric: %s wall time, channel height %d -> %d", runID, time.Since(start).Round(time.Millisecond), height0, height1)
}
