package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The trustee process's own HTTP API (docs/live/trustee-api.md): the sign-in
// routes the trustee app already uses, one status route, the three actions,
// and one public route the other trustees compare the roster with.

// trusteeRouteAccess is the trustee process's route -> access table. A route
// missing from it is refused (the zero value is accessAdmin, which no account
// of this process holds). TestTrusteeRouteAccessCoversEveryRoute holds it to
// the registered routes.
var trusteeRouteAccess = map[string]access{
	"/api/login":           accessPublic,
	"/api/logout":          accessPublic,
	"/api/me":              accessPublic,
	"/api/trustee/peer":    accessPublic,
	"/api/trustee/status":  accessTrustee,
	"/api/trustee/join":    accessTrustee,
	"/api/trustee/decrypt": accessTrustee,
	"/api/trustee/sign":    accessTrustee,
	"/trustee/":            accessPublic,
	"/trustee":             accessPublic,
	"/favicon.ico":         accessPublic,
	"/":                    accessPublic, // 404 for every other path
}

// TrusteeServerOptions configures the trustee process's HTTP side.
type TrusteeServerOptions struct {
	// AuthFile is this process's own accounts file: trustee accounts with
	// this process's trustee id only.
	AuthFile string
	// AllowHosts is the Host allowlist (empty accepts any; main always sets it).
	AllowHosts []string
	// WebDir serves /trustee/ from <WebDir>/trustee; "" serves no app.
	WebDir string
}

// TrusteeServer is the trustee process's http.Handler.
type TrusteeServer struct {
	T       *TrusteeService
	auth    *authState
	routes  []string
	handler http.Handler
}

// NewTrusteeServer builds the handler over T. The accounts file must hold
// only trustee accounts, each with T's trustee id.
func NewTrusteeServer(T *TrusteeService, o TrusteeServerOptions) (*TrusteeServer, error) {
	if o.AuthFile == "" {
		return nil, errors.New("--auth-file is required: this trustee's own accounts")
	}
	users, err := LoadUsers(o.AuthFile)
	if err != nil {
		return nil, fmt.Errorf("--auth-file %s: %w", o.AuthFile, err)
	}
	for name, u := range users {
		if u.Role != RoleTrustee || u.TrusteeID != T.idStr {
			return nil, fmt.Errorf("--auth-file %s: account %q is not a trustee account of trustee %d; this process's accounts file holds only trustee %d's accounts",
				o.AuthFile, name, T.id, T.id)
		}
	}
	ts := &TrusteeServer{T: T, auth: newAuthState(users)}
	allow := map[string]bool{}
	for _, h := range o.AllowHosts {
		allow[h] = true
	}
	mux := &routeMux{mux: http.NewServeMux()}
	mux.HandleFunc("/api/login", ts.auth.handleLogin)
	mux.HandleFunc("/api/logout", ts.auth.handleLogout)
	mux.HandleFunc("/api/me", handleMe)
	mux.HandleFunc("/api/trustee/peer", ts.handlePeer)
	mux.HandleFunc("/api/trustee/status", ts.own(http.MethodGet, ts.handleStatus))
	mux.HandleFunc("/api/trustee/join", ts.own(http.MethodPost, ts.handleJoin))
	mux.HandleFunc("/api/trustee/decrypt", ts.own(http.MethodPost, ts.handleDecrypt))
	mux.HandleFunc("/api/trustee/sign", ts.own(http.MethodPost, ts.handleSign))
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResp(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})
	if strings.TrimSpace(o.WebDir) != "" {
		mux.Handle("/trustee/", http.StripPrefix("/trustee/", wasmType(http.FileServer(http.Dir(filepath.Join(o.WebDir, "trustee"))))))
		mux.HandleFunc("/trustee", func(w http.ResponseWriter, r *http.Request) {
			target := r.URL.Path + "/"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
	}
	ts.routes = mux.patterns
	ts.handler = guardHosts(allow, ts.authorize(mux))
	return ts, nil
}

func (ts *TrusteeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ts.handler.ServeHTTP(w, r)
}

// authorize resolves the session and applies trusteeRouteAccess.
func (ts *TrusteeServer) authorize(mux *routeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		a, ok := trusteeRouteAccess[pattern]
		if !ok {
			writeJSONResp(w, http.StatusForbidden, map[string]string{"error": "not a route of this trustee process"})
			return
		}
		if sess := ts.auth.lookup(r); sess != nil {
			r = r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess))
		}
		if code, reason := a.denial(sessionFrom(r)); code != 0 {
			writeJSONResp(w, code, map[string]string{"error": reason})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// own wraps a route for this process's own trustee: the session's trustee id
// must be this process's id.
func (ts *TrusteeServer) own(method string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r)
		if sess == nil || sess.Role != RoleTrustee || sess.TrusteeID != ts.T.idStr {
			writeJSONResp(w, http.StatusForbidden, map[string]string{"error": "only trustee " + ts.T.idStr + " may act on this process"})
			return
		}
		if r.Method != method {
			writeJSONResp(w, http.StatusMethodNotAllowed, map[string]string{"error": method + " required"})
			return
		}
		h(w, r)
	}
}

func (ts *TrusteeServer) handlePeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}
	writeJSONResp(w, http.StatusOK, ts.T.PeerView())
}

func (ts *TrusteeServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSONResp(w, http.StatusOK, ts.T.Status())
}

// readOptionalBody decodes an optional JSON body (empty is fine) strictly.
func readOptionalBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && err.Error() != "EOF" {
		writeJSONResp(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	return true
}

func (ts *TrusteeServer) handleJoin(w http.ResponseWriter, r *http.Request) {
	var body struct{}
	if !readOptionalBody(w, r, &body) {
		return
	}
	if err := ts.T.RequestJoin(); err != nil {
		trusteeFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusAccepted, ts.T.Status())
}

func (ts *TrusteeServer) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	var body struct{}
	if !readOptionalBody(w, r, &body) {
		return
	}
	if err := ts.T.RequestDecrypt(); err != nil {
		trusteeFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusAccepted, ts.T.Status())
}

func (ts *TrusteeServer) handleSign(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Totals []uint64 `json:"totals"`
	}
	if !readOptionalBody(w, r, &body) {
		return
	}
	if err := ts.T.RequestSign(body.Totals); err != nil {
		trusteeFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusAccepted, ts.T.Status())
}

// trusteeFail answers an action's refusal: 409 for a refusal or an alarm, 502
// when the chain could not be read.
func trusteeFail(w http.ResponseWriter, err error) {
	var chainErr tChainErr
	if errors.As(err, &chainErr) {
		writeJSONResp(w, http.StatusBadGateway, map[string]string{"error": chainErr.Error()})
		return
	}
	writeJSONResp(w, http.StatusConflict, map[string]string{"error": err.Error()})
}

// --- actions -------------------------------------------------------------------

// request marks step asked for and wakes the driver; a failed step starts
// again. check runs under mu and may refuse.
func (T *TrusteeService) request(step string, check func(p *trusteeProgress) error) error {
	T.mu.Lock()
	known := T.p != nil
	T.mu.Unlock()
	if !known {
		// Pressed before the driver's first poll: follow the console's
		// current election now.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		v, err := T.console.election(ctx)
		cancel()
		if err == nil && v != nil {
			if err := T.adopt(v); err != nil {
				return err
			}
			T.mu.Lock()
			T.view = v
			T.mu.Unlock()
		}
	}
	T.mu.Lock()
	if T.p == nil {
		T.mu.Unlock()
		return errors.New("no live election is set up on the console yet")
	}
	if a := T.p.blocked(step); a != nil {
		T.mu.Unlock()
		return fmt.Errorf("blocked by an alarm: %s", a.Message)
	}
	if !T.identity.OK && T.identity.Checked {
		T.mu.Unlock()
		return errors.New(T.identity.Error)
	}
	if err := check(T.p); err != nil {
		T.mu.Unlock()
		return err
	}
	switch T.p.step(step).State {
	case stepDone, stepRunning, stepWaiting:
	default:
		T.p.Steps[step] = stepStatus{State: stepRunning, UpdatedAt: T.now().UTC()}
	}
	err := T.saveLocked()
	T.mu.Unlock()
	if err != nil {
		return err
	}
	T.poke()
	return nil
}

// RequestJoin is the Join ceremony button.
func (T *TrusteeService) RequestJoin() error {
	return T.request("join", func(p *trusteeProgress) error {
		if v := T.view; v != nil && v.ElectionID == p.ElectionID && !p.ReceiveKeyPosted &&
			(v.State == LiveAbandoned || liveStateIndex(v.State) > liveStateIndex(LiveCeremony)) {
			return fmt.Errorf("the election is %s; joining is possible only during the ceremony", v.State)
		}
		p.JoinRequested = true
		return nil
	})
}

// RequestDecrypt is the Decrypt button. It checks on the chain, at once, that
// the election is closed.
func (T *TrusteeService) RequestDecrypt() error {
	T.mu.Lock()
	ready := T.p != nil && T.p.TranscriptCheck == "ok"
	T.mu.Unlock()
	if !ready {
		return errors.New("join the ceremony first: decryption needs this trustee's checked key share")
	}
	closed, status, err := T.ChainClosed()
	if err != nil {
		return err
	}
	if !closed {
		return fmt.Errorf("the chain says the election is %s, not closed: decryption waits for CloseElection", status)
	}
	return T.request("decrypt", func(p *trusteeProgress) error {
		p.DecryptRequested = true
		return nil
	})
}

// RequestSign is the Sign tally button: totals must be the ones the status
// showed, this trustee's own combine.
func (T *TrusteeService) RequestSign(totals []uint64) error {
	return T.request("sign", func(p *trusteeProgress) error {
		if len(p.Totals) == 0 {
			return errors.New("there are no totals to sign yet: this trustee's own combine needs at least threshold trustees' partials on the chain")
		}
		if !slices.Equal(totals, p.Totals) {
			return fmt.Errorf("the totals to sign must be the ones shown, this trustee's own combine %v (got %v)", p.Totals, totals)
		}
		p.SignRequested, p.SignTotals = true, slices.Clone(totals)
		return nil
	})
}

// --- status --------------------------------------------------------------------

// TrusteeStatus is GET /api/trustee/status: everything a screen needs in one
// read. Every value is public (fingerprints, digests, keys, counts).
type TrusteeStatus struct {
	TrusteeID    int                   `json:"trustee_id"`
	Console      TrusteeConsoleStatus  `json:"console"`
	Identity     identityState         `json:"identity"`
	Election     *TrusteeElection      `json:"election"`
	Step         string                `json:"step"`
	Steps        map[string]stepStatus `json:"steps"`
	Alarms       []trusteeAlarm        `json:"alarms"`
	Fingerprints TrusteeFingerprints   `json:"fingerprints"`
	Ceremony     TrusteeCeremony       `json:"ceremony"`
	Decryption   TrusteeDecryption     `json:"decryption"`
	Tally        TrusteeTally          `json:"tally"`
	UpdatedAt    time.Time             `json:"updated_at"`
}

type TrusteeConsoleStatus struct {
	URL       string `json:"url"`
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}

type TrusteeElection struct {
	ElectionID string         `json:"election_id"`
	Title      string         `json:"title"`
	State      string         `json:"state"`
	Trustees   int            `json:"trustees"`
	Threshold  int            `json:"threshold"`
	Positions  []LivePosition `json:"positions"`
	ContestIDs []string       `json:"contest_ids"`
	// ParamsChecked: the console's parameters equal the chain's.
	ParamsChecked bool `json:"params_checked"`
	BallotRecords int  `json:"ballot_records"`
}

type TrusteeFingerprints struct {
	ReceiveKey string `json:"receive_key,omitempty"`
	Roster     string `json:"roster,omitempty"`
	Share      string `json:"share,omitempty"`
	JointKey   string `json:"joint_key,omitempty"`
	Ballots    string `json:"ballots,omitempty"`
}

type TrusteeRosterEntry struct {
	TrusteeID             int    `json:"trustee_id"`
	ReceiveKeyFingerprint string `json:"receive_key_fingerprint"`
	Self                  bool   `json:"self"`
	PeerCheck             string `json:"peer_check"` // self, ok, waiting, mismatch, pending
	Detail                string `json:"detail,omitempty"`
}

type TrusteeCeremony struct {
	ReceiveKeyPosted    bool                 `json:"receive_key_posted"`
	RosterComplete      bool                 `json:"roster_complete"`
	RosterDigest        string               `json:"roster_digest,omitempty"`
	Roster              []TrusteeRosterEntry `json:"roster"`
	RosterChecked       bool                 `json:"roster_checked"`
	Dealt               bool                 `json:"dealt"`
	Received            bool                 `json:"received"`
	Acknowledged        bool                 `json:"acknowledged"`
	JointPublicKey      string               `json:"joint_public_key,omitempty"`
	VerificationKey     string               `json:"verification_key,omitempty"`
	TranscriptPublished bool                 `json:"transcript_published"`
	// TranscriptCheck is "", "ok" or "mismatch".
	TranscriptCheck string `json:"transcript_check"`
	CeremonyError   string `json:"ceremony_error,omitempty"`
}

type TrusteePeerBallotCheck struct {
	TrusteeID int    `json:"trustee_id"`
	State     string `json:"state"`
	Detail    string `json:"detail,omitempty"`
}

type TrusteeDecryption struct {
	MinBallots        int                      `json:"min_ballots"`
	BallotCount       int                      `json:"ballot_count"`
	BallotsByPosition map[string]int           `json:"ballots_by_position"`
	BallotsDigest     string                   `json:"ballots_digest,omitempty"`
	PeerChecks        []TrusteePeerBallotCheck `json:"peer_checks"`
	PartialComputed   bool                     `json:"partial_computed"`
	PartialRecorded   bool                     `json:"partial_recorded"`
	// PartialReadBack is "", "ok" or "mismatch".
	PartialReadBack   string `json:"partial_read_back"`
	TrusteesDecrypted int    `json:"trustees_decrypted"`
	Threshold         int    `json:"threshold"`
}

type TrusteeTally struct {
	Totals          []uint64              `json:"totals"`
	Contests        []trusteeContestTotal `json:"contests"`
	ReadyToSign     bool                  `json:"ready_to_sign"`
	SignaturePosted bool                  `json:"signature_posted"`
	SignatureNote   string                `json:"signature_note,omitempty"`
	Published       bool                  `json:"published"`
	PublishedTotals []uint64              `json:"published_totals"`
	// Matches is null until both totals are known.
	Matches *bool `json:"matches"`
}

// Status is the one read a screen needs.
func (T *TrusteeService) Status() TrusteeStatus {
	T.mu.Lock()
	defer T.mu.Unlock()
	st := TrusteeStatus{
		TrusteeID: T.id,
		Console:   TrusteeConsoleStatus{URL: T.console.base, Reachable: T.consoleErr == "", Error: T.consoleErr},
		Identity:  T.identity,
		Steps:     map[string]stepStatus{},
		Alarms:    []trusteeAlarm{},
		Ceremony:  TrusteeCeremony{Roster: []TrusteeRosterEntry{}},
		Decryption: TrusteeDecryption{MinBallots: T.minBallots, BallotsByPosition: map[string]int{},
			PeerChecks: []TrusteePeerBallotCheck{}},
		Tally:     TrusteeTally{Totals: []uint64{}, Contests: []trusteeContestTotal{}, PublishedTotals: []uint64{}},
		UpdatedAt: T.now().UTC(),
	}
	for _, n := range []string{"join", "decrypt", "sign"} {
		st.Steps[n] = stepStatus{State: stepIdle}
	}
	v := T.view
	p := T.p
	if p == nil {
		return st
	}
	if v != nil && v.ElectionID != p.ElectionID {
		v = nil // the console moved on; this process follows on its next poll
	}
	st.Election = &TrusteeElection{ElectionID: p.ElectionID, Trustees: p.Trustees, Threshold: p.Threshold,
		ContestIDs: p.ContestIDs, ParamsChecked: p.Params != "", Positions: []LivePosition{}}
	if v != nil {
		st.Election.Title, st.Election.State = v.Title, v.State
		st.Election.Positions = v.Positions
		st.Election.Trustees, st.Election.Threshold = v.Trustees, v.Threshold
		st.Election.BallotRecords = v.Counts.BallotRecords
		if len(st.Election.ContestIDs) == 0 {
			st.Election.ContestIDs = v.ContestIDs
		}
		st.Ceremony.CeremonyError = v.CeremonyError
		st.Decryption.TrusteesDecrypted = v.Counts.TrusteesDecrypted
	}
	st.Decryption.Threshold = st.Election.Threshold
	for n, s := range p.Steps {
		st.Steps[n] = s
	}
	for _, want := range []string{stepRunning, stepWaiting} {
		for _, n := range []string{"join", "decrypt", "sign"} {
			if st.Step == "" && st.Steps[n].State == want {
				st.Step = n
			}
		}
	}
	st.Alarms = append(st.Alarms, p.Alarms...)
	ack := p.ack()
	st.Fingerprints = TrusteeFingerprints{ReceiveKey: p.ReceiveKeyFingerprint, Roster: p.RosterFingerprint, Ballots: p.BallotsFingerprint}
	if ack != nil {
		st.Fingerprints.Share, st.Fingerprints.JointKey = ack.Fingerprint, ack.JointKeyFingerprint
		st.Ceremony.JointPublicKey, st.Ceremony.VerificationKey = ack.JointPublicKey, ack.VerificationKey
	}
	c := &st.Ceremony
	c.ReceiveKeyPosted, c.RosterComplete, c.RosterDigest = p.ReceiveKeyPosted, p.RosterDigest != "", p.RosterDigest
	c.RosterChecked, c.Dealt, c.Received, c.Acknowledged = p.RosterChecked, p.DealPosted, len(p.Ack) > 0, p.AckPosted
	c.TranscriptPublished, c.TranscriptCheck = p.TranscriptPublished, p.TranscriptCheck
	if v != nil && liveStateIndex(v.State) >= liveStateIndex(LiveOpen) {
		c.TranscriptPublished = true
	}
	for _, peer := range p.RosterPeers {
		e := TrusteeRosterEntry{TrusteeID: peer.TrusteeID, ReceiveKeyFingerprint: p.RosterKeyFPs[strconv.Itoa(peer.TrusteeID)], PeerCheck: "pending"}
		if peer.TrusteeID == T.id {
			e.Self, e.PeerCheck = true, "self"
		} else if pc, ok := p.PeerChecks[strconv.Itoa(peer.TrusteeID)]; ok {
			e.PeerCheck, e.Detail = pc.State, pc.Detail
		}
		c.Roster = append(c.Roster, e)
	}
	d := &st.Decryption
	d.BallotCount, d.BallotsDigest = p.BallotCount, p.BallotsDigest
	for k, n := range p.BallotsByPosition {
		d.BallotsByPosition[k] = n
	}
	for id := 1; id <= p.Trustees; id++ {
		if pc, ok := p.PeerBallotChecks[strconv.Itoa(id)]; ok {
			d.PeerChecks = append(d.PeerChecks, TrusteePeerBallotCheck{TrusteeID: id, State: pc.State, Detail: pc.Detail})
		}
	}
	d.PartialComputed, d.PartialRecorded, d.PartialReadBack = len(p.Partial) > 0, p.PartialPosted, p.PartialReadBack
	t := &st.Tally
	if len(p.Totals) > 0 {
		t.Totals, t.Contests = slices.Clone(p.Totals), slices.Clone(p.Contests)
	}
	t.SignaturePosted, t.SignatureNote = p.SignaturePosted, p.SignatureNote
	t.ReadyToSign = len(p.Totals) > 0 && !p.SignRequested && p.blocked("sign") == nil
	t.Published = p.TallyPublished
	if p.TallyPublished {
		t.PublishedTotals = slices.Clone(p.TallyTotals)
		if len(p.Totals) > 0 {
			m := slices.Equal(p.TallyTotals, p.Totals)
			t.Matches = &m
		}
	}
	return st
}
