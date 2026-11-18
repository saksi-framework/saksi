package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"
)

// The /api/live/* routes (docs/live/http-api.md). Each is registered in
// NewServer whether or not live mode is on, so the role table always covers
// them; with live mode off every one answers 404.

func registerLiveRoutes(mux *routeMux, s *Server) {
	mux.HandleFunc("/api/live/election", s.liveGET(s.handleLiveElection))
	mux.HandleFunc("/api/live/ledger", s.liveGET(s.handleLiveLedger))
	mux.HandleFunc("/api/live/ballot", s.handleLiveBallot)
	mux.HandleFunc("/api/live/issue/presign", s.livePhone(s.handleLivePresign))
	mux.HandleFunc("/api/live/issue/sign", s.livePhone(s.handleLiveSign))
	mux.HandleFunc("/api/live/checkin", s.liveGET(s.handleCheckinPoll))
	mux.HandleFunc("/api/live/checkin/find", s.livePhone(s.handleCheckinFind))
	mux.HandleFunc("/api/live/checkin/declare", s.livePhone(s.handleCheckinDeclare))
	mux.HandleFunc("/api/live/checkin/sign", s.livePhone(s.handleCheckinSign))
	mux.HandleFunc("/api/live/voter-list", s.liveAdmin(s.handleVoterList))
	mux.HandleFunc("/api/live/voter-list/preview", s.liveAdmin(s.handleVoterListPreview))
	mux.HandleFunc("/api/live/desk/approve", s.liveAdmin(s.handleDesk("approve")))
	mux.HandleFunc("/api/live/desk/refuse", s.liveAdmin(s.handleDesk("refuse")))
	mux.HandleFunc("/api/live/desk/reset", s.liveAdmin(s.handleDesk("reset")))
	mux.HandleFunc("/api/live/dkg/receive-key", s.liveTrustee(http.MethodPost, s.handleLiveReceiveKey))
	mux.HandleFunc("/api/live/dkg/roster", s.liveTrustee(http.MethodGet, s.handleLiveRoster))
	mux.HandleFunc("/api/live/dkg/deal", s.liveTrustee(http.MethodPost, s.handleLiveDeal))
	mux.HandleFunc("/api/live/dkg/inbox", s.liveTrustee(http.MethodGet, s.handleLiveInbox))
	mux.HandleFunc("/api/live/dkg/ack", s.liveTrustee(http.MethodPost, s.handleLiveAck))
	mux.HandleFunc("/api/live/partial", s.liveTrustee(http.MethodPost, s.handleLivePartial))
	mux.HandleFunc("/api/live/tally-sig", s.liveTrustee(http.MethodPost, s.handleLiveTallySig))
	mux.HandleFunc("/api/live/elections", s.liveAdmin(s.handleLiveCreate))
	mux.HandleFunc("/api/live/close", s.liveAdmin(s.handleLiveClose))
	mux.HandleFunc("/api/live/tally/publish", s.liveAdmin(s.handleLivePublish))
	mux.HandleFunc("/api/live/verify", s.liveAdmin(s.handleLiveVerify))
	mux.HandleFunc("/api/live/abandon", s.liveAdmin(s.handleLiveAbandon))
}

// liveOpTimeout bounds one route's CLI ops and chain calls.
const liveOpTimeout = 2 * time.Minute

func liveFail(w http.ResponseWriter, err error) {
	var coded errCoded
	if errors.As(err, &coded) {
		writeJSONResp(w, coded.status, map[string]string{"error": coded.msg, "code": coded.code})
		return
	}
	var (
		conflict  errConflict
		bad       errBadRequest
		refused   errRefused
		chain     errChain
		forbidden errForbidden
		notFound  errNotFound
		tooMany   errTooMany
	)
	switch {
	case errors.As(err, &refused):
		writeJSONResp(w, http.StatusUnprocessableEntity, map[string]any{
			"error": refused.Fn + " was refused by the chain", "refused": true,
			"gate": refused.Gate, "reason": refused.Reason,
		})
	case errors.As(err, &conflict):
		writeJSONResp(w, http.StatusConflict, map[string]string{"error": conflict.msg})
	case errors.As(err, &bad):
		body := map[string]string{"error": bad.msg}
		if bad.code != "" {
			body["code"] = bad.code
		}
		writeJSONResp(w, http.StatusBadRequest, body)
	case errors.As(err, &forbidden):
		writeJSONResp(w, http.StatusForbidden, map[string]string{"error": forbidden.msg})
	case errors.As(err, &notFound):
		writeJSONResp(w, http.StatusNotFound, map[string]string{"error": notFound.msg})
	case errors.As(err, &tooMany):
		writeJSONResp(w, http.StatusTooManyRequests, map[string]string{"error": tooMany.msg})
	case errors.As(err, &chain):
		writeJSONResp(w, http.StatusBadGateway, map[string]string{"error": chain.Error()})
	default:
		// A 500 says nothing about the console's files: the detail (which may
		// name a path in the run folder) goes to the server log only, and an
		// issuance error carries none (errInternal).
		var internal errInternal
		if errors.As(err, &internal) {
			log.Printf("live: internal error: %s", internal.log)
		} else {
			log.Printf("live: internal error: %v", err)
		}
		writeJSONResp(w, http.StatusInternalServerError, map[string]string{"error": liveInternalError})
	}
}

// liveInternalError is every 500's message.
const liveInternalError = "internal error in the console; the operator can see the detail in the console log"

// errInternal is a 500 whose log line is log, never the wrapped error: the
// issuance paths name an account's session file, so their errors are logged
// without them.
type errInternal struct{ log string }

func (e errInternal) Error() string { return e.log }

func liveCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), liveOpTimeout)
}

// decodeLive decodes a POST body of at most limit bytes into v, refusing
// unknown fields when strict.
func decodeLive(w http.ResponseWriter, r *http.Request, limit int64, strict bool, v any) bool {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeJSONResp(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
			return false
		}
		writeJSONResp(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	return true
}

func (s *Server) liveOn(w http.ResponseWriter) bool {
	if s.live == nil {
		writeJSONResp(w, http.StatusNotFound, map[string]string{"error": "live mode is off"})
		return false
	}
	return true
}

func (s *Server) liveGET(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.liveOn(w) {
			return
		}
		if r.Method != http.MethodGet {
			writeJSONResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
			return
		}
		h(w, r)
	}
}

func (s *Server) liveAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.liveOn(w) {
			return
		}
		// authorize enforced the admin role; this holds even if auth were off.
		if sess := sessionFrom(r); sess == nil || sess.Role != RoleAdmin {
			writeJSONResp(w, http.StatusForbidden, map[string]string{"error": "admin role required"})
			return
		}
		h(w, r)
	}
}

// livePhone is a phone's route: public, acting on the check-in its
// saksi_checkin cookie is bound to (live_checkin.go). It never reads a
// session: no account, of any role, stands in for a check-in.
func (s *Server) livePhone(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.liveOn(w) {
			return
		}
		h(w, r, checkinToken(r))
	}
}

func (s *Server) liveTrustee(method string, h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.liveOn(w) {
			return
		}
		id := tokenTrustee(r)
		if id == "" {
			writeJSONResp(w, http.StatusUnauthorized, map[string]string{"error": errTrusteeToken})
			return
		}
		if r.Method != method {
			writeJSONResp(w, http.StatusMethodNotAllowed, map[string]string{"error": method + " required"})
			return
		}
		h(w, r, id)
	}
}

// --- admin ---------------------------------------------------------------------

func (s *Server) handleLiveCreate(w http.ResponseWriter, r *http.Request) {
	var req LiveElectionRequest
	if !decodeLive(w, r, voterListBodyMax, true, &req) {
		return
	}
	ctx, cancel := liveCtx(r)
	defer cancel()
	status, err := s.live.createElection(ctx, req)
	if err != nil {
		if status != 0 {
			// Set up, but CreateElection did not go through: the run stays in
			// setup, and the next POST elections (or console start) retries it.
			log.Printf("live: CreateElection: %v", err)
		}
		liveFail(w, err)
		return
	}
	writeJSONResp(w, status, s.live.electionView())
}

func (s *Server) handleLiveAbandon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	if err := s.live.abandon(); err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, s.live.electionView())
}

func (s *Server) handleLiveClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	if _, err := s.live.close(); err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, s.live.electionView())
}

func (s *Server) handleLivePublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	ctx, cancel := liveCtx(r)
	defer cancel()
	out, err := s.live.publishNow(ctx)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleLiveVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	ctx, cancel := liveCtx(r)
	defer cancel()
	out, err := s.live.verify(ctx)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

// --- public --------------------------------------------------------------------

func (s *Server) handleLiveElection(w http.ResponseWriter, r *http.Request) {
	sn := s.live.snapshot()
	if sn == nil {
		liveFail(w, errNotFound{"no live election has been set up"})
		return
	}
	writeJSONResp(w, http.StatusOK, s.live.electionViewOf(sn))
}

// handleLiveLedger reads every ballot and partial from the chain, so it has
// a limiter of its own (not the ballots'): a client looping it can neither
// load the peer without limit nor starve the ballots.
func (s *Server) handleLiveLedger(w http.ResponseWriter, r *http.Request) {
	if !s.live.ledgerLimit.allow() {
		w.Header().Set("Retry-After", "1")
		writeJSONResp(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests at once; try again in a moment"})
		return
	}
	led, err := s.live.readLedger()
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, led)
}

// handleLiveBallot is the anonymous ballot relay. authorize has already
// dropped the Cookie header; this handler reads no session, no address and no
// header, logs nothing about the request, and passes only the ballot hex on.
func (s *Server) handleLiveBallot(w http.ResponseWriter, r *http.Request) {
	if !s.liveOn(w) {
		return
	}
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	if !s.live.limit.allow() {
		w.Header().Set("Retry-After", "1")
		writeJSONResp(w, http.StatusTooManyRequests, map[string]string{"error": "too many ballots at once; try again in a moment"})
		return
	}
	var body struct {
		Ballot string `json:"ballot"`
	}
	if !decodeLive(w, r, liveMaxBallotBody, true, &body) {
		return
	}
	rc, err := s.live.relayBallot(body.Ballot)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, rc)
}

// --- voter list and check-in ------------------------------------------------------

func (s *Server) handleVoterListPreview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CSV string `json:"csv"`
	}
	if !decodeLive(w, r, voterListBodyMax, true, &body) {
		return
	}
	writeJSONResp(w, http.StatusOK, previewOf(parseVoterList(body.CSV, s.live.precinct, s.live.now())))
}

func (s *Server) handleVoterList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET required"})
		return
	}
	v, err := s.live.voterList()
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, v)
}

func (s *Server) handleDesk(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Seq int `json:"seq"`
		}
		if !decodeLive(w, r, 1<<10, true, &body) {
			return
		}
		var (
			v   DeskEntryView
			err error
		)
		switch action {
		case "approve":
			v, err = s.live.deskApprove(body.Seq)
		case "refuse":
			v, err = s.live.deskEnd(body.Seq, checkinRefused)
		default:
			v, err = s.live.deskEnd(body.Seq, checkinReset)
		}
		if err != nil {
			liveFail(w, err)
			return
		}
		writeJSONResp(w, http.StatusOK, v)
	}
}

// findAllowed applies the per-address limit of find and declare.
func (s *Server) findAllowed(w http.ResponseWriter, r *http.Request) bool {
	ok, wait := s.live.findLimit.allow(remoteIP(r))
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int((wait+time.Second-1)/time.Second)))
		writeJSONResp(w, http.StatusTooManyRequests, map[string]string{"error": "too many tries from this device; wait a moment and try again", "code": "rate-limited"})
	}
	return ok
}

func (s *Server) handleCheckinFind(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	if !s.findAllowed(w, r) {
		return
	}
	var d CheckinDetails
	if !decodeLive(w, r, 4<<10, true, &d) {
		return
	}
	v, err := s.live.checkinFind(d)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, v)
}

func (s *Server) handleCheckinDeclare(w http.ResponseWriter, r *http.Request, held string) {
	if r.Method != http.MethodPost {
		writeJSONResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	if !s.findAllowed(w, r) {
		return
	}
	var body struct {
		CheckinDetails
		Declaration bool `json:"declaration"`
	}
	if !decodeLive(w, r, 4<<10, true, &body) {
		return
	}
	v, token, err := s.live.checkinDeclare(body.CheckinDetails, body.Declaration, held)
	if err != nil {
		liveFail(w, err)
		return
	}
	setCheckinCookie(w, token)
	writeJSONResp(w, http.StatusOK, v)
}

func (s *Server) handleCheckinPoll(w http.ResponseWriter, r *http.Request) {
	v, err := s.live.checkinPoll(checkinToken(r))
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, v)
}

func (s *Server) handleCheckinSign(w http.ResponseWriter, r *http.Request, token string) {
	var sig CheckinSignature
	if !decodeLive(w, r, sigMaxBody, true, &sig) {
		return
	}
	v, err := s.live.checkinSign(token, sig)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, v)
}

// --- issuance ------------------------------------------------------------------

func (s *Server) handleLivePresign(w http.ResponseWriter, r *http.Request, token string) {
	var body struct {
		BlindedCommitment string `json:"blinded_commitment"`
	}
	if !decodeLive(w, r, 4<<10, true, &body) {
		return
	}
	ctx, cancel := liveCtx(r)
	defer cancel()
	out, err := s.live.presign(ctx, token, body.BlindedCommitment)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleLiveSign(w http.ResponseWriter, r *http.Request, token string) {
	var body struct {
		EPrime string `json:"e_prime"`
	}
	if !decodeLive(w, r, 4<<10, true, &body) {
		return
	}
	ctx, cancel := liveCtx(r)
	defer cancel()
	out, err := s.live.sign(ctx, token, body.EPrime)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

// --- trustee -------------------------------------------------------------------

func (s *Server) handleLiveReceiveKey(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		TrusteeID        json.Number `json:"trustee_id"`
		ReceivePublicKey string      `json:"receive_public_key"`
	}
	if !decodeLive(w, r, 4<<10, false, &body) {
		return
	}
	ctx, cancel := liveCtx(r)
	defer cancel()
	out, err := s.live.postReceiveKey(ctx, id, body)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleLiveRoster(w http.ResponseWriter, r *http.Request, id string) {
	out, err := s.live.roster(id)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleLiveDeal(w http.ResponseWriter, r *http.Request, id string) {
	var body LiveDealBody
	if !decodeLive(w, r, 256<<10, false, &body) {
		return
	}
	out, err := s.live.postDeal(id, body)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleLiveInbox(w http.ResponseWriter, r *http.Request, id string) {
	out, err := s.live.inbox(id)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleLiveAck(w http.ResponseWriter, r *http.Request, id string) {
	var body LiveAckBody
	if !decodeLive(w, r, 16<<10, false, &body) {
		return
	}
	ctx, cancel := liveCtx(r)
	defer cancel()
	out, err := s.live.postAck(ctx, id, body)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleLivePartial(w http.ResponseWriter, r *http.Request, id string) {
	var body LivePartialBody
	if !decodeLive(w, r, 1<<20, false, &body) {
		return
	}
	out, err := s.live.postPartials(id, body)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleLiveTallySig(w http.ResponseWriter, r *http.Request, id string) {
	var body LiveTallySigBody
	if !decodeLive(w, r, 16<<10, false, &body) {
		return
	}
	ctx, cancel := liveCtx(r)
	defer cancel()
	out, err := s.live.postTallySig(ctx, id, body)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

// --- the public view -------------------------------------------------------------

// LiveCounts are the election's running counts.
type LiveCounts struct {
	// VotersOnRoll and VotersOnList are both the number of entries on the
	// voter list (voters_on_roll is the older name, kept for the pages).
	VotersOnRoll int `json:"voters_on_roll"`
	VotersOnList int `json:"voters_on_list"`
	// CheckedIn is the entries that signed the list: signed or
	// credential_issued.
	CheckedIn         int `json:"checked_in"`
	CredentialsIssued int `json:"credentials_issued"`
	// BallotRecords is the chain's committed nullifier count, or the run
	// folder's count with BallotRecordsSource "console" if the chain did not
	// answer.
	BallotRecords       int    `json:"ballot_records"`
	BallotRecordsSource string `json:"ballot_records_source"`
	// MinBallotRecords is the console's figure for the fewest ballot records
	// decryption needs (--live-min-ballots per position), from open on. A
	// closed election under it cannot be decrypted: the chain takes no
	// ballot after CloseElection. Reported only; the console refuses nothing
	// on it, and the trustee processes check their own --min-ballots.
	MinBallotRecords  int `json:"min_ballot_records,omitempty"`
	TrusteesDecrypted int `json:"trustees_decrypted"`
	TallySignatures   int `json:"tally_signatures"`
	// TrusteesJoined is the number of trustees whose receive key is in the
	// election's roster: 0 after setup, the trustee count once the roster is
	// complete, and unchanged after that.
	TrusteesJoined int `json:"trustees_joined"`
}

// LiveElectionView is GET /api/live/election.
type LiveElectionView struct {
	RunID               string          `json:"run_id"`
	ElectionID          string          `json:"election_id"`
	Title               string          `json:"title"`
	State               string          `json:"state"`
	Positions           []LivePosition  `json:"positions"`
	Trustees            int             `json:"trustees"`
	Threshold           int             `json:"threshold"`
	Params              string          `json:"params"`
	ContestIDs          []string        `json:"contest_ids"`
	IssuerPublicKey     string          `json:"issuer_public_key"`
	DKG                 string          `json:"dkg,omitempty"`
	JointPublicKey      string          `json:"joint_public_key,omitempty"`
	JointKeyFingerprint string          `json:"joint_key_fingerprint,omitempty"`
	VerificationKeys    json.RawMessage `json:"verification_keys,omitempty"`
	RosterFingerprint   string          `json:"roster_fingerprint,omitempty"`
	CeremonyError       string          `json:"ceremony_error,omitempty"`
	// The voter list's public facts (no names, no dates).
	Precinct                  string            `json:"precinct,omitempty"`
	PrecinctLabel             string            `json:"precinct_label,omitempty"`
	VoterListFingerprint      string            `json:"voter_list_fingerprint,omitempty"`
	VoterListFingerprintShort string            `json:"voter_list_fingerprint_short,omitempty"`
	Counts                    LiveCounts        `json:"counts"`
	Lifecycle                 map[string]LiveTx `json:"lifecycle"`
	Totals                    []uint64          `json:"totals,omitempty"`
	VerifyOverall             string            `json:"verify_overall,omitempty"`
	CreatedAt                 time.Time         `json:"created_at"`
	UpdatedAt                 time.Time         `json:"updated_at"`
}

// electionView is GET /api/live/election, built from the public snapshot: it
// never waits on mu, so a transition held up by a slow chain does not freeze
// it. Caller has checked that an election exists.
func (L *liveService) electionView() LiveElectionView {
	return L.electionViewOf(L.snapshot())
}

func (L *liveService) electionViewOf(sn *liveSnapshot) LiveElectionView {
	v := LiveElectionView{
		RunID: sn.RunID, ElectionID: sn.ElectionID, Title: sn.Title, State: sn.State,
		Positions: sn.Positions, Trustees: sn.Trustees, Threshold: sn.Threshold,
		Params: sn.Params, ContestIDs: sn.ContestIDs, IssuerPublicKey: sn.IssuerPublicKey,
		DKG: sn.DKG, JointPublicKey: sn.JointPublicKey, JointKeyFingerprint: sn.JointKeyFingerprint,
		VerificationKeys: sn.VerificationKeys, RosterFingerprint: sn.RosterFingerprint,
		CeremonyError: sn.CeremonyError, Lifecycle: sn.Lifecycle,
		Totals: sn.Totals, VerifyOverall: sn.VerifyOverall,
		CreatedAt: sn.CreatedAt, UpdatedAt: sn.UpdatedAt,
		Counts: LiveCounts{
			VotersOnRoll: sn.VotersOnList, VotersOnList: sn.VotersOnList, CredentialsIssued: sn.Issued,
			BallotRecords: sn.Ballots, BallotRecordsSource: "console",
			MinBallotRecords:  L.minBallotRecords(sn.State, sn.ContestIDs),
			TrusteesDecrypted: len(sn.Decrypted), TallySignatures: len(sn.TallySignatures),
			TrusteesJoined: sn.TrusteesJoined,
		},
	}
	if sn.Precinct != "" {
		v.Precinct, v.PrecinctLabel = sn.Precinct, precinctLabel(sn.Precinct)
		v.VoterListFingerprint, v.VoterListFingerprintShort = sn.VoterListFingerprint, fingerprintShort(sn.VoterListFingerprint)
	}
	// Both counts come from the issuance record itself: an issuance that
	// could not take mu (live_issue.go) still shows at once.
	if c, ok := L.checkinCountsOf(sn.RunID, sn.Dir); ok {
		v.Counts.CheckedIn, v.Counts.CredentialsIssued = c.CheckedIn, c.Issued
	}
	if sn.stateIndex() >= liveStateIndex(LiveCeremony) {
		if n := L.chainCount(sn.ElectionID); n >= 0 {
			v.Counts.BallotRecords, v.Counts.BallotRecordsSource = n, "chain"
		}
	}
	return v
}
