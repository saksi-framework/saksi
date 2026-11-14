package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"
)

// The /api/live/* routes (docs/live/http-api.md). Each is registered in
// NewServer whether or not live mode is on, so the role table always covers
// them; with live mode off every one answers 404.

func registerLiveRoutes(mux *routeMux, s *Server) {
	mux.HandleFunc("/api/live/election", s.liveGET(s.handleLiveElection))
	mux.HandleFunc("/api/live/ledger", s.liveGET(s.handleLiveLedger))
	mux.HandleFunc("/api/live/ballot", s.handleLiveBallot)
	mux.HandleFunc("/api/live/issue/presign", s.liveVoter(s.handleLivePresign))
	mux.HandleFunc("/api/live/issue/sign", s.liveVoter(s.handleLiveSign))
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
}

// liveOpTimeout bounds one route's CLI ops and chain calls.
const liveOpTimeout = 2 * time.Minute

func liveFail(w http.ResponseWriter, err error) {
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
		writeJSONResp(w, http.StatusBadRequest, map[string]string{"error": bad.msg})
	case errors.As(err, &forbidden):
		writeJSONResp(w, http.StatusForbidden, map[string]string{"error": forbidden.msg})
	case errors.As(err, &notFound):
		writeJSONResp(w, http.StatusNotFound, map[string]string{"error": notFound.msg})
	case errors.As(err, &tooMany):
		writeJSONResp(w, http.StatusTooManyRequests, map[string]string{"error": tooMany.msg})
	case errors.As(err, &chain):
		writeJSONResp(w, http.StatusBadGateway, map[string]string{"error": chain.Error()})
	default:
		writeJSONResp(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}

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

func (s *Server) liveVoter(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.liveOn(w) {
			return
		}
		sess := sessionFrom(r)
		if sess == nil || sess.Role != RoleVoter {
			writeJSONResp(w, http.StatusForbidden, map[string]string{"error": "only a voter account may obtain a credential"})
			return
		}
		h(w, r, sess.Username)
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
	if !decodeLive(w, r, 64<<10, true, &req) {
		return
	}
	ctx, cancel := liveCtx(r)
	defer cancel()
	st, err := s.live.createElection(ctx, req)
	if err != nil && st == nil {
		liveFail(w, err)
		return
	}
	if err != nil {
		// Set up, but CreateElection did not go through: the run stays in setup
		// and a console restart (or the next start) finishes it.
		log.Printf("live: CreateElection: %v", err)
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusCreated, s.live.electionView())
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
	s.live.mu.Lock()
	none := s.live.st == nil
	s.live.mu.Unlock()
	if none {
		liveFail(w, errNotFound{"no live election has been set up"})
		return
	}
	writeJSONResp(w, http.StatusOK, s.live.electionView())
}

func (s *Server) handleLiveLedger(w http.ResponseWriter, r *http.Request) {
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

// --- voter ---------------------------------------------------------------------

func (s *Server) handleLivePresign(w http.ResponseWriter, r *http.Request, account string) {
	var body struct {
		BlindedCommitment string `json:"blinded_commitment"`
	}
	if !decodeLive(w, r, 4<<10, true, &body) {
		return
	}
	ctx, cancel := liveCtx(r)
	defer cancel()
	out, err := s.live.presign(ctx, account, body.BlindedCommitment)
	if err != nil {
		liveFail(w, err)
		return
	}
	writeJSONResp(w, http.StatusOK, out)
}

func (s *Server) handleLiveSign(w http.ResponseWriter, r *http.Request, account string) {
	var body struct {
		EPrime string `json:"e_prime"`
	}
	if !decodeLive(w, r, 4<<10, true, &body) {
		return
	}
	ctx, cancel := liveCtx(r)
	defer cancel()
	out, err := s.live.sign(ctx, account, body.EPrime)
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
	VotersOnRoll      int `json:"voters_on_roll"`
	CredentialsIssued int `json:"credentials_issued"`
	// BallotRecords is the chain's committed nullifier count, or the run
	// folder's count with BallotRecordsSource "console" if the chain did not
	// answer.
	BallotRecords       int    `json:"ballot_records"`
	BallotRecordsSource string `json:"ballot_records_source"`
	TrusteesDecrypted   int    `json:"trustees_decrypted"`
	TallySignatures     int    `json:"tally_signatures"`
}

// LiveElectionView is GET /api/live/election.
type LiveElectionView struct {
	RunID               string            `json:"run_id"`
	ElectionID          string            `json:"election_id"`
	Title               string            `json:"title"`
	State               string            `json:"state"`
	Positions           []LivePosition    `json:"positions"`
	Trustees            int               `json:"trustees"`
	Threshold           int               `json:"threshold"`
	Params              string            `json:"params"`
	ContestIDs          []string          `json:"contest_ids"`
	IssuerPublicKey     string            `json:"issuer_public_key"`
	DKG                 string            `json:"dkg,omitempty"`
	JointPublicKey      string            `json:"joint_public_key,omitempty"`
	JointKeyFingerprint string            `json:"joint_key_fingerprint,omitempty"`
	VerificationKeys    json.RawMessage   `json:"verification_keys,omitempty"`
	RosterFingerprint   string            `json:"roster_fingerprint,omitempty"`
	CeremonyError       string            `json:"ceremony_error,omitempty"`
	Counts              LiveCounts        `json:"counts"`
	Lifecycle           map[string]LiveTx `json:"lifecycle"`
	Totals              []uint64          `json:"totals,omitempty"`
	VerifyOverall       string            `json:"verify_overall,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

func (L *liveService) electionView() LiveElectionView {
	L.mu.Lock()
	st := L.st
	v := LiveElectionView{
		RunID: st.RunID, ElectionID: st.ElectionID, Title: st.Title, State: st.State,
		Positions: st.Positions, Trustees: st.Trustees, Threshold: st.Threshold,
		Params: st.Params, ContestIDs: st.ContestIDs, IssuerPublicKey: st.IssuerPublicKey,
		DKG: st.DKG, JointPublicKey: st.JointPublicKey, JointKeyFingerprint: st.JointKeyFingerprint,
		CeremonyError: st.CeremonyError, Lifecycle: st.Lifecycle,
		Totals: st.Totals, VerifyOverall: st.VerifyOverall,
		CreatedAt: st.CreatedAt, UpdatedAt: st.UpdatedAt,
		Counts: LiveCounts{
			VotersOnRoll: len(L.voterRoll()), CredentialsIssued: st.Issued,
			BallotRecords: st.Ballots, BallotRecordsSource: "console",
			TrusteesDecrypted: L.decryptedLocked(), TallySignatures: len(st.Signatures),
		},
	}
	if st.Transcript != nil {
		var tr struct {
			VerificationKeys json.RawMessage `json:"verification_keys"`
		}
		if json.Unmarshal(st.Transcript, &tr) == nil {
			v.VerificationKeys = tr.VerificationKeys
		}
	}
	if st.Roster != nil {
		var ro struct {
			RosterFingerprint string `json:"roster_fingerprint"`
		}
		if json.Unmarshal(st.Roster, &ro) == nil {
			v.RosterFingerprint = ro.RosterFingerprint
		}
	}
	electionID, onChain := st.ElectionID, st.stateIndex() >= liveStateIndex(LiveCeremony)
	L.mu.Unlock()
	if onChain {
		if n := L.chainCount(electionID); n >= 0 {
			v.Counts.BallotRecords, v.Counts.BallotRecordsSource = n, "chain"
		}
	}
	return v
}
