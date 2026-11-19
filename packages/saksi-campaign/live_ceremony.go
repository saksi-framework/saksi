package campaign

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
)

// The key-ceremony relay. The console holds no trustee secret: it collects the
// receive keys into a roster, relays each dealer's commitments to everyone and
// each masked share to its recipient with an unchanged JSON value (it cannot
// unmask them), collects each trustee's public acknowledgement, and then
// assembles and publishes the transcript.

var hex64 = func(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// identityPoint is the compressed ristretto255 identity: 32 zero bytes.
const identityPoint = "0000000000000000000000000000000000000000000000000000000000000000"

func (L *liveService) requireTrustee(id string) error {
	n, err := strconv.Atoi(id)
	if err != nil || n < 1 || n > L.st.Trustees {
		return errForbidden{fmt.Sprintf("trustee %s is not a trustee of election %s", id, L.st.ElectionID)}
	}
	return nil
}

// errForbidden is a trustee acting outside its own id or election: 403.
type errForbidden struct{ msg string }

func (e errForbidden) Error() string { return e.msg }

func (L *liveService) current() (*liveState, error) {
	if L.st == nil {
		return nil, errNotFound{"no live election has been set up"}
	}
	return L.st, nil
}

// errNotFound is 404.
type errNotFound struct{ msg string }

func (e errNotFound) Error() string { return e.msg }

func (L *liveService) inState(want ...string) error {
	st, err := L.current()
	if err != nil {
		return err
	}
	for _, w := range want {
		if st.State == w {
			return nil
		}
	}
	return conflictf("the live election is %s; this needs it %s", st.State, strings.Join(want, " or "))
}

// postReceiveKey records trustee id's receive public key (trustee-keygen's
// output). Once every trustee's key is in, the roster is computed and frozen.
func (L *liveService) postReceiveKey(ctx context.Context, id string, body struct {
	TrusteeID        json.Number `json:"trustee_id"`
	ReceivePublicKey string      `json:"receive_public_key"`
}) (map[string]any, error) {
	L.mu.Lock()
	defer L.mu.Unlock()
	if err := L.inState(LiveCeremony); err != nil {
		return nil, err
	}
	if err := L.requireTrustee(id); err != nil {
		return nil, err
	}
	if body.TrusteeID != "" && body.TrusteeID.String() != id {
		return nil, errForbidden{fmt.Sprintf("this token is trustee %s's; it cannot post for trustee %s", id, body.TrusteeID)}
	}
	key := strings.ToLower(body.ReceivePublicKey)
	if !hex64(key) {
		return nil, badRequestf("receive_public_key must be a 64-hex-digit point")
	}
	st := L.st
	if st.Roster != nil {
		if st.ReceiveKeys[id] == key {
			return L.rosterStatusLocked(), nil
		}
		return nil, conflictf("the roster is complete and frozen; a receive key cannot change now")
	}
	st.ReceiveKeys[id] = key
	if len(st.ReceiveKeys) == st.Trustees {
		var roster json.RawMessage
		if err := L.opJSON(ctx, "dkg-roster", map[string]any{"params": st.Params, "peers": L.peersLocked()}, &roster); err != nil {
			delete(st.ReceiveKeys, id)
			return nil, conflictf("%v", err)
		}
		var r struct {
			RosterDigest string `json:"roster_digest"`
		}
		if err := json.Unmarshal(roster, &r); err != nil || !hex64(r.RosterDigest) {
			delete(st.ReceiveKeys, id)
			return nil, fmt.Errorf("dkg-roster gave no roster digest")
		}
		st.Roster, st.RosterDigest = roster, r.RosterDigest
		log.Printf("live: %s roster complete", st.RunID)
	}
	if err := L.save(); err != nil {
		return nil, err
	}
	return L.rosterStatusLocked(), nil
}

// livePeer is dkg-deal's and dkg-receive's roster entry.
type livePeer struct {
	TrusteeID        int    `json:"trustee_id"`
	ReceivePublicKey string `json:"receive_public_key"`
}

func (L *liveService) peersLocked() []livePeer {
	var peers []livePeer
	for id, key := range L.st.ReceiveKeys {
		n, _ := strconv.Atoi(id)
		peers = append(peers, livePeer{TrusteeID: n, ReceivePublicKey: key})
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].TrusteeID < peers[j].TrusteeID })
	return peers
}

func sortedIDs[V any](m map[string]V) []int {
	var ids []int
	for id := range m {
		n, _ := strconv.Atoi(id)
		ids = append(ids, n)
	}
	sort.Ints(ids)
	return ids
}

// rosterStatusLocked is GET /api/live/dkg/roster.
func (L *liveService) rosterStatusLocked() map[string]any {
	st := L.st
	out := map[string]any{
		"election_id": st.ElectionID, "state": st.State, "trustees": st.Trustees, "threshold": st.Threshold,
		"complete": st.Roster != nil, "received": sortedIDs(st.ReceiveKeys),
		"params": st.Params,
	}
	if st.Roster != nil {
		var r map[string]any
		_ = json.Unmarshal(st.Roster, &r)
		// peers is dkg-deal's roster input as it is; fingerprints are each
		// key's trustee-keygen fingerprint, for the trustee pages.
		out["peers"] = L.peersLocked()
		out["fingerprints"] = r["peers"]
		for _, k := range []string{"roster_digest", "roster_fingerprint"} {
			out[k] = r[k]
		}
		out["dealt"] = sortedIDs(st.Deals)
		out["acknowledged"] = sortedIDs(st.Acks)
	}
	return out
}

func (L *liveService) roster(id string) (map[string]any, error) {
	L.mu.Lock()
	defer L.mu.Unlock()
	if _, err := L.current(); err != nil {
		return nil, err
	}
	if err := L.requireTrustee(id); err != nil {
		return nil, err
	}
	return L.rosterStatusLocked(), nil
}

// liveMaskedShare is the part of a masked share the relay checks. The share
// itself is stored and returned with an unchanged JSON value.
type liveMaskedShare struct {
	DealerID    int    `json:"dealer_id"`
	RecipientID int    `json:"recipient_id"`
	Nonce       string `json:"nonce"`
	Ciphertext  string `json:"ciphertext"`
	Tag         string `json:"tag"`
}

// LiveDealBody is POST /api/live/dkg/deal: dkg-deal's output as it is.
type LiveDealBody struct {
	ElectionID   string            `json:"election_id"`
	DealerID     int               `json:"dealer_id"`
	Commitments  []string          `json:"commitments"`
	MaskedShares []json.RawMessage `json:"masked_shares"`
	RosterDigest string            `json:"roster_digest"`
}

func (L *liveService) postDeal(id string, body LiveDealBody) (map[string]any, error) {
	L.mu.Lock()
	defer L.mu.Unlock()
	if err := L.inState(LiveCeremony); err != nil {
		return nil, err
	}
	if err := L.requireTrustee(id); err != nil {
		return nil, err
	}
	st := L.st
	if st.Roster == nil {
		return nil, conflictf("the roster is not complete yet: %d of %d receive keys", len(st.ReceiveKeys), st.Trustees)
	}
	if strconv.Itoa(body.DealerID) != id {
		return nil, errForbidden{fmt.Sprintf("this token is trustee %s's; it cannot deal as dealer %d", id, body.DealerID)}
	}
	if body.ElectionID != st.ElectionID {
		return nil, badRequestf("the deal is for election %q, not %q", body.ElectionID, st.ElectionID)
	}
	if !strings.EqualFold(body.RosterDigest, st.RosterDigest) {
		return nil, conflictf("the deal was made over roster %s, but the published roster is %s: the dealer saw a different roster", body.RosterDigest, st.RosterDigest)
	}
	if len(body.Commitments) != st.Threshold {
		return nil, badRequestf("a deal carries %d commitments (the threshold), got %d", st.Threshold, len(body.Commitments))
	}
	for k, c := range body.Commitments {
		if !hex64(c) {
			return nil, badRequestf("commitment %d is not a 64-hex-digit point", k)
		}
	}
	if len(body.MaskedShares) != st.Trustees {
		return nil, badRequestf("a deal carries one masked share per trustee (%d), got %d", st.Trustees, len(body.MaskedShares))
	}
	for k, raw := range body.MaskedShares {
		var ms liveMaskedShare
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&ms); err != nil {
			return nil, badRequestf("masked share %d is not a {dealer_id, recipient_id, nonce, ciphertext, tag} object", k)
		}
		if strconv.Itoa(ms.DealerID) != id || ms.RecipientID != k+1 {
			return nil, badRequestf("masked share %d is from %d to %d; want from %s to %d", k, ms.DealerID, ms.RecipientID, id, k+1)
		}
		if !hex64(ms.Nonce) || !hex64(ms.Ciphertext) || !hex64(ms.Tag) {
			return nil, badRequestf("masked share %d: nonce, ciphertext and tag are 32-byte hex each", k)
		}
	}
	deal := liveDeal{Commitments: body.Commitments, MaskedShares: body.MaskedShares}
	if prev, ok := st.Deals[id]; ok {
		if sameDeal(prev, deal) {
			return L.rosterStatusLocked(), nil
		}
		// A second deal would hand the peers shares of a second polynomial.
		return nil, conflictf("trustee %s has dealt already; a deal is made once", id)
	}
	st.Deals[id] = deal
	if err := L.save(); err != nil {
		return nil, err
	}
	return L.rosterStatusLocked(), nil
}

func sameDeal(a, b liveDeal) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}

// liveInboxDealer is one entry of dkg-receive's dealers input.
type liveInboxDealer struct {
	DealerID         int             `json:"dealer_id"`
	ReceivePublicKey string          `json:"receive_public_key"`
	Commitments      []string        `json:"commitments"`
	MaskedShare      json.RawMessage `json:"masked_share"`
}

// inbox is trustee id's dkg-receive input pieces: the roster and, from every
// dealer, its commitments and the masked share addressed to id.
func (L *liveService) inbox(id string) (map[string]any, error) {
	L.mu.Lock()
	defer L.mu.Unlock()
	if _, err := L.current(); err != nil {
		return nil, err
	}
	if err := L.requireTrustee(id); err != nil {
		return nil, err
	}
	st := L.st
	out := map[string]any{
		"election_id": st.ElectionID, "state": st.State, "trustee_id": mustAtoi(id),
		"complete": st.Roster != nil && len(st.Deals) == st.Trustees,
		"dealt":    sortedIDs(st.Deals),
	}
	if !out["complete"].(bool) {
		return out, nil
	}
	k := mustAtoi(id) - 1
	var dealers []liveInboxDealer
	for _, d := range sortedIDs(st.Deals) {
		deal := st.Deals[strconv.Itoa(d)]
		dealers = append(dealers, liveInboxDealer{
			DealerID: d, ReceivePublicKey: st.ReceiveKeys[strconv.Itoa(d)],
			Commitments: deal.Commitments, MaskedShare: deal.MaskedShares[k],
		})
	}
	out["params"] = st.Params
	out["peers"] = L.peersLocked()
	out["roster_digest"] = st.RosterDigest
	out["dealers"] = dealers
	return out, nil
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// LiveAckBody is POST /api/live/dkg/ack: dkg-receive's output as it is.
type LiveAckBody struct {
	ElectionID          string `json:"election_id"`
	TrusteeID           int    `json:"trustee_id"`
	VerificationKey     string `json:"verification_key"`
	Fingerprint         string `json:"fingerprint"`
	JointPublicKey      string `json:"joint_public_key"`
	JointKeyFingerprint string `json:"joint_key_fingerprint"`
	RosterDigest        string `json:"roster_digest"`
	RosterFingerprint   string `json:"roster_fingerprint"`
}

// postAck records a trustee's acknowledgement that it received and verified
// every share. The last one triggers the transcript and PublishDKGTranscript.
func (L *liveService) postAck(ctx context.Context, id string, body LiveAckBody) (map[string]any, error) {
	L.mu.Lock()
	defer L.mu.Unlock()
	if err := L.inState(LiveCeremony); err != nil {
		return nil, err
	}
	if err := L.requireTrustee(id); err != nil {
		return nil, err
	}
	st := L.st
	if len(st.Deals) != st.Trustees {
		return nil, conflictf("not every trustee has dealt yet: %d of %d", len(st.Deals), st.Trustees)
	}
	if strconv.Itoa(body.TrusteeID) != id {
		return nil, errForbidden{fmt.Sprintf("this token is trustee %s's; it cannot acknowledge for trustee %d", id, body.TrusteeID)}
	}
	if body.ElectionID != st.ElectionID {
		return nil, badRequestf("the acknowledgement is for election %q, not %q", body.ElectionID, st.ElectionID)
	}
	if !strings.EqualFold(body.RosterDigest, st.RosterDigest) {
		return nil, conflictf("trustee %s received under roster %s, not the published %s", id, body.RosterDigest, st.RosterDigest)
	}
	if !hex64(body.VerificationKey) || !hex64(body.JointPublicKey) {
		return nil, badRequestf("verification_key and joint_public_key are 64-hex-digit points")
	}
	ack := liveAck{
		VerificationKey: strings.ToLower(body.VerificationKey), Fingerprint: body.Fingerprint,
		JointPublicKey: strings.ToLower(body.JointPublicKey), JointKeyFingerprint: body.JointKeyFingerprint,
		RosterDigest: strings.ToLower(body.RosterDigest),
	}
	if prev, ok := st.Acks[id]; ok && prev != ack {
		return nil, conflictf("trustee %s acknowledged a different key share already", id)
	}
	st.Acks[id] = ack
	if err := L.save(); err != nil {
		return nil, err
	}
	out := map[string]any{"acknowledged": sortedIDs(st.Acks), "trustees": st.Trustees, "published": false}
	if len(st.Acks) == st.Trustees {
		if err := L.finishCeremonyLocked(ctx); err != nil {
			return nil, err
		}
		out["published"] = true
		out["joint_public_key"] = st.JointPublicKey
		out["joint_key_fingerprint"] = st.JointKeyFingerprint
		out["transaction"] = st.Lifecycle["PublishDKGTranscript"]
	}
	return out, nil
}

// liveTranscript is dkg-transcript's output.
type liveTranscript struct {
	DKG                 string `json:"dkg"`
	ElectionID          string `json:"election_id"`
	JointPublicKey      string `json:"joint_public_key"`
	JointKeyFingerprint string `json:"joint_key_fingerprint"`
	VerificationKeys    []struct {
		TrusteeID       string `json:"trustee_id"`
		VerificationKey string `json:"verification_key"`
		Fingerprint     string `json:"fingerprint"`
	} `json:"verification_keys"`
}

// finishCeremonyLocked assembles the transcript from the dealers'
// commitments, checks it against every trustee's acknowledgement, refuses an
// identity key, records PublishDKGTranscript and opens the election. Caller
// holds mu; every acknowledgement is in.
func (L *liveService) finishCeremonyLocked(ctx context.Context) error {
	st := L.st
	if st.DKG == "" {
		type dealerIn struct {
			DealerID    int      `json:"dealer_id"`
			Commitments []string `json:"commitments"`
		}
		var dealers []dealerIn
		for _, d := range sortedIDs(st.Deals) {
			dealers = append(dealers, dealerIn{DealerID: d, Commitments: st.Deals[strconv.Itoa(d)].Commitments})
		}
		var raw json.RawMessage
		if err := L.opJSON(ctx, "dkg-transcript", map[string]any{"params": st.Params, "dealers": dealers}, &raw); err != nil {
			if isRunFailure(err) {
				// Not a refusal of the transcript: nothing is recorded, and
				// the next acknowledgement post (or a restart) tries again.
				return err
			}
			st.CeremonyError = err.Error()
			_ = L.save()
			return conflictf("the transcript was refused: %v", err)
		}
		var tr liveTranscript
		if err := json.Unmarshal(raw, &tr); err != nil {
			return fmt.Errorf("dkg-transcript output: %v", err)
		}
		if why := checkTranscript(st, tr); why != "" {
			st.CeremonyError = why
			_ = L.save()
			return conflictf("the transcript is not published: %s", why)
		}
		st.Transcript, st.DKG = raw, tr.DKG
		st.JointPublicKey, st.JointKeyFingerprint = strings.ToLower(tr.JointPublicKey), tr.JointKeyFingerprint
		st.CeremonyError = ""
		if err := L.save(); err != nil {
			return err
		}
	}
	rc, err := L.chainSubmit("PublishDKGTranscript", st.DKG)
	if err != nil {
		if ref, ok := err.(errRefused); ok && ref.Gate == "dkg-duplicate" {
			// Already recorded: a resume after a crash before the state write.
			err = nil
		} else {
			return err
		}
	}
	if rc.TxID != "" {
		st.Lifecycle["PublishDKGTranscript"] = txOf(rc)
		L.appendLifecycleLocked("PublishDKGTranscript", "", rc)
	}
	st.State = LiveOpen
	log.Printf("live: %s open", st.RunID)
	return L.save()
}

// checkTranscript compares the assembled transcript with every trustee's own
// acknowledgement and refuses an identity key; "" means it may be published.
func checkTranscript(st *liveState, tr liveTranscript) string {
	if tr.ElectionID != st.ElectionID {
		return fmt.Sprintf("the transcript is for election %q", tr.ElectionID)
	}
	if strings.EqualFold(tr.JointPublicKey, identityPoint) {
		return "the joint public key is the identity: every vote would be in the clear"
	}
	if len(tr.VerificationKeys) != st.Trustees {
		return fmt.Sprintf("the transcript has %d verification keys for %d trustees", len(tr.VerificationKeys), st.Trustees)
	}
	for _, vk := range tr.VerificationKeys {
		if strings.EqualFold(vk.VerificationKey, identityPoint) {
			return fmt.Sprintf("trustee %s's verification key is the identity", vk.TrusteeID)
		}
		ack, ok := st.Acks[vk.TrusteeID]
		if !ok {
			return fmt.Sprintf("trustee %s has not acknowledged", vk.TrusteeID)
		}
		if !strings.EqualFold(ack.VerificationKey, vk.VerificationKey) {
			return fmt.Sprintf("trustee %s's key share does not match the transcript's verification key: it was shown other commitments", vk.TrusteeID)
		}
		if !strings.EqualFold(ack.JointPublicKey, tr.JointPublicKey) {
			return fmt.Sprintf("trustee %s computed a different joint key", vk.TrusteeID)
		}
	}
	return ""
}
