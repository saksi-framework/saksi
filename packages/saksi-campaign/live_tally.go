package campaign

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// --- abandon -------------------------------------------------------------------

// abandon gives up the current election in setup or ceremony, before any
// credential or ballot exists, so that a stuck setup or ceremony can be left
// without a fresh --runs folder. The state is written atomically; the run is
// terminal, and a new election may then be created. Nothing is sent to the
// chain: the chain keeps its record of the election (open, with no
// transcript), which no ballot can ever use, since no credential was issued
// under its issuer key.
func (L *liveService) abandon() error {
	L.mu.Lock()
	defer L.mu.Unlock()
	if err := L.inState(LiveSetup, LiveCeremony); err != nil {
		return err
	}
	if L.st.Issued != 0 || L.st.Ballots != 0 {
		return conflictf("the live election has credentials or ballots; it cannot be abandoned")
	}
	from := L.st.State
	L.st.State = LiveAbandoned
	log.Printf("live: %s abandoned in %s", L.st.RunID, from)
	return L.save()
}

// --- close ---------------------------------------------------------------------

func (L *liveService) close() (*liveState, error) {
	L.mu.Lock()
	defer L.mu.Unlock()
	if err := L.inState(LiveOpen); err != nil {
		return nil, err
	}
	rc, err := L.chainSubmit("CloseElection", L.st.ElectionID)
	var ref errRefused
	if errors.As(err, &ref) && ref.Gate == "already-closed" {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	if rc.TxID != "" {
		L.st.Lifecycle["CloseElection"] = txOf(rc)
		L.appendLifecycleLocked("CloseElection", "", rc)
	}
	L.st.State = LiveClosed
	log.Printf("live: %s closed", L.st.RunID)
	return L.st, L.save()
}

// --- ballot relay ----------------------------------------------------------------

// LiveBallotReceipt is POST /api/live/ballot's answer.
type LiveBallotReceipt struct {
	ElectionID        string `json:"election_id"`
	PositionID        string `json:"position_id"`
	Nullifier         string `json:"nullifier"`
	TrackingCode      string `json:"tracking_code"`
	BallotFingerprint string `json:"ballot_fingerprint"`
	TxID              string `json:"tx_id"`
	BlockNumber       uint64 `json:"block_number"`
	// RecordedBytesMatch reports that the record read back from the chain is
	// byte for byte the one submitted.
	RecordedBytesMatch bool `json:"recorded_bytes_match"`
}

// relayBallot submits one ballot record as the phone built it. Nothing here
// knows who sent it: the handler passes only the ballot hex.
func (L *liveService) relayBallot(ballotHex string) (*LiveBallotReceipt, error) {
	// The state check reads the public snapshot: a ballot never waits on mu,
	// which a transition holds across a chain submit.
	sn := L.snapshot()
	if sn == nil {
		return nil, errNotFound{"no live election has been set up"}
	}
	electionID, state := sn.ElectionID, sn.State
	if state != LiveOpen {
		return nil, conflictf("the election is %s; ballots are accepted while it is open", state)
	}
	if ballotHex == "" || len(ballotHex)%2 != 0 {
		return nil, badRequestf("ballot must be the record's protobuf bytes as hex")
	}
	raw, err := hex.DecodeString(ballotHex)
	if err != nil {
		return nil, badRequestf("ballot is not valid hex")
	}

	// A copy is decoded to check that the record is for this election: the
	// chaincode files a ballot under the election named inside it, so without
	// this check the console would relay anonymous ballots into any open
	// election on the channel and file them in this run. A record that does
	// not decode is still relayed, and the chaincode's decode gate answers it.
	var pre pb.Ballot
	if proto.Unmarshal(raw, &pre) == nil && pre.ElectionId != electionID {
		return nil, errBadRequest{code: "wrong-election",
			msg: fmt.Sprintf("the ballot is for election %q, not the live election %q; it was not relayed", pre.ElectionId, electionID)}
	}

	// The exact string the phone sent goes to the chain, never a re-encoding.
	// The copy is used only to read the nullifier for the read-back.
	rc, err := L.chainSubmit("SubmitBallot", ballotHex)
	if err != nil {
		return nil, err
	}
	var b pb.Ballot
	if err := proto.Unmarshal(raw, &b); err != nil || b.CredentialPresentation == nil || b.CredentialPresentation.Nullifier == nil {
		return nil, fmt.Errorf("the chain accepted a record the console cannot read a nullifier from")
	}
	nullifier := hex.EncodeToString(b.CredentialPresentation.Nullifier.Value)

	// Read the record back: the fingerprint is of the bytes the chain holds.
	recorded := raw
	match := false
	if c, err := L.getChain(); err == nil {
		if h, err := c.GetBallot(b.ElectionId, nullifier); err == nil {
			if got, err := hex.DecodeString(h); err == nil {
				recorded = got
				match = bytes.Equal(got, raw)
			}
		}
	}
	if !match {
		log.Printf("live: a ballot record read back from the chain differs from the submitted bytes or could not be read")
	}

	L.mu.Lock()
	defer L.mu.Unlock()
	if L.st == nil || L.st.ElectionID != electionID {
		return nil, fmt.Errorf("the live election changed while the ballot was in flight")
	}
	if err := L.appendBallotLocked(recorded, &rc); err != nil {
		return nil, fmt.Errorf("the ballot is on the chain (tx %s) but the run folder could not record it: %w", rc.TxID, err)
	}
	if err := L.save(); err != nil {
		return nil, err
	}
	return &LiveBallotReceipt{
		ElectionID: b.ElectionId, PositionID: b.PositionId, Nullifier: nullifier,
		TrackingCode: formatTrackingCode(nullifier), BallotFingerprint: ballotFingerprint(recorded),
		TxID: rc.TxID, BlockNumber: rc.BlockNumber, RecordedBytesMatch: match,
	}, nil
}

// --- the ledger read back -----------------------------------------------------------

// LiveLedgerBallot is one ballot record as the chain holds it.
type LiveLedgerBallot struct {
	Nullifier         string `json:"nullifier"`
	PositionID        string `json:"position_id"`
	TrackingCode      string `json:"tracking_code"`
	BallotFingerprint string `json:"ballot_fingerprint"`
	Ballot            string `json:"ballot"`
}

// LiveLedgerPartial is one recorded partial decryption.
type LiveLedgerPartial struct {
	TrusteeID string `json:"trustee_id"`
	ContestID string `json:"contest_id"`
	Partial   string `json:"partial"`
}

// LiveLedger is GET /api/live/ledger: the election read back from the chain.
type LiveLedger struct {
	ElectionID     string              `json:"election_id"`
	Status         string              `json:"status"`
	Params         string              `json:"params"`
	DKG            string              `json:"dkg,omitempty"`
	Tally          string              `json:"tally,omitempty"`
	NullifierCount int                 `json:"nullifier_count"`
	Ballots        []LiveLedgerBallot  `json:"ballots"`
	Partials       []LiveLedgerPartial `json:"partials"`
}

// readLedger reads the election back from the chain, not from the run folder.
func (L *liveService) readLedger() (*LiveLedger, error) {
	sn := L.snapshot()
	if sn == nil {
		return nil, errNotFound{"no live election has been set up"}
	}
	electionID, contests, trustees := sn.ElectionID, sn.ContestIDs, trusteeIDs(sn.Trustees)
	c, err := L.getChain()
	if err != nil {
		return nil, errChain{err}
	}
	out := &LiveLedger{ElectionID: electionID, Ballots: []LiveLedgerBallot{}, Partials: []LiveLedgerPartial{}}
	if out.Params, err = c.GetElection(electionID); err != nil {
		return nil, errChain{err}
	}
	if out.Status, err = c.GetElectionStatus(electionID); err != nil {
		return nil, errChain{err}
	}
	if out.DKG, err = c.GetDKGTranscript(electionID); err != nil && !chainAbsent(err) {
		return nil, errChain{err}
	}
	if out.Tally, err = c.GetTally(electionID); err != nil && !chainAbsent(err) {
		return nil, errChain{err}
	}
	if out.Tally != "" {
		out.Status = "published"
	}
	nullifiers, err := allNullifiers(c, electionID)
	if err != nil {
		return nil, errChain{err}
	}
	out.NullifierCount = len(nullifiers)
	hexes, err := getBallots(c, electionID, nullifiers)
	if err != nil {
		return nil, errChain{err}
	}
	for i, h := range hexes {
		raw, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("chain ballot %d is not hex", i)
		}
		var b pb.Ballot
		position := ""
		if proto.Unmarshal(raw, &b) == nil {
			position = b.PositionId
		}
		out.Ballots = append(out.Ballots, LiveLedgerBallot{
			Nullifier: nullifiers[i], PositionID: position,
			TrackingCode:      formatTrackingCode(nullifiers[i]),
			BallotFingerprint: ballotFingerprint(raw),
			Ballot:            hex.EncodeToString(raw),
		})
	}
	if out.Status == "closed" || out.Status == "published" {
		for _, t := range trustees {
			for _, contest := range contests {
				p, err := c.GetPartialDecryption(electionID, contest, t)
				if chainAbsent(err) {
					continue
				}
				if err != nil {
					return nil, errChain{err}
				}
				out.Partials = append(out.Partials, LiveLedgerPartial{TrusteeID: t, ContestID: contest, Partial: p})
			}
		}
	}
	return out, nil
}

func ledgerBallotHexes(l *LiveLedger) []string {
	out := make([]string, len(l.Ballots))
	for i, b := range l.Ballots {
		out[i] = b.Ballot
	}
	return out
}

func ledgerPartialHexes(l *LiveLedger) []string {
	out := make([]string, len(l.Partials))
	for i, p := range l.Partials {
		out[i] = p.Partial
	}
	return out
}

// --- partial decryptions ---------------------------------------------------------------

// LivePartialBody is POST /api/live/partial: the partial op's output (its
// other fields are ignored).
type LivePartialBody struct {
	Partials []struct {
		ContestID string `json:"contest_id"`
		Partial   string `json:"partial"`
	} `json:"partials"`
}

// postPartials records trustee id's partial decryptions, one
// SubmitPartialDecryption per contest. A contest already recorded for this
// trustee is answered with its transaction, so a retry is harmless.
func (L *liveService) postPartials(id string, body LivePartialBody) (map[string]any, error) {
	L.mu.Lock()
	defer L.mu.Unlock()
	if err := L.inState(LiveClosed); err != nil {
		return nil, err
	}
	if err := L.requireTrustee(id); err != nil {
		return nil, err
	}
	st := L.st
	if len(body.Partials) == 0 {
		return nil, badRequestf("no partials in the body")
	}
	seen := map[string]bool{}
	for k, p := range body.Partials {
		raw, err := hex.DecodeString(p.Partial)
		if err != nil {
			return nil, badRequestf("partial %d is not hex", k)
		}
		var pd pb.PartialDecryption
		if err := proto.Unmarshal(raw, &pd); err != nil {
			return nil, badRequestf("partial %d is not a PartialDecryption", k)
		}
		if pd.TrusteeId != id {
			return nil, errForbidden{fmt.Sprintf("partial %d is trustee %q's; this token is trustee %s's", k, pd.TrusteeId, id)}
		}
		if pd.ContestId != p.ContestID || !slices.Contains(st.ContestIDs, pd.ContestId) {
			return nil, badRequestf("partial %d is for contest %q, labelled %q; the election's contests are %v", k, pd.ContestId, p.ContestID, st.ContestIDs)
		}
		if seen[pd.ContestId] {
			return nil, badRequestf("contest %q appears twice", pd.ContestId)
		}
		seen[pd.ContestId] = true
	}
	if st.Partials[id] == nil {
		st.Partials[id] = map[string]LiveTx{}
	}
	if L.partialBusy == nil {
		L.partialBusy = map[string]bool{}
	}
	if L.partialBusy[id] {
		return nil, conflictf("trustee %s's partials are being recorded already", id)
	}
	// The transactions go out together and without mu held: a trustee's six
	// commits take one block wait instead of six, and the polling pages are
	// not held up meanwhile.
	type result struct {
		rc  clientsdk.Receipt
		err error
		// onChain: the chain already held this exact partial (a commit whose
		// receipt was lost, or a crash before the state write).
		onChain bool
	}
	todo := map[string]string{}
	for _, p := range body.Partials {
		if _, ok := st.Partials[id][p.ContestID]; !ok {
			todo[p.ContestID] = p.Partial
		}
	}
	electionID := st.ElectionID
	L.partialBusy[id] = true
	L.mu.Unlock()
	results := make(map[string]result, len(todo))
	var rmu sync.Mutex
	var wg sync.WaitGroup
	for contest, partial := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rc, err := L.chainSubmit("SubmitPartialDecryption", electionID, partial)
			r := result{rc: rc, err: err}
			var ref errRefused
			if errors.As(err, &ref) && ref.Gate == "partial-duplicate" {
				r.onChain, r.err = L.partialOnChain(electionID, contest, id, partial)
			}
			rmu.Lock()
			results[contest] = r
			rmu.Unlock()
		}()
	}
	wg.Wait()
	L.mu.Lock()
	delete(L.partialBusy, id)
	if L.st != st {
		return nil, conflictf("the live election changed while the partials were being recorded")
	}
	var firstErr error
	for _, p := range body.Partials { // body order, so the first error is stable
		r, ok := results[p.ContestID]
		if !ok {
			continue
		}
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		if r.onChain {
			// Recorded from the chain: no transaction of this console's.
			st.Partials[id][p.ContestID] = LiveTx{}
			continue
		}
		st.Partials[id][p.ContestID] = txOf(r.rc)
		L.appendLifecycleLocked("SubmitPartialDecryption", id+"/"+p.ContestID, r.rc)
	}
	if err := L.save(); err != nil {
		return nil, err
	}
	if firstErr != nil {
		return nil, firstErr
	}
	recorded := []map[string]any{}
	for _, p := range body.Partials {
		tx := st.Partials[id][p.ContestID]
		recorded = append(recorded, map[string]any{"contest_id": p.ContestID, "tx_id": tx.TxID, "block_number": tx.BlockNumber,
			"already_on_chain": tx.TxID == ""})
	}
	return map[string]any{
		"trustee_id": id, "recorded": recorded,
		"trustees_decrypted": L.decryptedLocked(), "threshold": st.Threshold,
	}, nil
}

// partialOnChain answers a partial-duplicate refusal: the chain already holds
// a partial from trustee id for contest. Byte-equal to the one posted means it
// is this very partial (its first submit committed but the console did not
// learn of it), so it counts as recorded; a different one is a conflict.
func (L *liveService) partialOnChain(electionID, contest, id, posted string) (bool, error) {
	c, err := L.getChain()
	if err != nil {
		return false, errChain{err}
	}
	got, err := c.GetPartialDecryption(electionID, contest, id)
	if err != nil {
		return false, errChain{err}
	}
	a, errA := hex.DecodeString(got)
	b, errB := hex.DecodeString(posted)
	if errA == nil && errB == nil && bytes.Equal(a, b) {
		return true, nil
	}
	return false, conflictf("the chain already holds a different partial decryption from trustee %s for contest %q; "+
		"the posted one does not match it byte for byte (read the chain's from GET /api/live/ledger)", id, contest)
}

// reconcilePartialsLocked records every partial the chain holds for this
// election that live.json lacks (a commit whose state write was cut off), so
// the decryption count is the chain's. Caller holds mu; the state is closed
// or later.
func (L *liveService) reconcilePartialsLocked(c liveChain) error {
	st := L.st
	added := 0
	for _, id := range trusteeIDs(st.Trustees) {
		for _, contest := range st.ContestIDs {
			if _, ok := st.Partials[id][contest]; ok {
				continue
			}
			_, err := c.GetPartialDecryption(st.ElectionID, contest, id)
			if chainAbsent(err) {
				continue
			}
			if err != nil {
				return err
			}
			if st.Partials[id] == nil {
				st.Partials[id] = map[string]LiveTx{}
			}
			st.Partials[id][contest] = LiveTx{}
			added++
		}
	}
	if added == 0 {
		return nil
	}
	log.Printf("live: %s resumed %d partial decryption(s) from the chain", st.RunID, added)
	return L.save()
}

// decryptedLocked counts trustees with a partial recorded for every contest.
func (L *liveService) decryptedLocked() int {
	n := 0
	for _, byContest := range L.st.Partials {
		if len(byContest) == len(L.st.ContestIDs) {
			n++
		}
	}
	return n
}

// --- tally signatures and publication ----------------------------------------------------

// LiveTallySigBody is POST /api/live/tally-sig: sign-tally's output (its other
// fields are ignored).
type LiveTallySigBody struct {
	TrusteeID string   `json:"trustee_id"`
	Totals    []uint64 `json:"totals"`
	Signature string   `json:"signature"`
}

type liveSigIn struct {
	TrusteeID string `json:"trustee_id"`
	Signature string `json:"signature"`
}

type liveAssembled struct {
	Tally          string   `json:"tally"`
	Totals         []uint64 `json:"totals"`
	Signatures     int      `json:"signatures"`
	Threshold      int      `json:"threshold"`
	MeetsThreshold bool     `json:"meets_threshold"`
}

// assemble runs tally-assemble over the chain's ballots and partials. It
// recomputes the totals from the on-chain partials and refuses totals that
// differ and any signature that does not verify over them, so the console
// never assembles numbers it cannot reproduce.
func (L *liveService) assemble(ctx context.Context, led *LiveLedger, st *liveState, totals []uint64, sigs []liveSigIn) (*liveAssembled, error) {
	var out liveAssembled
	if sigs == nil {
		sigs = []liveSigIn{}
	}
	err := L.opJSON(ctx, "tally-assemble", map[string]any{
		"params": st.Params, "dkg": st.DKG,
		"ballots": ledgerBallotHexes(led), "partials": ledgerPartialHexes(led),
		"totals": totals, "signatures": sigs,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// postTallySig records trustee id's signature after checking it, over the
// chain's record, with tally-assemble. At threshold signatures over the same
// totals the tally is published.
func (L *liveService) postTallySig(ctx context.Context, id string, body LiveTallySigBody) (map[string]any, error) {
	L.mu.Lock()
	defer L.mu.Unlock()
	if err := L.inState(LiveClosed); err != nil {
		return nil, err
	}
	if err := L.requireTrustee(id); err != nil {
		return nil, err
	}
	if body.TrusteeID != "" && body.TrusteeID != id {
		return nil, errForbidden{fmt.Sprintf("this token is trustee %s's; it cannot sign for trustee %s", id, body.TrusteeID)}
	}
	st := L.st
	if len(body.Totals) != len(st.ContestIDs) {
		return nil, badRequestf("totals has %d entries for %d contests", len(body.Totals), len(st.ContestIDs))
	}
	if len(body.Signature) != 128 {
		return nil, badRequestf("signature must be 64 bytes of hex")
	}
	if prev, ok := st.Signatures[id]; ok {
		if prev.Signature == body.Signature && slices.Equal(prev.Totals, body.Totals) {
			return L.sigStatusLocked(nil), nil
		}
		return nil, conflictf("trustee %s has signed the tally already", id)
	}
	L.mu.Unlock()
	led, err := L.readLedger()
	L.mu.Lock()
	if err != nil {
		return nil, err
	}
	if st != L.st || st.State != LiveClosed {
		return nil, conflictf("the live election changed while the signature was being checked")
	}
	if _, ok := st.Signatures[id]; ok {
		return nil, conflictf("trustee %s has signed the tally already", id)
	}
	if _, err := L.assemble(ctx, led, st, body.Totals, []liveSigIn{{TrusteeID: id, Signature: body.Signature}}); err != nil {
		return nil, badRequestf("the signature is refused: %v", err)
	}
	st.Signatures[id] = liveSig{Totals: body.Totals, Signature: body.Signature, At: L.now().UTC()}
	if err := L.save(); err != nil {
		return nil, err
	}
	totals, sigs := L.bestSignaturesLocked()
	if len(sigs) < st.Threshold {
		return L.sigStatusLocked(nil), nil
	}
	pub, err := L.publishLocked(ctx, led, totals, sigs)
	if err != nil {
		return L.sigStatusLocked(map[string]any{"published": false, "publish_error": err.Error()}), nil
	}
	return L.sigStatusLocked(pub), nil
}

func (L *liveService) sigStatusLocked(extra map[string]any) map[string]any {
	out := map[string]any{
		"signatures": sortedIDs(L.st.Signatures), "threshold": L.st.Threshold,
		"state": L.st.State, "published": L.st.State == LiveTallied || L.st.State == LiveVerified,
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// bestSignaturesLocked groups the signatures by the totals they sign and
// returns the largest group, in trustee order.
func (L *liveService) bestSignaturesLocked() ([]uint64, []liveSigIn) {
	groups := map[string][]liveSigIn{}
	totalsOf := map[string][]uint64{}
	for _, n := range sortedIDs(L.st.Signatures) {
		id := strconv.Itoa(n)
		s := L.st.Signatures[id]
		key := fmt.Sprint(s.Totals)
		groups[key] = append(groups[key], liveSigIn{TrusteeID: id, Signature: s.Signature})
		totalsOf[key] = s.Totals
	}
	best := ""
	for k, g := range groups {
		if best == "" || len(g) > len(groups[best]) || (len(g) == len(groups[best]) && k < best) {
			best = k
		}
	}
	return totalsOf[best], groups[best]
}

// publishLocked assembles a tally from the given trustee signatures and sends
// PublishTally. A refusal changes no state. Caller holds mu.
func (L *liveService) publishLocked(ctx context.Context, led *LiveLedger, totals []uint64, sigs []liveSigIn) (map[string]any, error) {
	st := L.st
	a, err := L.assemble(ctx, led, st, totals, sigs)
	if err != nil {
		return nil, conflictf("the tally cannot be assembled: %v", err)
	}
	rc, err := L.chainSubmit("PublishTally", a.Tally)
	var ref errRefused
	if errors.As(err, &ref) && ref.Gate == "already-published" {
		return L.tallyOnChainLocked(a)
	}
	if err != nil {
		return nil, err
	}
	st.Lifecycle["PublishTally"] = txOf(rc)
	L.appendLifecycleLocked("PublishTally", "", rc)
	st.Tally, st.Totals, st.State = a.Tally, a.Totals, LiveTallied
	log.Printf("live: %s tallied with %d signatures", st.RunID, len(sigs))
	if err := L.save(); err != nil {
		return nil, err
	}
	L.startAutoVerifyLocked()
	return map[string]any{"published": true, "totals": a.Totals, "signatures_used": len(sigs),
		"tx_id": rc.TxID, "block_number": rc.BlockNumber}, nil
}

// tallyOnChainLocked answers an already-published refusal: an earlier
// PublishTally committed but the console did not learn of it. The chain's
// tally is adopted when it carries the totals the console just assembled
// (its signature set may differ: a later signer can join the group after the
// lost receipt); different totals are a conflict. Caller holds mu.
func (L *liveService) tallyOnChainLocked(a *liveAssembled) (map[string]any, error) {
	st := L.st
	c, err := L.getChain()
	if err != nil {
		return nil, errChain{err}
	}
	tally, err := c.GetTally(st.ElectionID)
	if err != nil {
		return nil, errChain{err}
	}
	totals, err := decodeTallyTotals(tally)
	if err != nil {
		return nil, fmt.Errorf("the chain's tally does not decode: %v", err)
	}
	if !slices.Equal(totals, a.Totals) {
		return nil, conflictf("a different tally is already on the chain: it carries totals %v, the signatures held are over %v", totals, a.Totals)
	}
	st.Tally, st.Totals, st.State = tally, totals, LiveTallied
	log.Printf("live: %s tallied (the tally was already on the chain)", st.RunID)
	if err := L.save(); err != nil {
		return nil, err
	}
	L.startAutoVerifyLocked()
	return map[string]any{"published": true, "already_on_chain": true, "totals": totals}, nil
}

// publishNow is the presenter's POST /api/live/tally/publish: publication
// with whatever signatures exist, so the chain's threshold refusal can be
// shown. With no signatures yet the totals come from combine.
func (L *liveService) publishNow(ctx context.Context) (map[string]any, error) {
	L.mu.Lock()
	if err := L.inState(LiveClosed); err != nil {
		L.mu.Unlock()
		return nil, err
	}
	L.mu.Unlock()
	led, err := L.readLedger()
	if err != nil {
		return nil, err
	}
	L.mu.Lock()
	defer L.mu.Unlock()
	if err := L.inState(LiveClosed); err != nil {
		return nil, err
	}
	totals, sigs := L.bestSignaturesLocked()
	if len(sigs) == 0 {
		var comb struct {
			Totals []uint64 `json:"totals"`
		}
		if err := L.opJSON(ctx, "combine", map[string]any{
			"params": L.st.Params, "dkg": L.st.DKG,
			"ballots": ledgerBallotHexes(led), "partials": ledgerPartialHexes(led),
		}, &comb); err != nil {
			return nil, conflictf("the partials on the chain do not combine yet: %v", err)
		}
		totals = comb.Totals
	}
	return L.publishLocked(ctx, led, totals, sigs)
}

// --- verification ------------------------------------------------------------------------

// The console verifies by itself: as soon as the tally is published (and
// again, once, at a start that finds the election tallied with no verdict),
// it runs the same verification a POST /api/live/verify runs. A pass moves
// the state to verified; a failed verdict is recorded as a press records it
// and the state stays tallied; an error records nothing but auto_verify's
// error, and the press retries. Only one verify-live run is in flight at a
// time: a press during a run waits for it and answers its result.

// liveAutoVerifyTimeout bounds the automatic run, as liveCtx bounds a press.
const liveAutoVerifyTimeout = liveOpTimeout

// The automatic verification's states (auto_verify.state).
const (
	autoVerifyRunning = "running" // the automatic run is in flight
	autoVerifyDone    = "done"    // it gave a verdict: verify_overall says which
	autoVerifyError   = "error"   // it gave no verdict: auto_verify.error says why
)

// LiveAutoVerify is the election view's auto_verify: the automatic
// verification of the current election. It is not saved: a console restart
// shows none until it starts one again.
type LiveAutoVerify struct {
	State string    `json:"state"`
	Error string    `json:"error,omitempty"`
	At    time.Time `json:"at"`
}

// liveVerifyCall is one verify-live run.
type liveVerifyCall struct {
	done chan struct{}
	out  map[string]any
	err  error
}

// startAutoVerifyLocked starts the automatic verification of the current
// election in the background. Caller holds mu, with the state just set to
// tallied.
func (L *liveService) startAutoVerifyLocked() {
	runID := L.st.RunID
	L.setAutoVerify(runID, LiveAutoVerify{State: autoVerifyRunning, At: L.now().UTC()})
	L.bg.Add(1)
	go func() {
		defer L.bg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), liveAutoVerifyTimeout)
		defer cancel()
		_, err := L.verify(ctx)
		a := LiveAutoVerify{State: autoVerifyDone, At: L.now().UTC()}
		if err != nil {
			a.State, a.Error = autoVerifyError, err.Error()
			log.Printf("live: %s automatic verification gave no verdict: %v", runID, err)
		}
		L.setAutoVerify(runID, a)
	}()
}

func (L *liveService) setAutoVerify(runID string, a LiveAutoVerify) {
	L.verifyMu.Lock()
	L.auto, L.autoRun = a, runID
	L.verifyMu.Unlock()
}

// autoVerifyOf is the automatic verification's status for runID, or nil.
func (L *liveService) autoVerifyOf(runID string) *LiveAutoVerify {
	L.verifyMu.Lock()
	defer L.verifyMu.Unlock()
	if L.autoRun != runID || L.auto.State == "" {
		return nil
	}
	a := L.auto
	return &a
}

// waitBackground waits for the background work (tests, and a clean stop).
func (L *liveService) waitBackground() { L.bg.Wait() }

// verify is POST /api/live/verify and the automatic run: one verify-live run
// at a time. A call while a run is in flight waits for that run and answers
// its result instead of starting another.
func (L *liveService) verify(ctx context.Context) (map[string]any, error) {
	L.verifyMu.Lock()
	if c := L.verifyCall; c != nil {
		L.verifyMu.Unlock()
		select {
		case <-c.done:
			return c.out, c.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c := &liveVerifyCall{done: make(chan struct{})}
	L.verifyCall = c
	L.verifyMu.Unlock()
	c.out, c.err = L.verifyRun(ctx)
	L.verifyMu.Lock()
	L.verifyCall = nil
	L.verifyMu.Unlock()
	close(c.done)
	return c.out, c.err
}

// verifyRun runs verify-live over the election read back from the chain, with
// expected_ballots the chain's nullifier count, and moves to verified only on
// a pass.
func (L *liveService) verifyRun(ctx context.Context) (map[string]any, error) {
	L.mu.Lock()
	if err := L.inState(LiveTallied, LiveVerified); err != nil {
		L.mu.Unlock()
		return nil, err
	}
	L.mu.Unlock()
	led, err := L.readLedger()
	if err != nil {
		return nil, err
	}
	if led.Tally == "" {
		return nil, conflictf("no tally is on the chain")
	}
	if led.DKG == "" {
		return nil, conflictf("no DKG transcript is on the chain")
	}
	params, err := hex.DecodeString(led.Params)
	if err != nil {
		return nil, fmt.Errorf("chain params are not hex")
	}
	var ep pb.ElectionParameters
	if err := proto.Unmarshal(params, &ep); err != nil {
		return nil, fmt.Errorf("chain params do not decode: %v", err)
	}
	var verdict json.RawMessage
	if err := L.opJSON(ctx, "verify-live", map[string]any{"record": map[string]any{
		"params": led.Params, "dkg": led.DKG, "issuer_public_key": hex.EncodeToString(ep.IssuerPublicKey),
		"ballots": ledgerBallotHexes(led), "partial_decryptions": ledgerPartialHexes(led),
		"tally": led.Tally, "expected_ballots": led.NullifierCount,
	}}, &verdict); err != nil {
		return nil, err
	}
	// Exit 0 means a verdict was produced; overall says which.
	var v struct {
		Overall      string            `json:"overall"`
		FailedChecks []json.RawMessage `json:"failed_checks"`
	}
	if err := json.Unmarshal(verdict, &v); err != nil || v.Overall == "" {
		return nil, fmt.Errorf("verify-live gave no overall verdict")
	}
	L.mu.Lock()
	defer L.mu.Unlock()
	if err := L.inState(LiveTallied, LiveVerified); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(L.dir, LiveVerifyFile), verdict, 0o644); err != nil {
		return nil, err
	}
	L.st.Verify, L.st.VerifyOverall = verdict, v.Overall
	switch {
	case v.Overall == "pass":
		L.st.State = LiveVerified
		log.Printf("live: %s verified", L.st.RunID)
	case L.st.State == LiveVerified:
		// A re-verify that fails takes the verified mark away: the board must
		// never show verified next to a failed check.
		L.st.State = LiveTallied
		log.Printf("live: %s re-verify failed; back to tallied", L.st.RunID)
	}
	if err := L.save(); err != nil {
		return nil, err
	}
	return map[string]any{
		"state": L.st.State, "overall": v.Overall, "failed_checks": v.FailedChecks,
		"expected_ballots": led.NullifierCount, "verdict": verdict,
		"verified_at": L.now().UTC().Format(time.RFC3339),
	}, nil
}

// liveChainCountTTL is how long a chain count is reused. The election view
// and the board are public and polled; without the cache each GET would list
// every nullifier on the peer. A count shown can be this old, or older while
// a read is in flight.
const liveChainCountTTL = 2 * time.Second

// chainCountCache is the last chain count read, per election, and whether a
// read is in flight.
type chainCountCache struct {
	mu         sync.Mutex
	electionID string
	n          int
	at         time.Time // when the last read finished; zero before any
	inFlight   bool
	now        func() time.Time
}

func (cc *chainCountCache) clock() time.Time {
	if cc.now != nil {
		return cc.now()
	}
	return time.Now()
}

// chainCount is the chain's committed nullifier count, or -1 if unreadable,
// read from the chain at most once per liveChainCountTTL. Only one read runs
// at a time, and nobody waits for it: a caller that finds a read in flight
// gets the last count for this election at once, or -1 if there is none (the
// views then show the console's own count). The time is stamped when the read
// finishes, and a failed or timed-out read (-1) is reused like any other. The
// cache lock is never held across the read, and it is never mu.
func (L *liveService) chainCount(electionID string) int {
	cc := &L.counts
	cc.mu.Lock()
	last := -1
	if cc.electionID == electionID && !cc.at.IsZero() {
		last = cc.n
		if cc.clock().Sub(cc.at) < liveChainCountTTL {
			cc.mu.Unlock()
			return last
		}
	}
	if cc.inFlight {
		cc.mu.Unlock()
		return last
	}
	cc.inFlight = true
	cc.mu.Unlock()
	// Cleared on every way out, a panic in the read included (net/http
	// recovers it): a flag left set would stop every later read.
	defer func() {
		cc.mu.Lock()
		cc.inFlight = false
		cc.mu.Unlock()
	}()

	n := -1
	if c, err := L.getChain(); err == nil {
		if all, err := allNullifiers(c, electionID); err == nil {
			n = len(all)
		}
	}

	cc.mu.Lock()
	cc.electionID, cc.n, cc.at = electionID, n, cc.clock()
	cc.mu.Unlock()
	return n
}
