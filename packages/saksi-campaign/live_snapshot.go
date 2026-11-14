package campaign

import (
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"time"
)

// liveSnapshot is an immutable copy of the live election's public view: what
// GET /api/live/election, the bulletin board, the issuance gate and the ballot
// relay's state check read. It is rebuilt under mu at every save and published
// through an atomic pointer, so those readers never wait on mu (which a
// transition holds across a chain submit) and never touch the live maps.
//
// Nothing in a snapshot is mutated after it is published: every slice and map
// in it is a fresh copy.
type liveSnapshot struct {
	// Dir is the run folder.
	Dir string

	RunID      string
	ElectionID string
	Title      string
	State      string
	Positions  []LivePosition
	Trustees   int
	Threshold  int

	Params          string
	ContestIDs      []string
	IssuerPublicKey string

	DKG                 string
	JointPublicKey      string
	JointKeyFingerprint string
	VerificationKeys    json.RawMessage
	RosterFingerprint   string
	CeremonyError       string

	// TrusteesJoined is how many trustees' receive keys are in the roster:
	// a count only, never which trustees or their keys.
	TrusteesJoined int

	Lifecycle map[string]LiveTx

	Ballots int
	Issued  int

	// Decrypted is the trustees with a partial recorded for every contest;
	// TallySignatures the trustees whose tally signature is held.
	Decrypted       []int
	TallySignatures []int

	Tallied       bool
	Totals        []uint64
	VerifyOverall string
	FailedChecks  []string

	CreatedAt time.Time
	UpdatedAt time.Time
}

func (sn *liveSnapshot) stateIndex() int { return liveStateIndex(sn.State) }

// snapshotOf copies the public view out of st. Caller holds mu when st is the
// console's live state.
func snapshotOf(st *liveState, dir string) *liveSnapshot {
	positions := make([]LivePosition, len(st.Positions))
	for i, p := range st.Positions {
		positions[i] = LivePosition{ID: p.ID, Candidates: slices.Clone(p.Candidates)}
	}
	sn := &liveSnapshot{
		Dir: dir, RunID: st.RunID, ElectionID: st.ElectionID, Title: st.Title, State: st.State,
		Positions: positions, Trustees: st.Trustees, Threshold: st.Threshold,
		Params: st.Params, ContestIDs: slices.Clone(st.ContestIDs), IssuerPublicKey: st.IssuerPublicKey,
		DKG: st.DKG, JointPublicKey: st.JointPublicKey, JointKeyFingerprint: st.JointKeyFingerprint,
		CeremonyError:  st.CeremonyError,
		TrusteesJoined: len(st.ReceiveKeys),
		Lifecycle:      maps.Clone(st.Lifecycle),
		Ballots:        st.Ballots, Issued: st.Issued,
		Decrypted:       []int{},
		TallySignatures: sortedIDs(st.Signatures),
		Tallied:         st.Tally != "",
		Totals:          slices.Clone(st.Totals),
		VerifyOverall:   st.VerifyOverall,
		CreatedAt:       st.CreatedAt, UpdatedAt: st.UpdatedAt,
	}
	if sn.Lifecycle == nil {
		sn.Lifecycle = map[string]LiveTx{}
	}
	if sn.TallySignatures == nil {
		sn.TallySignatures = []int{}
	}
	for _, n := range sortedIDs(st.Partials) {
		if len(st.Partials[strconv.Itoa(n)]) == len(st.ContestIDs) {
			sn.Decrypted = append(sn.Decrypted, n)
		}
	}
	if st.Transcript != nil {
		var tr struct {
			VerificationKeys json.RawMessage `json:"verification_keys"`
		}
		if json.Unmarshal(st.Transcript, &tr) == nil {
			sn.VerificationKeys = slices.Clone(tr.VerificationKeys)
		}
	}
	if st.Roster != nil {
		sn.RosterFingerprint = jsonField(st.Roster, "roster_fingerprint")
	}
	if st.Verify != nil {
		sn.FailedChecks = failedCheckNames(st.Verify)
	}
	return sn
}

// publishSnapshotLocked rebuilds the public snapshot from the live state.
// Caller holds mu.
func (L *liveService) publishSnapshotLocked() {
	if L.st == nil {
		L.snap.Store(nil)
		return
	}
	L.snap.Store(snapshotOf(L.st, L.dir))
}

// snapshot is the current public view, or nil before any setup. It never
// waits on mu.
func (L *liveService) snapshot() *liveSnapshot { return L.snap.Load() }
