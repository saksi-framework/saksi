package campaign

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// The bulletin board's view of a live election. GET /api/board/<run> keeps
// its shape; every existing field keeps its meaning, and the live state, the
// counts, the decryption progress and each ballot's tracking code and
// fingerprint are added under "live".

// LiveBoardBallot is one recorded ballot on the board.
type LiveBoardBallot struct {
	Index             int    `json:"index"`
	PositionID        string `json:"position_id"`
	TrackingCode      string `json:"tracking_code"`
	BallotFingerprint string `json:"ballot_fingerprint"`
	TxID              string `json:"tx_id,omitempty"`
	BlockNumber       uint64 `json:"block_number,omitempty"`
}

// LiveBoardDecryption is the decryption progress: k of threshold.
type LiveBoardDecryption struct {
	TrusteesDecrypted int   `json:"trustees_decrypted"`
	Threshold         int   `json:"threshold"`
	Trustees          int   `json:"trustees"`
	Decrypted         []int `json:"decrypted"`
	TallySignatures   []int `json:"tally_signatures"`
}

// LiveBoard is BoardResponse.live.
type LiveBoard struct {
	State string `json:"state"`
	Title string `json:"title"`
	// The voter list's public facts: never a name or a date.
	Precinct                  string              `json:"precinct,omitempty"`
	PrecinctLabel             string              `json:"precinct_label,omitempty"`
	VoterListFingerprint      string              `json:"voter_list_fingerprint,omitempty"`
	VoterListFingerprintShort string              `json:"voter_list_fingerprint_short,omitempty"`
	VoterListNote             string              `json:"voter_list_note,omitempty"`
	Counts                    LiveCounts          `json:"counts"`
	Decryption                LiveBoardDecryption `json:"decryption"`
	JointKeyFingerprint       string              `json:"joint_key_fingerprint,omitempty"`
	RosterFingerprint         string              `json:"roster_fingerprint,omitempty"`
	Ballots                   []LiveBoardBallot   `json:"ballots"`
	Totals                    []uint64            `json:"totals,omitempty"`
	ContestIDs                []string            `json:"contest_ids"`
	VerifyOverall             string              `json:"verify_overall,omitempty"`
	FailedChecks              []string            `json:"failed_checks,omitempty"`
}

// liveRunState reads a live run's state from its folder (it may not be the
// console's current election).
func liveRunState(dir string) (*liveState, error) {
	var st liveState
	if err := readJSON(filepath.Join(dir, liveStateFile), &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *Server) buildLiveBoard(rec RunRecord, dir string) BoardResponse {
	resp := BoardResponse{
		ElectionID: rec.RunID, Name: rec.Config.Name, Mode: ModeLive, OnChain: true,
		OpenedAt: rec.CreatedAt, Sealed: true, Artifacts: artifactsIn(dir), Files: []string{},
		Checks: []Check{},
	}
	// The console's current election comes from the public snapshot, so the
	// board never waits on mu and never reads the live maps; any other live
	// run is read from its folder.
	var st *liveSnapshot
	current := false
	if s.live != nil {
		if sn := s.live.snapshot(); sn != nil && sn.RunID == rec.RunID {
			st, current = sn, true
		}
	}
	if st == nil {
		disk, err := liveRunState(dir)
		if err != nil {
			resp.Partial, resp.PartialReason = true, "live election state unreadable"
			return resp
		}
		st = snapshotOf(disk, dir)
	}
	resp.Name = st.Title
	resp.Status = st.State
	tallied := st.stateIndex() >= liveStateIndex(LiveTallied)
	resp.Sealed = !tallied
	resp.Verified = st.State == LiveVerified
	if tallied {
		resp.Files = publicFilesIn(dir)
	}
	resp.Integrity = BoardIntegrity{
		Voters: rec.Config.Voters, Positions: len(st.Positions), Candidates: rec.Config.Candidates,
		BallotRecords: st.Ballots, Verified: 0,
		TurnoutNote: "turnout is ballot records over voters on the list times positions",
	}
	if resp.Verified {
		resp.Integrity.Verified = st.Ballots
	}
	if d := rec.Config.Voters * len(st.Positions); d > 0 {
		resp.Integrity.TurnoutPct = float64(st.Ballots) / float64(d) * 100
	}
	k := len(st.Decrypted)
	resp.Crypto = BoardCrypto{
		TallyProofVerified: resp.Verified, TrusteesSubmitted: k,
		TrusteesTotal: st.Trustees, Threshold: st.Threshold, IssuerPublicKey: st.IssuerPublicKey,
	}
	live := &LiveBoard{
		State: st.State, Title: st.Title, ContestIDs: st.ContestIDs,
		JointKeyFingerprint: st.JointKeyFingerprint,
		Counts: LiveCounts{
			VotersOnRoll: rec.Config.Voters, VotersOnList: rec.Config.Voters, CredentialsIssued: st.Issued,
			BallotRecords: st.Ballots, BallotRecordsSource: "console",
			MinBallotRecords:  s.live.minBallotRecords(st.State, len(st.Positions)),
			TrusteesDecrypted: k, TallySignatures: len(st.TallySignatures),
			TrusteesJoined: st.TrusteesJoined,
		},
		Decryption: LiveBoardDecryption{
			TrusteesDecrypted: k, Threshold: st.Threshold, Trustees: st.Trustees,
			Decrypted: st.Decrypted, TallySignatures: st.TallySignatures,
		},
		VerifyOverall:     st.VerifyOverall,
		RosterFingerprint: st.RosterFingerprint,
		FailedChecks:      st.FailedChecks,
	}
	if st.Precinct != "" {
		live.Precinct, live.PrecinctLabel = st.Precinct, precinctLabel(st.Precinct)
		live.VoterListFingerprint, live.VoterListFingerprintShort = st.VoterListFingerprint, fingerprintShort(st.VoterListFingerprint)
		live.VoterListNote = voterListNote
	}
	// Both counts come from the issuance record itself (live_issue.go).
	if c, ok := s.live.checkinCountsOf(rec.RunID, dir); ok {
		live.Counts.CheckedIn, live.Counts.CredentialsIssued = c.CheckedIn, c.Issued
	}
	if current {
		if n := s.live.chainCount(st.ElectionID); n >= 0 {
			live.Counts.BallotRecords, live.Counts.BallotRecordsSource = n, "chain"
			resp.Crypto.CommittedNullifiers = n
		}
	}
	ballots, err := liveBoardBallots(dir)
	if err != nil {
		resp.Partial, resp.PartialReason = true, "ballot table unreadable"
	}
	live.Ballots = ballots
	if tallied && len(st.Totals) == len(st.ContestIDs) {
		live.Totals = st.Totals
		flat := map[string]uint64{}
		for i, c := range st.ContestIDs {
			flat[c] = st.Totals[i]
		}
		resp.Contests = groupContests(rec.Config, flat)
		// groupContests sorts candidates by id; the ballot order is the
		// positions' own, so re-order the races to match it.
		order := make([]string, len(st.Positions))
		for i, p := range st.Positions {
			order[i] = p.ID
		}
		slices.SortStableFunc(resp.Contests, func(a, b BoardContest) int {
			return slices.Index(order, a.ID) - slices.Index(order, b.ID)
		})
	}
	resp.Live = live
	resp.Checks = liveBoardChecks(st, live)
	return resp
}

func jsonField(raw []byte, key string) string {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

func failedCheckNames(verdict []byte) []string {
	var v struct {
		FailedChecks []struct {
			Check string `json:"check"`
		} `json:"failed_checks"`
	}
	if json.Unmarshal(verdict, &v) != nil {
		return nil
	}
	var out []string
	for _, c := range v.FailedChecks {
		out = append(out, c.Check)
	}
	return out
}

// liveBoardBallots reads each recorded ballot's tracking code and
// fingerprint from ballots.csv (ballot_sha256 is of the bytes the chain
// returned) and its receipt from receipts.csv.
func liveBoardBallots(dir string) ([]LiveBoardBallot, error) {
	out := []LiveBoardBallot{}
	f, err := os.Open(filepath.Join(dir, BallotsCSV))
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil || len(rows) == 0 {
		return out, err
	}
	receipts := map[string]LiveTx{}
	if evs, _ := readReceipts(dir); evs != nil {
		for _, ev := range evs {
			if ev.Event == "SubmitBallot" {
				receipts[ev.Ref] = LiveTx{TxID: ev.Receipt.TxID, BlockNumber: ev.Receipt.BlockNumber}
			}
		}
	}
	idx := columnIndex(rows[0])
	for _, r := range rows[1:] {
		i, _ := strconv.Atoi(field(r, idx, "index"))
		sha := field(r, idx, "ballot_sha256")
		b := LiveBoardBallot{
			Index: i, PositionID: field(r, idx, "position_id"),
			TrackingCode: formatTrackingCode(strings.ToLower(field(r, idx, "nullifier"))),
		}
		if len(sha) >= 32 {
			b.BallotFingerprint = groupFingerprint(sha[:32])
		}
		if tx, ok := receipts[field(r, idx, "index")]; ok {
			b.TxID, b.BlockNumber = tx.TxID, tx.BlockNumber
		}
		out = append(out, b)
	}
	return out, nil
}

func liveBoardChecks(st *liveSnapshot, live *LiveBoard) []Check {
	var checks []Check
	if st.DKG != "" {
		checks = append(checks, pass("The election key was made by the trustees' ceremony",
			"joint key fingerprint "+st.JointKeyFingerprint))
	} else {
		checks = append(checks, fail("The election key was made by the trustees' ceremony", "the key ceremony has not finished"))
	}
	dec := fmt.Sprintf("%d of %d trustees decrypted; %d required",
		live.Decryption.TrusteesDecrypted, st.Trustees, st.Threshold)
	if live.Decryption.TrusteesDecrypted >= st.Threshold {
		checks = append(checks, pass("Enough trustees decrypted", dec))
	} else {
		checks = append(checks, fail("Enough trustees decrypted", dec))
	}
	if st.Tallied {
		checks = append(checks, pass("The tally was published on the chain",
			fmt.Sprintf("%d trustee signatures", len(st.TallySignatures))))
	} else {
		checks = append(checks, fail("The tally was published on the chain", "no tally has been published yet"))
	}
	// The console runs verify-live itself, so the check does not claim an
	// independent party; anyone can run verify-live over GET /api/live/ledger.
	switch st.VerifyOverall {
	case "pass":
		checks = append(checks, pass(liveVerifierCheck,
			"every proof verifies and the totals match the published tally"))
	case "":
		checks = append(checks, fail(liveVerifierCheck, "not verified yet"))
	default:
		checks = append(checks, fail(liveVerifierCheck,
			"failed: "+strings.Join(live.FailedChecks, ", ")))
	}
	return checks
}

// serveLiveBoardFile serves a live run's public files once the tally is
// published. The private folder and live.json are never among them.
func (s *Server) serveLiveBoardFile(w http.ResponseWriter, r *http.Request, dir, name string) {
	if !slices.Contains(publicFiles, name) {
		http.Error(w, "not a public file of this run", http.StatusNotFound)
		return
	}
	st, err := liveRunState(dir)
	if err != nil || st.stateIndex() < liveStateIndex(LiveTallied) {
		http.Error(w, "sealed until the tally is published", http.StatusConflict)
		return
	}
	http.ServeFile(w, r, filepath.Join(dir, filepath.FromSlash(name)))
}

// liveVerifierCheck names the board's verifier check on a live run.
const liveVerifierCheck = "The verifier (verify-live) passed the on-chain record"
