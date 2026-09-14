package campaign

import (
	"bufio"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The public bulletin board and the trustee console, served as JSON.
//
// WHY THIS IS NOT /api/trail. buildTrail dials Fabric unconditionally and its
// handler returns 502 "chain unreachable" when there is no network, because a
// trail IS the on-chain record and a stale one would be a lie. The board is a
// different claim: it reports what this console recorded for a run, offline or
// on-chain, and only *enriches* from the ledger when one is reachable. So it
// reads the run folder first and treats every chain read as best-effort, with
// the same Partial/PartialReason honesty flag buildTrail uses.
//
// SCOPE. The published tally is the generator's seeded result, not a
// recomputation from whichever shares were submitted (see the header comment in
// ceremony.go). Nothing here implies otherwise: Verified reports what the
// independent auditor found, and the trustee counts report who contributed.

// SenatePositionID is the multi-seat race's position id — the value
// ph_position_id(2) emits in the Rust generator. SenatePosition (config.go) is
// the same race by ballot index; this is the same race by wire id, which is
// what the contest ids in correctness.csv actually carry.
const SenatePositionID = "senator"

// BoardCandidate is one candidate's line on a race card.
type BoardCandidate struct {
	ID      string  `json:"id"`    // "cand0"
	Label   string  `json:"label"` // "Candidate 1"
	Votes   uint64  `json:"votes"`
	Rank    int     `json:"rank"` // 1-based, ties share the lower number
	Elected bool    `json:"elected"`
	Share   float64 `json:"share"` // percent of this race's votes
}

// BoardContest is one race, ranked.
type BoardContest struct {
	ID         string `json:"id"`    // "president"
	Label      string `json:"label"` // "President"
	Seats      int    `json:"seats"`
	TotalVotes uint64 `json:"total_votes"`
	// Contested reports that the cut is not decided — more candidates are level
	// at the last elected place than there are seats left. Nothing is awarded.
	Contested  bool             `json:"contested"`
	Candidates []BoardCandidate `json:"candidates"`
}

// BoardIntegrity is the ballot-accounting panel.
type BoardIntegrity struct {
	Voters        int     `json:"voters"`
	Positions     int     `json:"positions"`
	Candidates    int     `json:"candidates"`
	BallotRecords int     `json:"ballot_records"`
	Verified      int     `json:"verified"`
	Rejected      int     `json:"rejected"`
	RejectedNote  string  `json:"rejected_note,omitempty"`
	TurnoutPct    float64 `json:"turnout_pct"`
	TurnoutNote   string  `json:"turnout_note"`
}

// BoardCrypto is the cryptographic-evidence panel.
type BoardCrypto struct {
	TallyProofVerified bool   `json:"tally_proof_verified"`
	TrusteesSubmitted  int    `json:"trustees_submitted"`
	TrusteesTotal      int    `json:"trustees_total"`
	Threshold          int    `json:"threshold"`
	TallySHA256        string `json:"tally_sha256,omitempty"`
	DKGSHA256          string `json:"dkg_sha256,omitempty"`
	BallotsSHA256      string `json:"ballots_sha256,omitempty"`
	IssuerPublicKey    string `json:"issuer_public_key,omitempty"`
	BindingContext     string `json:"binding_context,omitempty"`
	// Chain fields are populated only when a ledger was reachable.
	ChainHeight         uint64 `json:"chain_height,omitempty"`
	TipHash             string `json:"tip_hash,omitempty"`
	CommittedNullifiers int    `json:"committed_nullifiers,omitempty"`
}

// BoardResponse is the GET /api/board/<run> body.
type BoardResponse struct {
	ElectionID   string     `json:"election_id"`
	Name         string     `json:"name"`
	Mode         string     `json:"mode"`
	Distribution string     `json:"distribution"`
	OnChain      bool       `json:"on_chain"`
	Status       string     `json:"status,omitempty"`
	OpenedAt     time.Time  `json:"opened_at"`
	ClosedAt     *time.Time `json:"closed_at,omitempty"`
	PublishedAt  *time.Time `json:"published_at,omitempty"`
	// Sealed reports that no tally has been published yet — the board shows the
	// pending state and no results, exactly as the trail page does.
	Sealed bool `json:"sealed"`
	// Verified is the independent auditor's verdict (correctness.csv, every
	// contest E = 0). False also means "not audited yet"; Checks says which.
	Verified  bool           `json:"verified"`
	Contests  []BoardContest `json:"contests,omitempty"`
	Integrity BoardIntegrity `json:"integrity"`
	Crypto    BoardCrypto    `json:"crypto"`
	Checks    []Check        `json:"checks"`
	Artifacts []string       `json:"artifacts"`
	// Files are the public verification records served at
	// /api/board/<run>/files/<name>; empty while the board is sealed.
	Files         []string `json:"files"`
	Partial       bool     `json:"partial,omitempty"`
	PartialReason string   `json:"partial_reason,omitempty"`
}

// --- labels ----------------------------------------------------------------

var positionLabels = map[string]string{
	"president":      "President",
	"vice-president": "Vice President",
	"senator":        "Senator",
}

var positionNumRe = regexp.MustCompile(`^position-(\d+)$`)
var candNumRe = regexp.MustCompile(`^cand(\d+)$`)

// posLabel renders a generator position id for humans. Mirrors posLabel in
// web/wizard.html so the two surfaces never disagree about a race's name.
func posLabel(id string) string {
	if l, ok := positionLabels[id]; ok {
		return l
	}
	if m := positionNumRe.FindStringSubmatch(id); m != nil {
		return "Position " + m[1]
	}
	return strings.ReplaceAll(id, "-", " ")
}

// candLabel renders cand0 as "Candidate 1" — 1-based, matching the CAND_PRES_01
// convention the ground-truth tables use.
func candLabel(id string) string {
	if m := candNumRe.FindStringSubmatch(id); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return "Candidate " + strconv.Itoa(n+1)
		}
	}
	return id
}

// seatsFor returns how many candidates win a race. Only the Senate elects
// several, and never all of them — a cut with no candidate below it decides
// nothing. Keyed off the position id rather than its ordinal in the file, so it
// stays correct however the contests happen to be ordered.
func seatsFor(c ElectionConfig, positionID string, candidates int) int {
	if positionID != SenatePositionID || c.SenateSeats <= 1 {
		return 1
	}
	s := c.SenateSeats
	if s > candidates-1 {
		s = candidates - 1
	}
	if s < 1 {
		s = 1
	}
	return s
}

// rankContest ranks one race's candidates and decides the cut.
//
// Ported from renderBoard in web/wizard.html, which is the reference. Ties are
// REPORTED, not resolved: if more candidates are level at the last elected
// place than there are seats left, nothing is awarded and Contested is set.
// Under a uniform distribution a 20-voter, 4-candidate election decrypts to
// exactly 5/5/5/5, so sorting and printing the first as the winner would invent
// a result the data does not support.
func rankContest(c ElectionConfig, positionID string, votes map[string]uint64) BoardContest {
	out := BoardContest{ID: positionID, Label: posLabel(positionID)}
	for id, v := range votes {
		out.Candidates = append(out.Candidates, BoardCandidate{ID: id, Label: candLabel(id), Votes: v})
		out.TotalVotes += v
	}
	if len(out.Candidates) == 0 {
		out.Seats = 1
		return out
	}
	sort.Slice(out.Candidates, func(i, j int) bool {
		if out.Candidates[i].Votes != out.Candidates[j].Votes {
			return out.Candidates[i].Votes > out.Candidates[j].Votes
		}
		return out.Candidates[i].ID < out.Candidates[j].ID
	})

	out.Seats = seatsFor(c, positionID, len(out.Candidates))
	cutoff := out.Candidates[out.Seats-1].Votes
	atCut, above := 0, 0
	for _, cand := range out.Candidates {
		if cand.Votes == cutoff {
			atCut++
		}
		if cand.Votes > cutoff {
			above++
		}
	}
	out.Contested = atCut > 1 && above < out.Seats

	for i := range out.Candidates {
		// Ties share the lower rank number: 5/5/3 ranks 1, 1, 3.
		rank := i + 1
		if i > 0 && out.Candidates[i].Votes == out.Candidates[i-1].Votes {
			rank = out.Candidates[i-1].Rank
		}
		out.Candidates[i].Rank = rank
		out.Candidates[i].Elected = !out.Contested && i < out.Seats
		if out.TotalVotes > 0 {
			out.Candidates[i].Share = float64(out.Candidates[i].Votes) / float64(out.TotalVotes) * 100
		}
	}
	return out
}

// groupContests splits flat "<position>/cand<N>" totals into ranked races, in
// the order the contest ids first appear (which is the generator's order:
// president, vice-president, senator, …).
func groupContests(c ElectionConfig, totals map[string]uint64) []BoardContest {
	byPosition := map[string]map[string]uint64{}
	var order []string
	for _, contestID := range sortedKeys(totals) {
		position, candidate := splitContestID(contestID)
		if byPosition[position] == nil {
			byPosition[position] = map[string]uint64{}
			order = append(order, position)
		}
		byPosition[position][candidate] = totals[contestID]
	}
	out := make([]BoardContest, 0, len(order))
	for _, p := range order {
		out = append(out, rankContest(c, p, byPosition[p]))
	}
	return out
}

func sortedKeys(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- artifact readers ------------------------------------------------------

// boardHeader is the header.json subset the board needs. It is a superset of
// electionHeader (csvexport.go) by one field — params, needed to decode the
// tally when Verify has not run yet.
type boardHeader struct {
	electionHeader
	Params string `json:"params"`
}

// readCorrectness parses correctness.csv into the per-contest rows Verify
// wrote. A missing file is not an error — it is a run that has not been audited.
func readCorrectness(dir string) ([]ContestCorrectness, error) {
	f, err := os.Open(filepath.Join(dir, CorrectnessFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil || len(rows) < 2 {
		return nil, err
	}
	idx := columnIndex(rows[0])
	out := make([]ContestCorrectness, 0, len(rows)-1)
	for _, r := range rows[1:] {
		var c ContestCorrectness
		c.Contest = field(r, idx, "contest")
		c.GroundTruth, _ = strconv.ParseUint(field(r, idx, "ground_truth"), 10, 64)
		c.Decoded, _ = strconv.ParseUint(field(r, idx, "decoded"), 10, 64)
		c.E, _ = strconv.ParseInt(field(r, idx, "E"), 10, 64)
		c.Pass = field(r, idx, "pass") == "true"
		out = append(out, c)
	}
	return out, nil
}

func columnIndex(header []string) map[string]int {
	m := make(map[string]int, len(header))
	for i, h := range header {
		m[strings.TrimSpace(h)] = i
	}
	return m
}

func field(row []string, idx map[string]int, name string) string {
	i, ok := idx[name]
	if !ok || i >= len(row) {
		return ""
	}
	return row[i]
}

// artifactsIn lists the downloadable artifacts that exist for a run, in
// exportOrder — the same set /runs reports, so the two agree.
func artifactsIn(dir string) []string {
	var arts []string
	for _, name := range exportOrder {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			arts = append(arts, name)
		}
	}
	return arts
}

// --- the board -------------------------------------------------------------

// handleBoard serves GET /api/board/<run>, and GET /api/board/<run>/files/<name>
// for the public copy of a run's verification records (serveBoardFile). Picking
// the files action from the path suffix is safe here only because both are
// public: nothing under this subtree may ever need a role.
func (s *Server) handleBoard(w http.ResponseWriter, r *http.Request) {
	id, file, isFile := strings.Cut(strings.TrimPrefix(r.URL.Path, "/api/board/"), "/files/")
	runID, err := validRun(s, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rec, err := s.record(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	dir, err := s.store.Dir(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if isFile {
		s.serveBoardFile(w, r, rec, dir, file)
		return
	}
	writeJSONResp(w, http.StatusOK, s.buildBoard(rec, dir))
}

// publicFiles is what GET /api/board/<run>/files/<name> serves to anyone once
// the tally is published: the records a reader needs to re-check a run without
// trusting the console. That is the stream header and the ballots it audited,
// the chain's own copy of both, the ledger receipts, and the trail. Everything
// else in the run folder stays behind the admin-only /export/: the seeded
// ground truth (ground-truth-*.csv, and correctness.csv's ground_truth and E
// columns), the plaintext ballots (ballots.csv, election.csv), and the
// operator's records (journal, perf, run.json).
var publicFiles = []string{
	headerFile, BallotsFile, "receipts.csv", trailNDJSONFile, trailJSONFile,
	LedgerDir + "/" + headerFile, LedgerDir + "/" + BallotsFile,
}

// publicFilesIn lists the public files a run folder holds, in publicFiles order.
func publicFilesIn(dir string) []string {
	files := []string{}
	for _, name := range publicFiles {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(name))); err == nil {
			files = append(files, name)
		}
	}
	return files
}

// privateHeaderFields are the header.json fields a public copy empties:
// ground_truth is the seeded plaintext totals, and voter_ids names the
// synthetic voter behind each ballot index, which the chain never publishes.
var privateHeaderFields = map[string]bool{"ground_truth": true, "voter_ids": true}

// serveBoardFile serves one of publicFiles. The name must match the list
// exactly, so no path the caller writes reaches the filesystem. Every file is
// refused while the board is sealed: header.json carries the tally and the
// partial decryptions from generation onwards, so serving it early would
// publish the result before the trustees do.
func (s *Server) serveBoardFile(w http.ResponseWriter, r *http.Request, rec RunRecord, dir, name string) {
	if !slices.Contains(publicFiles, name) {
		http.Error(w, "not a public file of this run", http.StatusNotFound)
		return
	}
	if ceremony, err := s.exec.CeremonyStatus(rec.RunID, rec.Config); err != nil || !ceremony.Published {
		http.Error(w, "sealed until the tally is published", http.StatusConflict)
		return
	}
	full := filepath.Join(dir, filepath.FromSlash(name))
	if path.Base(name) != headerFile {
		http.ServeFile(w, r, full)
		return
	}
	f, err := os.Open(full)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/json")
	if err := writePublicHeader(w, f); err != nil {
		// Past the first buffered 4 KiB the status is already sent, so the
		// client sees a truncated body; the log says why.
		log.Printf("board: %s public %s: %v", rec.RunID, name, err)
	}
}

// writePublicHeader copies a stream header to w with privateHeaderFields
// written as empty arrays, which keeps the v1 header shape. It streams token by
// token because at the largest tier voter_ids alone is hundreds of megabytes.
func writePublicHeader(w io.Writer, r io.Reader) error {
	dec := json.NewDecoder(r)
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return fmt.Errorf("header is not a JSON object")
	}
	bw := bufio.NewWriter(w)
	bw.WriteByte('{')
	for first := true; dec.More(); first = false {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := json.Marshal(t)
		if !first {
			bw.WriteByte(',')
		}
		bw.Write(key)
		bw.WriteByte(':')
		if privateHeaderFields[t.(string)] {
			if err := skipJSONValue(dec); err != nil {
				return err
			}
			bw.WriteString("[]")
			continue
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return err
		}
		bw.Write(v)
	}
	bw.WriteByte('}')
	return bw.Flush()
}

// skipJSONValue consumes the next value from dec without holding it.
func skipJSONValue(dec *json.Decoder) error {
	depth := 0
	for {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		switch t {
		case json.Delim('['), json.Delim('{'):
			depth++
		case json.Delim(']'), json.Delim('}'):
			depth--
		}
		if depth == 0 {
			return nil
		}
	}
}

// buildBoard assembles the board from the run folder, enriching from the ledger
// only when one is configured. Every read is best-effort: a missing or
// unreadable artifact leaves its fields zero and, where that would be
// indistinguishable from a real zero, sets Partial.
func (s *Server) buildBoard(rec RunRecord, dir string) BoardResponse {
	c := rec.Config
	resp := BoardResponse{
		ElectionID:   rec.RunID,
		Name:         c.Name,
		Mode:         c.Mode,
		Distribution: c.Distribution,
		OpenedAt:     rec.CreatedAt,
		Sealed:       true,
		Artifacts:    artifactsIn(dir),
		Files:        []string{},
		Integrity: BoardIntegrity{
			Voters: c.Voters, Positions: c.Positions, Candidates: c.Candidates,
		},
		Crypto: BoardCrypto{Threshold: c.Threshold, TrusteesTotal: len(c.Trustees)},
	}

	// Ground-truth runs produce plaintext tables and no ciphertexts, so there is
	// no ceremony, no tally and nothing to seal or verify. Report that rather
	// than an empty board that looks like a failure.
	if groundTruthOnly(c) {
		resp.Integrity.BallotRecords = 0
		resp.Integrity.TurnoutNote = "ground-truth mode: plaintext tables only, no ballots were encrypted"
		resp.Checks = groundTruthChecks(dir)
		return resp
	}

	var h boardHeader
	haveHeader := readJSON(filepath.Join(dir, "header.json"), &h) == nil
	if haveHeader {
		if strings.TrimSpace(h.ElectionName) != "" {
			resp.Name = h.ElectionName
		}
		resp.Integrity.BallotRecords = h.N
		resp.Crypto.IssuerPublicKey = h.IssuerPk
		resp.Crypto.BindingContext = h.BindingContext
	}
	resp.Crypto.DKGSHA256, resp.Crypto.TallySHA256, resp.Crypto.BallotsSHA256 = runDigests(dir)

	// Turnout is 100% by construction: the generator gives every voter a full
	// ballot. Saying so beats inventing a registered-voter denominator.
	if c.Voters > 0 && resp.Integrity.BallotRecords > 0 {
		resp.Integrity.TurnoutPct = 100
	}
	resp.Integrity.TurnoutNote = "synthetic population — every generated voter casts a full ballot, so turnout is 100% by construction"

	ceremony, cerr := s.exec.CeremonyStatus(rec.RunID, c)
	if cerr != nil {
		log.Printf("board: %s ceremony status: %v", rec.RunID, cerr)
	}
	resp.Sealed = !ceremony.Published
	if !resp.Sealed {
		resp.Files = publicFilesIn(dir)
	}
	resp.PublishedAt = ceremony.PublishedAt
	resp.ClosedAt = ceremony.ClosedAt
	resp.Crypto.TrusteesSubmitted = ceremony.Submitted
	if ceremony.Threshold > 0 {
		resp.Crypto.Threshold = ceremony.Threshold
	}
	if n := len(ceremony.Trustees); n > 0 {
		resp.Crypto.TrusteesTotal = n
	}

	correctness, err := readCorrectness(dir)
	if err != nil {
		log.Printf("board: %s read correctness: %v", rec.RunID, err)
	}
	audited := len(correctness) > 0
	allPass := audited
	for _, row := range correctness {
		if !row.Pass {
			allPass = false
		}
	}
	resp.Verified = allPass
	resp.Crypto.TallyProofVerified = allPass
	if allPass {
		resp.Integrity.Verified = resp.Integrity.BallotRecords
	}

	if !resp.Sealed {
		resp.Contests = s.boardContests(c, dir, correctness, h, haveHeader, &resp)
	}

	scenarios, serr := readScenarioResults(dir)
	if serr != nil {
		log.Printf("board: %s read scenarios: %v", rec.RunID, serr)
	}
	resp.Integrity.Rejected, resp.Integrity.RejectedNote = tamperedRefused(scenarios)

	resp.Checks = boardChecks(correctness, audited, ceremony, scenarios, resp.Crypto.BallotsSHA256)
	s.enrichFromChain(&resp, rec.RunID)
	return resp
}

// boardContests produces the ranked races. correctness.csv's `decoded` column is
// preferred: those are the values threshold decryption actually recovered. When
// Verify has not run, the published tally is decoded instead so a freshly
// published board is not blank.
func (s *Server) boardContests(
	c ElectionConfig, dir string, correctness []ContestCorrectness,
	h boardHeader, haveHeader bool, resp *BoardResponse,
) []BoardContest {
	if len(correctness) > 0 {
		totals := make(map[string]uint64, len(correctness))
		for _, row := range correctness {
			totals[row.Contest] = row.Decoded
		}
		return groupContests(c, totals)
	}
	if !haveHeader || h.Tally == "" || h.Params == "" {
		return nil
	}
	decoded, err := decodeTally(h.Tally, h.Params)
	if err != nil {
		log.Printf("board: decode tally: %v", err)
		resp.Partial, resp.PartialReason = true, "tally decode failed"
		return nil
	}
	flat := map[string]uint64{}
	for position, cands := range decoded {
		for cand, v := range cands {
			flat[position+"/"+cand] = v
		}
	}
	return groupContests(c, flat)
}

// tamperedRefused counts the ballot-stage attacks the system refused. This is
// the only honest source for a "rejected" figure: a synthetic run has no
// spoiled ballots, so the number reports tampered ballots the verifier caught,
// not voters' ballots thrown out. SKIPPED (never mounted) rows are not counted
// either way.
func tamperedRefused(results []ScenarioResult) (int, string) {
	n, ran := 0, 0
	for _, r := range results {
		if r.Stage != StageBallots {
			continue
		}
		if r.Verdict == "PASS" {
			n++
			ran++
		} else if r.Verdict == "FAIL" {
			ran++
		}
	}
	if ran == 0 {
		return 0, "no ballot-stage negative tests have been run for this election"
	}
	return n, fmt.Sprintf("tampered ballots refused, out of %d ballot-stage negative tests", ran)
}

// boardChecks composes the verifier's check list from the artifacts this run
// already carries.
//
// HONEST SCOPE: this is a console-side summary, not the independent auditor's
// own findings. The auditor builds an AuditReport with one finding per check
// (saksi-auditor/src/report.rs), but `audit-stream --json` serializes only
// {overall, contests} — so the findings never reach this process. Surfacing
// them is a Rust change to StreamAudit and is deliberately not done here.
func boardChecks(
	correctness []ContestCorrectness, audited bool,
	ceremony CeremonyState, scenarios []ScenarioResult, ballotsSHA string,
) []Check {
	var checks []Check

	const eName = "Every contest decodes to the seeded ground truth"
	if !audited {
		checks = append(checks, fail(eName, "this run has not been audited yet — run Verify"))
	} else {
		worst := int64(0)
		bad := ""
		for _, row := range correctness {
			if !row.Pass && bad == "" {
				bad = fmt.Sprintf("%s: ground truth %d, decoded %d (E = %d)",
					row.Contest, row.GroundTruth, row.Decoded, row.E)
			}
			if row.E > worst || -row.E > worst {
				worst = row.E
			}
		}
		if bad == "" {
			checks = append(checks, pass(eName,
				fmt.Sprintf("E = 0 on all %d contests, recovered by threshold decryption", len(correctness))))
		} else {
			checks = append(checks, fail(eName, bad))
		}
	}

	const pubName = "The tally was published by the trustee ceremony"
	if ceremony.Published {
		checks = append(checks, pass(pubName, "the ceremony reached its threshold and published"))
	} else {
		checks = append(checks, fail(pubName, "no tally has been published for this election yet"))
	}

	const thrName = "Enough trustees contributed"
	detail := fmt.Sprintf("%d of %d trustees contributed; %d required",
		ceremony.Submitted, len(ceremony.Trustees), ceremony.Threshold)
	if ceremony.Submitted >= ceremony.Threshold && ceremony.Threshold > 0 {
		checks = append(checks, pass(thrName, detail))
	} else {
		checks = append(checks, fail(thrName, detail))
	}

	const negName = "Every tampered ballot was refused"
	refused, ran := 0, 0
	for _, r := range scenarios {
		if r.Stage != StageBallots {
			continue
		}
		switch r.Verdict {
		case "PASS":
			refused++
			ran++
		case "FAIL":
			ran++
		}
	}
	switch {
	case ran == 0:
		checks = append(checks, fail(negName, "no ballot-stage negative tests have been run"))
	case refused == ran:
		checks = append(checks, pass(negName,
			fmt.Sprintf("all %d tampered ballots were rejected by the verifier", ran)))
	default:
		checks = append(checks, fail(negName,
			fmt.Sprintf("%d of %d tampered ballots were NOT rejected", ran-refused, ran)))
	}

	const fpName = "The ballot set is fingerprinted"
	if ballotsSHA != "" {
		checks = append(checks, pass(fpName, "sha256 "+ballotsSHA))
	} else {
		checks = append(checks, fail(fpName, "no ballot set digest could be computed"))
	}

	// The chain-backed checks are appended by enrichFromChain, which is the
	// only place that knows whether a ledger actually answered.
	return checks
}

// groundTruthChecks surfaces the data-validation gate's report, if it has been
// run. Ground-truth runs have no ceremony and no tally, so this is the only
// check list they can carry.
func groundTruthChecks(dir string) []Check {
	var rep CheckReport
	if err := readJSON(filepath.Join(dir, CheckFile), &rep); err != nil {
		return []Check{fail("Ground-truth tables validated",
			"the data-validation gate has not been run for this election")}
	}
	return rep.Checks
}

// enrichFromChain adds the ledger's view when a network is configured. Every
// read is best-effort: a failure leaves the field unset and records why, rather
// than reporting a zero that cannot be told apart from a real one.
func (s *Server) enrichFromChain(resp *BoardResponse, electionID string) {
	if !s.fabric.Enabled() {
		return
	}
	reader, led, err := s.dial()
	if err != nil {
		resp.Checks = append(resp.Checks, fail("The election is committed to the ledger",
			"no Fabric network was reachable: "+err.Error()))
		return
	}
	if _, err := reader.GetElection(electionID); err != nil {
		resp.Checks = append(resp.Checks, fail("The election is committed to the ledger",
			"this election id is not on the ledger"))
		return
	}
	resp.OnChain = true
	if st, err := reader.GetElectionStatus(electionID); err == nil {
		resp.Status = st
	}
	if n, err := reader.CountCommittedBallots(electionID); err == nil {
		resp.Crypto.CommittedNullifiers = n
	} else if !resp.Partial {
		resp.Partial, resp.PartialReason = true, "committed nullifier count unavailable"
	}
	if height, tip, err := led.ChainInfo(); err == nil {
		resp.Crypto.ChainHeight = height
		resp.Crypto.TipHash = hex.EncodeToString(tip)
	} else if !resp.Partial {
		resp.Partial, resp.PartialReason = true, "chain height/tip unavailable"
	}
	resp.Checks = append(resp.Checks, pass("The election is committed to the ledger",
		fmt.Sprintf("status %q at block %d", resp.Status, resp.Crypto.ChainHeight)))

	const nName = "The committed ballot count matches the generated set"
	switch {
	case resp.Crypto.CommittedNullifiers == 0:
		// Not an assertion either way — the read failed or nothing is committed.
	case resp.Crypto.CommittedNullifiers == resp.Integrity.BallotRecords:
		resp.Checks = append(resp.Checks, pass(nName,
			fmt.Sprintf("%d nullifiers on-chain, %d ballots generated",
				resp.Crypto.CommittedNullifiers, resp.Integrity.BallotRecords)))
	default:
		resp.Checks = append(resp.Checks, fail(nName,
			fmt.Sprintf("%d nullifiers on-chain, %d ballots generated",
				resp.Crypto.CommittedNullifiers, resp.Integrity.BallotRecords)))
	}
}

// --- verify your vote ------------------------------------------------------

// VerifyCodeResponse is the GET /api/verify-code/<run>/<code> body.
//
// A nullifier is derived per voter PER POSITION, so a tracking code identifies
// one ballot RECORD — one position of one voter — not a voter's whole ballot.
// The position is named for that reason. Nothing here reveals a selection: the
// nullifier is unlinkable to the choice by construction.
type VerifyCodeResponse struct {
	Found            bool       `json:"found"`
	TrackingCode     string     `json:"tracking_code"`
	BallotIndex      int        `json:"ballot_index"`
	PositionID       string     `json:"position_id,omitempty"`
	PositionLabel    string     `json:"position_label,omitempty"`
	Nullifier        string     `json:"nullifier,omitempty"`
	BallotSHA256     string     `json:"ballot_sha256,omitempty"`
	RecordedAt       *time.Time `json:"recorded_at,omitempty"`
	CommittedOnChain bool       `json:"committed_on_chain"`
}

var hexRe = regexp.MustCompile(`^[0-9a-f]{8}$`)

// trackingPrefix normalises a BC-XXXX-XXXX code to the 8 lowercase hex chars it
// encodes. The code IS the first 8 hex characters of the ballot's nullifier, so
// anything outside [0-9a-f] can never match and is rejected here rather than
// scanned for.
func trackingPrefix(code string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(code))
	s = strings.TrimPrefix(s, "bc-")
	s = strings.ReplaceAll(s, "-", "")
	if !hexRe.MatchString(s) {
		return "", fmt.Errorf("tracking codes look like BC-XXXX-XXXX, with hex digits")
	}
	return s, nil
}

// formatTrackingCode is the inverse: nullifier -> BC-XXXX-XXXX.
func formatTrackingCode(nullifier string) string {
	if len(nullifier) < 8 {
		return ""
	}
	up := strings.ToUpper(nullifier[:8])
	return "BC-" + up[:4] + "-" + up[4:]
}

// ballotGetter is the one chaincode getter the lookup needs. Declared here
// rather than added to chainReader so this file stays additive. Named for the
// getter, not the file reader: ballots.go already owns ballotReader, the
// index-wise reader over the local ballots file.
type ballotGetter interface {
	GetBallot(electionID, nullifier string) (string, error)
}

func (s *Server) handleVerifyCode(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/verify-code/")
	rawRun, rawCode, found := strings.Cut(rest, "/")
	if !found {
		http.Error(w, "usage: /api/verify-code/<run>/<code>", http.StatusBadRequest)
		return
	}
	runID, err := validRun(s, rawRun)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	prefix, err := trackingPrefix(rawCode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	dir, err := s.store.Dir(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	matches, err := scanBallotsForPrefix(dir, prefix)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// 8 hex chars is 32 bits. At ten thousand ballots a collision is unlikely
	// but not impossible, and picking the first match would quietly show
	// someone else's record.
	if len(matches) > 1 {
		writeJSONResp(w, http.StatusConflict, map[string]string{
			"error": "this tracking code matches more than one ballot record — ask for the full nullifier",
		})
		return
	}
	if len(matches) == 0 {
		writeJSONResp(w, http.StatusOK, VerifyCodeResponse{Found: false})
		return
	}

	m := matches[0]
	resp := VerifyCodeResponse{
		Found:         true,
		TrackingCode:  formatTrackingCode(m.Nullifier),
		BallotIndex:   m.Index,
		PositionID:    m.PositionID,
		PositionLabel: posLabel(m.PositionID),
		Nullifier:     m.Nullifier,
		BallotSHA256:  m.SHA256,
	}
	resp.RecordedAt = submitBallotTime(dir, m.Index)
	if s.fabric.Enabled() {
		if reader, _, err := s.dial(); err == nil {
			if br, ok := reader.(ballotGetter); ok {
				if _, err := br.GetBallot(runID, m.Nullifier); err == nil {
					resp.CommittedOnChain = true
				}
			}
		}
	}
	writeJSONResp(w, http.StatusOK, resp)
}

// ballotRow is one match from the ballots table.
type ballotRow struct {
	Index      int
	PositionID string
	Nullifier  string
	SHA256     string
}

// scanBallotsForPrefix streams ballots.csv looking for nullifiers with the
// given prefix. Streaming, not ReadAll: the file is one row per ballot and each
// row carries the ballot's full JSON, so a capstone run's table is hundreds of
// megabytes.
func scanBallotsForPrefix(dir, prefix string) ([]ballotRow, error) {
	f, err := os.Open(filepath.Join(dir, BallotsCSV))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("this election has no ballot table — it has not been generated yet")
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rd := csv.NewReader(f)
	rd.ReuseRecord = true
	header, err := rd.Read()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", BallotsCSV, err)
	}
	idx := columnIndex(header)

	var out []ballotRow
	for {
		row, err := rd.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", BallotsCSV, err)
		}
		nullifier := strings.ToLower(field(row, idx, "nullifier"))
		if nullifier == "" || !strings.HasPrefix(nullifier, prefix) {
			continue
		}
		i, _ := strconv.Atoi(field(row, idx, "index"))
		out = append(out, ballotRow{
			Index:      i,
			PositionID: field(row, idx, "position_id"),
			Nullifier:  nullifier,
			SHA256:     field(row, idx, "ballot_sha256"),
		})
		if len(out) > 1 {
			break // ambiguous; no point reading the rest
		}
	}
	return out, nil
}

// submitBallotTime finds the ledger receipt for one ballot. Offline there is no
// trail.json and no timestamp exists — nil, and the UI says so, rather than
// substituting the run's creation time as if it were a commit time.
func submitBallotTime(dir string, index int) *time.Time {
	events, err := readTrailEvents(dir)
	if err != nil {
		return nil
	}
	ref := strconv.Itoa(index)
	for _, ev := range events {
		if ev.Event == "SubmitBallot" && ev.Ref == ref && !ev.Receipt.Timestamp.IsZero() {
			t := ev.Receipt.Timestamp
			return &t
		}
	}
	return nil
}
