package campaign

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// seedRun creates a run and returns its id and directory. The config is `good()`
// (ceremony_test.go) with the caller's tweaks applied.
func seedRun(t *testing.T, s *Server, tweak func(*ElectionConfig)) (string, string) {
	t.Helper()
	c := good()
	if tweak != nil {
		tweak(&c)
	}
	runID, dir, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	return runID, dir
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeCorrectness plants a correctness.csv with the columns writeCorrectnessCSV
// emits, so the reader is exercised against the real header.
func writeCorrectness(t *testing.T, dir string, rows ...string) {
	t.Helper()
	body := "contest,ground_truth,decoded,E,pass,published_tally,recovered_point," +
		"aggregate_ciphertext,dkg_sha256,tally_sha256,ballots_sha256\n"
	for _, r := range rows {
		body += r + "\n"
	}
	writeFile(t, dir, CorrectnessFile, body)
}

func getBoard(t *testing.T, h http.Handler, runID string) (*httptest.ResponseRecorder, BoardResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/board/"+runID, nil))
	var b BoardResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
			t.Fatalf("decode board: %v (body %s)", err, rec.Body)
		}
	}
	return rec, b
}

// The board must answer for an offline run with no Fabric configured. /api/trail
// returns 502 in exactly this situation, which is why the board is a separate
// endpoint rather than a view over it.
func TestBoardOfflineRunNeedsNoChain(t *testing.T) {
	s, h, _ := testServer(t, nil)
	runID, _ := seedRun(t, s, nil)

	rec, board := getBoard(t, h, runID)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	if board.OnChain {
		t.Error("no Fabric is configured, so on_chain must be false")
	}
	if board.ElectionID != runID {
		t.Errorf("election_id = %q, want %q", board.ElectionID, runID)
	}
	if board.Integrity.TurnoutNote == "" {
		t.Error("turnout must carry its by-construction note, never a bare 100%")
	}
}

func TestBoardRejectsUnknownRun(t *testing.T) {
	_, h, _ := testServer(t, nil)
	for _, path := range []string{"/api/board/Bad_Id", "/api/board/never-generated"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusOK {
			t.Errorf("%s should not be 200", path)
		}
	}
}

// Until the ceremony publishes, the board shows nothing — the whole point of
// the threshold demonstration is that the result is not readable early.
func TestBoardSealedUntilPublished(t *testing.T) {
	s, h, exec := testServer(t, nil)
	runID, dir := seedRun(t, s, nil)
	writeCorrectness(t, dir, "president/cand0,7,7,0,true,7,,,,,")

	_, board := getBoard(t, h, runID)
	if !board.Sealed {
		t.Fatal("an unpublished ceremony must leave the board sealed")
	}
	if len(board.Contests) != 0 {
		t.Fatalf("a sealed board must carry no results, got %d contests", len(board.Contests))
	}

	if err := exec.markPublished(runID, good()); err != nil {
		t.Fatal(err)
	}
	_, board = getBoard(t, h, runID)
	if board.Sealed {
		t.Fatal("board should unseal once the tally is published")
	}
	if len(board.Contests) != 1 {
		t.Fatalf("want 1 contest after publish, got %d", len(board.Contests))
	}
	if board.PublishedAt == nil {
		t.Error("published_at must be recorded, it is the board's tally date")
	}
	if !board.Verified {
		t.Error("every correctness row passed, so verified must be true")
	}
}

func TestBoardRanksSeatsAndCut(t *testing.T) {
	c := good()
	c.SenateSeats = 3
	totals := map[string]uint64{
		"senator/cand0": 90, "senator/cand1": 80, "senator/cand2": 70,
		"senator/cand3": 60, "senator/cand4": 50,
	}
	contests := groupContests(c, totals)
	if len(contests) != 1 {
		t.Fatalf("want 1 race, got %d", len(contests))
	}
	race := contests[0]
	if race.Label != "Senator" {
		t.Errorf("label = %q, want Senator", race.Label)
	}
	if race.Seats != 3 {
		t.Fatalf("seats = %d, want 3", race.Seats)
	}
	if race.Contested {
		t.Fatal("strictly decreasing counts decide the cut")
	}
	if race.TotalVotes != 350 {
		t.Errorf("total = %d, want 350", race.TotalVotes)
	}
	for i, cand := range race.Candidates {
		wantElected := i < 3
		if cand.Elected != wantElected {
			t.Errorf("candidate %d (%s, %d votes): elected = %v, want %v",
				i, cand.Label, cand.Votes, cand.Elected, wantElected)
		}
		if cand.Rank != i+1 {
			t.Errorf("candidate %d rank = %d, want %d", i, cand.Rank, i+1)
		}
	}
	if race.Candidates[0].Label != "Candidate 1" {
		t.Errorf("cand0 renders as %q, want 1-based Candidate 1", race.Candidates[0].Label)
	}
}

// A uniform 20-voter, 4-candidate election really does decrypt to 5/5/5/5.
// Sorting and printing the first row as the winner would invent a result the
// data does not support, so the cut must be reported as undecided.
func TestBoardReportsTieRatherThanInventingAWinner(t *testing.T) {
	c := good()
	totals := map[string]uint64{
		"president/cand0": 5, "president/cand1": 5,
		"president/cand2": 5, "president/cand3": 5,
	}
	race := groupContests(c, totals)[0]
	if !race.Contested {
		t.Fatal("a four-way tie for one seat must be reported as contested")
	}
	for _, cand := range race.Candidates {
		if cand.Elected {
			t.Fatalf("%s must not be elected on an undecided cut", cand.Label)
		}
		if cand.Rank != 1 {
			t.Errorf("%s rank = %d, want 1 — level candidates share a rank", cand.Label, cand.Rank)
		}
	}
}

// A multi-seat race where the last seat is contested awards nothing either.
func TestBoardReportsTieAtTheCut(t *testing.T) {
	c := good()
	c.SenateSeats = 2
	totals := map[string]uint64{
		"senator/cand0": 90, "senator/cand1": 40, "senator/cand2": 40, "senator/cand3": 10,
	}
	race := groupContests(c, totals)[0]
	if race.Seats != 2 {
		t.Fatalf("seats = %d, want 2", race.Seats)
	}
	if !race.Contested {
		t.Fatal("two candidates level for one remaining seat is an undecided cut")
	}
	if race.Candidates[0].Elected {
		t.Error("nothing is awarded while the cut is undecided, not even the clear leader")
	}
}

// The senate cut must leave at least one candidate below it, or the race
// decides nothing.
func TestSeatsNeverElectEveryCandidate(t *testing.T) {
	c := good()
	c.SenateSeats = 9
	if got := seatsFor(c, SenatePositionID, 4); got != 3 {
		t.Errorf("seats = %d, want 3 (capped at candidates-1)", got)
	}
	if got := seatsFor(c, "president", 4); got != 1 {
		t.Errorf("president seats = %d, want 1", got)
	}
}

func TestBoardChecksReflectArtifacts(t *testing.T) {
	s, h, exec := testServer(t, nil)
	runID, dir := seedRun(t, s, nil)
	writeCorrectness(t, dir,
		"president/cand0,7,7,0,true,7,,,,,",
		"president/cand1,3,4,1,false,3,,,,,")
	writeFile(t, dir, ScenarioStateFile, `[
	  {"Scenario":"tamper-ballot-proof","Stage":"ballots","Verdict":"PASS"},
	  {"Scenario":"reused-nullifier","Stage":"ballots","Verdict":"FAIL"},
	  {"Scenario":"late-ballot","Stage":"close","Verdict":"PASS"}
	]`)
	if err := exec.markSubmitted(runID, good(), "1"); err != nil {
		t.Fatal(err)
	}

	_, board := getBoard(t, h, runID)
	byName := map[string]Check{}
	for _, c := range board.Checks {
		byName[c.Name] = c
	}
	for name, wantPass := range map[string]bool{
		"Every contest decodes to the seeded ground truth": false, // one row has E=1
		"The tally was published by the trustee ceremony":  false, // never published
		"Enough trustees contributed":                      false, // 1 of 3 required
		"Every tampered ballot was refused":                false, // one ballot-stage FAIL
	} {
		c, ok := byName[name]
		if !ok {
			t.Fatalf("missing check %q (have %v)", name, board.Checks)
		}
		if c.Pass != wantPass {
			t.Errorf("check %q pass = %v, want %v (%s)", name, c.Pass, wantPass, c.Detail)
		}
	}
	if board.Verified {
		t.Error("a failing correctness row must not be reported as verified")
	}
	// Only the ballot-stage PASS counts; the close-stage one is different evidence.
	if board.Integrity.Rejected != 1 {
		t.Errorf("rejected = %d, want 1", board.Integrity.Rejected)
	}
	if !strings.Contains(board.Integrity.RejectedNote, "negative test") {
		t.Errorf("rejected must be labelled as negative-test evidence, got %q", board.Integrity.RejectedNote)
	}
}

// A ground-truth run has no ciphertexts, no ceremony and no tally. It must say
// so rather than looking like a failed encrypted run.
func TestBoardExplainsGroundTruthRuns(t *testing.T) {
	s, h, _ := testServer(t, nil)
	runID, _ := seedRun(t, s, func(c *ElectionConfig) { c.Mode = ModeGroundTruth })

	rec, board := getBoard(t, h, runID)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if board.Mode != ModeGroundTruth {
		t.Errorf("mode = %q", board.Mode)
	}
	if !strings.Contains(board.Integrity.TurnoutNote, "ground-truth") {
		t.Errorf("note should explain the mode, got %q", board.Integrity.TurnoutNote)
	}
	if len(board.Checks) == 0 {
		t.Error("a ground-truth board should still carry the validation-gate checks")
	}
}

// --- verify your vote ------------------------------------------------------

var nullA = "cafe0001" + strings.Repeat("ab", 28)
var nullB = "beef0002" + strings.Repeat("cd", 28)

func writeBallotsCSVFixture(t *testing.T, dir string, rows ...[3]string) {
	t.Helper()
	body := "index,election_id,position_id,voter_credential_commitment,nullifier," +
		"num_ciphertexts,num_wellformedness_proofs,ballot_sha256,ballot_json\n"
	for _, r := range rows {
		// index, position_id, nullifier
		body += r[0] + ",e1," + r[1] + ",aa," + r[2] + ",4,4,deadbeef,\"{\"\"a\"\":1}\"\n"
	}
	writeFile(t, dir, BallotsCSV, body)
}

func getCode(t *testing.T, h http.Handler, runID, code string) (*httptest.ResponseRecorder, VerifyCodeResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/verify-code/"+runID+"/"+code, nil))
	var v VerifyCodeResponse
	if rec.Code == http.StatusOK {
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
	}
	return rec, v
}

func TestVerifyCodeFindsNullifierPrefix(t *testing.T) {
	s, h, _ := testServer(t, nil)
	runID, dir := seedRun(t, s, nil)
	writeBallotsCSVFixture(t, dir,
		[3]string{"0", "president", nullA},
		[3]string{"1", "senator", nullB})

	rec, v := getCode(t, h, runID, "BC-CAFE-0001")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	if !v.Found || v.BallotIndex != 0 {
		t.Fatalf("want ballot 0, got %+v", v)
	}
	// A nullifier is per voter PER POSITION, so the answer must name which
	// record it is — otherwise it reads as "your ballot", which it is not.
	if v.PositionID != "president" || v.PositionLabel != "President" {
		t.Errorf("position = %q/%q, want president/President", v.PositionID, v.PositionLabel)
	}
	if v.TrackingCode != "BC-CAFE-0001" {
		t.Errorf("tracking_code = %q", v.TrackingCode)
	}
	// Offline there is no ledger receipt, so there is no commit time to show.
	if v.RecordedAt != nil {
		t.Error("an offline run has no ledger timestamp; it must stay null")
	}
	if v.CommittedOnChain {
		t.Error("nothing is on-chain without a configured network")
	}
}

func TestVerifyCodeNotFound(t *testing.T) {
	s, h, _ := testServer(t, nil)
	runID, dir := seedRun(t, s, nil)
	writeBallotsCSVFixture(t, dir, [3]string{"0", "president", nullA})

	rec, v := getCode(t, h, runID, "BC-9999-9999")
	if rec.Code != http.StatusOK {
		t.Fatalf("a miss is a normal answer, want 200, got %d", rec.Code)
	}
	if v.Found {
		t.Error("found must be false")
	}
}

func TestVerifyCodeRejectsMalformed(t *testing.T) {
	s, h, _ := testServer(t, nil)
	runID, dir := seedRun(t, s, nil)
	writeBallotsCSVFixture(t, dir, [3]string{"0", "president", nullA})

	// The code is a hex nullifier prefix, so non-hex can never match.
	for _, bad := range []string{"BC-ZZZZ-0001", "nonsense", "BC-CAFE", "cafe00011"} {
		rec, _ := getCode(t, h, runID, bad)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q should be 400, got %d", bad, rec.Code)
		}
	}
	// Bare hex and lowercase are accepted — same eight characters.
	if rec, _ := getCode(t, h, runID, "cafe0001"); rec.Code != http.StatusOK {
		t.Errorf("bare hex should be accepted, got %d", rec.Code)
	}
}

// Eight hex characters is 32 bits. Picking the first match on a collision would
// quietly show someone else's record.
func TestVerifyCodeAmbiguousPrefixIsRefused(t *testing.T) {
	s, h, _ := testServer(t, nil)
	runID, dir := seedRun(t, s, nil)
	writeBallotsCSVFixture(t, dir,
		[3]string{"0", "president", nullA},
		[3]string{"1", "senator", "cafe0001" + strings.Repeat("ff", 28)})

	rec, _ := getCode(t, h, runID, "BC-CAFE-0001")
	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409 on an ambiguous prefix, got %d: %s", rec.Code, rec.Body)
	}
}

func TestTrackingCodeRoundTrips(t *testing.T) {
	code := formatTrackingCode(nullA)
	if code != "BC-CAFE-0001" {
		t.Fatalf("formatTrackingCode = %q", code)
	}
	prefix, err := trackingPrefix(code)
	if err != nil {
		t.Fatal(err)
	}
	if prefix != "cafe0001" {
		t.Fatalf("trackingPrefix = %q", prefix)
	}
}

// --- static apps + ceremony view -------------------------------------------

func TestWebDirServesBoardTrusteeAndAdmin(t *testing.T) {
	dir := t.TempDir()
	for _, app := range []string{"board", "trustee", "admin"} {
		if err := os.MkdirAll(filepath.Join(dir, app), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, app), "index.html", "<title>"+app+"</title>")
	}
	t.Setenv("SAKSI_WEB_DIR", dir)
	_, h, _ := testServer(t, nil)

	for _, app := range []string{"board", "trustee", "admin"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/"+app+"/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /%s/ want 200, got %d", app, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "<title>"+app) {
			t.Errorf("/%s/ served the wrong app: %s", app, rec.Body)
		}
		// The bare path must not fall through to handleIndex's 404.
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/"+app+"?run=x", nil))
		if rec.Code != http.StatusMovedPermanently {
			t.Errorf("GET /%s want a redirect, got %d", app, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/"+app+"/?run=x" {
			t.Errorf("redirect to %q, want the query preserved", loc)
		}
	}
}

// Unset, the routes must not exist at all — the console behaves as before.
func TestWithoutWebDirTheAppRoutesAreAbsent(t *testing.T) {
	t.Setenv("SAKSI_WEB_DIR", "")
	_, h, _ := testServer(t, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/board/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 with no web dir, got %d", rec.Code)
	}
}

// The trustee console gets its context on the ceremony poll, and every field
// the wizard already reads must stay at the same JSON path.
func TestCeremonyViewEmbedsStateAndEvents(t *testing.T) {
	s, h, exec := testServer(t, nil)
	runID, dir := seedRun(t, s, nil)
	writeBundle(t, dir, runID, 4, 3)
	if err := exec.writeCeremony(runID, good(), nil); err != nil {
		t.Fatal(err)
	}
	if err := exec.markSubmitted(runID, good(), "2"); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ceremony/"+runID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}

	// Raw-map assertion: the wizard reads these paths, so a rename would break
	// a page that nothing else type-checks.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"threshold", "trustees", "submitted", "unlocked", "published", "on_chain", "ready"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("CeremonyState field %q must stay at the top level", key)
		}
	}

	var v CeremonyView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.ElectionID != runID {
		t.Errorf("election_id = %q", v.ElectionID)
	}
	if v.Submitted != 1 {
		t.Errorf("submitted = %d, want 1", v.Submitted)
	}
	// Offline there are no ledger receipts, which is exactly why the ceremony
	// timestamps exist: without them the log would be empty.
	if len(v.Events) < 2 {
		t.Fatalf("want the opened + contributed lines, got %d events: %+v", len(v.Events), v.Events)
	}
	var sawTrustee bool
	for _, e := range v.Events {
		if e.Kind == "trustee" && e.At == nil {
			t.Error("a locally recorded contribution must carry its timestamp")
		}
		if e.Kind == "trustee" {
			sawTrustee = true
		}
	}
	if !sawTrustee {
		t.Error("the trustee's contribution is missing from the timeline")
	}
}

func TestCeremonyTimestampsSurviveAReload(t *testing.T) {
	s, _, exec := testServer(t, nil)
	runID, _ := seedRun(t, s, nil)
	if err := exec.writeCeremony(runID, good(), nil); err != nil {
		t.Fatal(err)
	}
	if err := exec.markSubmitted(runID, good(), "1"); err != nil {
		t.Fatal(err)
	}
	if err := exec.markPublished(runID, good()); err != nil {
		t.Fatal(err)
	}

	st := exec.readCeremony(runID, good())
	if st.StartedAt == nil || st.ClosedAt == nil || st.PublishedAt == nil {
		t.Fatalf("timestamps lost on reload: %+v", st)
	}
	if st.Trustees[0].SubmittedAt == nil {
		t.Error("trustee submitted_at lost on reload")
	}
	// ClosedAt is stamped at ceremony start — the moment CloseElection runs —
	// so it must not drift to the publish time.
	if st.PublishedAt.Before(*st.ClosedAt) {
		t.Error("published_at must not precede closed_at")
	}
}

func getPath(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// The public verification files: the allowlist only, nothing while sealed, and
// a header with the seeded ground truth and the voter ids emptied.
func TestBoardFilesArePublicRecordsOnly(t *testing.T) {
	s, h, exec := testServer(t, nil)
	runID, dir := seedRun(t, s, nil)
	const header = `{"election_id":"e","tally":"abcd","ground_truth":[7,0],"voter_ids":["V-1","V-2"],"n":2}`
	writeFile(t, dir, "header.json", header)
	writeFile(t, dir, BallotsFile, "0a01\n0a02\n")
	if err := os.MkdirAll(filepath.Join(dir, LedgerDir), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, LedgerDir+"/"+BallotsFile, "0a02\n0a01\n")
	writeFile(t, dir, GroundTruthSummaryCSV, "secret")
	writeCorrectness(t, dir, "president/cand0,7,7,0,true,7,,,,,")
	base := "/api/board/" + runID + "/files/"

	if rec := getPath(h, base+"header.json"); rec.Code != http.StatusConflict {
		t.Fatalf("sealed header.json: want 409, got %d: %s", rec.Code, rec.Body)
	}
	if _, board := getBoard(t, h, runID); len(board.Files) != 0 {
		t.Fatalf("a sealed board lists no files, got %v", board.Files)
	}
	if err := exec.markPublished(runID, good()); err != nil {
		t.Fatal(err)
	}

	rec := getPath(h, base+"header.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("header.json: want 200, got %d: %s", rec.Code, rec.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("public header is not JSON: %v (%s)", err, rec.Body)
	}
	for _, k := range []string{"ground_truth", "voter_ids"} {
		if v, ok := got[k].([]any); !ok || len(v) != 0 {
			t.Errorf("%s must be an empty array, got %v", k, got[k])
		}
	}
	if got["tally"] != "abcd" || got["n"] != float64(2) {
		t.Errorf("public fields must pass through unchanged, got %v", got)
	}
	if rec := getPath(h, base+"ledger/ballots.ndjson"); rec.Code != http.StatusOK || rec.Body.String() != "0a02\n0a01\n" {
		t.Errorf("ledger/ballots.ndjson: got %d %q", rec.Code, rec.Body)
	}
	_, board := getBoard(t, h, runID)
	if want := []string{"header.json", BallotsFile, LedgerDir + "/" + BallotsFile}; !slices.Equal(board.Files, want) {
		t.Errorf("files = %v, want %v", board.Files, want)
	}

	for _, name := range []string{
		GroundTruthSummaryCSV, CorrectnessFile, BallotsCSV, ElectionCSV, JournalFile, PerfCSV, RunFile,
		"../" + RunFile, "ledger/../" + GroundTruthSummaryCSV, "..%2f" + RunFile, "%2e%2e/" + RunFile, "ledger", "",
	} {
		rec := getPath(h, base+name)
		if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "secret") ||
			strings.Contains(rec.Body.String(), "ground_truth") {
			t.Errorf("%q must not be served, got %d: %s", name, rec.Code, rec.Body)
		}
	}
}

// A header that is not a JSON object is an error, never a partial copy that
// passes for one.
func TestWritePublicHeaderRejectsNonObject(t *testing.T) {
	var b strings.Builder
	if err := writePublicHeader(&b, strings.NewReader(`["ground_truth"]`)); err == nil {
		t.Fatal("want an error for a non-object header")
	}
}
