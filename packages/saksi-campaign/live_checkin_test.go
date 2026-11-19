package campaign

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests of the voter list routes, the precinct check-in and the issuance gate
// (docs/live/voter-list-api.md). The fixtures are live_test.go's; every voter
// is fictional.

// openConsole is a console with an election in state open and no check-in.
func openConsole(t *testing.T) (*liveFixture, *liveConsole, string) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.setup()
	c.ceremony(runID)
	if c.state() != LiveOpen {
		t.Fatalf("state %s", c.state())
	}
	return fx, c, runID
}

func wantCode(t *testing.T, what string, code int, out map[string]any, status int, errCode string) {
	t.Helper()
	if code != status || (errCode != "" && out["code"] != errCode) {
		t.Fatalf("%s: %d %v, want %d %s", what, code, out, status, errCode)
	}
}

var allDOBs = []string{"1990-01-01", "1991-02-02", "1992-03-03", "1993-04-04", "1994-05-05"}

// noDOB fails if any answer the console gave carries a date of birth.
func noDOB(t *testing.T, c *liveConsole) {
	t.Helper()
	for _, b := range c.bodies {
		for _, d := range allDOBs {
			if strings.Contains(b, d) {
				t.Fatalf("an answer carries a date of birth: %.300s", b)
			}
		}
	}
}

func TestVoterListPreviewChangesNothing(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	out := c.ok(http.MethodPost, "/api/live/voter-list/preview", "admin", map[string]any{"csv": testVoterList})
	want := parseVoterList(testVoterList, DefaultLivePrecinct, time.Now())
	if out["valid"] != true || out["count"] != 5.0 || out["fingerprint"] != want.Fingerprint ||
		out["fingerprint_short"] != want.Fingerprint[:16] || out["precinct_label"] != "Precinct 0001A (demonstration)" {
		t.Fatalf("preview: %v", out)
	}
	rows := out["rows"].([]any)
	first := rows[0].(map[string]any)
	if first["seq"] != 1.0 || first["last_name"] != "Halimbawa" || first["first_name"] != "Dos" || first["date_of_birth_valid"] != true {
		t.Fatalf("first row: %v", first)
	}
	// A list in error: per-row errors, no fingerprint, a date only as valid
	// or not.
	bad := testVoterList + "Sampol,Tres,,1992-03-03\nHalimbawa,Anim,,1995-13-01\n"
	out = c.ok(http.MethodPost, "/api/live/voter-list/preview", "admin", map[string]any{"csv": bad})
	if out["valid"] != false || out["fingerprint"] != "" || len(out["errors"].([]any)) != 2 {
		t.Fatalf("preview in error: %v", out)
	}
	invalidDates := 0
	for _, r := range out["rows"].([]any) {
		if r.(map[string]any)["date_of_birth_valid"] == false {
			invalidDates++
		}
	}
	if invalidDates != 1 {
		t.Fatalf("%d rows with an invalid date, want 1", invalidDates)
	}
	noDOB(t, c)
	if entries, _ := os.ReadDir(fx.runs); len(entries) != 0 || c.s.live.snapshot() != nil {
		t.Fatal("a preview changed the console's state")
	}
	// The body is capped.
	if code, _ := c.do(http.MethodPost, "/api/live/voter-list/preview", "admin", map[string]any{"csv": strings.Repeat("x", voterListBodyMax)}); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized preview: %d", code)
	}
}

// The election view and the board carry the precinct, the counts and the
// fingerprint; never a name or a date.
func TestLiveElectionViewAndBoardCarryTheListFacts(t *testing.T) {
	_, c, runID := openConsole(t)
	fp := parseVoterList(testVoterList, DefaultLivePrecinct, time.Now()).Fingerprint
	c.issue("voter1")
	c.checkIn("voter2")
	c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:voter3", detailsBody(testVoters["voter3"], true))
	el := c.ok(http.MethodGet, "/api/live/election", "", nil)
	counts := el["counts"].(map[string]any)
	if el["precinct"] != "0001A" || el["precinct_label"] != "Precinct 0001A (demonstration)" || el["voter_list_fingerprint"] != fp ||
		el["voter_list_fingerprint_short"] != fp[:16] || counts["voters_on_list"] != 5.0 || counts["voters_on_roll"] != 5.0 ||
		counts["checked_in"] != 2.0 || counts["credentials_issued"] != 1.0 {
		t.Fatalf("election view: %v", el)
	}
	board := c.ok(http.MethodGet, "/api/board/"+runID, "", nil)
	lb := board["live"].(map[string]any)
	bc := lb["counts"].(map[string]any)
	if lb["precinct"] != "0001A" || lb["voter_list_fingerprint"] != fp || lb["voter_list_note"] != voterListNote ||
		bc["voters_on_list"] != 5.0 || bc["checked_in"] != 2.0 || bc["credentials_issued"] != 1.0 ||
		board["integrity"].(map[string]any)["voters"] != 5.0 {
		t.Fatalf("board: %v", lb)
	}
	for _, b := range c.bodies[len(c.bodies)-2:] {
		for _, name := range []string{"Halimbawa", "Sampol", "Uno", "Pagsubok"} {
			if strings.Contains(b, name) {
				t.Fatalf("a public answer names a voter: %.300s", b)
			}
		}
	}
	noDOB(t, c)
}

// The happy path, the phone's poll at every step, and the presenter's list.
func TestCheckinFlowAndPoll(t *testing.T) {
	_, c, runID := openConsole(t)
	code, out := c.do(http.MethodGet, "/api/live/checkin", "phone:voter1", nil)
	wantCode(t, "poll with no cookie", code, out, http.StatusNotFound, "no-checkin")

	out = c.ok(http.MethodPost, "/api/live/checkin/find", "phone:voter1", detailsBody(testVoters["voter1"], false))
	entry := out["entry"].(map[string]any)
	if entry["seq"] != 2.0 || entry["last_name"] != "Halimbawa" || entry["first_name"] != "Uno" || entry["middle_name"] != "Pagsubok" ||
		out["precinct_label"] != "Precinct 0001A (demonstration)" {
		t.Fatalf("find: %v", out)
	}
	if c.fx.phones["voter1"] != "" {
		t.Fatal("find set a cookie")
	}
	// Declare: the cookie, its attributes, the desk.
	req := httptest.NewRequest(http.MethodPost, "/api/live/checkin/declare", bytes.NewReader(mustJSON(detailsBody(testVoters["voter1"], true))))
	rec := httptest.NewRecorder()
	c.s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("declare: %d %s", rec.Code, rec.Body)
	}
	var ck *http.Cookie
	for _, k := range rec.Result().Cookies() {
		if k.Name == checkinCookie {
			ck = k
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/api/live/" ||
		ck.MaxAge != 43200 || len(ck.Value) < 43 {
		t.Fatalf("check-in cookie: %+v", ck)
	}
	c.fx.phones["voter1"] = ck.Value
	// The cookie is stored only as its election-bound hash.
	data, _ := os.ReadFile(filepath.Join(c.fx.runs, runID, livePrivateDir, liveCheckinFile))
	if bytes.Contains(data, []byte(ck.Value)) || !bytes.Contains(data, []byte(checkinCookieHash(runID, ck.Value))) {
		t.Fatal("checkin.json does not hold the cookie as its hash only")
	}
	poll := func(want string) map[string]any {
		t.Helper()
		out := c.ok(http.MethodGet, "/api/live/checkin", "phone:voter1", nil)
		if out["state"] != want || out["election_state"] != LiveOpen || out["election_id"] != runID {
			t.Fatalf("poll: %v, want %s", out, want)
		}
		return out
	}
	poll(CheckinAtDesk)
	list := c.ok(http.MethodGet, "/api/live/voter-list", "admin", nil)
	desk := list["desk"].([]any)
	if len(desk) != 1 || desk[0].(map[string]any)["seq"] != 2.0 || desk[0].(map[string]any)["status"] != CheckinAtDesk ||
		list["count"].(float64) != 5 || list["counts"].(map[string]any)["at_desk"] != 1.0 {
		t.Fatalf("voter list: %v", list)
	}
	// Signing before approval is refused.
	code, out = c.do(http.MethodPost, "/api/live/checkin/sign", "phone:voter1", map[string]any{"cannot_sign": true})
	wantCode(t, "sign at the desk", code, out, http.StatusConflict, "wrong-state")
	c.ok(http.MethodPost, "/api/live/desk/approve", "admin", map[string]any{"seq": 2})
	code, out = c.do(http.MethodPost, "/api/live/desk/approve", "admin", map[string]any{"seq": 2})
	wantCode(t, "approve twice", code, out, http.StatusConflict, "wrong-state")
	poll(CheckinApproved)
	strokes := [][][]int{{{0, 0}, {1000, 400}}, {{500, 200}}}
	c.ok(http.MethodPost, "/api/live/checkin/sign", "phone:voter1", map[string]any{"strokes": strokes})
	poll(CheckinSigned)
	code, out = c.do(http.MethodPost, "/api/live/checkin/sign", "phone:voter1", map[string]any{"strokes": strokes})
	wantCode(t, "sign twice", code, out, http.StatusConflict, "wrong-state")
	c.presignSign("voter1")
	out = poll(CheckinIssued)
	if out["entry"].(map[string]any)["seq"] != 2.0 {
		t.Fatalf("poll entry: %v", out)
	}
	// The presenter's list: the signature strokes, no date of birth.
	list = c.ok(http.MethodGet, "/api/live/voter-list", "admin", nil)
	e := list["entries"].([]any)[1].(map[string]any)
	got, _ := json.Marshal(e["signature"].(map[string]any)["strokes"])
	want, _ := json.Marshal(strokes)
	if e["status"] != CheckinIssued || !bytes.Equal(got, want) || len(list["desk"].([]any)) != 0 ||
		list["counts"].(map[string]any)["checked_in"] != 1.0 || list["fingerprint"] == "" {
		t.Fatalf("list after issuance: %v", list)
	}
	if strings.Contains(c.bodies[len(c.bodies)-1], "date_of_birth") {
		t.Fatal("the presenter's list carries a date_of_birth field")
	}
	noDOB(t, c)
	// "I cannot sign" is recorded and issuance follows it as a signature.
	c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:voter2", detailsBody(testVoters["voter2"], true))
	c.ok(http.MethodPost, "/api/live/desk/approve", "admin", map[string]any{"seq": 1})
	c.ok(http.MethodPost, "/api/live/checkin/sign", "phone:voter2", map[string]any{"cannot_sign": true})
	c.presignSign("voter2")
	list = c.ok(http.MethodGet, "/api/live/voter-list", "admin", nil)
	if s := list["entries"].([]any)[0].(map[string]any)["signature"].(map[string]any); s["cannot_sign"] != true || s["strokes"] != nil {
		t.Fatalf("cannot-sign record: %v", s)
	}
}

func mustJSON(v any) []byte {
	data, _ := json.Marshal(v)
	return data
}

// The two refusals are told apart, and "not on the list" never says which
// field was wrong.
func TestCheckinRefusalsAreDistinctAndSayNoField(t *testing.T) {
	_, c, _ := openConsole(t)
	c.s.live.findLimit = newAddrLimiter(findPerSec, 100, findMaxAddrs) // many tries from one address
	var bodies []string
	for _, d := range []CheckinDetails{
		{LastName: "Halimbawa", FirstName: "Uno", DateOfBirth: "1990-01-02"},  // wrong date
		{LastName: "Halimbawe", FirstName: "Uno", DateOfBirth: "1990-01-01"},  // wrong last name
		{LastName: "Halimbawa", FirstName: "Unos", DateOfBirth: "1990-01-01"}, // wrong first name
		{LastName: "", FirstName: "Uno", DateOfBirth: "1990-01-01"},           // empty
	} {
		code, out := c.do(http.MethodPost, "/api/live/checkin/find", "phone:x", detailsBody(d, false))
		wantCode(t, "find "+d.LastName+"/"+d.FirstName, code, out, http.StatusNotFound, "not-on-list")
		bodies = append(bodies, c.bodies[len(c.bodies)-1])
		code, out = c.do(http.MethodPost, "/api/live/checkin/declare", "phone:x", detailsBody(d, true))
		wantCode(t, "declare "+d.LastName, code, out, http.StatusNotFound, "not-on-list")
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("not-on-list answers differ: %s vs %s", b, bodies[0])
		}
	}
	if !strings.Contains(bodies[0], "No voter with these details is on this precinct") {
		t.Fatalf("not-on-list sentence: %s", bodies[0])
	}
	// Spelling the plan allows: case, spaces, a missing tilde.
	c.ok(http.MethodPost, "/api/live/checkin/find", "phone:x", detailsBody(CheckinDetails{LastName: "  pena ", FirstName: "SINGKO", DateOfBirth: "1994-05-05"}, false))
	// A malformed date is a 400 about the form, not about the list.
	code, out := c.do(http.MethodPost, "/api/live/checkin/find", "phone:x", detailsBody(CheckinDetails{LastName: "Halimbawa", FirstName: "Uno", DateOfBirth: "01/01/1990"}, false))
	wantCode(t, "malformed date", code, out, http.StatusBadRequest, "bad-date")
	// Already checked in.
	c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:voter1", detailsBody(testVoters["voter1"], true))
	code, out = c.do(http.MethodPost, "/api/live/checkin/find", "phone:x", detailsBody(testVoters["voter1"], false))
	wantCode(t, "find a checked-in voter", code, out, http.StatusConflict, "already-checked-in")
	if !strings.Contains(out["error"].(string), "already checked in") {
		t.Fatalf("already-checked-in sentence: %v", out)
	}
	// The declaration must be accepted.
	code, out = c.do(http.MethodPost, "/api/live/checkin/declare", "phone:y", detailsBody(testVoters["voter2"], false))
	wantCode(t, "declare without the declaration", code, out, http.StatusBadRequest, "declaration-required")
	// Unknown fields are refused.
	body := detailsBody(testVoters["voter2"], true)
	body["seq"] = 1
	code, _ = c.do(http.MethodPost, "/api/live/checkin/declare", "phone:y", body)
	if code != http.StatusBadRequest {
		t.Fatalf("declare with an extra field: %d", code)
	}
	noDOB(t, c)
}

// Two phones claim one entry: the first to declare holds it; the second is
// refused at find and at declare, and has no check-in to act on.
func TestCheckinTwoPhonesOneEntry(t *testing.T) {
	_, c, _ := openConsole(t)
	c.ok(http.MethodPost, "/api/live/checkin/find", "phone:a", detailsBody(testVoters["voter1"], false))
	c.ok(http.MethodPost, "/api/live/checkin/find", "phone:b", detailsBody(testVoters["voter1"], false))
	c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:a", detailsBody(testVoters["voter1"], true))
	code, out := c.do(http.MethodPost, "/api/live/checkin/declare", "phone:b", detailsBody(testVoters["voter1"], true))
	wantCode(t, "second phone's declare", code, out, http.StatusConflict, "already-checked-in")
	if c.fx.phones["b"] != "" {
		t.Fatal("the second phone got a cookie")
	}
	code, out = c.do(http.MethodPost, "/api/live/checkin/find", "phone:b", detailsBody(testVoters["voter1"], false))
	wantCode(t, "second phone's find", code, out, http.StatusConflict, "already-checked-in")
	// At every later state too.
	c.ok(http.MethodPost, "/api/live/desk/approve", "admin", map[string]any{"seq": testSeqs["voter1"]})
	code, out = c.do(http.MethodPost, "/api/live/checkin/declare", "phone:b", detailsBody(testVoters["voter1"], true))
	wantCode(t, "declare an approved entry", code, out, http.StatusConflict, "already-checked-in")
	c.ok(http.MethodPost, "/api/live/checkin/sign", "phone:a", map[string]any{"cannot_sign": true})
	c.presignSign("a")
	code, out = c.do(http.MethodPost, "/api/live/checkin/declare", "phone:b", detailsBody(testVoters["voter1"], true))
	wantCode(t, "declare an issued entry", code, out, http.StatusConflict, "already-checked-in")
	// The second phone cannot sign the list or obtain a credential.
	code, out = c.do(http.MethodPost, "/api/live/checkin/sign", "phone:b", map[string]any{"cannot_sign": true})
	wantCode(t, "sign without a check-in", code, out, http.StatusForbidden, "no-checkin")
	code, out = c.do(http.MethodPost, "/api/live/issue/presign", "phone:b", map[string]string{"blinded_commitment": pt(1)})
	wantCode(t, "presign without a check-in", code, out, http.StatusForbidden, "no-checkin")
	// A forged cookie is no check-in.
	c.fx.phones["b"] = strings.Repeat("A", 43)
	code, out = c.do(http.MethodGet, "/api/live/checkin", "phone:b", nil)
	wantCode(t, "poll with a forged cookie", code, out, http.StatusNotFound, "no-checkin")
	// A phone mid-check-in may not start another.
	c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:c", detailsBody(testVoters["voter2"], true))
	code, out = c.do(http.MethodPost, "/api/live/checkin/declare", "phone:c", detailsBody(testVoters["voter3"], true))
	wantCode(t, "a second check-in on one phone", code, out, http.StatusConflict, "checkin-in-progress")
	// A phone whose voter was issued may check another voter in.
	c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:a", detailsBody(testVoters["voter4"], true))
}

func TestCheckinOnlyWhileOpen(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	c.setup() // ceremony
	try := func(state string) {
		t.Helper()
		code, out := c.do(http.MethodPost, "/api/live/checkin/find", "phone:z", detailsBody(testVoters["voter4"], false))
		wantCode(t, "find in "+state, code, out, http.StatusConflict, "not-open")
		code, out = c.do(http.MethodPost, "/api/live/checkin/declare", "phone:z", detailsBody(testVoters["voter4"], true))
		wantCode(t, "declare in "+state, code, out, http.StatusConflict, "not-open")
		code, out = c.do(http.MethodPost, "/api/live/desk/approve", "admin", map[string]any{"seq": testSeqs["voter5"]})
		wantCode(t, "approve in "+state, code, out, http.StatusConflict, "not-open")
		code, out = c.do(http.MethodPost, "/api/live/checkin/sign", "phone:voter5", map[string]any{"cannot_sign": true})
		wantCode(t, "sign in "+state, code, out, http.StatusConflict, "not-open")
	}
	try(LiveCeremony)
	c.ceremony(c.s.live.snapshot().ElectionID)
	c.issue("voter1")
	c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:voter5", detailsBody(testVoters["voter5"], true))
	c.ok(http.MethodPost, "/api/live/close", "admin", nil)
	try(LiveClosed)
	// The poll still answers, and the desk may still clear an entry.
	if out := c.ok(http.MethodGet, "/api/live/checkin", "phone:voter1", nil); out["state"] != CheckinIssued || out["election_state"] != LiveClosed {
		t.Fatalf("poll after close: %v", out)
	}
	c.ok(http.MethodPost, "/api/live/desk/refuse", "admin", map[string]any{"seq": testSeqs["voter5"]})
}

// Refuse and reset: the entry goes back, the phone's cookie is dead and its
// poll says which, the real voter can check in, and nothing resets after
// issuance.
func TestCheckinRefuseAndReset(t *testing.T) {
	fx, c, runID := openConsole(t)
	c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:impostor", detailsBody(testVoters["voter1"], true))
	code, out := c.do(http.MethodPost, "/api/live/desk/reset", "admin", map[string]any{"seq": testSeqs["voter2"]})
	wantCode(t, "reset of an entry not checked in", code, out, http.StatusConflict, "wrong-state")
	code, out = c.do(http.MethodPost, "/api/live/desk/refuse", "admin", map[string]any{"seq": 99})
	wantCode(t, "refuse of no entry", code, out, http.StatusNotFound, "no-such-entry")
	out = c.ok(http.MethodPost, "/api/live/desk/refuse", "admin", map[string]any{"seq": testSeqs["voter1"]})
	if out["status"] != CheckinNotCheckedIn {
		t.Fatalf("refuse: %v", out)
	}
	if out := c.ok(http.MethodGet, "/api/live/checkin", "phone:impostor", nil); out["state"] != checkinRefused || out["entry"] != nil {
		t.Fatalf("impostor's poll after refuse: %v", out)
	}
	code, out = c.do(http.MethodPost, "/api/live/checkin/sign", "phone:impostor", map[string]any{"cannot_sign": true})
	wantCode(t, "sign after refuse", code, out, http.StatusForbidden, "no-checkin")
	// The real voter checks in on their own phone and is issued.
	c.issue("voter1")

	// Reset of an approved, then of a signed entry with an open session.
	c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:voter2", detailsBody(testVoters["voter2"], true))
	c.ok(http.MethodPost, "/api/live/desk/approve", "admin", map[string]any{"seq": testSeqs["voter2"]})
	c.ok(http.MethodPost, "/api/live/desk/reset", "admin", map[string]any{"seq": testSeqs["voter2"]})
	if out := c.ok(http.MethodGet, "/api/live/checkin", "phone:voter2", nil); out["state"] != checkinReset {
		t.Fatalf("poll after reset: %v", out)
	}
	delete(fx.phones, "voter2")
	c.checkIn("voter2")
	c.ok(http.MethodPost, "/api/live/issue/presign", "phone:voter2", map[string]string{"blinded_commitment": pt(0x20)})
	session := sessionPath(filepath.Join(fx.runs, runID), entrySessionKey(testSeqs["voter2"]))
	if _, err := os.Stat(session); err != nil {
		t.Fatal("no session file after presign")
	}
	c.ok(http.MethodPost, "/api/live/desk/reset", "admin", map[string]any{"seq": testSeqs["voter2"]})
	if _, err := os.Stat(session); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reset left the entry's issuance session")
	}
	code, out = c.do(http.MethodPost, "/api/live/issue/sign", "phone:voter2", map[string]string{"e_prime": pt(0x21)})
	wantCode(t, "sign after reset", code, out, http.StatusForbidden, "no-checkin")
	list := c.ok(http.MethodGet, "/api/live/voter-list", "admin", nil)
	if e := list["entries"].([]any)[testSeqs["voter2"]-1].(map[string]any); e["status"] != CheckinNotCheckedIn || e["signature"] != nil {
		t.Fatalf("entry after reset: %v", e)
	}
	// After issuance: no reset, no refuse.
	for _, action := range []string{"reset", "refuse"} {
		code, out = c.do(http.MethodPost, "/api/live/desk/"+action, "admin", map[string]any{"seq": testSeqs["voter1"]})
		wantCode(t, action+" after issuance", code, out, http.StatusConflict, "already-issued")
	}
}

// Issuance needs a signed check-in: no cookie, at the desk, approved, and an
// account of any role are all refused; a second issuance is refused.
func TestIssuanceNeedsASignedCheckin(t *testing.T) {
	_, c, _ := openConsole(t)
	presign := func(who string) (int, map[string]any) {
		return c.do(http.MethodPost, "/api/live/issue/presign", who, map[string]string{"blinded_commitment": pt(1)})
	}
	for _, who := range []string{"", "voter1", "admin", "t1", "phone:voter1"} {
		code, out := presign(who)
		wantCode(t, "presign as "+who, code, out, http.StatusForbidden, "no-checkin")
		code, out = c.do(http.MethodPost, "/api/live/issue/sign", who, map[string]string{"e_prime": pt(1)})
		wantCode(t, "sign as "+who, code, out, http.StatusForbidden, "no-checkin")
	}
	c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:voter1", detailsBody(testVoters["voter1"], true))
	code, out := presign("phone:voter1")
	wantCode(t, "presign at the desk", code, out, http.StatusConflict, "not-signed")
	c.ok(http.MethodPost, "/api/live/desk/approve", "admin", map[string]any{"seq": testSeqs["voter1"]})
	code, out = presign("phone:voter1")
	wantCode(t, "presign approved, not signed", code, out, http.StatusConflict, "not-signed")
	c.ok(http.MethodPost, "/api/live/checkin/sign", "phone:voter1", map[string]any{"strokes": [][][]int{{{1, 1}}}})
	c.presignSign("voter1")
	code, out = presign("phone:voter1")
	wantCode(t, "second presign", code, out, http.StatusConflict, "already-issued")
	code, out = c.do(http.MethodPost, "/api/live/issue/sign", "phone:voter1", map[string]string{"e_prime": pt(1)})
	wantCode(t, "second sign", code, out, http.StatusConflict, "already-issued")
	if n := len(c.fx.ops.signed); n != 1 {
		t.Fatalf("%d signatures made, want 1", n)
	}
}

// A restart in every check-in state keeps the state and the phone's cookie,
// and the next step works.
func TestCheckinRestartInEveryState(t *testing.T) {
	steps := []struct {
		state string
		next  func(c *liveConsole)
	}{
		{CheckinNotCheckedIn, func(c *liveConsole) {
			c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:voter1", detailsBody(testVoters["voter1"], true))
		}},
		{CheckinAtDesk, func(c *liveConsole) {
			c.ok(http.MethodPost, "/api/live/desk/approve", "admin", map[string]any{"seq": testSeqs["voter1"]})
		}},
		{CheckinApproved, func(c *liveConsole) {
			c.ok(http.MethodPost, "/api/live/checkin/sign", "phone:voter1", map[string]any{"strokes": [][][]int{{{3, 4}, {5, 6}}}})
		}},
		{CheckinSigned, func(c *liveConsole) { c.presignSign("voter1") }},
		{CheckinIssued, nil},
	}
	fx, c, _ := openConsole(t)
	for _, st := range steps {
		c = fx.console() // restart
		list := c.ok(http.MethodGet, "/api/live/voter-list", "admin", nil)
		if got := list["entries"].([]any)[testSeqs["voter1"]-1].(map[string]any)["status"]; got != st.state {
			t.Fatalf("after restart: %v, want %s", got, st.state)
		}
		if st.state != CheckinNotCheckedIn {
			if out := c.ok(http.MethodGet, "/api/live/checkin", "phone:voter1", nil); out["state"] != st.state {
				t.Fatalf("poll after restart in %s: %v", st.state, out)
			}
		}
		if st.next != nil {
			st.next(c)
		}
	}
	el := c.ok(http.MethodGet, "/api/live/election", "", nil)
	if el["counts"].(map[string]any)["credentials_issued"] != 1.0 || el["counts"].(map[string]any)["checked_in"] != 1.0 {
		t.Fatalf("counts after the restarts: %v", el["counts"])
	}
	// Ended cookies stay ended across a restart.
	c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:voter2", detailsBody(testVoters["voter2"], true))
	c.ok(http.MethodPost, "/api/live/desk/refuse", "admin", map[string]any{"seq": testSeqs["voter2"]})
	c = fx.console()
	if out := c.ok(http.MethodGet, "/api/live/checkin", "phone:voter2", nil); out["state"] != checkinRefused {
		t.Fatalf("refused cookie after restart: %v", out)
	}
}

// A cookie is bound to its election: the next election knows it not.
func TestCheckinCookieIsBoundToItsElection(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	c.toState(LiveVerified) // voter1 issued in the first election
	old := fx.phones["voter1"]
	c.setup()
	c.ceremony(c.s.live.snapshot().ElectionID)
	code, out := c.do(http.MethodGet, "/api/live/checkin", "phone:voter1", nil)
	wantCode(t, "old cookie in a new election", code, out, http.StatusNotFound, "no-checkin")
	c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:voter1", detailsBody(testVoters["voter1"], true))
	if fx.phones["voter1"] == old {
		t.Fatal("a new check-in reused the old token")
	}
}

func TestCheckinSignatureCaps(t *testing.T) {
	_, c, _ := openConsole(t)
	c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:voter1", detailsBody(testVoters["voter1"], true))
	c.ok(http.MethodPost, "/api/live/desk/approve", "admin", map[string]any{"seq": testSeqs["voter1"]})
	stroke := func(n int) [][]int {
		s := make([][]int, n)
		for i := range s {
			s[i] = []int{i % 1000, i % 400}
		}
		return s
	}
	many := func(strokes, each int) [][][]int {
		out := make([][][]int, strokes)
		for i := range out {
			out[i] = stroke(each)
		}
		return out
	}
	for name, body := range map[string]any{
		"no strokes":       map[string]any{"strokes": [][][]int{}},
		"empty body":       map[string]any{},
		"both":             map[string]any{"strokes": many(1, 2), "cannot_sign": true},
		"empty stroke":     map[string]any{"strokes": [][][]int{{}}},
		"too many strokes": map[string]any{"strokes": many(sigMaxStrokes+1, 1)},
		"long stroke":      map[string]any{"strokes": many(1, sigMaxStrokePoints+1)},
		"too many points":  map[string]any{"strokes": many(5, sigMaxPoints/5+1)},
		"x out of range":   map[string]any{"strokes": [][][]int{{{1001, 0}}}},
		"y out of range":   map[string]any{"strokes": [][][]int{{{0, 401}}}},
		"negative":         map[string]any{"strokes": [][][]int{{{-1, 0}}}},
		"three numbers":    map[string]any{"strokes": [][][]int{{{1, 2, 3}}}},
		"one number":       map[string]any{"strokes": [][][]int{{{1}}}},
		"fraction":         []byte(`{"strokes":[[[1.5,2]]]}`),
		"markup":           []byte(`{"strokes":[[["<svg>",2]]]}`),
		"an image instead": []byte(`{"image":"data:image/png;base64,AAAA"}`),
	} {
		code, out := c.do(http.MethodPost, "/api/live/checkin/sign", "phone:voter1", body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	// Over the byte cap: 413, before any parsing.
	big := []byte(`{"strokes":[[` + strings.Repeat("[1000,400],", sigMaxBody/11) + `[1,1]]]}`)
	if code, _ := c.do(http.MethodPost, "/api/live/checkin/sign", "phone:voter1", big); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("signature over the byte cap: %d", code)
	}
	// Nothing was recorded; the largest allowed signature is.
	if out := c.ok(http.MethodGet, "/api/live/checkin", "phone:voter1", nil); out["state"] != CheckinApproved {
		t.Fatalf("after refused signatures: %v", out)
	}
	c.ok(http.MethodPost, "/api/live/checkin/sign", "phone:voter1", map[string]any{"strokes": many(4, sigMaxPoints/4)})
}

func TestCheckinFindIsRateLimitedPerAddress(t *testing.T) {
	_, c, _ := openConsole(t)
	now := time.Now()
	c.s.live.findLimit.now = func() time.Time { return now }
	wrong := detailsBody(CheckinDetails{LastName: "Wala", FirstName: "Wala", DateOfBirth: "2000-01-01"}, false)
	c.addr = "198.51.100.1:4000"
	// Three honest phones behind one address, each with typos, fit the burst.
	for i := 0; i < findBurst; i++ {
		code, out := c.do(http.MethodPost, "/api/live/checkin/find", "phone:x", wrong)
		wantCode(t, "find within the burst", code, out, http.StatusNotFound, "not-on-list")
	}
	code, out := c.do(http.MethodPost, "/api/live/checkin/find", "phone:x", detailsBody(testVoters["voter1"], false))
	wantCode(t, "find over the burst", code, out, http.StatusTooManyRequests, "rate-limited")
	code, out = c.do(http.MethodPost, "/api/live/checkin/declare", "phone:x", detailsBody(testVoters["voter1"], true))
	wantCode(t, "declare over the burst", code, out, http.StatusTooManyRequests, "rate-limited")
	// Another address is not affected.
	c.addr = "198.51.100.2:4000"
	c.ok(http.MethodPost, "/api/live/checkin/find", "phone:y", detailsBody(testVoters["voter1"], false))
	// The first address gets a try back after 10 seconds, not before.
	c.addr = "198.51.100.1:4000"
	now = now.Add(9 * time.Second)
	code, out = c.do(http.MethodPost, "/api/live/checkin/find", "phone:x", detailsBody(testVoters["voter1"], false))
	wantCode(t, "find before the refill", code, out, http.StatusTooManyRequests, "rate-limited")
	now = now.Add(time.Second)
	c.ok(http.MethodPost, "/api/live/checkin/find", "phone:x", detailsBody(testVoters["voter1"], false))
	code, _ = c.do(http.MethodPost, "/api/live/checkin/find", "phone:x", detailsBody(testVoters["voter1"], false))
	if code != http.StatusTooManyRequests {
		t.Fatalf("second try after one refill: %d", code)
	}
}

func TestAddrLimiterFloodFailsClosed(t *testing.T) {
	l := newAddrLimiter(findPerSec, 2, 3)
	for _, a := range []string{"a", "b", "c"} {
		l.allow(a)
	}
	if ok, _ := l.allow("d"); ok {
		t.Fatal("a fourth address was let in while three buckets are in use")
	}
	now := time.Now().Add(time.Hour)
	l.now = func() time.Time { return now }
	if ok, _ := l.allow("d"); !ok {
		t.Fatal("refilled buckets were not dropped for a new address")
	}
}

// Nothing about check-in, no name and no date of birth reaches the log.
func TestCheckinLogsNothingAboutVoters(t *testing.T) {
	logs := captureLog(t)
	_, c, _ := openConsole(t)
	c.issue("voter1")
	c.do(http.MethodPost, "/api/live/checkin/find", "phone:x", detailsBody(CheckinDetails{LastName: "Wala", FirstName: "Wala", DateOfBirth: "1999-09-09"}, false))
	c.ok(http.MethodPost, "/api/live/checkin/declare", "phone:voter2", detailsBody(testVoters["voter2"], true))
	c.ok(http.MethodPost, "/api/live/desk/refuse", "admin", map[string]any{"seq": testSeqs["voter2"]})
	for _, needle := range []string{"Halimbawa", "Uno", "Dos", "Wala", "1990-01-01", "1991-02-02", "1999-09-09", "192.0.2.7", c.fx.phones["voter1"]} {
		if strings.Contains(logs.String(), needle) {
			t.Fatalf("the log carries %q:\n%s", needle, logs.String())
		}
	}
}

func TestLivePrecinctOption(t *testing.T) {
	fx := newLiveFixture(t)
	store := NewRunStore(fx.runs)
	hub := NewHub()
	s := NewServer(store, NewExecutor(store, hub, "saksi-demo", "", FabricConfig{}), hub, FabricConfig{}, nil, time.Minute)
	if err := s.EnableAuth(fx.users); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableLive(LiveOptions{TrusteeTokens: fx.tokFile, Runner: fx.ops.run, Precinct: "12A"}); err == nil {
		t.Fatal("a malformed precinct was accepted")
	}
	if err := s.EnableLive(LiveOptions{TrusteeTokens: fx.tokFile, Runner: fx.ops.run, Precinct: "0420B",
		Dial: func() (liveChain, error) { return fx.chain, nil }}); err != nil {
		t.Fatal(err)
	}
	c := &liveConsole{t: t, s: s, fx: fx, sessions: map[string]string{}}
	out := c.ok(http.MethodPost, "/api/live/voter-list/preview", "admin", map[string]any{"csv": testVoterList})
	if out["precinct"] != "0420B" || out["precinct_label"] != "Precinct 0420B (demonstration)" {
		t.Fatalf("preview precinct: %v", out)
	}
	fp := out["fingerprint"].(string)
	if fp == parseVoterList(testVoterList, DefaultLivePrecinct, time.Now()).Fingerprint {
		t.Fatal("the precinct is not in the fingerprint")
	}
	// The setup confirms against this precinct's fingerprint.
	body := map[string]any{"title": "x", "positions": livePositions, "trustees": 3, "threshold": 2,
		"voter_list": testVoterList, "voter_list_fingerprint": fp}
	el := c.ok(http.MethodPost, "/api/live/elections", "admin", body)
	if el["precinct"] != "0420B" || el["voter_list_fingerprint"] != fp {
		t.Fatalf("election: %v", el)
	}
}

// A restart between presign and sign: the session and the check-in are on
// disk, and the sign after the restart issues the one credential.
func TestIssuanceSurvivesARestartBetweenPresignAndSign(t *testing.T) {
	fx, c, _ := openConsole(t)
	c.checkIn("voter1")
	c.ok(http.MethodPost, "/api/live/issue/presign", "phone:voter1", map[string]string{"blinded_commitment": pt(0x10)})
	c2 := fx.console()
	if out := c2.ok(http.MethodGet, "/api/live/checkin", "phone:voter1", nil); out["state"] != CheckinSigned {
		t.Fatalf("after restart: %v", out)
	}
	c2.ok(http.MethodPost, "/api/live/issue/sign", "phone:voter1", map[string]string{"e_prime": pt(0x11)})
	if out := c2.ok(http.MethodGet, "/api/live/checkin", "phone:voter1", nil); out["state"] != CheckinIssued {
		t.Fatalf("after sign: %v", out)
	}
	if len(fx.ops.signed) != 1 || !strings.Contains(fx.ops.signed[0], "nonce-1") {
		t.Fatalf("signed with %v, want the session made before the restart", fx.ops.signed)
	}
	code, out := c2.do(http.MethodPost, "/api/live/issue/sign", "phone:voter1", map[string]string{"e_prime": pt(0x11)})
	wantCode(t, "sign again", code, out, http.StatusConflict, "already-issued")
}

// Two phones declare one entry at the same moment: exactly one holds it.
func TestCheckinConcurrentDeclareOneWins(t *testing.T) {
	_, c, _ := openConsole(t)
	body := mustJSON(detailsBody(testVoters["voter1"], true))
	const n = 2
	codes := make([]int, n)
	cookies := make([]int, n)
	start := make(chan struct{})
	done := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			req := httptest.NewRequest(http.MethodPost, "/api/live/checkin/declare", bytes.NewReader(body))
			req.RemoteAddr = "198.51.100." + string(rune('1'+i)) + ":4000"
			rec := httptest.NewRecorder()
			<-start
			c.s.ServeHTTP(rec, req)
			codes[i] = rec.Code
			for _, k := range rec.Result().Cookies() {
				if k.Name == checkinCookie {
					cookies[i]++
				}
			}
		}()
	}
	close(start)
	for i := 0; i < n; i++ {
		<-done
	}
	ok, conflict := 0, 0
	for i := 0; i < n; i++ {
		switch {
		case codes[i] == http.StatusOK && cookies[i] == 1:
			ok++
		case codes[i] == http.StatusConflict && cookies[i] == 0:
			conflict++
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("concurrent declares: codes %v, cookies %v", codes, cookies)
	}
	list := c.ok(http.MethodGet, "/api/live/voter-list", "admin", nil)
	if n := list["counts"].(map[string]any)["at_desk"]; n != 1.0 {
		t.Fatalf("at_desk %v, want 1", n)
	}
}

// If live.json cannot be written after the list was, the new run folder (and
// the list in it) is removed, and the console keeps no half-made election.
func TestLiveSetupRemovesTheRunFolderWhenLiveJSONFails(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	fx.ops.onKeygen = func(keyFile string) {
		// live.json as a folder: its atomic rename fails after the list is written.
		_ = os.Mkdir(filepath.Join(filepath.Dir(filepath.Dir(keyFile)), liveStateFile), 0o755)
	}
	body := listBody(map[string]any{"title": "x", "positions": livePositions, "trustees": 3, "threshold": 2})
	code, out := c.do(http.MethodPost, "/api/live/elections", "admin", body)
	if code != http.StatusInternalServerError {
		t.Fatalf("setup with live.json unwritable: %d %v", code, out)
	}
	if entries, _ := os.ReadDir(fx.runs); len(entries) != 0 {
		t.Fatalf("the failed setup left %d run folder(s)", len(entries))
	}
	if c.s.live.snapshot() != nil || c.state() != "" {
		t.Fatal("the failed setup left an election in the console")
	}
	fx.ops.onKeygen = nil
	c.setup()
	if c.state() != LiveCeremony {
		t.Fatalf("setup after the failure: %s", c.state())
	}
}

// The same failure with an earlier election in the console (verified, or
// abandoned): that election stays the console's, its snapshot, folder,
// live.json and voter list unchanged, and only the new folder is removed.
func TestLiveSetupFailureKeepsTheEarlierElection(t *testing.T) {
	for _, earlier := range []string{LiveVerified, LiveAbandoned} {
		t.Run(earlier, func(t *testing.T) {
			fx := newLiveFixture(t)
			c := fx.console()
			var runID string
			if earlier == LiveAbandoned {
				runID = c.setup()
				c.ok(http.MethodPost, "/api/live/abandon", "admin", nil)
			} else {
				runID = c.toState(LiveVerified)
			}
			before := *c.s.live.snapshot()
			dirBefore := c.s.live.dir
			stateBefore, _ := os.ReadFile(filepath.Join(dirBefore, liveStateFile))
			listBefore := c.ok(http.MethodGet, "/api/live/voter-list", "admin", nil)
			viewBefore := c.ok(http.MethodGet, "/api/live/election", "", nil)

			fx.ops.onKeygen = func(keyFile string) {
				_ = os.Mkdir(filepath.Join(filepath.Dir(filepath.Dir(keyFile)), liveStateFile), 0o755)
			}
			body := listBody(map[string]any{"title": "x", "positions": livePositions, "trustees": 3, "threshold": 2})
			if code, out := c.do(http.MethodPost, "/api/live/elections", "admin", body); code != http.StatusInternalServerError {
				t.Fatalf("setup with live.json unwritable: %d %v", code, out)
			}
			after := c.s.live.snapshot()
			if after == nil || after.RunID != runID || after.State != earlier || after.Dir != before.Dir ||
				!after.UpdatedAt.Equal(before.UpdatedAt) || after.Issued != before.Issued || c.s.live.dir != dirBefore ||
				c.state() != earlier || c.s.live.st.RunID != runID {
				t.Fatalf("the earlier election changed: %+v (was %+v)", after, before)
			}
			if stateAfter, _ := os.ReadFile(filepath.Join(dirBefore, liveStateFile)); !bytes.Equal(stateAfter, stateBefore) {
				t.Fatal("the earlier election's live.json changed")
			}
			entries, _ := os.ReadDir(fx.runs)
			if len(entries) != 1 || entries[0].Name() != runID {
				t.Fatalf("run folders after the failure: %v, want only %s", entries, runID)
			}
			listAfter := c.ok(http.MethodGet, "/api/live/voter-list", "admin", nil)
			viewAfter := c.ok(http.MethodGet, "/api/live/election", "", nil)
			if a, b := mustJSON(listAfter), mustJSON(listBefore); !bytes.Equal(a, b) {
				t.Fatalf("voter list changed:\n%s\nwas\n%s", a, b)
			}
			if viewAfter["run_id"] != runID || viewAfter["state"] != earlier || viewAfter["updated_at"] != viewBefore["updated_at"] {
				t.Fatalf("election view changed: %v", viewAfter)
			}
			// A restart still loads the earlier election, and the next setup works.
			if c2 := fx.console(); c2.state() != earlier || c2.s.live.st.RunID != runID {
				t.Fatalf("restart after the failure: %s %s", c2.state(), c2.s.live.st.RunID)
			}
			fx.ops.onKeygen = nil
			if next := c.setup(); next == runID || c.state() != LiveCeremony {
				t.Fatalf("setup after the failure: %s %s", next, c.state())
			}
		})
	}
}
