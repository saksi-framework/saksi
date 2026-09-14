package campaign

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	"golang.org/x/crypto/bcrypt"
)

// fixtureHashes maps each fixture password to a precomputed cost-12 hash: the
// users file accepts only cost 12, and generating those takes seconds under
// -race. The login tests fail if a hash stops matching its password.
func fixtureHashes() map[string]string {
	return map[string]string{
		"admin-pw": "$2a$12$uZB8nfhHls0y5nuOU9MCQOgGIT11PZQQZOMIoSGEeXp/djLna9gnm",
		"t1-pw":    "$2a$12$ky1Xf/1W8PnDgsrwppIhC.vci4svtER878hjE4LAjumTHwq19i7rS",
		"t2-pw":    "$2a$12$bMQW4I6jg1z7RSfM/UA8B.xGwOXT38iKyURf21hz0kkPqiMAVruQ6",
	}
}

// burst sends n identical logins at once.
func burst(h http.Handler, n int, remote, username, password string) []*httptest.ResponseRecorder {
	recs := make([]*httptest.ResponseRecorder, n)
	var wg sync.WaitGroup
	for i := range recs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recs[i] = login(h, remote, username, password)
		}()
	}
	wg.Wait()
	return recs
}

// authServer is a console with auth on (through EnableAuth and a real users
// file) and all three static apps mounted, so every route in the table exists.
// Passwords are "<username>-pw".
func authServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	web := t.TempDir()
	for _, app := range []string{"board", "trustee", "admin"} {
		if err := os.MkdirAll(filepath.Join(web, app), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(web, app), "index.html", "<title>"+app+"</title>")
	}
	t.Setenv("SAKSI_WEB_DIR", web)
	s, h, _ := testServer(t, nil)
	s.dial = func() (chainReader, clientsdk.Ledger, error) { return nil, nil, errors.New("offline") }

	users := []User{
		{Username: "admin", Role: RoleAdmin, PasswordBcrypt: fixtureHashes()["admin-pw"]},
		{Username: "t1", Role: RoleTrustee, TrusteeID: "1", PasswordBcrypt: fixtureHashes()["t1-pw"]},
		{Username: "t2", Role: RoleTrustee, TrusteeID: "2", PasswordBcrypt: fixtureHashes()["t2-pw"]},
	}
	data, _ := json.Marshal(users)
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableAuth(path); err != nil {
		t.Fatalf("EnableAuth: %v", err)
	}
	return s, h
}

// signIn attaches a fresh session for username to req ("" = anonymous).
func signIn(t *testing.T, s *Server, username string, req *http.Request) *http.Request {
	t.Helper()
	if username == "" {
		return req
	}
	tok, err := s.auth.create(s.auth.users[username])
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	return req
}

func login(h http.Handler, remote, username, password string) *httptest.ResponseRecorder {
	req := postJSON("/api/login", map[string]string{"username": username, "password": password})
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func sessionCookieOf(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatalf("no %s cookie in %v", sessionCookie, rec.Header()["Set-Cookie"])
	return nil
}

// Every row of the plan's route-role table: allowed, 401 or 403 for an
// anonymous caller, a trustee, and an admin. 0 means "allowed": the auth layer
// let the request through to its handler, whatever that handler then answered.
// Bodies are empty, so no allowed POST ever gets far enough to start a phase.
func TestRouteRolesWhenAuthOn(t *testing.T) {
	s, h := authServer(t)
	const get, post = http.MethodGet, http.MethodPost
	type probe struct{ method, path string }
	rows := []struct {
		name                 string
		anon, trustee, admin int
		probes               []probe
	}{
		{"public", 0, 0, 0, []probe{
			{get, "/api/board/r1"}, {get, "/api/verify-code/r1/BC-CAFE-0001"}, {get, "/trail/r1"},
			{get, "/api/trail"}, {get, "/api/trail/r1"}, {get, "/api/capabilities"},
			{get, "/api/ceremony/r1"}, {get, "/runs"}, {get, "/board/"}, {get, "/trustee/"},
			{get, "/admin/"}, {get, "/admin"}, {post, "/api/login"}, {post, "/api/logout"},
			{get, "/wizard"},
		}},
		{"trustee or admin", 401, 0, 0, []probe{{post, "/ceremony/publish"}, {get, "/events"}}},
		{"trustee, own shares", 401, 0, 403, []probe{{post, "/ceremony/submit"}}},
		{"admin", 401, 403, 0, []probe{
			{post, "/generate"}, {post, "/submit"}, {post, "/verify"}, {post, "/run-all"},
			{post, "/cancel"}, {post, "/scenarios"}, {post, "/attack"}, {post, "/ceremony/start"},
			{post, "/api/runs/r1/resume"}, {get, "/api/runs/r1/status"}, {get, "/api/check/r1"},
			{get, "/api/scenarios/r1"}, {get, "/export/r1/run.json"}, {get, "/api/preflight"}, {get, "/"},
			{get, "/no-such-page"},
		}},
	}
	for _, row := range rows {
		for _, p := range row.probes {
			for _, who := range []struct {
				user string
				want int
			}{{"", row.anon}, {"t1", row.trustee}, {"admin", row.admin}} {
				t.Run(row.name+" "+p.method+" "+p.path+" as "+who.user, func(t *testing.T) {
					rec := httptest.NewRecorder()
					h.ServeHTTP(rec, signIn(t, s, who.user, httptest.NewRequest(p.method, p.path, nil)))
					switch who.want {
					case 0:
						if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
							t.Fatalf("want allowed, got %d %s", rec.Code, rec.Body)
						}
					case http.StatusUnauthorized:
						if rec.Code != who.want || strings.TrimSpace(rec.Body.String()) != `{"error":"login required"}` {
							t.Fatalf("want 401 login required, got %d %s", rec.Code, rec.Body)
						}
					case http.StatusForbidden:
						var body map[string]string
						if rec.Code != who.want || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body["error"] == "" {
							t.Fatalf("want 403 with a JSON reason, got %d %s", rec.Code, rec.Body)
						}
					}
				})
			}
		}
	}
}

// A route added to NewServer without a role would fail closed (admin-only),
// but it should be a decision, not an accident: every registered pattern must
// be in the table, and the table must not name routes that no longer exist.
func TestRouteAccessCoversEveryRoute(t *testing.T) {
	s, _ := authServer(t)
	if len(s.routes) < len(routeAccess) {
		t.Fatalf("only %d routes recorded; is the web dir mounted?", len(s.routes))
	}
	registered := make(map[string]bool, len(s.routes))
	for _, p := range s.routes {
		registered[p] = true
		if _, ok := routeAccess[p]; !ok {
			t.Errorf("route %q is registered in NewServer but has no entry in routeAccess", p)
		}
	}
	for p := range routeAccess {
		if !registered[p] {
			t.Errorf("routeAccess names %q, which NewServer does not register", p)
		}
	}
}

// Off by default: no users file, no login, every route open, and the auth
// routes are as absent as they were before they existed.
func TestAuthOffLeavesEveryRouteOpen(t *testing.T) {
	_, h, _ := testServer(t, nil)
	for path, want := range map[string]int{"/wizard": 200, "/": 200, "/api/me": 404} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("GET %s with auth off: want %d, got %d", path, want, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, postJSON("/api/login", map[string]string{"username": "a", "password": "b"}))
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST /api/login with auth off: want 404, got %d", rec.Code)
	}
}

func TestLoginSetsSessionCookieAndMe(t *testing.T) {
	_, h := authServer(t)
	rec := login(h, "192.0.2.1:1000", "t1", "t1-pw")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("login want 204, got %d %s", rec.Code, rec.Body)
	}
	c := sessionCookieOf(t, rec)
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.MaxAge != 43200 || c.Secure {
		t.Fatalf("cookie flags wrong: %+v", c)
	}
	if len(c.Value) != 43 { // base64url, no padding, of 32 bytes
		t.Fatalf("token %d chars, want 43", len(c.Value))
	}
	raw := rec.Header().Get("Set-Cookie")
	for _, want := range []string{"HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=43200"} {
		if !strings.Contains(raw, want) {
			t.Errorf("Set-Cookie %q lacks %s", raw, want)
		}
	}

	me := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	me.AddCookie(c)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, me)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"username":"t1","role":"trustee","trustee_id":"1"}` {
		t.Fatalf("/api/me: %d %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/me", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/api/me without a session: want 401, got %d", rec.Code)
	}
}

func TestLoginCookieIsSecureOverTLS(t *testing.T) {
	_, h := authServer(t)
	req := httptest.NewRequest(http.MethodPost, "https://console.example/api/login",
		strings.NewReader(`{"username":"admin","password":"admin-pw"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("login want 204, got %d %s", rec.Code, rec.Body)
	}
	if c := sessionCookieOf(t, rec); !c.Secure {
		t.Fatalf("cookie over TLS must be Secure: %+v", c)
	}
}

// Unknown user and wrong password are indistinguishable in the response.
func TestLoginFailuresLookTheSame(t *testing.T) {
	_, h := authServer(t)
	wrong := login(h, "192.0.2.2:1000", "admin", "nope")
	unknown := login(h, "192.0.2.2:1000", "mallory", "nope")
	for name, rec := range map[string]*httptest.ResponseRecorder{"wrong password": wrong, "unknown user": unknown} {
		if rec.Code != http.StatusUnauthorized || strings.TrimSpace(rec.Body.String()) != `{"error":"invalid credentials"}` {
			t.Errorf("%s: got %d %s", name, rec.Code, rec.Body)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s set a cookie", name)
		}
	}
	// An unknown user still pays a real bcrypt compare: the dummy hash must be a
	// well-formed cost-12 hash, or CompareHashAndPassword returns instantly.
	if cost, err := bcrypt.Cost(dummyHash); err != nil || cost != hashPasswordCost {
		t.Fatalf("dummy hash cost %d, err %v", cost, err)
	}
}

func TestLoginLocksOutAfterFiveFailures(t *testing.T) {
	s, h := authServer(t)
	now := time.Now()
	s.auth.now = func() time.Time { return now }
	const ip = "192.0.2.3:1000"

	// Eight guesses at once: exactly five are checked, the rest refused, so
	// concurrency cannot overrun the limit while bcrypt runs.
	codes := map[int]int{}
	for _, rec := range burst(h, 8, ip, "admin", "wrong") {
		codes[rec.Code]++
	}
	if codes[http.StatusUnauthorized] != 5 || codes[http.StatusTooManyRequests] != 3 {
		t.Fatalf("8 concurrent guesses: want 5x401 and 3x429, got %v", codes)
	}
	rec := login(h, ip, "admin", "admin-pw")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "30" {
		t.Fatalf("correct password while locked: want 429 Retry-After 30, got %d %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if rec := login(h, "198.51.100.9:1000", "admin", "admin-pw"); rec.Code != http.StatusNoContent {
		t.Fatalf("another address must not be locked out, got %d", rec.Code)
	}
	now = now.Add(31 * time.Second)
	if rec := login(h, ip, "admin", "admin-pw"); rec.Code != http.StatusNoContent {
		t.Fatalf("after the 30 s lockout: want 204, got %d %s", rec.Code, rec.Body)
	}
}

// Everyone on loopback shares one address, so a lockout keyed by address alone
// let one trustee's typos lock the admin out.
func TestLoginLockoutIsPerUsername(t *testing.T) {
	_, h := authServer(t)
	const ip = "127.0.0.1:1000"
	burst(h, 5, ip, "t2", "typo")
	if rec := login(h, ip, "admin", "admin-pw"); rec.Code != http.StatusNoContent {
		t.Fatalf("t2's typos must not lock admin out: got %d %s", rec.Code, rec.Body)
	}
	if rec := login(h, ip, "t2", "t2-pw"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("t2 itself should be locked: got %d", rec.Code)
	}
}

// The lockout is keyed on the submitted name and never on whether it exists,
// so neither the 401s nor the 429 tell a real account from an unknown one.
func TestLoginLockoutTreatsUnknownUsersLikeKnownOnes(t *testing.T) {
	s, h := authServer(t)
	now := time.Now()
	s.auth.now = func() time.Time { return now }
	const ip = "127.0.0.1:2000"
	for _, user := range []string{"admin", "mallory"} {
		for _, rec := range burst(h, 5, ip, user, "wrong") {
			if rec.Code != http.StatusUnauthorized || strings.TrimSpace(rec.Body.String()) != `{"error":"invalid credentials"}` {
				t.Fatalf("%s guess: got %d %s", user, rec.Code, rec.Body)
			}
		}
	}
	known, unknown := login(h, ip, "admin", "admin-pw"), login(h, ip, "mallory", "x")
	if known.Code != http.StatusTooManyRequests || unknown.Code != known.Code ||
		unknown.Body.String() != known.Body.String() ||
		unknown.Header().Get("Retry-After") != known.Header().Get("Retry-After") {
		t.Fatalf("locked known vs unknown differ: %d %q %q vs %d %q %q",
			known.Code, known.Body, known.Header().Get("Retry-After"),
			unknown.Code, unknown.Body, unknown.Header().Get("Retry-After"))
	}
}

// Fifty failures from one address across any usernames lock the address. The
// cap is checked before the per-username record, so it also bounds how many
// records one address can create, and an over-long username counts against the
// address without a record of its own.
func TestLoginPerAddressCapTripsAt50(t *testing.T) {
	s, h := authServer(t)
	const ip = "192.0.2.7"
	// 49 failures across 49 names, settled directly: through HTTP each one
	// would cost a cost-12 bcrypt compare.
	for i := 0; i < 49; i++ {
		user := fmt.Sprintf("user%d", i)
		if _, ok := s.auth.attempt(ip, user); !ok {
			t.Fatalf("attempt %d refused before the cap", i+1)
		}
		s.auth.settle(ip, user, false)
	}
	long := strings.Repeat("x", maxUsernameBytes+1)
	if rec := login(h, ip+":3000", long, "x"); rec.Code != http.StatusUnauthorized ||
		strings.TrimSpace(rec.Body.String()) != `{"error":"invalid credentials"}` {
		t.Fatalf("over-long username: want the usual 401, got %d %s", rec.Code, rec.Body)
	}
	for _, user := range []string{"admin", "someone-new"} {
		if rec := login(h, ip+":3000", user, "admin-pw"); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("%s after 50 failures from the address: want 429, got %d", user, rec.Code)
		}
	}
	if n := len(s.auth.userFails); n != 49 {
		t.Fatalf("want 49 per-username records (none for the long name, none once capped), got %d", n)
	}
	if _, ok := s.auth.attempt("192.0.2.9", "admin"); !ok {
		t.Fatal("another address must not be capped")
	}
}

// A local process can use any loopback address as its source, so every
// loopback alias shares one lockout budget: per username and per address.
func TestLoginLockoutTreatsEveryLoopbackAddressAsOne(t *testing.T) {
	s, h := authServer(t)
	burst(h, 5, "127.0.0.1:1000", "t2", "typo")
	for _, alias := range []string{"127.0.0.2:1000", "[::1]:1000"} {
		if rec := login(h, alias, "t2", "t2-pw"); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("t2 locked from 127.0.0.1, then from %s: want 429, got %d", alias, rec.Code)
		}
	}

	// 5 failures so far on the shared address; 45 more across the aliases (settled
	// directly, keyed exactly as the handler keys them) reach the cap of 50.
	aliases := []string{"127.0.0.1:2000", "127.0.0.2:2000", "[::1]:2000"}
	for i := 0; i < 45; i++ {
		ip := remoteIP(&http.Request{RemoteAddr: aliases[i%len(aliases)]})
		user := fmt.Sprintf("user%d", i)
		if _, ok := s.auth.attempt(ip, user); !ok {
			t.Fatalf("failure %d refused before the cap", i+6)
		}
		s.auth.settle(ip, user, false)
	}
	for _, alias := range aliases {
		if rec := login(h, alias, "admin", "admin-pw"); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("admin from %s after 50 loopback failures: want 429, got %d", alias, rec.Code)
		}
	}
}

// A success clears its own (address, username) record only. The address keeps
// its failures, so a trustee cannot launder guesses at the admin password with
// logins of its own.
func TestLoginSuccessResetsOnlyItsOwnKey(t *testing.T) {
	s, _ := authServer(t)
	a := s.auth
	const ip = "127.0.0.1"
	fail := func(user string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, ok := a.attempt(ip, user); !ok {
				t.Fatalf("%s attempt refused", user)
			}
			a.settle(ip, user, false)
		}
	}
	fail("t1", 4)
	fail("admin", 4)
	if _, ok := a.attempt(ip, "t1"); !ok {
		t.Fatal("t1 refused before its limit")
	}
	a.settle(ip, "t1", true)

	if _, left := a.userFails[failKey{ip, "t1"}]; left {
		t.Fatal("t1's success must reset t1's record")
	}
	if got := a.ipFails[ip].count; got != 8 {
		t.Fatalf("address count %d: the success must hand back only its own reservation (want 8)", got)
	}
	fail("admin", 1)
	if _, ok := a.attempt(ip, "admin"); ok {
		t.Fatal("admin's earlier failures must stand: its fifth locks it")
	}
	fail("t1", 4) // t1 starts fresh: four more do not lock it
}

// With auth on, loopback alone no longer unseals the trail: every tunnel user
// and local process is loopback. Anyone but an admin gets the sealed view.
func TestTrailOperatorViewNeedsAdminWhenAuthOn(t *testing.T) {
	s, h := authServer(t)
	dir, err := s.store.Dir("run-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixtureTrail(t, dir)
	s.dial = func() (chainReader, clientsdk.Ledger, error) {
		return &fakeChainReader{status: "open", nullifiers: 1}, &fakeLedger{}, nil
	}
	for user, wantSealed := range map[string]bool{"": true, "t1": true, "admin": false} {
		req := signIn(t, s, user, httptest.NewRequest(http.MethodGet, "/api/trail/run-1?operator=1", nil))
		req.RemoteAddr = "127.0.0.1:54321"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var resp trailResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &resp) != nil {
			t.Fatalf("as %q: got %d %s", user, rec.Code, rec.Body)
		}
		if resp.Sealed != wantSealed {
			t.Errorf("as %q from loopback with operator=1: sealed=%v, want %v", user, resp.Sealed, wantSealed)
		}
	}
}

// A trustee id that holds no seat in the run must not publish its tally.
func TestPublishRefusesATrusteeOutsideTheElection(t *testing.T) {
	s, h := authServer(t)
	s.auth.users["t9"] = User{Username: "t9", Role: RoleTrustee, TrusteeID: "9"}
	runID, _ := seedRun(t, s, nil) // 3 trustees, threshold 2, nothing submitted
	publish := func(user string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, signIn(t, s, user, postJSON("/ceremony/publish", map[string]string{"run_id": runID})))
		return rec
	}
	if rec := publish("t9"); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("trustee 9 publishing a 3-trustee run: want 403 JSON, got %d %s", rec.Code, rec.Body)
	}
	// Members pass the check and reach the threshold gate (409), not a dispatch.
	for _, user := range []string{"t1", "admin"} {
		if rec := publish(user); rec.Code != http.StatusConflict {
			t.Errorf("%s: want the below-threshold 409, got %d %s", user, rec.Code, rec.Body)
		}
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	_, h := authServer(t)
	c := sessionCookieOf(t, login(h, "192.0.2.5:1000", "admin", "admin-pw"))

	out := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	out.AddCookie(c)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, out)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout want 204, got %d", rec.Code)
	}
	if cleared := sessionCookieOf(t, rec); cleared.MaxAge >= 0 || cleared.Value != "" {
		t.Fatalf("logout must clear the cookie: %+v", cleared)
	}

	for _, path := range []string{"/api/me", "/api/preflight"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(c)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with a logged-out token: want 401, got %d", path, rec.Code)
		}
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	s, h := authServer(t)
	now := time.Now()
	s.auth.now = func() time.Time { return now }
	req := signIn(t, s, "admin", httptest.NewRequest(http.MethodGet, "/api/me", nil))

	now = now.Add(sessionTTL + time.Second)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired session: want 401, got %d", rec.Code)
	}
	if n := len(s.auth.sessions); n != 0 {
		t.Fatalf("expired session not pruned: %d left", n)
	}
}

func TestTrusteeCannotSubmitAnotherTrusteesShares(t *testing.T) {
	s, h := authServer(t)
	submit := func(user, trustee string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, signIn(t, s, user,
			postJSON("/ceremony/submit", map[string]string{"run_id": "r1", "trustee_id": trustee})))
		return rec
	}
	if rec := submit("t1", "2"); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("t1 submitting trustee 2's shares: want 403 JSON, got %d %s", rec.Code, rec.Body)
	}
	if rec := submit("admin", "1"); rec.Code != http.StatusForbidden {
		t.Fatalf("admin submitting trustee 1's shares: want 403, got %d", rec.Code)
	}
	// Own shares pass the ownership check and reach the run lookup; "r1" does
	// not exist, so the handler refuses there instead of starting a phase.
	if rec := submit("t1", "1"); rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Fatalf("t1 submitting its own shares was refused: %d %s", rec.Code, rec.Body)
	}
}

func TestUsersFileValidation(t *testing.T) {
	hash := fixtureHashes()["admin-pw"]
	ok := `[{"username":"a","role":"admin","password_bcrypt":"` + hash + `"},` +
		`{"username":"t","role":"trustee","trustee_id":"1","password_bcrypt":"` + hash + `"},` +
		`{"username":"u","role":"trustee","trustee_id":"10","password_bcrypt":"` + hash + `"}]`
	if users, err := parseUsers([]byte(ok)); err != nil || len(users) != 3 {
		t.Fatalf("valid file rejected: %v", err)
	}
	cheap, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	trustee := func(name, id string) string {
		return `{"username":"` + name + `","role":"trustee","trustee_id":"` + id + `","password_bcrypt":"` + hash + `"}`
	}
	for name, tc := range map[string]struct{ file, wantErr string }{
		"cost other than 12":    {`[{"username":"a","role":"admin","password_bcrypt":"` + string(cheap) + `"}]`, "has cost 4, want 12"},
		"duplicate trustee id":  {`[` + trustee("t", "1") + `,` + trustee("u", "1") + `]`, `trustee_id "1" is already assigned to "t"`},
		"trustee id zero pad":   {`[` + trustee("t", "01") + `]`, "no leading zero"},
		"trustee id zero":       {`[` + trustee("t", "0") + `]`, "no leading zero"},
		"trustee id not digits": {`[` + trustee("t", "1a") + `]`, "digits"},
		"username too long": {`[{"username":"` + strings.Repeat("x", maxUsernameBytes+1) +
			`","role":"admin","password_bcrypt":"` + hash + `"}]`, "longer than 256 bytes"},
		"unknown role":          {`[{"username":"a","role":"root","password_bcrypt":"` + hash + `"}]`, "unknown role"},
		"trustee without id":    {`[{"username":"a","role":"trustee","password_bcrypt":"` + hash + `"}]`, "needs a trustee_id"},
		"admin with trustee id": {`[{"username":"a","role":"admin","trustee_id":"1","password_bcrypt":"` + hash + `"}]`, "must not have a trustee_id"},
		"duplicate username": {`[{"username":"a","role":"admin","password_bcrypt":"` + hash + `"},` +
			`{"username":"a","role":"trustee","trustee_id":"1","password_bcrypt":"` + hash + `"}]`, "duplicate username"},
		"bad hash":       {`[{"username":"a","role":"admin","password_bcrypt":"hunter2"}]`, "not a bcrypt hash"},
		"empty username": {`[{"username":"","role":"admin","password_bcrypt":"` + hash + `"}]`, "username is empty"},
		"no users":       {`[]`, "no users"},
		"not an array":   {`{"username":"a"}`, "JSON array"},
		"unknown field":  {`[{"username":"a","role":"admin","password":"x"}]`, "JSON array"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseUsers([]byte(tc.file))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
	s, _, _ := testServer(t, nil)
	if err := s.EnableAuth(filepath.Join(t.TempDir(), "missing.json")); err == nil || s.auth != nil {
		t.Fatalf("a missing users file must fail and leave auth off: %v", err)
	}
}

func TestHashPasswordRoundTrips(t *testing.T) {
	for _, input := range []string{"correct horse\r\n"} { // cost 12 is slow; CRLF covers the trim
		h, err := HashPassword(strings.NewReader(input))
		if err != nil {
			t.Fatalf("%q: %v", input, err)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(h), []byte("correct horse")); err != nil {
			t.Fatalf("%q: hash does not verify: %v", input, err)
		}
		if cost, _ := bcrypt.Cost([]byte(h)); cost != 12 {
			t.Fatalf("cost %d, want 12", cost)
		}
		if _, err := parseUsers([]byte(`[{"username":"a","role":"admin","password_bcrypt":"` + h + `"}]`)); err != nil {
			t.Fatalf("hash-password output rejected by the users file: %v", err)
		}
	}
}

func TestHashPasswordRejectsEmpty(t *testing.T) {
	for _, input := range []string{"", "\n", "\r\n"} {
		if _, err := HashPassword(strings.NewReader(input)); err == nil {
			t.Errorf("%q: want an error", input)
		}
	}
}
