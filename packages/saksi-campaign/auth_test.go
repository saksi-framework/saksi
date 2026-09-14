package campaign

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	"golang.org/x/crypto/bcrypt"
)

func mustHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
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
		{Username: "admin", Role: RoleAdmin, PasswordBcrypt: mustHash(t, "admin-pw")},
		{Username: "t1", Role: RoleTrustee, TrusteeID: "1", PasswordBcrypt: mustHash(t, "t1-pw")},
		{Username: "t2", Role: RoleTrustee, TrusteeID: "2", PasswordBcrypt: mustHash(t, "t2-pw")},
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
		}},
		{"trustee or admin", 401, 0, 0, []probe{{post, "/ceremony/publish"}, {get, "/events"}}},
		{"trustee, own shares", 401, 0, 403, []probe{{post, "/ceremony/submit"}}},
		{"admin", 401, 403, 0, []probe{
			{post, "/generate"}, {post, "/submit"}, {post, "/verify"}, {post, "/run-all"},
			{post, "/cancel"}, {post, "/scenarios"}, {post, "/attack"}, {post, "/ceremony/start"},
			{post, "/api/runs/r1/resume"}, {get, "/api/runs/r1/status"}, {get, "/api/check/r1"},
			{get, "/api/scenarios/r1"}, {get, "/export/r1/run.json"}, {get, "/wizard"}, {get, "/"},
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

	for i := 1; i <= 5; i++ {
		if rec := login(h, ip, "admin", "wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: want 401, got %d", i, rec.Code)
		}
	}
	rec := login(h, ip, "admin", "admin-pw")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "30" {
		t.Fatalf("sixth attempt, correct password: want 429 Retry-After 30, got %d %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if rec := login(h, "198.51.100.9:1000", "admin", "admin-pw"); rec.Code != http.StatusNoContent {
		t.Fatalf("another address must not be locked out, got %d", rec.Code)
	}
	now = now.Add(31 * time.Second)
	if rec := login(h, ip, "admin", "admin-pw"); rec.Code != http.StatusNoContent {
		t.Fatalf("after the 30 s lockout: want 204, got %d %s", rec.Code, rec.Body)
	}

	// A success of one's own does not wipe earlier failures, so a trustee
	// cannot reset the counter between guesses at the admin password.
	const insider = "192.0.2.4:1000"
	for i := 0; i < 4; i++ {
		login(h, insider, "admin", "guess")
	}
	if rec := login(h, insider, "t1", "t1-pw"); rec.Code != http.StatusNoContent {
		t.Fatalf("insider's own login: want 204, got %d", rec.Code)
	}
	login(h, insider, "admin", "guess")
	if rec := login(h, insider, "admin", "admin-pw"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("fifth failure after an interleaved success must lock out, got %d", rec.Code)
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

	for _, path := range []string{"/api/me", "/wizard"} {
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
	req := signIn(t, s, "admin", httptest.NewRequest(http.MethodGet, "/wizard", nil))

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
	hash := mustHash(t, "pw")
	ok := `[{"username":"a","role":"admin","password_bcrypt":"` + hash + `"},` +
		`{"username":"t","role":"trustee","trustee_id":"1","password_bcrypt":"` + hash + `"}]`
	if users, err := parseUsers([]byte(ok)); err != nil || len(users) != 2 {
		t.Fatalf("valid file rejected: %v", err)
	}
	for name, tc := range map[string]struct{ file, wantErr string }{
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
