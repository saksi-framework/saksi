package campaign

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Simple, optional console authentication. Off unless the operator passes
// --auth-file (env SAKSI_AUTH_FILE): without it Server.auth stays nil, the
// middleware passes every request straight through, and the three auth routes
// answer 404 exactly as the unregistered paths did before.
//
// Demo-grade by design: users in a file, sessions in memory, no TLS
// termination, no audit log of logins.

const (
	RoleAdmin   = "admin"
	RoleTrustee = "trustee"

	sessionCookie     = "saksi_session"
	sessionTTL        = 12 * time.Hour // the cookie's Max-Age=43200
	maxLoginFailures  = 5
	loginFailWindow   = 5 * time.Minute
	loginLockout      = 30 * time.Second
	hashPasswordCost  = 12
	errLoginRequired  = "login required"
	errBadCredentials = "invalid credentials"
)

// dummyHash is compared against when the username does not exist, so an
// unknown user costs the same bcrypt work as a wrong password. Cost 12, the
// same as hash-password; its password is never valid for any account.
var dummyHash = []byte("$2a$12$O/ckBLOYgz3kbuKTtSKRF.agFl431gkqGI0a8.Y7TIqRLYSu5zQ0S")

// User is one entry of the users file.
type User struct {
	Username       string `json:"username"`
	Role           string `json:"role"`
	TrusteeID      string `json:"trustee_id,omitempty"`
	PasswordBcrypt string `json:"password_bcrypt"`
}

// access is what a route requires. The zero value is accessAdmin, so a route
// missing from routeAccess fails closed rather than open.
type access int

const (
	accessAdmin    access = iota
	accessPublic          // anyone, signed in or not
	accessSignedIn        // any trustee or admin
	accessTrustee         // trustees only; the handler also checks share ownership
)

// routeAccess is the single route -> role table, keyed by the ServeMux pattern
// the request resolves to (so it cannot disagree with the mux about which
// handler runs). Enforced only when auth is on. TestRouteAccessCoversEveryRoute
// fails if NewServer registers a route that is not listed here.
var routeAccess = map[string]access{
	// public: the bulletin board, the audit trail, ceremony status, the static
	// apps, and the auth routes themselves.
	"/api/board/":       accessPublic,
	"/api/verify-code/": accessPublic,
	"/trail/":           accessPublic,
	"/api/trail":        accessPublic,
	"/api/trail/":       accessPublic,
	"/api/capabilities": accessPublic,
	"/api/ceremony/":    accessPublic,
	"/runs":             accessPublic,
	"/board/":           accessPublic,
	"/board":            accessPublic,
	"/trustee/":         accessPublic,
	"/trustee":          accessPublic,
	"/admin/":           accessPublic,
	"/admin":            accessPublic,
	"/api/login":        accessPublic,
	"/api/logout":       accessPublic,
	"/api/me":           accessPublic,

	// trustee or admin
	"/ceremony/publish": accessSignedIn,
	"/events":           accessSignedIn,

	// trustee, own shares only (ownership checked in handleCeremonySubmit)
	"/ceremony/submit": accessTrustee,

	// admin. /export/ is admin-only because run exports include the seeded
	// ground truth; "/" also catches every unknown path.
	"/":               accessAdmin,
	"/generate":       accessAdmin,
	"/submit":         accessAdmin,
	"/verify":         accessAdmin,
	"/run-all":        accessAdmin,
	"/cancel":         accessAdmin,
	"/scenarios":      accessAdmin,
	"/attack":         accessAdmin,
	"/ceremony/start": accessAdmin,
	"/api/runs/":      accessAdmin,
	"/api/check/":     accessAdmin,
	"/api/scenarios/": accessAdmin,
	"/export/":        accessAdmin,
	"/wizard":         accessAdmin,
}

// denial returns the HTTP status and reason when sess may not use a route that
// needs a; status 0 means allowed.
func (a access) denial(sess *session) (int, string) {
	if a == accessPublic {
		return 0, ""
	}
	if sess == nil {
		return http.StatusUnauthorized, errLoginRequired
	}
	switch a {
	case accessSignedIn:
		return 0, ""
	case accessTrustee:
		if sess.Role != RoleTrustee {
			return http.StatusForbidden, "only a trustee may submit trustee shares"
		}
		return 0, ""
	default:
		if sess.Role != RoleAdmin {
			return http.StatusForbidden, "admin role required"
		}
		return 0, ""
	}
}

// routeMux is a ServeMux that remembers the patterns registered on it, so a
// test can prove every route has an entry in routeAccess.
type routeMux struct {
	*http.ServeMux
	patterns []string
}

func (m *routeMux) Handle(pattern string, h http.Handler) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.Handle(pattern, h)
}

func (m *routeMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	m.Handle(pattern, http.HandlerFunc(h))
}

type session struct {
	Username  string
	Role      string
	TrusteeID string
	expires   time.Time
}

type failRecord struct {
	count       int
	start       time.Time
	lockedUntil time.Time
}

// authState holds the users and the live sessions.
//
// ponytail: sessions and login failures live in memory, so a console restart
// logs everyone out and resets lockouts. A persistent store is the upgrade
// path if sessions ever need to outlive the process.
type authState struct {
	users map[string]User
	now   func() time.Time

	mu       sync.Mutex
	sessions map[string]session
	fails    map[string]*failRecord
}

func newAuthState(users map[string]User) *authState {
	return &authState{
		users:    users,
		now:      time.Now,
		sessions: make(map[string]session),
		fails:    make(map[string]*failRecord),
	}
}

// EnableAuth turns on login and per-route roles, reading users from path.
// Call it once, before serving. Without it every route stays open.
func (s *Server) EnableAuth(path string) error {
	users, err := LoadUsers(path)
	if err != nil {
		return err
	}
	s.auth = newAuthState(users)
	return nil
}

// LoadUsers reads and validates a users file: a JSON array of User.
func LoadUsers(path string) (map[string]User, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read users file: %w", err)
	}
	return parseUsers(data)
}

func parseUsers(data []byte) (map[string]User, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var list []User
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("users file must be a JSON array of {username, role, trustee_id, password_bcrypt}: %w", err)
	}
	if len(list) == 0 {
		return nil, errors.New("users file has no users: nobody could log in")
	}
	users := make(map[string]User, len(list))
	for i, u := range list {
		where := fmt.Sprintf("user %d (%q)", i+1, u.Username)
		switch {
		case strings.TrimSpace(u.Username) == "":
			return nil, fmt.Errorf("user %d: username is empty", i+1)
		case u.Role != RoleAdmin && u.Role != RoleTrustee:
			return nil, fmt.Errorf("%s: unknown role %q (want %q or %q)", where, u.Role, RoleAdmin, RoleTrustee)
		case u.Role == RoleTrustee && u.TrusteeID == "":
			return nil, fmt.Errorf("%s: a trustee needs a trustee_id", where)
		case u.Role == RoleAdmin && u.TrusteeID != "":
			return nil, fmt.Errorf("%s: an admin must not have a trustee_id", where)
		}
		if _, dup := users[u.Username]; dup {
			return nil, fmt.Errorf("%s: duplicate username", where)
		}
		if _, err := bcrypt.Cost([]byte(u.PasswordBcrypt)); err != nil {
			return nil, fmt.Errorf("%s: password_bcrypt is not a bcrypt hash (make one with `saksi-campaign hash-password`): %v", where, err)
		}
		users[u.Username] = u
	}
	return users, nil
}

// HashPassword reads one password line from in and returns its bcrypt hash at
// cost 12. The password never comes from argv, where it would land in shell
// history and the process list.
func HashPassword(in io.Reader) (string, error) {
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read password: %w", err)
	}
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		return "", errors.New("empty password")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), hashPasswordCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// authorize is the single enforcement point, run after guard(). It resolves
// the session (if any) into the request context, then applies routeAccess.
func (s *Server) authorize(mux *routeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.auth == nil {
			mux.ServeHTTP(w, r)
			return
		}
		sess := s.auth.lookup(r)
		if sess != nil {
			r = r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess))
		}
		_, pattern := mux.Handler(r)
		if code, reason := routeAccess[pattern].denial(sess); code != 0 {
			writeJSONResp(w, code, map[string]string{"error": reason})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

type sessionKey struct{}

// sessionFrom returns the signed-in session, or nil when auth is off or the
// caller has none.
func sessionFrom(r *http.Request) *session {
	sess, _ := r.Context().Value(sessionKey{}).(*session)
	return sess
}

// prune drops expired sessions and stale failure records. Caller holds mu.
func (a *authState) prune(now time.Time) {
	for tok, sess := range a.sessions {
		if !now.Before(sess.expires) {
			delete(a.sessions, tok)
		}
	}
	for ip, rec := range a.fails {
		if !now.Before(rec.lockedUntil) && now.Sub(rec.start) > loginFailWindow {
			delete(a.fails, ip)
		}
	}
}

func (a *authState) lookup(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prune(a.now())
	sess, ok := a.sessions[c.Value]
	if !ok {
		return nil
	}
	return &sess
}

func (a *authState) create(u User) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.prune(now)
	a.sessions[token] = session{
		Username: u.Username, Role: u.Role, TrusteeID: u.TrusteeID,
		expires: now.Add(sessionTTL),
	}
	return token, nil
}

func (a *authState) end(token string) {
	a.mu.Lock()
	delete(a.sessions, token)
	a.mu.Unlock()
}

// attempt reserves a login attempt for ip, or reports how long ip must wait.
// The reservation counts BEFORE the password is checked, so concurrent guesses
// cannot all slip past the limit while bcrypt runs. settle then undoes it on
// success, or locks ip out once the failures reach the limit. A success never
// clears earlier failures, so a user with a valid account of their own cannot
// reset the counter between guesses at someone else's.
func (a *authState) attempt(ip string) (time.Duration, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.prune(now)
	rec := a.fails[ip]
	if rec != nil && now.Before(rec.lockedUntil) {
		return rec.lockedUntil.Sub(now), false
	}
	if rec == nil || now.Sub(rec.start) > loginFailWindow {
		rec = &failRecord{start: now}
		a.fails[ip] = rec
	}
	if rec.count >= maxLoginFailures {
		return loginLockout, false
	}
	rec.count++
	return 0, true
}

func (a *authState) settle(ip string, success bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec := a.fails[ip]
	switch {
	case rec == nil:
	case success:
		if rec.count > 0 {
			rec.count--
		}
	case rec.count >= maxLoginFailures:
		now := a.now()
		*rec = failRecord{start: now, lockedUntil: now.Add(loginLockout)}
	}
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.NotFound(w, r)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	ip := remoteIP(r)
	wait, ok := s.auth.attempt(ip)
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int((wait+time.Second-1)/time.Second)))
		writeJSONResp(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed logins; try again shortly"})
		return
	}
	u, known := s.auth.users[body.Username]
	hash := dummyHash
	if known {
		hash = []byte(u.PasswordBcrypt)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(body.Password)); err != nil || !known {
		s.auth.settle(ip, false)
		writeJSONResp(w, http.StatusUnauthorized, map[string]string{"error": errBadCredentials})
		return
	}
	s.auth.settle(ip, true)
	token, err := s.auth.create(u)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]string{"error": "cannot create session"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		MaxAge: int(sessionTTL.Seconds()), HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.auth.end(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.NotFound(w, r)
		return
	}
	sess := sessionFrom(r)
	if sess == nil {
		writeJSONResp(w, http.StatusUnauthorized, map[string]string{"error": errLoginRequired})
		return
	}
	writeJSONResp(w, http.StatusOK, struct {
		Username  string `json:"username"`
		Role      string `json:"role"`
		TrusteeID string `json:"trustee_id,omitempty"`
	}{sess.Username, sess.Role, sess.TrusteeID})
}
