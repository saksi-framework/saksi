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
	"regexp"
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

	sessionCookie      = "saksi_session"
	sessionTTL         = 12 * time.Hour // the cookie's Max-Age=43200
	maxLoginFailures   = 5              // per (remote IP, submitted username)
	maxIPLoginFailures = 50             // per remote IP, across usernames
	maxUsernameBytes   = 256
	loginFailWindow    = 5 * time.Minute
	loginLockout       = 30 * time.Second
	hashPasswordCost   = 12
	errLoginRequired   = "login required"
	errBadCredentials  = "invalid credentials"
)

var trusteeIDPattern = regexp.MustCompile(`^[1-9][0-9]*$`)

// dummyHash is compared against when the username does not exist, so an
// unknown user costs the same bcrypt work as a wrong password. Cost 12, the
// cost hash-password uses and the only cost the users file accepts; its
// password is never valid for any account.
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
//
// A handler behind a public subtree pattern (one ending in "/") must never pick
// an action from the path suffix: the mux matches the escaped path, while the
// handler reads the decoded r.URL.Path, so a suffix is not proof of which
// action the table approved. Put actions that need a role on their own routes.
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
	// study campaigns: preflight, the ladder job, campaigns and their exports
	"/api/preflight":  accessAdmin,
	"/api/ladder":     accessAdmin,
	"/api/jobs/":      accessAdmin,
	"/api/campaigns":  accessAdmin,
	"/api/campaigns/": accessAdmin,
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
// test can prove every route has an entry in routeAccess. The ServeMux is a
// named field, not embedded, so no registration bypasses the recording by
// accident (code in this package could still call m.mux.HandleFunc on
// purpose; such a route would not be in the test's list, and authorize would
// still treat it as admin-only, the zero value of access).
type routeMux struct {
	mux      *http.ServeMux
	patterns []string
}

func (m *routeMux) Handle(pattern string, h http.Handler) {
	m.patterns = append(m.patterns, pattern)
	m.mux.Handle(pattern, h)
}

func (m *routeMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	m.Handle(pattern, http.HandlerFunc(h))
}

func (m *routeMux) Handler(r *http.Request) (http.Handler, string) { return m.mux.Handler(r) }

func (m *routeMux) ServeHTTP(w http.ResponseWriter, r *http.Request) { m.mux.ServeHTTP(w, r) }

type session struct {
	Username  string
	Role      string
	TrusteeID string
	expires   time.Time
}

// failRecord counts login attempts in one window: reservations still being
// checked plus failures. At its limit it locks for loginLockout.
type failRecord struct {
	count       int
	start       time.Time
	lockedUntil time.Time
}

// lapsed reports whether the record's window is over with no lockout in force.
func (rec *failRecord) lapsed(now time.Time) bool {
	return !now.Before(rec.lockedUntil) && now.Sub(rec.start) > loginFailWindow
}

// blocked reports how long the record refuses attempts: while locked, or while
// its count already reaches limit (concurrent attempts still being checked).
func (rec *failRecord) blocked(now time.Time, limit int) (time.Duration, bool) {
	if now.Before(rec.lockedUntil) {
		return rec.lockedUntil.Sub(now), true
	}
	if rec.count >= limit {
		return loginLockout, true
	}
	return 0, false
}

// failKey is one address guessing at one username. user is the submitted
// string whether or not such a user exists, so a lockout reveals nothing
// about which accounts are real.
type failKey struct{ ip, user string }

// authState holds the users and the live sessions.
//
// ponytail: sessions and login failures live in memory, so a console restart
// logs everyone out and resets lockouts. A persistent store is the upgrade
// path if sessions ever need to outlive the process.
type authState struct {
	users map[string]User
	now   func() time.Time

	mu        sync.Mutex
	sessions  map[string]session
	ipFails   map[string]*failRecord  // per remote IP: the loose cap
	userFails map[failKey]*failRecord // per (remote IP, submitted username)
}

func newAuthState(users map[string]User) *authState {
	return &authState{
		users:     users,
		now:       time.Now,
		sessions:  make(map[string]session),
		ipFails:   make(map[string]*failRecord),
		userFails: make(map[failKey]*failRecord),
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
	trusteeOwner := make(map[string]string)
	for i, u := range list {
		where := fmt.Sprintf("user %d (%q)", i+1, u.Username)
		switch {
		case strings.TrimSpace(u.Username) == "":
			return nil, fmt.Errorf("user %d: username is empty", i+1)
		case len(u.Username) > maxUsernameBytes:
			return nil, fmt.Errorf("user %d: username is longer than %d bytes", i+1, maxUsernameBytes)
		case u.Role != RoleAdmin && u.Role != RoleTrustee:
			return nil, fmt.Errorf("%s: unknown role %q (want %q or %q)", where, u.Role, RoleAdmin, RoleTrustee)
		case u.Role == RoleTrustee && u.TrusteeID == "":
			return nil, fmt.Errorf("%s: a trustee needs a trustee_id", where)
		case u.Role == RoleTrustee && !trusteeIDPattern.MatchString(u.TrusteeID):
			return nil, fmt.Errorf("%s: trustee_id %q must be the trustee's wire id: digits, no leading zero", where, u.TrusteeID)
		case u.Role == RoleAdmin && u.TrusteeID != "":
			return nil, fmt.Errorf("%s: an admin must not have a trustee_id", where)
		}
		if _, dup := users[u.Username]; dup {
			return nil, fmt.Errorf("%s: duplicate username", where)
		}
		if owner, dup := trusteeOwner[u.TrusteeID]; dup && u.TrusteeID != "" {
			return nil, fmt.Errorf("%s: trustee_id %q is already assigned to %q", where, u.TrusteeID, owner)
		}
		cost, err := bcrypt.Cost([]byte(u.PasswordBcrypt))
		if err != nil {
			return nil, fmt.Errorf("%s: password_bcrypt is not a bcrypt hash (make one with `saksi-campaign hash-password`): %v", where, err)
		}
		// One cost for every account and for the unknown-user dummy compare, so
		// response time cannot tell a real username from an unknown one.
		if cost != hashPasswordCost {
			return nil, fmt.Errorf("%s: password_bcrypt has cost %d, want %d (make one with `saksi-campaign hash-password`)", where, cost, hashPasswordCost)
		}
		users[u.Username] = u
		if u.TrusteeID != "" {
			trusteeOwner[u.TrusteeID] = u.Username
		}
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
		// An internal call (internal.go) is the console driving itself: no
		// session, and only the routes the repeat driver calls, auth on or off.
		if internalCall(r) {
			if !internalRouteAllowed(mux, r) {
				writeJSONResp(w, http.StatusForbidden, map[string]string{"error": "not a route the campaign driver uses"})
				return
			}
			mux.ServeHTTP(w, r)
			return
		}
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
	for ip, rec := range a.ipFails {
		if rec.lapsed(now) {
			delete(a.ipFails, ip)
		}
	}
	for key, rec := range a.userFails {
		if rec.lapsed(now) {
			delete(a.userFails, key)
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

// attempt reserves a login attempt by ip for the submitted username, or reports
// how long the caller must wait. Two counters apply: 5 per (ip, username) and a
// looser 50 per ip across usernames. The ip is checked first, so its cap also
// bounds how many (ip, username) records one address can create. The username
// is keyed as submitted, never checked for existence; one over
// maxUsernameBytes gets no record of its own and counts against the ip only.
//
// Reservations count BEFORE the password is checked, so concurrent guesses
// cannot overrun a limit while bcrypt runs; settle then resolves them.
func (a *authState) attempt(ip, user string) (time.Duration, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.prune(now)
	ipRec := a.ipFails[ip]
	if ipRec == nil || ipRec.lapsed(now) {
		ipRec = &failRecord{start: now}
		a.ipFails[ip] = ipRec
	}
	if wait, blocked := ipRec.blocked(now, maxIPLoginFailures); blocked {
		return wait, false
	}
	if len(user) <= maxUsernameBytes {
		key := failKey{ip, user}
		rec := a.userFails[key]
		if rec == nil || rec.lapsed(now) {
			rec = &failRecord{start: now}
			a.userFails[key] = rec
		}
		if wait, blocked := rec.blocked(now, maxLoginFailures); blocked {
			return wait, false
		}
		rec.count++
	}
	ipRec.count++
	return 0, true
}

// settle resolves a reservation. A failure locks whichever counter reached its
// limit. A success resets its own (ip, username) record and hands back only its
// own reservation on the ip counter: earlier failures from that address stand,
// so a valid login of one's own cannot launder guesses at another account.
func (a *authState) settle(ip, user string, success bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	lockAt := func(rec *failRecord, limit int) {
		if rec != nil && rec.count >= limit {
			*rec = failRecord{start: now, lockedUntil: now.Add(loginLockout)}
		}
	}
	switch ipRec := a.ipFails[ip]; {
	case !success:
		lockAt(ipRec, maxIPLoginFailures)
	case ipRec != nil && ipRec.count > 0:
		ipRec.count--
	}
	if len(user) > maxUsernameBytes {
		return
	}
	key := failKey{ip, user}
	if success {
		delete(a.userFails, key)
		return
	}
	lockAt(a.userFails[key], maxLoginFailures)
}

// remoteIP is the lockout key for the caller's address. Every loopback address
// (127.0.0.0/8, ::1) is one key: a local process can use any of them as its
// source, and separate keys would hand it a fresh budget per alias.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return "loopback"
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
	wait, ok := s.auth.attempt(ip, body.Username)
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int((wait+time.Second-1)/time.Second)))
		writeJSONResp(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed logins; try again shortly"})
		return
	}
	// A username over maxUsernameBytes is never in the map (parseUsers refuses
	// one), so it takes the unknown-user path with the same dummy compare.
	u, known := s.auth.users[body.Username]
	hash := dummyHash
	if known {
		hash = []byte(u.PasswordBcrypt)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(body.Password)); err != nil || !known {
		s.auth.settle(ip, body.Username, false)
		writeJSONResp(w, http.StatusUnauthorized, map[string]string{"error": errBadCredentials})
		return
	}
	s.auth.settle(ip, body.Username, true)
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
