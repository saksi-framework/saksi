package campaign

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Precinct check-in for a live election (docs/live/voter-list-api.md).
//
// Each list entry moves
//
//	not_checked_in -> at_desk -> approved -> signed -> credential_issued
//
// at_desk: the phone matched the entry and sent the declaration; approved: the
// presenter, as the Electoral Board, confirmed the person; signed: the phone
// signed the list (or recorded "I cannot sign"); credential_issued: the one
// blind credential for the entry was signed. Refuse (at_desk only) and reset
// (any state before credential_issued) send the entry back to
// not_checked_in and end the phone's cookie. There is no way back from
// credential_issued.
//
// A phone holds its place with the saksi_checkin cookie: 32 random bytes,
// stored only as a SHA-256 bound to the election id and compared in constant
// time. The list (with dates of birth) and the check-in record live in the
// run's private folder, written atomically before any answer is sent.
//
// Blind issuance stays blind: the check-in record holds, per entry, its state,
// its cookie hash and its signature strokes. It holds no time, no address and
// nothing from the issuance (no commitment, challenge or signature), and the
// ballot relay never sees the cookie (authorize drops it).

// Check-in states of one list entry.
const (
	CheckinNotCheckedIn = "not_checked_in"
	CheckinAtDesk       = "at_desk"
	CheckinApproved     = "approved"
	CheckinSigned       = "signed"
	CheckinIssued       = "credential_issued"

	// What a phone's ended cookie reads as.
	checkinRefused = "refused"
	checkinReset   = "reset"
)

const (
	liveVoterListFile = "voter-list.json"
	liveCheckinFile   = "checkin.json"
	voterListSchema   = "saksi-live-voter-list-v1"
	checkinSchema     = "saksi-live-checkin-v1"

	checkinCookie     = "saksi_checkin"
	checkinCookiePath = "/api/live/"
	checkinCookieTTL  = 12 * time.Hour

	// The signature: strokes of [x, y] points in a 1000 x 400 box.
	sigMaxStrokes      = 64
	sigMaxStrokePoints = 1000
	sigMaxPoints       = 4000
	sigMaxX            = 1000
	sigMaxY            = 400
	sigMaxBody         = 64 << 10

	// Find and declare, per address: a burst of 12, then one every 10 s.
	findBurst    = 12
	findPerSec   = 1.0 / 10
	findMaxAddrs = 4096

	// voterListBodyMax caps a request that carries the CSV text.
	voterListBodyMax = 192 << 10

	voterListNote = "The list is kept by the election console. It is not written to the ledger."
)

// errCoded is an error answer with a status and a stable code.
type errCoded struct {
	status int
	code   string
	msg    string
}

func (e errCoded) Error() string { return e.msg }

var (
	errNotOnList       = errCoded{http.StatusNotFound, "not-on-list", "No voter with these details is on this precinct's list. Check the spelling or see the Electoral Board."}
	errAlreadyIn       = errCoded{http.StatusConflict, "already-checked-in", "This voter has already checked in. See the Electoral Board."}
	errNoCheckin       = errCoded{http.StatusForbidden, "no-checkin", "This phone has no check-in. Check in at the precinct first."}
	errCheckinEnded    = errCoded{http.StatusForbidden, "no-checkin", "This check-in was ended by the Electoral Board. Check in again."}
	errNotSigned       = errCoded{http.StatusConflict, "not-signed", "The credential is issued after the voter signs the list."}
	errAlreadyIssued   = errCoded{http.StatusConflict, "already-issued", "This voter has been issued a credential for this election already; it cannot be issued again."}
	errNoVoterList     = errCoded{http.StatusConflict, "no-voter-list", "This election has no voter list."}
	errCheckinBusy     = errCoded{http.StatusConflict, "checkin-in-progress", "This phone is already checking in a voter. Finish that check-in, or ask the Electoral Board to reset it."}
	errDeclaration     = errCoded{http.StatusBadRequest, "declaration-required", "The declaration must be accepted."}
	errCheckinNotFound = errCoded{http.StatusNotFound, "no-checkin", "This phone has no check-in."}
)

func checkinNotOpen(state string) error {
	return errCoded{http.StatusConflict, "not-open", "Check-in is open while the election is open; it is " + state + "."}
}

// voterListRecord is private/voter-list.json: the locked list. Written once
// at setup, never changed.
type voterListRecord struct {
	Schema      string     `json:"schema"`
	ElectionID  string     `json:"election_id"`
	Precinct    string     `json:"precinct"`
	Fingerprint string     `json:"fingerprint"`
	Rows        []VoterRow `json:"rows"`
}

// CheckinSignature is a signature on the list: strokes of [x, y] points, or
// the record that the voter cannot sign.
type CheckinSignature struct {
	Strokes    [][][]int `json:"strokes,omitempty"`
	CannotSign bool      `json:"cannot_sign,omitempty"`
}

// checkinEntry is one list entry's check-in. No time, no address.
type checkinEntry struct {
	State      string            `json:"state"`
	CookieHash string            `json:"cookie_hash,omitempty"`
	DeskOrder  int               `json:"desk_order,omitempty"`
	Signature  *CheckinSignature `json:"signature,omitempty"`
}

// checkinRecord is private/checkin.json. Entries[i] is sequence number i+1.
// Ended maps an ended cookie's hash to "refused" or "reset", so that phone's
// poll can say which; such a cookie can do nothing else.
type checkinRecord struct {
	Schema      string            `json:"schema"`
	ElectionID  string            `json:"election_id"`
	Entries     []checkinEntry    `json:"entries"`
	Ended       map[string]string `json:"ended"`
	DeskCounter int               `json:"desk_counter"`
}

// checkinBook is the current election's list and check-in record. Guarded by
// liveService.ckMu.
type checkinBook struct {
	dir         string
	electionID  string
	precinct    string
	fingerprint string
	rows        []VoterRow
	keys        []voterRowKey
	rec         checkinRecord
}

func voterListPath(dir string) string { return filepath.Join(dir, livePrivateDir, liveVoterListFile) }
func checkinPath(dir string) string   { return filepath.Join(dir, livePrivateDir, liveCheckinFile) }

// newCheckinBook writes a new election's list and an all-not-checked-in record.
func newCheckinBook(dir, electionID string, p ParsedVoterList) (*checkinBook, error) {
	lr := voterListRecord{Schema: voterListSchema, ElectionID: electionID, Precinct: p.Precinct,
		Fingerprint: p.Fingerprint, Rows: p.Rows}
	data, err := json.MarshalIndent(lr, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(voterListPath(dir), data, 0o600); err != nil {
		return nil, err
	}
	b := bookOf(dir, lr, checkinRecord{Schema: checkinSchema, ElectionID: electionID,
		Entries: make([]checkinEntry, len(p.Rows)), Ended: map[string]string{}})
	for i := range b.rec.Entries {
		b.rec.Entries[i].State = CheckinNotCheckedIn
	}
	if err := b.save(); err != nil {
		return nil, err
	}
	return b, nil
}

func bookOf(dir string, lr voterListRecord, rec checkinRecord) *checkinBook {
	b := &checkinBook{dir: dir, electionID: lr.ElectionID, precinct: lr.Precinct,
		fingerprint: lr.Fingerprint, rows: lr.Rows, rec: rec}
	for _, r := range lr.Rows {
		b.keys = append(b.keys, keyOfRow(r))
	}
	if b.rec.Ended == nil {
		b.rec.Ended = map[string]string{}
	}
	return b
}

// loadCheckinBook reads a run's list and record; nil with no error when the
// run has no list (an election made before lists existed).
func loadCheckinBook(dir string) (*checkinBook, error) {
	var lr voterListRecord
	data, err := os.ReadFile(voterListPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("voter list: %w", err)
	}
	if err := json.Unmarshal(data, &lr); err != nil || lr.Schema != voterListSchema {
		return nil, errors.New("voter list: unreadable or of another schema")
	}
	if voterListFingerprint(lr.Precinct, lr.Rows) != lr.Fingerprint {
		return nil, errors.New("voter list: the rows do not match the recorded fingerprint")
	}
	var rec checkinRecord
	data, err = os.ReadFile(checkinPath(dir))
	if err != nil {
		return nil, fmt.Errorf("check-in record: %w", err)
	}
	if err := json.Unmarshal(data, &rec); err != nil || rec.Schema != checkinSchema ||
		len(rec.Entries) != len(lr.Rows) || rec.ElectionID != lr.ElectionID {
		return nil, errors.New("check-in record: unreadable, of another schema, or not this list's")
	}
	return bookOf(dir, lr, rec), nil
}

func (b *checkinBook) save() error {
	data, err := json.MarshalIndent(b.rec, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(checkinPath(b.dir), data, 0o600)
}

// set replaces entry i (and the desk counter) and writes the record; on a
// failed write the record is as before and the answer is a 500 that names no
// file. ended, if set, ends that cookie hash with that outcome.
func (b *checkinBook) set(i int, e checkinEntry, endHash, endWhy string) error {
	old, oldCounter := b.rec.Entries[i], b.rec.DeskCounter
	b.rec.Entries[i] = e
	if endHash != "" {
		b.rec.Ended[endHash] = endWhy
	}
	if e.State == CheckinAtDesk && e.DeskOrder > b.rec.DeskCounter {
		b.rec.DeskCounter = e.DeskOrder
	}
	if b.atDesk() == 0 {
		b.rec.DeskCounter = 0 // the order of an empty desk says nothing more
	}
	if err := b.save(); err != nil {
		b.rec.Entries[i], b.rec.DeskCounter = old, oldCounter
		if endHash != "" {
			delete(b.rec.Ended, endHash)
		}
		return errInternal{"the check-in record could not be written"}
	}
	return nil
}

func (b *checkinBook) atDesk() int {
	n := 0
	for _, e := range b.rec.Entries {
		if e.State == CheckinAtDesk {
			n++
		}
	}
	return n
}

// CheckinCounts are a list's entries per state.
type CheckinCounts struct {
	NotCheckedIn int `json:"not_checked_in"`
	AtDesk       int `json:"at_desk"`
	Approved     int `json:"approved"`
	Signed       int `json:"signed"`
	Issued       int `json:"credential_issued"`
	// CheckedIn is signed plus credential_issued: the voters who signed the
	// list.
	CheckedIn int `json:"checked_in"`
}

func (b *checkinBook) counts() CheckinCounts {
	var c CheckinCounts
	for _, e := range b.rec.Entries {
		switch e.State {
		case CheckinNotCheckedIn:
			c.NotCheckedIn++
		case CheckinAtDesk:
			c.AtDesk++
		case CheckinApproved:
			c.Approved++
		case CheckinSigned:
			c.Signed++
		case CheckinIssued:
			c.Issued++
		}
	}
	c.CheckedIn = c.Signed + c.Issued
	return c
}

// checkinView is the published counts of the current election's list.
type checkinView struct {
	RunID  string
	Counts CheckinCounts
}

// publishCheckinLocked republishes the counts. Caller holds ckMu.
func (L *liveService) publishCheckinLocked() {
	if L.ck == nil {
		L.ckView.Store(nil)
		return
	}
	L.ckView.Store(&checkinView{RunID: filepath.Base(L.ck.dir), Counts: L.ck.counts()})
}

// checkinCountsOf is the current run's counts, or a run folder's from disk.
func (L *liveService) checkinCountsOf(runID, dir string) (CheckinCounts, bool) {
	if L != nil {
		if v := L.ckView.Load(); v != nil && v.RunID == runID {
			return v.Counts, true
		}
	}
	b, err := loadCheckinBook(dir)
	if err != nil || b == nil {
		return CheckinCounts{}, false
	}
	return b.counts(), true
}

// --- the cookie ------------------------------------------------------------------

func newCheckinToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// checkinCookieHash binds a token to one election.
func checkinCookieHash(electionID, token string) string {
	sum := sha256.Sum256([]byte("saksi.live.checkin.v1\x00" + electionID + "\x00" + token))
	return hex.EncodeToString(sum[:])
}

// byToken finds the entry a phone's token is bound to: its index, or -1, and
// the outcome if the token was ended. Every entry is compared in constant
// time.
func (b *checkinBook) byToken(token string) (int, string) {
	if token == "" {
		return -1, ""
	}
	h := []byte(checkinCookieHash(b.electionID, token))
	found := -1
	for i, e := range b.rec.Entries {
		if subtle.ConstantTimeCompare([]byte(e.CookieHash), h) == 1 {
			found = i
		}
	}
	if found >= 0 {
		return found, ""
	}
	return -1, b.rec.Ended[string(h)]
}

func checkinToken(r *http.Request) string {
	c, err := r.Cookie(checkinCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func setCheckinCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: checkinCookie, Value: token, Path: checkinCookiePath,
		MaxAge: int(checkinCookieTTL.Seconds()), HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// --- per-address limit -------------------------------------------------------------

// addrLimiter is a token bucket per caller address, for find and declare. The
// addresses live in memory only, are never logged or written, and a full
// bucket is dropped.
type addrLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	max     int
	buckets map[string]*addrBucket
	now     func() time.Time
}

type addrBucket struct {
	tokens float64
	last   time.Time
}

func newAddrLimiter(perSecond, burst float64, max int) *addrLimiter {
	return &addrLimiter{rate: perSecond, burst: burst, max: max, buckets: map[string]*addrBucket{}, now: time.Now}
}

// allow takes one token for addr, or says how long until one is there.
func (l *addrLimiter) allow(addr string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	refill := func(b *addrBucket) {
		b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
		b.last = now
	}
	b := l.buckets[addr]
	if b == nil {
		if len(l.buckets) >= l.max {
			for a, o := range l.buckets {
				if refill(o); o.tokens >= l.burst {
					delete(l.buckets, a)
				}
			}
		}
		if len(l.buckets) >= l.max {
			return false, time.Second // fail closed under an address flood
		}
		b = &addrBucket{tokens: l.burst, last: now}
		l.buckets[addr] = b
	}
	refill(b)
	if b.tokens < 1 {
		wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
		return false, wait
	}
	b.tokens--
	return true, 0
}

// --- views -------------------------------------------------------------------------

// CheckinEntryView is a list entry as the phone and the presenter see it:
// never the date of birth.
type CheckinEntryView struct {
	Seq        int    `json:"seq"`
	LastName   string `json:"last_name"`
	FirstName  string `json:"first_name"`
	MiddleName string `json:"middle_name"`
}

func (b *checkinBook) entryView(i int) CheckinEntryView {
	r := b.rows[i]
	return CheckinEntryView{Seq: r.Seq, LastName: r.LastName, FirstName: r.FirstName, MiddleName: r.MiddleName}
}

// CheckinFindView answers find.
type CheckinFindView struct {
	Precinct      string           `json:"precinct"`
	PrecinctLabel string           `json:"precinct_label"`
	Entry         CheckinEntryView `json:"entry"`
}

// CheckinPollView is the phone's check-in.
type CheckinPollView struct {
	// State is the entry's check-in state, or "refused" / "reset" for a
	// cookie the presenter ended.
	State         string            `json:"state"`
	ElectionID    string            `json:"election_id"`
	ElectionState string            `json:"election_state"`
	Precinct      string            `json:"precinct"`
	PrecinctLabel string            `json:"precinct_label"`
	Entry         *CheckinEntryView `json:"entry,omitempty"`
}

// DeskEntryView is one entry on the presenter's election-day list.
type DeskEntryView struct {
	CheckinEntryView
	Status    string            `json:"status"`
	Signature *CheckinSignature `json:"signature,omitempty"`
}

// VoterListView is GET /api/live/voter-list.
type VoterListView struct {
	ElectionID       string          `json:"election_id"`
	ElectionState    string          `json:"election_state"`
	Precinct         string          `json:"precinct"`
	PrecinctLabel    string          `json:"precinct_label"`
	Fingerprint      string          `json:"fingerprint"`
	FingerprintShort string          `json:"fingerprint_short"`
	Count            int             `json:"count"`
	Counts           CheckinCounts   `json:"counts"`
	Desk             []DeskEntryView `json:"desk"`
	Entries          []DeskEntryView `json:"entries"`
}

func (b *checkinBook) deskView(i int) DeskEntryView {
	e := b.rec.Entries[i]
	return DeskEntryView{CheckinEntryView: b.entryView(i), Status: e.State, Signature: e.Signature}
}

// --- the operations -------------------------------------------------------------

// currentBook is the open election's book under ckMu, or why there is none.
// Caller holds ckMu.
func (L *liveService) bookLocked(needOpen bool) (*checkinBook, *liveSnapshot, error) {
	sn := L.snapshot()
	if sn == nil {
		return nil, nil, errNotFound{"no live election has been set up"}
	}
	if L.ck == nil || L.ck.dir != sn.Dir {
		return nil, sn, errNoVoterList
	}
	if needOpen && sn.State != LiveOpen {
		return nil, sn, checkinNotOpen(sn.State)
	}
	return L.ck, sn, nil
}

// CheckinDetails is what the phone types.
type CheckinDetails struct {
	LastName    string `json:"last_name"`
	FirstName   string `json:"first_name"`
	DateOfBirth string `json:"date_of_birth"`
}

// match finds the one entry with these details. Caller holds ckMu.
func (b *checkinBook) match(d CheckinDetails, now time.Time) (int, error) {
	if len(d.LastName) > 4*voterNameMaxBytes || len(d.FirstName) > 4*voterNameMaxBytes {
		return -1, errCoded{http.StatusBadRequest, "bad-request", "a name is too long"}
	}
	if ok, _ := parseDOB(d.DateOfBirth, now); !ok {
		return -1, errCoded{http.StatusBadRequest, "bad-date", "date_of_birth must be a date in the form YYYY-MM-DD"}
	}
	k := voterRowKey{voterNameKey(d.LastName), voterNameKey(d.FirstName), d.DateOfBirth}
	if k.last == "" || k.first == "" {
		return -1, errNotOnList
	}
	for i, rk := range b.keys {
		if rk == k {
			return i, nil
		}
	}
	return -1, errNotOnList
}

func (L *liveService) checkinFind(d CheckinDetails) (CheckinFindView, error) {
	L.ckMu.Lock()
	defer L.ckMu.Unlock()
	b, _, err := L.bookLocked(true)
	if err != nil {
		return CheckinFindView{}, err
	}
	i, err := b.match(d, L.now())
	if err != nil {
		return CheckinFindView{}, err
	}
	if b.rec.Entries[i].State != CheckinNotCheckedIn {
		return CheckinFindView{}, errAlreadyIn
	}
	return CheckinFindView{Precinct: b.precinct, PrecinctLabel: precinctLabel(b.precinct), Entry: b.entryView(i)}, nil
}

// checkinDeclare matches the details again and, when the entry is not checked
// in, moves it to the desk and binds a new token to it.
func (L *liveService) checkinDeclare(d CheckinDetails, declared bool, held string) (CheckinPollView, string, error) {
	if !declared {
		return CheckinPollView{}, "", errDeclaration
	}
	L.ckMu.Lock()
	defer L.ckMu.Unlock()
	b, sn, err := L.bookLocked(true)
	if err != nil {
		return CheckinPollView{}, "", err
	}
	if j, _ := b.byToken(held); j >= 0 {
		switch b.rec.Entries[j].State {
		case CheckinAtDesk, CheckinApproved, CheckinSigned:
			return CheckinPollView{}, "", errCheckinBusy
		}
	}
	i, err := b.match(d, L.now())
	if err != nil {
		return CheckinPollView{}, "", err
	}
	if b.rec.Entries[i].State != CheckinNotCheckedIn {
		return CheckinPollView{}, "", errAlreadyIn
	}
	token, err := newCheckinToken()
	if err != nil {
		return CheckinPollView{}, "", errInternal{"no randomness for a check-in token"}
	}
	e := checkinEntry{State: CheckinAtDesk, CookieHash: checkinCookieHash(b.electionID, token), DeskOrder: b.rec.DeskCounter + 1}
	if err := b.set(i, e, "", ""); err != nil {
		return CheckinPollView{}, "", err
	}
	L.publishCheckinLocked()
	return pollOf(b, sn, i, ""), token, nil
}

func pollOf(b *checkinBook, sn *liveSnapshot, i int, ended string) CheckinPollView {
	v := CheckinPollView{ElectionID: b.electionID, ElectionState: sn.State,
		Precinct: b.precinct, PrecinctLabel: precinctLabel(b.precinct)}
	if i < 0 {
		v.State = ended
		return v
	}
	ev := b.entryView(i)
	v.State, v.Entry = b.rec.Entries[i].State, &ev
	return v
}

func (L *liveService) checkinPoll(token string) (CheckinPollView, error) {
	L.ckMu.Lock()
	defer L.ckMu.Unlock()
	b, sn, err := L.bookLocked(false)
	if err != nil {
		return CheckinPollView{}, err
	}
	i, ended := b.byToken(token)
	if i < 0 && ended == "" {
		return CheckinPollView{}, errCheckinNotFound
	}
	return pollOf(b, sn, i, ended), nil
}

// phoneEntryLocked is the entry the phone's token is bound to. Caller holds
// ckMu.
func phoneEntryLocked(b *checkinBook, token string) (int, error) {
	i, ended := b.byToken(token)
	switch {
	case i >= 0:
		return i, nil
	case ended != "":
		return -1, errCheckinEnded
	default:
		return -1, errNoCheckin
	}
}

// checkSignature validates a signature body.
func checkSignature(s CheckinSignature) error {
	bad := func(msg string) error { return errCoded{http.StatusBadRequest, "bad-signature", msg} }
	if s.CannotSign {
		if len(s.Strokes) != 0 {
			return bad("send strokes or cannot_sign, not both")
		}
		return nil
	}
	if len(s.Strokes) == 0 {
		return bad("the signature has no strokes")
	}
	if len(s.Strokes) > sigMaxStrokes {
		return bad(fmt.Sprintf("at most %d strokes", sigMaxStrokes))
	}
	total := 0
	for _, st := range s.Strokes {
		if len(st) == 0 || len(st) > sigMaxStrokePoints {
			return bad(fmt.Sprintf("each stroke has 1 to %d points", sigMaxStrokePoints))
		}
		total += len(st)
		for _, p := range st {
			if len(p) != 2 || p[0] < 0 || p[0] > sigMaxX || p[1] < 0 || p[1] > sigMaxY {
				return bad(fmt.Sprintf("each point is [x, y] with 0 <= x <= %d and 0 <= y <= %d", sigMaxX, sigMaxY))
			}
		}
	}
	if total > sigMaxPoints {
		return bad(fmt.Sprintf("at most %d points in all", sigMaxPoints))
	}
	return nil
}

func (L *liveService) checkinSign(token string, s CheckinSignature) (CheckinPollView, error) {
	if err := checkSignature(s); err != nil {
		return CheckinPollView{}, err
	}
	L.ckMu.Lock()
	defer L.ckMu.Unlock()
	b, sn, err := L.bookLocked(true)
	if err != nil {
		return CheckinPollView{}, err
	}
	i, err := phoneEntryLocked(b, token)
	if err != nil {
		return CheckinPollView{}, err
	}
	e := b.rec.Entries[i]
	if e.State != CheckinApproved {
		return CheckinPollView{}, errCoded{http.StatusConflict, "wrong-state", "The list is signed after the Electoral Board approves; this check-in is " + e.State + "."}
	}
	sig := s
	e.State, e.Signature = CheckinSigned, &sig
	if err := b.set(i, e, "", ""); err != nil {
		return CheckinPollView{}, err
	}
	L.publishCheckinLocked()
	return pollOf(b, sn, i, ""), nil
}

// deskEntry finds a list entry by sequence number. Caller holds ckMu.
func deskEntry(b *checkinBook, seq int) (int, error) {
	if seq < 1 || seq > len(b.rows) {
		return -1, errCoded{http.StatusNotFound, "no-such-entry", "no entry with sequence number " + strconv.Itoa(seq) + " on the list"}
	}
	return seq - 1, nil
}

func wrongDeskState(action string, seq int, state string) error {
	return errCoded{http.StatusConflict, "wrong-state", fmt.Sprintf("entry %d is %s; %s is not possible", seq, state, action)}
}

// deskApprove: at_desk -> approved, while the election is open.
func (L *liveService) deskApprove(seq int) (DeskEntryView, error) {
	L.ckMu.Lock()
	defer L.ckMu.Unlock()
	b, _, err := L.bookLocked(true)
	if err != nil {
		return DeskEntryView{}, err
	}
	i, err := deskEntry(b, seq)
	if err != nil {
		return DeskEntryView{}, err
	}
	e := b.rec.Entries[i]
	if e.State != CheckinAtDesk {
		return DeskEntryView{}, wrongDeskState("approve", seq, e.State)
	}
	e.State, e.DeskOrder = CheckinApproved, 0
	if err := b.set(i, e, "", ""); err != nil {
		return DeskEntryView{}, err
	}
	L.publishCheckinLocked()
	return b.deskView(i), nil
}

// deskEnd is refuse (at_desk only) and reset (any state before
// credential_issued): the entry goes back to not_checked_in, its signature is
// dropped, its open issuance session is removed, and the phone's cookie ends.
// It takes issueMu, so it never runs inside an issuance.
func (L *liveService) deskEnd(seq int, why string) (DeskEntryView, error) {
	L.issueMu.Lock()
	defer L.issueMu.Unlock()
	L.ckMu.Lock()
	defer L.ckMu.Unlock()
	b, _, err := L.bookLocked(false)
	if err != nil {
		return DeskEntryView{}, err
	}
	i, err := deskEntry(b, seq)
	if err != nil {
		return DeskEntryView{}, err
	}
	e := b.rec.Entries[i]
	switch {
	case e.State == CheckinIssued:
		return DeskEntryView{}, errCoded{http.StatusConflict, "already-issued", fmt.Sprintf("entry %d has been issued its credential; there is no reset and no replacement", seq)}
	case why == checkinRefused && e.State != CheckinAtDesk:
		return DeskEntryView{}, wrongDeskState("refuse", seq, e.State)
	case e.State == CheckinNotCheckedIn:
		return DeskEntryView{}, wrongDeskState("reset", seq, e.State)
	}
	if err := os.Remove(sessionPath(b.dir, entrySessionKey(seq))); err != nil && !errors.Is(err, os.ErrNotExist) {
		return DeskEntryView{}, errInternal{"an issuance session could not be removed"}
	}
	if err := b.set(i, checkinEntry{State: CheckinNotCheckedIn}, e.CookieHash, why); err != nil {
		return DeskEntryView{}, err
	}
	L.publishCheckinLocked()
	return b.deskView(i), nil
}

func (L *liveService) voterList() (VoterListView, error) {
	L.ckMu.Lock()
	defer L.ckMu.Unlock()
	b, sn, err := L.bookLocked(false)
	if err != nil {
		return VoterListView{}, err
	}
	v := VoterListView{ElectionID: b.electionID, ElectionState: sn.State,
		Precinct: b.precinct, PrecinctLabel: precinctLabel(b.precinct),
		Fingerprint: b.fingerprint, FingerprintShort: fingerprintShort(b.fingerprint),
		Count: len(b.rows), Counts: b.counts(), Desk: []DeskEntryView{}, Entries: []DeskEntryView{}}
	var desk []int
	for i, e := range b.rec.Entries {
		v.Entries = append(v.Entries, b.deskView(i))
		if e.State == CheckinAtDesk {
			desk = append(desk, i)
		}
	}
	sort.Slice(desk, func(x, y int) bool { return b.rec.Entries[desk[x]].DeskOrder < b.rec.Entries[desk[y]].DeskOrder })
	for _, i := range desk {
		v.Desk = append(v.Desk, b.deskView(i))
	}
	return v, nil
}

// entrySessionKey names a list entry's issuance session file.
func entrySessionKey(seq int) string { return "list-entry:" + strconv.Itoa(seq) }
