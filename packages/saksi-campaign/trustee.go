package campaign

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// The trustee process: `saksi-campaign trustee --id N` (docs/live/trustee-api.md).
//
// One process per trustee. It holds that trustee's secrets (the receive key
// and the key share, by file path in its own state folder), runs that
// trustee's `saksi-demo live` ops, reads the ledger itself through its own
// Fabric gateway connection, and talks to the console only to post what the
// trustee produced. Its human presses three buttons over an election's life
// (join, decrypt, sign); a background driver does the rest and keeps a status
// any page can read.
//
// What it trusts the console for: nothing it acts on. The console's
// GET /api/live/election names the current election id and its state for
// display; the parameters, the transcript, the ballots and the partials are
// read from the chain, and the roster is checked against the other trustees'
// own hosts.

// Trustee step states (status.steps.<step>.state).
const (
	stepIdle    = "idle"    // not asked for
	stepRunning = "running" // working
	stepWaiting = "waiting" // waiting for someone else (the roster, the deals, the peers, the console)
	stepDone    = "done"
	stepFailed  = "failed"  // an error; press the button again to retry
	stepRefused = "refused" // the process refuses this (wrong state, too few ballots, another ballot set)
	stepBlocked = "blocked" // an alarm stops this step for this election
)

const (
	trusteeProgressFile   = "progress.json"
	trusteeCurrentFile    = "current.json"
	trusteeElectionsDir   = "elections"
	trusteeReceiveKey     = "receive.key"
	trusteeShareFile      = "share.json"
	trusteeNewSuffix      = ".new"
	trusteeProgressSchema = "saksi-live-trustee-progress-v1"

	// DefaultMinBallots is --min-ballots: a position with fewer ballot
	// records is not decrypted, because its aggregate is one voter's choice.
	DefaultMinBallots = 2
	// DefaultTrusteePoll is how often the driver reads the console and the
	// chain while a step waits.
	DefaultTrusteePoll = 2 * time.Second
	// trusteeConsoleTimeout bounds one console call. The roster and inbox
	// polls can wait on the console's state lock for up to about 2.5 minutes
	// while it submits to a stalled chain, so it is above 3 minutes; a
	// timeout is a wait, never a refusal.
	trusteeConsoleTimeout = 4 * time.Minute
	trusteePeerTimeout    = 15 * time.Second
	trusteeOpTimeout      = 2 * time.Minute
)

// electionDirName is an election id that is safe as a folder name.
var electionDirName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// trusteeChain is what the trustee reads from the bulletin chaincode. It has no
// Submit: the trustee never writes to the chain itself.
// *clientsdk.BulletinClient satisfies it.
type trusteeChain interface {
	GetElection(electionID string) (string, error)
	GetElectionStatus(electionID string) (string, error)
	GetDKGTranscript(electionID string) (string, error)
	GetTally(electionID string) (string, error)
	ListNullifiers(electionID string, pageSize int, bookmark string) (clientsdk.NullifierPage, error)
	GetBallots(electionID string, nullifiers []string) ([]string, error)
	GetPartialDecryption(electionID, contestID, trusteeID string) (string, error)
}

// TrusteeOptions configures one trustee process.
type TrusteeOptions struct {
	// ID is this trustee's id, 1..n.
	ID int
	// ConsoleURL is the console's base URL (https://host:port). Its host and
	// port must be in the console's --allow-host list and its name must be on
	// the console's certificate.
	ConsoleURL string
	// ConsoleCA is an extra PEM CA file trusted for the console and the
	// peers (tests); the system roots are always trusted.
	ConsoleCA string
	// Token is this trustee's bearer token (LoadTrusteeTokenFile).
	Token string
	// StateDir is this trustee's private folder (0700).
	StateDir string
	// Peers are the other trustees' base URLs by id.
	Peers map[int]string
	// MinBallots is the fewest ballot records a position may be decrypted
	// over; 0 = DefaultMinBallots.
	MinBallots int
	// Runner runs the live ops (`saksi-demo live <op>`).
	Runner LiveRunner
	// Dial opens the read connection to the chain.
	Dial func() (trusteeChain, error)
	// Poll is the driver's polling interval; 0 = DefaultTrusteePoll.
	Poll time.Duration
	// Now is the clock; nil = time.Now.
	Now func() time.Time
	// crash is a test hook: true at a named point stops the driver there, as
	// a kill would.
	crash func(point string) bool
}

// trusteeAlarm is something a check caught. It is shown until the election
// changes, and the steps it names stay blocked.
type trusteeAlarm struct {
	Code    string    `json:"code"`
	Message string    `json:"message"`
	Blocks  []string  `json:"blocks"`
	At      time.Time `json:"at"`
}

// stepStatus is one step's progress.
type stepStatus struct {
	State     string    `json:"state"`
	Detail    string    `json:"detail,omitempty"`
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// peerCheck is one peer's comparison result.
type peerCheck struct {
	State  string `json:"state"` // ok, waiting, mismatch
	Detail string `json:"detail,omitempty"`
}

// trusteeAck is dkg-receive's output (no secret in it).
type trusteeAck struct {
	ElectionID          string `json:"election_id"`
	TrusteeID           int    `json:"trustee_id"`
	VerificationKey     string `json:"verification_key"`
	Fingerprint         string `json:"fingerprint"`
	JointPublicKey      string `json:"joint_public_key"`
	JointKeyFingerprint string `json:"joint_key_fingerprint"`
	RosterDigest        string `json:"roster_digest"`
	RosterFingerprint   string `json:"roster_fingerprint"`
}

// trusteeContestTotal is one contest's total from this trustee's own combine.
type trusteeContestTotal struct {
	ContestID string `json:"contest_id"`
	Total     uint64 `json:"total"`
}

// trusteeProgress is <state-dir>/elections/<id>/progress.json: where this
// trustee stands in one election. It holds public values only (keys,
// digests, fingerprints, the trustee's own public outputs); the secrets are
// the receive key and share files next to it, which only the CLI reads.
type trusteeProgress struct {
	Schema     string    `json:"schema"`
	ElectionID string    `json:"election_id"`
	TrusteeID  int       `json:"trustee_id"`
	CreatedAt  time.Time `json:"created_at"`

	JoinRequested    bool     `json:"join_requested"`
	DecryptRequested bool     `json:"decrypt_requested"`
	SignRequested    bool     `json:"sign_requested"`
	SignTotals       []uint64 `json:"sign_totals,omitempty"`

	// The election as created on the chain.
	Params     string   `json:"params,omitempty"`
	Trustees   int      `json:"trustees,omitempty"`
	Threshold  int      `json:"threshold,omitempty"`
	ContestIDs []string `json:"contest_ids,omitempty"`

	ReceivePublicKey      string `json:"receive_public_key,omitempty"`
	ReceiveKeyFingerprint string `json:"receive_key_fingerprint,omitempty"`
	ReceiveKeyPosted      bool   `json:"receive_key_posted"`

	RosterPeers         []livePeer           `json:"roster_peers,omitempty"`
	RosterKeyFPs        map[string]string    `json:"roster_key_fingerprints,omitempty"`
	RosterDigest        string               `json:"roster_digest,omitempty"`
	RosterFingerprint   string               `json:"roster_fingerprint,omitempty"`
	PeerChecks          map[string]peerCheck `json:"peer_checks,omitempty"`
	RosterChecked       bool                 `json:"roster_checked"`
	Deal                json.RawMessage      `json:"deal,omitempty"`
	DealPosted          bool                 `json:"deal_posted"`
	Ack                 json.RawMessage      `json:"ack,omitempty"`
	AckPosted           bool                 `json:"ack_posted"`
	TranscriptCheck     string               `json:"transcript_check,omitempty"` // ok, mismatch
	ChainDKG            string               `json:"chain_dkg,omitempty"`
	TranscriptPublished bool                 `json:"transcript_published"`

	BallotsDigest      string               `json:"ballots_digest,omitempty"`
	BallotsFingerprint string               `json:"ballots_fingerprint,omitempty"`
	BallotCount        int                  `json:"ballot_count,omitempty"`
	BallotsByPosition  map[string]int       `json:"ballots_by_position,omitempty"`
	PeerBallotChecks   map[string]peerCheck `json:"peer_ballot_checks,omitempty"`
	Partial            json.RawMessage      `json:"partial,omitempty"`
	PartialPosted      bool                 `json:"partial_posted"`
	PartialReadBack    string               `json:"partial_read_back,omitempty"` // ok, mismatch

	CombinePartials []string              `json:"combine_partials,omitempty"`
	Totals          []uint64              `json:"totals,omitempty"`
	Contests        []trusteeContestTotal `json:"contests,omitempty"`
	Signature       json.RawMessage       `json:"signature,omitempty"`
	SignaturePosted bool                  `json:"signature_posted"`
	SignatureNote   string                `json:"signature_note,omitempty"`

	TallyPublished bool     `json:"tally_published"`
	TallyTotals    []uint64 `json:"tally_totals,omitempty"`

	Steps  map[string]stepStatus `json:"steps"`
	Alarms []trusteeAlarm        `json:"alarms,omitempty"`
}

func (p *trusteeProgress) ack() *trusteeAck {
	if len(p.Ack) == 0 {
		return nil
	}
	var a trusteeAck
	if json.Unmarshal(p.Ack, &a) != nil {
		return nil
	}
	return &a
}

// blocked reports whether an alarm blocks step.
func (p *trusteeProgress) blocked(step string) *trusteeAlarm {
	for i := range p.Alarms {
		if slices.Contains(p.Alarms[i].Blocks, step) {
			return &p.Alarms[i]
		}
	}
	return nil
}

func (p *trusteeProgress) step(name string) stepStatus {
	if s, ok := p.Steps[name]; ok {
		return s
	}
	return stepStatus{State: stepIdle}
}

// TrusteeService is one trustee process's state and its background driver.
type TrusteeService struct {
	id         int
	idStr      string
	console    *trusteeConsole
	peers      map[int]string
	peerClient *trusteeHTTP
	run        LiveRunner
	dial       func() (trusteeChain, error)
	stateDir   string
	minBallots int
	poll       time.Duration
	now        func() time.Time
	crash      func(string) bool

	chainMu sync.Mutex
	chain   trusteeChain

	// mu guards everything below and every write to the state folder.
	mu         sync.Mutex
	p          *trusteeProgress
	view       *LiveElectionView
	consoleErr string
	identity   identityState
	killed     bool

	wake   chan struct{}
	cancel context.CancelFunc
	done   chan struct{}
}

// identityState is whether the console agrees this token is trustee id's.
type identityState struct {
	Checked bool   `json:"checked"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// errTrusteeKilled is the crash test hook stopping the driver.
var errTrusteeKilled = errors.New("trustee driver stopped at a test crash point")

// NewTrusteeService checks the options and the state folder and loads the
// current election's progress. Call Start to run the driver.
func NewTrusteeService(o TrusteeOptions) (*TrusteeService, error) {
	if o.ID < 1 || o.ID > MaxTrustees {
		return nil, fmt.Errorf("--id must be 1..%d (got %d)", MaxTrustees, o.ID)
	}
	if o.Token == "" {
		return nil, errors.New("no trustee token (--token-file)")
	}
	if o.Runner == nil {
		return nil, errors.New("no live op runner (--demo)")
	}
	if o.Dial == nil {
		return nil, errors.New("no chain connection: a trustee reads the ledger itself (--fabric-tls-cert, --fabric-cert, --fabric-key)")
	}
	if err := ensurePrivateDir(o.StateDir); err != nil {
		return nil, err
	}
	httpc, err := newTrusteeHTTP(o.ConsoleCA, trusteeConsoleTimeout)
	if err != nil {
		return nil, err
	}
	peerc, err := newTrusteeHTTP(o.ConsoleCA, trusteePeerTimeout)
	if err != nil {
		return nil, err
	}
	base, err := checkHTTPSBase("--console", o.ConsoleURL)
	if err != nil {
		return nil, err
	}
	peers := map[int]string{}
	for id, u := range o.Peers {
		if id == o.ID {
			continue
		}
		b, err := checkHTTPSBase(fmt.Sprintf("--peers %d", id), u)
		if err != nil {
			return nil, err
		}
		peers[id] = b
	}
	T := &TrusteeService{
		id: o.ID, idStr: strconv.Itoa(o.ID),
		console: &trusteeConsole{base: base, token: o.Token, http: httpc},
		peers:   peers, peerClient: peerc,
		run: o.Runner, dial: o.Dial, stateDir: o.StateDir,
		minBallots: o.MinBallots, poll: o.Poll, now: o.Now, crash: o.crash,
		wake: make(chan struct{}, 1),
	}
	if T.minBallots <= 0 {
		T.minBallots = DefaultMinBallots
	}
	if T.poll <= 0 {
		T.poll = DefaultTrusteePoll
	}
	if T.now == nil {
		T.now = time.Now
	}
	if err := T.loadCurrent(); err != nil {
		return nil, err
	}
	return T, nil
}

// ensurePrivateDir makes dir 0700 or checks that an existing one grants
// nothing to group or other users.
func ensurePrivateDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("--state-dir is required: the trustee's private folder")
	}
	info, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		return os.Chmod(dir, 0o700)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("--state-dir %s is not a folder", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("--state-dir %s is mode %o; want 0700 (it holds this trustee's key share)", dir, info.Mode().Perm())
	}
	return nil
}

// LoadTrusteeTokenFile reads a trustee's bearer token from a file that grants
// nothing to group or other users.
func LoadTrusteeTokenFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("--token-file is required: this trustee's bearer token for the console")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("token file %s is mode %o; want 0600 (chmod 600 %s)", path, info.Mode().Perm(), path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	tok := strings.TrimSpace(string(data))
	if len(tok) < minTrusteeTokenBytes || strings.ContainsAny(tok, " \t\r\n") {
		return "", fmt.Errorf("token file %s must hold one token of at least %d bytes (make one with `saksi-campaign new-token`)", path, minTrusteeTokenBytes)
	}
	return tok, nil
}

// ParseTrusteePeers parses --peers: "1=https://t1:9001,2=https://t2:9002".
func ParseTrusteePeers(s string) (map[int]string, error) {
	out := map[int]string{}
	if strings.TrimSpace(s) == "" {
		return out, nil
	}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		id, err := strconv.Atoi(k)
		if !ok || err != nil || id < 1 || !trusteeIDPattern.MatchString(k) {
			return nil, fmt.Errorf("--peers entry %q: want <id>=<https URL>", part)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("--peers names trustee %d twice", id)
		}
		out[id] = strings.TrimSpace(v)
	}
	return out, nil
}

func (T *TrusteeService) electionDir(id string) string {
	return filepath.Join(T.stateDir, trusteeElectionsDir, id)
}

func (T *TrusteeService) keyFile(p *trusteeProgress) string {
	return filepath.Join(T.electionDir(p.ElectionID), trusteeReceiveKey)
}

func (T *TrusteeService) shareFile(p *trusteeProgress) string {
	return filepath.Join(T.electionDir(p.ElectionID), trusteeShareFile)
}

// loadCurrent loads the election the process was last on, if any.
func (T *TrusteeService) loadCurrent() error {
	var cur struct {
		ElectionID string `json:"election_id"`
	}
	err := readJSON(filepath.Join(T.stateDir, trusteeCurrentFile), &cur)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", trusteeCurrentFile, err)
	}
	if !electionDirName.MatchString(cur.ElectionID) || cur.ElectionID == "." || cur.ElectionID == ".." {
		return fmt.Errorf("%s names an unusable election id", trusteeCurrentFile)
	}
	p, err := T.loadProgress(cur.ElectionID)
	if err != nil {
		return err
	}
	T.p = p
	return nil
}

// loadProgress reads an election's progress (nil, nil if none) and finishes
// a file move a kill cut off.
func (T *TrusteeService) loadProgress(electionID string) (*trusteeProgress, error) {
	dir := T.electionDir(electionID)
	var p trusteeProgress
	err := readJSON(filepath.Join(dir, trusteeProgressFile), &p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read progress of %s: %w", electionID, err)
	}
	if p.Schema != trusteeProgressSchema || p.ElectionID != electionID || p.TrusteeID != T.id {
		return nil, fmt.Errorf("progress of %s is not trustee %d's (schema %q, trustee %d)", electionID, T.id, p.Schema, p.TrusteeID)
	}
	if p.Steps == nil {
		p.Steps = map[string]stepStatus{}
	}
	if err := T.recoverFiles(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// recoverFiles finishes or undoes a secret-file write a kill interrupted. A
// receive key or share is written to <name>.new by the CLI, its public half
// is saved in the progress record, and only then is it renamed into place: a
// .new file whose public half was saved is renamed, and one whose public half
// was not (so it was never used) is removed.
func (T *TrusteeService) recoverFiles(p *trusteeProgress) error {
	for _, f := range []struct {
		path  string
		saved bool
	}{
		{T.keyFile(p), p.ReceivePublicKey != ""},
		{T.shareFile(p), len(p.Ack) > 0},
	} {
		tmp := f.path + trusteeNewSuffix
		if _, err := os.Stat(tmp); err != nil {
			continue
		}
		if !f.saved {
			if err := os.Remove(tmp); err != nil {
				return err
			}
			continue
		}
		if _, err := os.Stat(f.path); err == nil {
			// Both exist: the renamed one is the one in use.
			if err := os.Remove(tmp); err != nil {
				return err
			}
			continue
		}
		if err := os.Rename(tmp, f.path); err != nil {
			return err
		}
	}
	return nil
}

// saveLocked writes the current progress atomically (0600). Caller holds mu.
func (T *TrusteeService) saveLocked() error {
	if T.p == nil {
		return nil
	}
	data, err := json.MarshalIndent(T.p, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(T.electionDir(T.p.ElectionID), trusteeProgressFile), data, 0o600)
}

// update applies f to the current progress under mu and saves it.
func (T *TrusteeService) update(f func(p *trusteeProgress)) error {
	T.mu.Lock()
	defer T.mu.Unlock()
	if T.p == nil {
		return errors.New("no election")
	}
	f(T.p)
	return T.saveLocked()
}

// setStep records a step's status.
func (T *TrusteeService) setStep(name, state, detail, errText string) {
	_ = T.update(func(p *trusteeProgress) {
		prev := p.Steps[name]
		if prev.State == state && prev.Detail == detail && prev.Error == errText {
			return
		}
		p.Steps[name] = stepStatus{State: state, Detail: detail, Error: errText, UpdatedAt: T.now().UTC()}
	})
}

// begin marks a step running, unless it is already waiting (whose detail
// says more).
func (T *TrusteeService) begin(name string) {
	T.mu.Lock()
	st := T.p.step(name).State
	T.mu.Unlock()
	if st != stepWaiting && st != stepRunning {
		T.setStep(name, stepRunning, "", "")
	}
}

// raise records an alarm (once per code) and logs it.
func (T *TrusteeService) raise(code, msg string, blocks ...string) {
	_ = T.update(func(p *trusteeProgress) {
		for _, a := range p.Alarms {
			if a.Code == code {
				return
			}
		}
		p.Alarms = append(p.Alarms, trusteeAlarm{Code: code, Message: msg, Blocks: blocks, At: T.now().UTC()})
	})
	log.Printf("trustee %d: ALARM %s: %s", T.id, code, msg)
}

// crashed is the kill test hook.
func (T *TrusteeService) crashed(point string) bool {
	if T.crash != nil && T.crash(point) {
		T.mu.Lock()
		T.killed = true
		T.mu.Unlock()
		return true
	}
	return false
}

// getChain dials once and caches the connection; a failure is not cached.
func (T *TrusteeService) getChain() (trusteeChain, error) {
	T.chainMu.Lock()
	defer T.chainMu.Unlock()
	if T.chain != nil {
		return T.chain, nil
	}
	c, err := T.dial()
	if err != nil {
		return nil, err
	}
	T.chain = c
	return c, nil
}

// --- the driver ----------------------------------------------------------------

// Step outcomes other than done.
type (
	// tWait: waiting on someone else; the driver polls again by itself.
	tWait struct{ msg string }
	// tRefused: the process refuses this step.
	tRefused struct{ msg string }
	// tAlarm: a check failed; the steps named are blocked for this election.
	tAlarm struct {
		code, msg string
		blocks    []string
	}
	// tChainErr: the chain could not be read. The step fails and is retried
	// when the trustee presses again; there is no fallback to the console.
	tChainErr struct {
		what string
		err  error
	}
)

func (e tWait) Error() string    { return e.msg }
func (e tRefused) Error() string { return e.msg }
func (e tAlarm) Error() string   { return e.msg }
func (e tChainErr) Error() string {
	return "could not read " + e.what + " from the chain: " + clientsdk.ErrorText(e.err) + " (press again to retry)"
}

func waitf(format string, args ...any) error    { return tWait{fmt.Sprintf(format, args...)} }
func refusedf(format string, args ...any) error { return tRefused{fmt.Sprintf(format, args...)} }

// Start runs the background driver until Close.
func (T *TrusteeService) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	T.cancel = cancel
	T.done = make(chan struct{})
	go func() {
		defer close(T.done)
		for {
			if err := T.tick(ctx); errors.Is(err, errTrusteeKilled) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-T.wake:
			case <-time.After(T.poll):
			}
		}
	}()
}

// Close stops the driver and waits for it.
func (T *TrusteeService) Close() {
	if T.cancel != nil {
		T.cancel()
		<-T.done
	}
}

func (T *TrusteeService) poke() {
	select {
	case T.wake <- struct{}{}:
	default:
	}
}

// tick reads the console's current election, follows it, and advances every
// step that was asked for as far as it can go.
func (T *TrusteeService) tick(ctx context.Context) error {
	v, err := T.console.election(ctx)
	if err != nil {
		T.mu.Lock()
		T.consoleErr = err.Error()
		T.mu.Unlock()
		return nil
	}
	T.mu.Lock()
	T.consoleErr = ""
	T.view = v
	T.mu.Unlock()
	if v == nil {
		return nil // no election set up yet
	}
	if err := T.adopt(v); err != nil {
		T.mu.Lock()
		T.consoleErr = err.Error()
		T.mu.Unlock()
		return nil
	}
	if !T.identityOK() {
		if err := T.CheckIdentity(ctx); err != nil || !T.identityOK() {
			return nil
		}
	}
	if v.State == LiveAbandoned {
		T.abandoned()
		return nil
	}
	T.mu.Lock()
	join, decrypt, sign := T.p.JoinRequested, T.p.DecryptRequested, T.p.SignRequested
	T.mu.Unlock()
	if join {
		if err := T.runStep(ctx, "join", func() error { return T.advanceJoin(ctx, v) }); err != nil {
			return err
		}
	}
	if decrypt {
		if err := T.runStep(ctx, "decrypt", func() error { return T.advanceDecrypt(ctx) }); err != nil {
			return err
		}
	}
	if err := T.advanceCombine(ctx, v); errors.Is(err, errTrusteeKilled) {
		return err
	}
	if sign {
		if err := T.runStep(ctx, "sign", func() error { return T.advanceSign(ctx) }); err != nil {
			return err
		}
	}
	T.checkPublished(v)
	return nil
}

// runStep runs one step unless it is finished, failed, refused or blocked,
// and records its outcome. Only errTrusteeKilled comes back.
func (T *TrusteeService) runStep(ctx context.Context, name string, f func() error) error {
	T.mu.Lock()
	s := T.p.step(name)
	alarm := T.p.blocked(name)
	T.mu.Unlock()
	if alarm != nil {
		if s.State != stepBlocked {
			T.setStep(name, stepBlocked, "", alarm.Message)
		}
		return nil
	}
	switch s.State {
	case stepDone, stepFailed, stepRefused, stepBlocked:
		return nil
	}
	err := f()
	var (
		wait    tWait
		refused tRefused
		alarm2  tAlarm
	)
	switch {
	case err == nil:
		T.setStep(name, stepDone, "", "")
	case errors.Is(err, errTrusteeKilled):
		return err
	case errors.As(err, &wait):
		T.setStep(name, stepWaiting, wait.msg, "")
	case errors.As(err, &refused):
		log.Printf("trustee %d: %s refused: %s", T.id, name, refused.msg)
		T.setStep(name, stepRefused, "", refused.msg)
	case errors.As(err, &alarm2):
		T.raise(alarm2.code, alarm2.msg, alarm2.blocks...)
		T.setStep(name, stepBlocked, "", alarm2.msg)
	case ctx.Err() != nil:
		// Shutting down: leave the step as it was, to resume on restart.
	default:
		log.Printf("trustee %d: %s failed: %v", T.id, name, err)
		T.setStep(name, stepFailed, "", err.Error())
	}
	return nil
}

// adopt follows the console's current election: a new id gets its own folder
// and a fresh receive key; the old folder is left as it is.
func (T *TrusteeService) adopt(v *LiveElectionView) error {
	T.mu.Lock()
	defer T.mu.Unlock()
	if T.p != nil && T.p.ElectionID == v.ElectionID {
		return nil
	}
	if !electionDirName.MatchString(v.ElectionID) || v.ElectionID == "." || v.ElectionID == ".." {
		return fmt.Errorf("the console names election %q, which is not a valid election id", v.ElectionID)
	}
	p, err := T.loadProgress(v.ElectionID)
	if err != nil {
		return err
	}
	prev := T.p
	if p == nil {
		dir := T.electionDir(v.ElectionID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(filepath.Join(T.stateDir, trusteeElectionsDir), 0o700); err != nil {
			return err
		}
		p = &trusteeProgress{
			Schema: trusteeProgressSchema, ElectionID: v.ElectionID, TrusteeID: T.id,
			CreatedAt: T.now().UTC(), Steps: map[string]stepStatus{},
		}
		// A ceremony given up part-way (abandoned) is joined again for the
		// next election, with a fresh key: the trustee asked to take part.
		if prev != nil && prev.JoinRequested && prev.step("join").State != stepDone {
			p.JoinRequested = true
			p.Steps["join"] = stepStatus{State: stepRunning, Detail: "joining the new election " + v.ElectionID + " (the previous one was given up)", UpdatedAt: T.now().UTC()}
		}
	}
	T.p = p
	// The identity is re-checked against each election's roster.
	T.identity = identityState{}
	if err := T.saveLocked(); err != nil {
		return err
	}
	cur, _ := json.Marshal(map[string]string{"election_id": v.ElectionID})
	if err := writeFileAtomic(filepath.Join(T.stateDir, trusteeCurrentFile), cur, 0o600); err != nil {
		return err
	}
	if prev != nil {
		log.Printf("trustee %d: the console's election is now %s (was %s)", T.id, v.ElectionID, prev.ElectionID)
	}
	return nil
}

// abandoned marks every unfinished step of an abandoned election.
func (T *TrusteeService) abandoned() {
	T.mu.Lock()
	var names []string
	for _, n := range []string{"join", "decrypt", "sign"} {
		s := T.p.step(n)
		if s.State != stepDone && s.State != stepIdle && s.State != stepFailed {
			names = append(names, n)
		}
	}
	T.mu.Unlock()
	for _, n := range names {
		T.setStep(n, stepFailed, "", "the presenter abandoned this election; a new one will be followed when it is set up")
	}
}

func (T *TrusteeService) identityOK() bool {
	T.mu.Lock()
	defer T.mu.Unlock()
	return T.identity.Checked && T.identity.OK
}

// CheckIdentity asks the console which trustee this token is: its inbox
// answers with the token's trustee id. A different id, or a token the console
// does not accept, is an identity error (nothing runs). With no election set
// up the console cannot say yet, and nil comes back unchecked.
func (T *TrusteeService) CheckIdentity(ctx context.Context) error {
	code, body, err := T.console.do(ctx, "GET", "/api/live/dkg/inbox", nil)
	if err != nil {
		return err
	}
	var st identityState
	switch code {
	case 200:
		var in struct {
			TrusteeID int `json:"trustee_id"`
		}
		if json.Unmarshal(body, &in) != nil {
			return errors.New("the console's inbox answer is unreadable")
		}
		st = identityState{Checked: true, OK: in.TrusteeID == T.id}
		if !st.OK {
			st.Error = fmt.Sprintf("the console says this token is trustee %d's, but this process is --id %d: give each process its own token", in.TrusteeID, T.id)
		}
	case 401:
		st = identityState{Checked: true, Error: "the console does not accept this token (401): check --token-file against the console's --trustee-tokens"}
	case 403:
		st = identityState{Checked: true, Error: "the console says this token's trustee is not a trustee of the current election (403): " + errorText(body)}
	case 404:
		return nil // no election yet: the console cannot tell
	default:
		return fmt.Errorf("the console answered %d to the identity check: %s", code, errorText(body))
	}
	T.mu.Lock()
	changed := T.identity != st
	T.identity = st
	T.mu.Unlock()
	if !st.OK {
		if changed {
			log.Printf("trustee %d: identity: %s", T.id, st.Error)
		}
		return errors.New(st.Error)
	}
	return nil
}

// --- step 1: join the key ceremony ---------------------------------------------

// advanceJoin takes the ceremony as far as it can. nil means joined and the
// published transcript checked.
func (T *TrusteeService) advanceJoin(ctx context.Context, v *LiveElectionView) error {
	T.begin("join")
	p := T.p // fields below are written only by this goroutine, under mu
	state := liveStateIndex(v.State)
	if state < liveStateIndex(LiveCeremony) {
		return waitf("the election is in %s; the ceremony has not started", v.State)
	}
	inCeremony := v.State == LiveCeremony

	// The election as created on the chain, checked against what the console
	// states, before anything is dealt.
	if p.Params == "" {
		if err := T.checkParams(v); err != nil {
			return err
		}
	}

	// A fresh receive key for this election id.
	if p.ReceivePublicKey == "" {
		if !inCeremony {
			return refusedf("the ceremony is over (the election is %s) and this trustee had not joined it", v.State)
		}
		tmp := T.keyFile(p) + trusteeNewSuffix
		_ = os.Remove(tmp)
		var k struct {
			ReceivePublicKey string `json:"receive_public_key"`
			Fingerprint      string `json:"fingerprint"`
		}
		if err := T.op(ctx, "trustee-keygen", map[string]any{"trustee_id": T.id, "key_file": tmp}, &k); err != nil {
			return err
		}
		if err := T.update(func(p *trusteeProgress) {
			p.ReceivePublicKey, p.ReceiveKeyFingerprint = strings.ToLower(k.ReceivePublicKey), k.Fingerprint
		}); err != nil {
			return err
		}
		if T.crashed("keygen-saved") {
			return errTrusteeKilled
		}
		if err := os.Rename(tmp, T.keyFile(p)); err != nil {
			return err
		}
	}

	if !p.ReceiveKeyPosted {
		if !inCeremony {
			return refusedf("the ceremony is over (the election is %s) before this trustee's receive key was posted", v.State)
		}
		code, body, err := T.console.do(ctx, "POST", "/api/live/dkg/receive-key", map[string]any{
			"trustee_id": T.id, "receive_public_key": p.ReceivePublicKey, "fingerprint": p.ReceiveKeyFingerprint,
		})
		if err != nil {
			return err
		}
		switch code {
		case 200:
		case 409:
			return fmt.Errorf("the console refused this trustee's receive key: %s (if the roster froze with another key for this trustee, the presenter must abandon the election)", errorText(body))
		default:
			return fmt.Errorf("posting the receive key: %d %s", code, errorText(body))
		}
		if err := T.update(func(p *trusteeProgress) { p.ReceiveKeyPosted = true }); err != nil {
			return err
		}
	}

	if p.RosterDigest == "" {
		if err := T.takeRoster(ctx); err != nil {
			return err
		}
	}

	if !p.RosterChecked {
		if err := T.checkPeersRoster(ctx); err != nil {
			return err
		}
	}

	if len(p.Deal) == 0 {
		if !inCeremony {
			return refusedf("the ceremony is over (the election is %s) before this trustee dealt", v.State)
		}
		raw, err := T.opRaw(ctx, "dkg-deal", map[string]any{
			"receive_key_file": T.keyFile(p), "params": p.Params, "dealer_id": T.id, "peers": p.RosterPeers,
		})
		if err != nil {
			return err
		}
		var d struct {
			RosterDigest string `json:"roster_digest"`
		}
		if json.Unmarshal(raw, &d) != nil || !strings.EqualFold(d.RosterDigest, p.RosterDigest) {
			return tAlarm{"deal-roster", "dkg-deal computed a roster digest other than the one checked with the peers", []string{"join", "decrypt", "sign"}}
		}
		if err := T.update(func(p *trusteeProgress) { p.Deal = raw }); err != nil {
			return err
		}
		if T.crashed("deal-saved") {
			return errTrusteeKilled
		}
	}

	if !p.DealPosted {
		code, body, err := T.console.doRaw(ctx, "POST", "/api/live/dkg/deal", p.Deal)
		if err != nil {
			return err
		}
		if code != 200 {
			return fmt.Errorf("the console refused this trustee's deal: %d %s", code, errorText(body))
		}
		if err := T.update(func(p *trusteeProgress) { p.DealPosted = true }); err != nil {
			return err
		}
	}

	if len(p.Ack) == 0 {
		if err := T.receive(ctx); err != nil {
			return err
		}
		if T.crashed("ack-saved") {
			return errTrusteeKilled
		}
	}
	if _, err := os.Stat(T.shareFile(p)); err != nil {
		if err := os.Rename(T.shareFile(p)+trusteeNewSuffix, T.shareFile(p)); err != nil {
			return fmt.Errorf("the share file is missing: %v", err)
		}
	}

	if !p.AckPosted {
		code, body, err := T.console.doRaw(ctx, "POST", "/api/live/dkg/ack", p.Ack)
		if err != nil {
			return err
		}
		if code != 200 {
			return fmt.Errorf("the console refused this trustee's acknowledgement: %d %s", code, errorText(body))
		}
		if err := T.update(func(p *trusteeProgress) { p.AckPosted = true }); err != nil {
			return err
		}
	}

	if p.TranscriptCheck == "" {
		return T.checkTranscript(ctx, v)
	}
	if p.TranscriptCheck != "ok" {
		return tAlarm{"transcript", "the transcript on the chain does not match this trustee's keys", []string{"join", "decrypt", "sign"}}
	}
	return nil
}

// checkParams compares the parameters the console states with the election as
// created on the chain, and records the chain's.
func (T *TrusteeService) checkParams(v *LiveElectionView) error {
	c, err := T.getChain()
	if err != nil {
		return tChainErr{"the election", err}
	}
	chainParams, err := c.GetElection(v.ElectionID)
	if err != nil {
		return tChainErr{"the election", err}
	}
	if !strings.EqualFold(chainParams, v.Params) {
		return tAlarm{"params", "the election parameters the console states differ from the election created on the chain", []string{"join", "decrypt", "sign"}}
	}
	raw, err := hex.DecodeString(chainParams)
	if err != nil {
		return tAlarm{"params", "the chain's election parameters are not hex", []string{"join", "decrypt", "sign"}}
	}
	var ep pb.ElectionParameters
	if err := proto.Unmarshal(raw, &ep); err != nil {
		return tAlarm{"params", "the chain's election parameters do not decode", []string{"join", "decrypt", "sign"}}
	}
	n := len(ep.TrusteeIds)
	why := ""
	switch {
	case ep.ElectionId != v.ElectionID:
		why = fmt.Sprintf("the chain's parameters are for election %q", ep.ElectionId)
	case !slices.Equal(ep.TrusteeIds, trusteeIDs(n)):
		why = "the chain's trustee ids are not 1..n"
	case n != v.Trustees || int(ep.Threshold) != v.Threshold:
		why = fmt.Sprintf("the console states %d of %d trustees, the chain %d of %d", v.Threshold, v.Trustees, ep.Threshold, n)
	case T.id > n:
		why = fmt.Sprintf("this process is trustee %d, but the election has %d trustees", T.id, n)
	case ep.Threshold < 1 || int(ep.Threshold) > n:
		why = "the chain's threshold is out of range"
	}
	if why != "" {
		return tAlarm{"params", why, []string{"join", "decrypt", "sign"}}
	}
	return T.update(func(p *trusteeProgress) {
		p.Params = strings.ToLower(chainParams)
		p.Trustees, p.Threshold = n, int(ep.Threshold)
		p.ContestIDs = append([]string(nil), ep.ContestIds...)
	})
}

// consoleRoster is GET /api/live/dkg/roster.
type consoleRoster struct {
	ElectionID   string     `json:"election_id"`
	State        string     `json:"state"`
	Trustees     int        `json:"trustees"`
	Threshold    int        `json:"threshold"`
	Params       string     `json:"params"`
	Complete     bool       `json:"complete"`
	Received     []int      `json:"received"`
	Peers        []livePeer `json:"peers"`
	RosterDigest string     `json:"roster_digest"`
}

// takeRoster polls the roster until it is complete, checks this trustee's own
// key in it, computes the digest itself and records the roster.
func (T *TrusteeService) takeRoster(ctx context.Context) error {
	p := T.p
	var r consoleRoster
	code, body, err := T.console.do(ctx, "GET", "/api/live/dkg/roster", nil)
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("reading the roster: %d %s", code, errorText(body))
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return fmt.Errorf("the roster answer is unreadable")
	}
	if r.ElectionID != p.ElectionID || r.State == LiveAbandoned {
		return waitf("the console's roster is for election %s (%s)", r.ElectionID, r.State)
	}
	if !r.Complete {
		return waitf("waiting for every receive key: %d of %d in", len(r.Received), p.Trustees)
	}
	if !strings.EqualFold(r.Params, p.Params) {
		return tAlarm{"roster-params", "the roster names parameters other than the election's on the chain", []string{"join", "decrypt", "sign"}}
	}
	if len(r.Peers) != p.Trustees {
		return tAlarm{"roster", fmt.Sprintf("the roster has %d entries for %d trustees", len(r.Peers), p.Trustees), []string{"join", "decrypt", "sign"}}
	}
	for i, peer := range r.Peers {
		r.Peers[i].ReceivePublicKey = strings.ToLower(peer.ReceivePublicKey)
		if peer.TrusteeID == T.id && !strings.EqualFold(peer.ReceivePublicKey, p.ReceivePublicKey) {
			return tAlarm{"roster-own-key", "the console's roster holds another receive key for this trustee", []string{"join", "decrypt", "sign"}}
		}
	}
	var dr struct {
		Peers []struct {
			TrusteeID   int    `json:"trustee_id"`
			Fingerprint string `json:"fingerprint"`
		} `json:"peers"`
		RosterDigest      string `json:"roster_digest"`
		RosterFingerprint string `json:"roster_fingerprint"`
	}
	if err := T.op(ctx, "dkg-roster", map[string]any{"params": p.Params, "peers": r.Peers}, &dr); err != nil {
		return tAlarm{"roster", "the roster is refused: " + err.Error(), []string{"join", "decrypt", "sign"}}
	}
	if !strings.EqualFold(dr.RosterDigest, r.RosterDigest) {
		return tAlarm{"roster-digest", "the roster digest this trustee computes differs from the one the console publishes", []string{"join", "decrypt", "sign"}}
	}
	fps := map[string]string{}
	for _, x := range dr.Peers {
		fps[strconv.Itoa(x.TrusteeID)] = x.Fingerprint
	}
	sort.Slice(r.Peers, func(i, j int) bool { return r.Peers[i].TrusteeID < r.Peers[j].TrusteeID })
	return T.update(func(p *trusteeProgress) {
		p.RosterPeers, p.RosterKeyFPs = r.Peers, fps
		p.RosterDigest, p.RosterFingerprint = strings.ToLower(dr.RosterDigest), dr.RosterFingerprint
	})
}

// TrusteePeerView is GET /api/trustee/peer: what this trustee states for
// itself about the current election, for the other trustees to compare.
type TrusteePeerView struct {
	TrusteeID             int    `json:"trustee_id"`
	ElectionID            string `json:"election_id,omitempty"`
	ReceivePublicKey      string `json:"receive_public_key,omitempty"`
	ReceiveKeyFingerprint string `json:"receive_key_fingerprint,omitempty"`
	RosterDigest          string `json:"roster_digest,omitempty"`
	RosterFingerprint     string `json:"roster_fingerprint,omitempty"`
	BallotsDigest         string `json:"ballots_digest,omitempty"`
	BallotsFingerprint    string `json:"ballots_fingerprint,omitempty"`
}

// PeerView is this trustee's public statement.
func (T *TrusteeService) PeerView() TrusteePeerView {
	T.mu.Lock()
	defer T.mu.Unlock()
	v := TrusteePeerView{TrusteeID: T.id}
	if T.p == nil {
		return v
	}
	p := T.p
	v.ElectionID = p.ElectionID
	if p.ReceiveKeyPosted {
		v.ReceivePublicKey, v.ReceiveKeyFingerprint = p.ReceivePublicKey, p.ReceiveKeyFingerprint
	}
	v.RosterDigest, v.RosterFingerprint = p.RosterDigest, p.RosterFingerprint
	v.BallotsDigest, v.BallotsFingerprint = p.BallotsDigest, p.BallotsFingerprint
	return v
}

// fetchPeer reads trustee id's own page.
func (T *TrusteeService) fetchPeer(ctx context.Context, id int) (*TrusteePeerView, error) {
	base, ok := T.peers[id]
	if !ok {
		return nil, fmt.Errorf("no --peers URL for trustee %d", id)
	}
	code, body, err := T.peerClient.get(ctx, base+"/api/trustee/peer")
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("answered %d", code)
	}
	var v TrusteePeerView
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("unreadable answer")
	}
	return &v, nil
}

// checkPeersRoster compares the roster with every other trustee's own host:
// the receive key each states for itself must be the roster's, and each
// one's roster digest must equal this trustee's. An unreachable peer is
// waited for; a mismatch stops the ceremony naming the peer.
func (T *TrusteeService) checkPeersRoster(ctx context.Context) error {
	p := T.p
	checks := map[string]peerCheck{}
	waiting := []string{}
	// A peer stating another receive key names the swapped entry, so it is
	// the alarm shown before any digest difference.
	var alarm, keyAlarm error
	for _, peer := range p.RosterPeers {
		if peer.TrusteeID == T.id {
			continue
		}
		key := strconv.Itoa(peer.TrusteeID)
		v, err := T.fetchPeer(ctx, peer.TrusteeID)
		var c peerCheck
		switch {
		case err != nil:
			c = peerCheck{State: "waiting", Detail: "not reachable: " + err.Error()}
		case v.TrusteeID != peer.TrusteeID:
			c = peerCheck{State: "mismatch", Detail: fmt.Sprintf("the host given for trustee %d says it is trustee %d", peer.TrusteeID, v.TrusteeID)}
		case v.ElectionID != p.ElectionID:
			c = peerCheck{State: "waiting", Detail: fmt.Sprintf("it is on election %q", v.ElectionID)}
		case v.ReceivePublicKey == "":
			c = peerCheck{State: "waiting", Detail: "it has not posted a receive key yet"}
		case !strings.EqualFold(v.ReceivePublicKey, peer.ReceivePublicKey):
			c = peerCheck{State: "mismatch", Detail: fmt.Sprintf("trustee %d's own host states receive key %s, but the console's roster has %s for it",
				peer.TrusteeID, v.ReceiveKeyFingerprint, p.RosterKeyFPs[key])}
			if keyAlarm == nil {
				keyAlarm = tAlarm{"roster-peer-" + key, c.Detail, []string{"join", "decrypt", "sign"}}
			}
		case v.RosterDigest == "":
			c = peerCheck{State: "waiting", Detail: "its receive key matches; it has not computed the roster digest yet"}
		case !strings.EqualFold(v.RosterDigest, p.RosterDigest):
			c = peerCheck{State: "mismatch", Detail: fmt.Sprintf("trustee %d computed roster %s, this trustee %s: the console showed you different rosters",
				peer.TrusteeID, v.RosterFingerprint, p.RosterFingerprint)}
		default:
			c = peerCheck{State: "ok"}
		}
		checks[key] = c
		switch c.State {
		case "waiting":
			waiting = append(waiting, key)
		case "mismatch":
			if alarm == nil {
				alarm = tAlarm{"roster-peer-" + key, c.Detail, []string{"join", "decrypt", "sign"}}
			}
		}
	}
	if keyAlarm != nil {
		alarm = keyAlarm
	}
	if err := T.update(func(p *trusteeProgress) {
		p.PeerChecks = checks
		p.RosterChecked = alarm == nil && len(waiting) == 0
	}); err != nil {
		return err
	}
	if alarm != nil {
		return alarm
	}
	if len(waiting) > 0 {
		return waitf("checking the roster with the other trustees: waiting for trustee(s) %s", strings.Join(waiting, ", "))
	}
	return nil
}

// consoleInbox is GET /api/live/dkg/inbox.
type consoleInbox struct {
	ElectionID   string            `json:"election_id"`
	State        string            `json:"state"`
	TrusteeID    int               `json:"trustee_id"`
	Complete     bool              `json:"complete"`
	Dealt        []int             `json:"dealt"`
	Params       string            `json:"params"`
	Peers        []livePeer        `json:"peers"`
	RosterDigest string            `json:"roster_digest"`
	Dealers      []liveInboxDealer `json:"dealers"`
}

// receive polls the inbox until every deal is in, checks it against the
// roster this trustee checked, and runs dkg-receive (which verifies every
// share against its dealer's commitments and writes the share file).
func (T *TrusteeService) receive(ctx context.Context) error {
	p := T.p
	code, body, err := T.console.do(ctx, "GET", "/api/live/dkg/inbox", nil)
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("reading the inbox: %d %s", code, errorText(body))
	}
	var in consoleInbox
	if err := json.Unmarshal(body, &in); err != nil {
		return errors.New("the inbox answer is unreadable")
	}
	if in.ElectionID != p.ElectionID || in.State == LiveAbandoned {
		return waitf("the console's inbox is for election %s (%s)", in.ElectionID, in.State)
	}
	if !in.Complete {
		return waitf("waiting for every deal: %d of %d in", len(in.Dealt), p.Trustees)
	}
	blocks := []string{"join", "decrypt", "sign"}
	if in.TrusteeID != T.id || !strings.EqualFold(in.Params, p.Params) || !strings.EqualFold(in.RosterDigest, p.RosterDigest) {
		return tAlarm{"inbox", "the inbox is for another trustee, other parameters or another roster than the one checked", blocks}
	}
	if len(in.Peers) != len(p.RosterPeers) {
		return tAlarm{"inbox", "the inbox carries a roster other than the one checked with the peers", blocks}
	}
	for i := range in.Peers {
		if in.Peers[i].TrusteeID != p.RosterPeers[i].TrusteeID || !strings.EqualFold(in.Peers[i].ReceivePublicKey, p.RosterPeers[i].ReceivePublicKey) {
			return tAlarm{"inbox", "the inbox carries a roster other than the one checked with the peers", blocks}
		}
	}
	var own struct {
		Commitments []string `json:"commitments"`
	}
	_ = json.Unmarshal(p.Deal, &own)
	for _, d := range in.Dealers {
		if d.DealerID == T.id && !equalFoldAll(d.Commitments, own.Commitments) {
			return tAlarm{"inbox-own-deal", "the inbox carries commitments for this trustee's own deal other than the ones it dealt", blocks}
		}
	}
	tmp := T.shareFile(p) + trusteeNewSuffix
	_ = os.Remove(tmp)
	raw, err := T.opRaw(ctx, "dkg-receive", map[string]any{
		"receive_key_file": T.keyFile(p), "share_file": tmp, "params": p.Params,
		"trustee_id": T.id, "peers": p.RosterPeers, "dealers": in.Dealers,
	})
	if err != nil {
		var opErr *liveOpError
		if errors.As(err, &opErr) {
			// A share that does not verify, or one masked under another
			// roster: dkg-receive names the dealer.
			return tAlarm{"receive", "dkg-receive refused the shares: " + opErr.Msg, blocks}
		}
		return err
	}
	var a trusteeAck
	if json.Unmarshal(raw, &a) != nil || a.TrusteeID != T.id || !strings.EqualFold(a.RosterDigest, p.RosterDigest) {
		return tAlarm{"receive", "dkg-receive's output is for another trustee or roster", blocks}
	}
	return T.update(func(p *trusteeProgress) { p.Ack = raw })
}

// checkTranscript reads the published transcript from the chain and checks it
// against this trustee's own deal and acknowledgement: its own commitments,
// the joint key and its own verification key. A mismatch is an alarm that
// blocks Decrypt and Sign for this election.
func (T *TrusteeService) checkTranscript(ctx context.Context, v *LiveElectionView) error {
	p := T.p
	if liveStateIndex(v.State) < liveStateIndex(LiveOpen) {
		if v.CeremonyError != "" {
			return fmt.Errorf("the console did not publish the transcript: %s", v.CeremonyError)
		}
		return waitf("acknowledged; waiting for every trustee's acknowledgement and the transcript on the chain")
	}
	c, err := T.getChain()
	if err != nil {
		return tChainErr{"the DKG transcript", err}
	}
	dkg, err := c.GetDKGTranscript(p.ElectionID)
	if chainAbsent(err) {
		return waitf("the console says the transcript is published; it is not on the chain yet")
	}
	if err != nil {
		return tChainErr{"the DKG transcript", err}
	}
	mismatch := func(why string) error {
		_ = T.update(func(p *trusteeProgress) { p.TranscriptCheck = "mismatch"; p.TranscriptPublished = true })
		return tAlarm{"transcript", "the transcript on the chain does not match this trustee's keys: " + why, []string{"join", "decrypt", "sign"}}
	}
	raw, err := hex.DecodeString(dkg)
	if err != nil {
		return mismatch("it is not hex")
	}
	var tr pb.DKGTranscript
	if err := proto.Unmarshal(raw, &tr); err != nil {
		return mismatch("it does not decode")
	}
	if tr.ElectionId != p.ElectionID || int(tr.Threshold) != p.Threshold {
		return mismatch("it is for another election or threshold")
	}
	var own struct {
		Commitments []string `json:"commitments"`
	}
	_ = json.Unmarshal(p.Deal, &own)
	type dealerIn struct {
		DealerID    int      `json:"dealer_id"`
		Commitments []string `json:"commitments"`
	}
	var dealers []dealerIn
	seenOwn := false
	for _, tc := range tr.TrusteeCommitments {
		id, err := strconv.Atoi(tc.TrusteeId)
		if err != nil {
			return mismatch(fmt.Sprintf("it names trustee %q", tc.TrusteeId))
		}
		var cs []string
		for _, b := range tc.CoefficientCommitments {
			cs = append(cs, hex.EncodeToString(b))
		}
		if id == T.id {
			seenOwn = true
			if !equalFoldAll(cs, own.Commitments) {
				return mismatch("this trustee's commitments under its id are not the ones it dealt")
			}
		}
		dealers = append(dealers, dealerIn{DealerID: id, Commitments: cs})
	}
	if !seenOwn {
		return mismatch("this trustee's commitments are missing")
	}
	var out liveTranscript
	if err := T.op(ctx, "dkg-transcript", map[string]any{"params": p.Params, "dealers": dealers}, &out); err != nil {
		var opErr *liveOpError
		if errors.As(err, &opErr) {
			return mismatch(opErr.Msg)
		}
		return err
	}
	ack := p.ack()
	if ack == nil {
		return errors.New("no acknowledgement recorded")
	}
	if !strings.EqualFold(out.DKG, dkg) {
		return mismatch("its encoding is not the transcript of its own commitments")
	}
	if !strings.EqualFold(out.JointPublicKey, ack.JointPublicKey) {
		return mismatch(fmt.Sprintf("its joint key %s is not the one this trustee derived, %s", out.JointKeyFingerprint, ack.JointKeyFingerprint))
	}
	vkOK := false
	for _, vk := range out.VerificationKeys {
		if vk.TrusteeID == T.idStr && strings.EqualFold(vk.VerificationKey, ack.VerificationKey) {
			vkOK = true
		}
	}
	if !vkOK {
		return mismatch("its verification key for this trustee is not this trustee's key share")
	}
	return T.update(func(p *trusteeProgress) {
		p.TranscriptCheck, p.ChainDKG, p.TranscriptPublished = "ok", strings.ToLower(dkg), true
	})
}

func equalFoldAll(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}

// --- step 2: decrypt -----------------------------------------------------------

// chainBallots reads every ballot record of the election from the chain and
// checks the count against the chain's nullifier count, read again after.
func (T *TrusteeService) chainBallots(eid string) ([]string, error) {
	c, err := T.getChain()
	if err != nil {
		return nil, tChainErr{"the ballots", err}
	}
	nullifiers, err := allNullifiers(c, eid)
	if err != nil {
		return nil, tChainErr{"the ballot list", err}
	}
	seen := map[string]bool{}
	for _, n := range nullifiers {
		if seen[n] {
			return nil, fmt.Errorf("the chain lists nullifier %s twice", n)
		}
		seen[n] = true
	}
	ballots, err := getBallots(c, eid, nullifiers)
	if err != nil {
		return nil, tChainErr{"the ballots", err}
	}
	again, err := allNullifiers(c, eid)
	if err != nil {
		return nil, tChainErr{"the ballot list", err}
	}
	if len(ballots) != len(nullifiers) || len(again) != len(nullifiers) {
		return nil, fmt.Errorf("read %d ballot records, but the chain's nullifier count is %d (then %d): refusing to decrypt a set that does not match the chain's count",
			len(ballots), len(nullifiers), len(again))
	}
	return ballots, nil
}

// chainParamsDKG reads the parameters and the transcript from the chain and
// checks them against the ones this trustee checked at the ceremony.
func (T *TrusteeService) chainParamsDKG() (string, string, error) {
	p := T.p
	c, err := T.getChain()
	if err != nil {
		return "", "", tChainErr{"the election", err}
	}
	params, err := c.GetElection(p.ElectionID)
	if err != nil {
		return "", "", tChainErr{"the election", err}
	}
	dkg, err := c.GetDKGTranscript(p.ElectionID)
	if err != nil {
		return "", "", tChainErr{"the DKG transcript", err}
	}
	if !strings.EqualFold(params, p.Params) || !strings.EqualFold(dkg, p.ChainDKG) {
		return "", "", tAlarm{"chain-changed", "the chain's parameters or transcript are not the ones checked at the ceremony", []string{"decrypt", "sign"}}
	}
	return p.Params, p.ChainDKG, nil
}

// ballotSet is the aggregate op's ballot-set fields.
type ballotSet struct {
	BallotCount        int            `json:"ballot_count"`
	BallotsDigest      string         `json:"ballots_digest"`
	BallotsFingerprint string         `json:"ballots_fingerprint"`
	BallotsByPosition  map[string]int `json:"ballots_by_position"`
}

// positionsOf is the election's position ids, from its contest ids.
func positionsOf(contestIDs []string) []string {
	var out []string
	for _, c := range contestIDs {
		pos, _, _ := strings.Cut(c, "/")
		if !slices.Contains(out, pos) {
			out = append(out, pos)
		}
	}
	return out
}

// ChainClosed reports whether the chain says the election is closed.
func (T *TrusteeService) ChainClosed() (bool, string, error) {
	T.mu.Lock()
	p := T.p
	T.mu.Unlock()
	if p == nil {
		return false, "", errors.New("no election")
	}
	c, err := T.getChain()
	if err != nil {
		return false, "", tChainErr{"the election status", err}
	}
	status, err := c.GetElectionStatus(p.ElectionID)
	if err != nil {
		return false, "", tChainErr{"the election status", err}
	}
	return status == "closed", status, nil
}

// advanceDecrypt decrypts once per election: over every ballot on the chain,
// recording the ballot set's digest, refusing a position under --min-ballots
// and a later run over another set; then posts the partial and reads it back.
func (T *TrusteeService) advanceDecrypt(ctx context.Context) error {
	T.begin("decrypt")
	p := T.p
	if p.TranscriptCheck != "ok" {
		return refusedf("this trustee has not joined the ceremony and checked the transcript, so it holds no checked key share")
	}
	if len(p.Partial) == 0 {
		closed, status, err := T.ChainClosed()
		if err != nil {
			return err
		}
		if !closed {
			return refusedf("the chain says the election is %s, not closed: decryption waits for CloseElection", status)
		}
		params, dkg, err := T.chainParamsDKG()
		if err != nil {
			return err
		}
		ballots, err := T.chainBallots(p.ElectionID)
		if err != nil {
			return err
		}
		var set ballotSet
		if err := T.op(ctx, "aggregate", map[string]any{"params": params, "dkg": dkg, "ballots": ballots}, &set); err != nil {
			return err
		}
		if set.BallotCount != len(ballots) {
			return fmt.Errorf("aggregate counted %d ballots of %d", set.BallotCount, len(ballots))
		}
		if p.BallotsDigest != "" && !strings.EqualFold(p.BallotsDigest, set.BallotsDigest) {
			return refusedf("this trustee already used ballot set %s for this election; the chain now gives %s: one decryption per election, over one ballot set",
				p.BallotsFingerprint, set.BallotsFingerprint)
		}
		for _, pos := range positionsOf(p.ContestIDs) {
			if n := set.BallotsByPosition[pos]; n < T.minBallots {
				return refusedf("position %s has %d ballot record(s), fewer than --min-ballots %d: its aggregate would show individual votes", pos, n, T.minBallots)
			}
		}
		if err := T.update(func(p *trusteeProgress) {
			p.BallotsDigest, p.BallotsFingerprint = strings.ToLower(set.BallotsDigest), set.BallotsFingerprint
			p.BallotCount, p.BallotsByPosition = set.BallotCount, set.BallotsByPosition
		}); err != nil {
			return err
		}
		if err := T.checkPeersBallots(ctx); err != nil {
			return err
		}
		raw, err := T.opRaw(ctx, "partial", map[string]any{"share_file": T.shareFile(p), "params": params, "dkg": dkg, "ballots": ballots})
		if err != nil {
			return err
		}
		var out ballotSet
		if json.Unmarshal(raw, &out) != nil || !strings.EqualFold(out.BallotsDigest, p.BallotsDigest) {
			return errors.New("partial decrypted a ballot set other than the one recorded")
		}
		if err := T.update(func(p *trusteeProgress) { p.Partial = raw }); err != nil {
			return err
		}
		if T.crashed("partial-saved") {
			return errTrusteeKilled
		}
	}

	if !p.PartialPosted {
		code, body, err := T.console.doRaw(ctx, "POST", "/api/live/partial", p.Partial)
		if err != nil {
			return err
		}
		switch {
		case code == 200:
		case code == 409 && strings.Contains(errorText(body), "different partial"):
			return tAlarm{"partial-conflict", "the chain holds a different partial decryption under this trustee's id: " + errorText(body), []string{"decrypt", "sign"}}
		case code == 409 && strings.Contains(errorText(body), "being recorded"):
			return waitf("the console is recording this trustee's partials")
		default:
			return fmt.Errorf("the console refused the partial decryption: %d %s", code, errorText(body))
		}
		if err := T.update(func(p *trusteeProgress) { p.PartialPosted = true }); err != nil {
			return err
		}
	}

	if p.PartialReadBack != "ok" {
		return T.readBackPartial()
	}
	return nil
}

// readBackPartial reads this trustee's partials back from the chain and
// compares bytes with what it computed.
func (T *TrusteeService) readBackPartial() error {
	p := T.p
	var out struct {
		Partials []struct {
			ContestID string `json:"contest_id"`
			Partial   string `json:"partial"`
		} `json:"partials"`
	}
	if err := json.Unmarshal(p.Partial, &out); err != nil {
		return err
	}
	c, err := T.getChain()
	if err != nil {
		return tChainErr{"this trustee's partial decryption", err}
	}
	for _, x := range out.Partials {
		got, err := c.GetPartialDecryption(p.ElectionID, x.ContestID, T.idStr)
		if chainAbsent(err) {
			return waitf("the partial for %s is not on the chain yet", x.ContestID)
		}
		if err != nil {
			return tChainErr{"this trustee's partial decryption", err}
		}
		a, _ := hex.DecodeString(got)
		b, _ := hex.DecodeString(x.Partial)
		if len(a) == 0 || !bytes.Equal(a, b) {
			_ = T.update(func(p *trusteeProgress) { p.PartialReadBack = "mismatch" })
			return tAlarm{"partial-readback", fmt.Sprintf("the chain's partial decryption for %s under this trustee's id is not the one it computed", x.ContestID), []string{"decrypt", "sign"}}
		}
	}
	return T.update(func(p *trusteeProgress) { p.PartialReadBack = "ok" })
}

// checkPeersBallots compares this trustee's ballot-set digest with every
// other trustee that has one for this election. A difference refuses the
// decryption; a peer that has none yet is not waited for, because every
// trustee reads the set from the chain itself.
func (T *TrusteeService) checkPeersBallots(ctx context.Context) error {
	p := T.p
	checks := map[string]peerCheck{}
	var alarm error
	for id := 1; id <= p.Trustees; id++ {
		if id == T.id {
			continue
		}
		key := strconv.Itoa(id)
		v, err := T.fetchPeer(ctx, id)
		switch {
		case err != nil:
			checks[key] = peerCheck{State: "waiting", Detail: "not reachable: " + err.Error()}
		case v.ElectionID != p.ElectionID || v.BallotsDigest == "":
			checks[key] = peerCheck{State: "waiting", Detail: "it has no ballot set for this election yet"}
		case !strings.EqualFold(v.BallotsDigest, p.BallotsDigest):
			checks[key] = peerCheck{State: "mismatch", Detail: fmt.Sprintf("trustee %d read ballot set %s, this trustee %s", id, v.BallotsFingerprint, p.BallotsFingerprint)}
			if alarm == nil {
				alarm = tAlarm{"ballots-peer-" + key, checks[key].Detail, []string{"decrypt", "sign"}}
			}
		default:
			checks[key] = peerCheck{State: "ok"}
		}
	}
	if err := T.update(func(p *trusteeProgress) { p.PeerBallotChecks = checks }); err != nil {
		return err
	}
	return alarm
}

// --- step 3: combine (automatic) and sign (on the trustee's press) -----------

// advanceCombine runs this trustee's own combine once at least threshold
// trustees' partials are on the chain, so the totals can be shown before
// anything is signed. It runs by itself; errors are shown on the sign step.
func (T *TrusteeService) advanceCombine(ctx context.Context, v *LiveElectionView) error {
	T.mu.Lock()
	p := T.p
	ready := p.TranscriptCheck == "ok" && len(p.Totals) == 0 && p.blocked("sign") == nil
	T.mu.Unlock()
	if !ready || liveStateIndex(v.State) < liveStateIndex(LiveClosed) {
		return nil
	}
	if v.Counts.TrusteesDecrypted < p.Threshold && liveStateIndex(v.State) < liveStateIndex(LiveTallied) {
		return nil
	}
	err := T.combine(ctx)
	var alarm tAlarm
	T.mu.Lock()
	signState := p.step("sign").State
	T.mu.Unlock()
	if signState != stepIdle && signState != stepWaiting {
		return nil // the trustee pressed Sign; that step reports from here on
	}
	switch {
	case err == nil:
		T.setStep("sign", stepWaiting, "your own combine gives the totals shown; press Sign tally to sign them", "")
	case errors.As(err, &alarm):
		T.raise(alarm.code, alarm.msg, alarm.blocks...)
		T.setStep("sign", stepBlocked, "", alarm.msg)
	default:
		var wait tWait
		if errors.As(err, &wait) {
			T.setStep("sign", stepWaiting, wait.msg, "")
		} else {
			T.setStep("sign", stepWaiting, "", "combining: "+err.Error())
		}
	}
	return err
}

func (T *TrusteeService) combine(ctx context.Context) error {
	p := T.p
	params, dkg, err := T.chainParamsDKG()
	if err != nil {
		return err
	}
	ballots, err := T.chainBallots(p.ElectionID)
	if err != nil {
		return err
	}
	var set ballotSet
	if err := T.op(ctx, "aggregate", map[string]any{"params": params, "dkg": dkg, "ballots": ballots}, &set); err != nil {
		return err
	}
	if p.BallotsDigest != "" && !strings.EqualFold(p.BallotsDigest, set.BallotsDigest) {
		return tAlarm{"ballots-changed", fmt.Sprintf("the chain's ballot set is now %s, not the %s this trustee used", set.BallotsFingerprint, p.BallotsFingerprint), []string{"sign"}}
	}
	c, err := T.getChain()
	if err != nil {
		return tChainErr{"the partial decryptions", err}
	}
	var partials []string
	complete := 0
	for id := 1; id <= p.Trustees; id++ {
		n := 0
		for _, contest := range p.ContestIDs {
			h, err := c.GetPartialDecryption(p.ElectionID, contest, strconv.Itoa(id))
			if chainAbsent(err) {
				continue
			}
			if err != nil {
				return tChainErr{"the partial decryptions", err}
			}
			partials = append(partials, h)
			n++
		}
		if n == len(p.ContestIDs) {
			complete++
		}
	}
	if complete < p.Threshold {
		return waitf("waiting for decryptions: %d of %d trustees' partials on the chain", complete, p.Threshold)
	}
	var out struct {
		Totals   []uint64              `json:"totals"`
		Contests []trusteeContestTotal `json:"contests"`
	}
	if err := T.op(ctx, "combine", map[string]any{"params": params, "dkg": dkg, "ballots": ballots, "partials": partials}, &out); err != nil {
		return err
	}
	return T.update(func(p *trusteeProgress) {
		if p.BallotsDigest == "" {
			p.BallotsDigest, p.BallotsFingerprint = strings.ToLower(set.BallotsDigest), set.BallotsFingerprint
			p.BallotCount, p.BallotsByPosition = set.BallotCount, set.BallotsByPosition
		}
		p.CombinePartials, p.Totals, p.Contests = partials, out.Totals, out.Contests
	})
}

// advanceSign signs the totals the trustee approved and posts the signature.
func (T *TrusteeService) advanceSign(ctx context.Context) error {
	T.begin("sign")
	p := T.p
	T.mu.Lock()
	approved := slices.Clone(p.SignTotals)
	T.mu.Unlock()
	if len(p.Totals) == 0 || !slices.Equal(p.Totals, approved) {
		return refusedf("the approved totals are not this trustee's own combine")
	}
	if len(p.Signature) == 0 {
		params, dkg, err := T.chainParamsDKG()
		if err != nil {
			return err
		}
		ballots, err := T.chainBallots(p.ElectionID)
		if err != nil {
			return err
		}
		raw, err := T.opRaw(ctx, "sign-tally", map[string]any{
			"share_file": T.shareFile(p), "params": params, "dkg": dkg,
			"ballots": ballots, "partials": p.CombinePartials, "totals": p.Totals,
		})
		if err != nil {
			return err
		}
		var out ballotSet
		if json.Unmarshal(raw, &out) != nil || !strings.EqualFold(out.BallotsDigest, p.BallotsDigest) {
			return refusedf("the chain's ballot set changed since this trustee combined; nothing was signed")
		}
		if err := T.update(func(p *trusteeProgress) { p.Signature = raw }); err != nil {
			return err
		}
		if T.crashed("sig-saved") {
			return errTrusteeKilled
		}
	}
	if !p.SignaturePosted {
		code, body, err := T.console.doRaw(ctx, "POST", "/api/live/tally-sig", p.Signature)
		if err != nil {
			return err
		}
		text := errorText(body)
		switch {
		case code == 200:
			var res struct {
				PublishError string `json:"publish_error"`
			}
			_ = json.Unmarshal(body, &res)
			note := ""
			if res.PublishError != "" {
				note = "signature kept; the console's publication failed: " + res.PublishError
			}
			if err := T.update(func(p *trusteeProgress) { p.SignaturePosted, p.SignatureNote = true, note }); err != nil {
				return err
			}
		case code == 400:
			return tAlarm{"tally-totals", "the console refused this trustee's signature, so its totals differ from this trustee's own combine: " + text, []string{"sign"}}
		case code == 409 && (strings.Contains(text, "is tallied") || strings.Contains(text, "is verified")):
			_ = T.update(func(p *trusteeProgress) {
				p.SignatureNote = "the tally was published with other trustees' signatures before this one was posted"
			})
			return nil
		default:
			return fmt.Errorf("the console refused the signature: %d %s", code, text)
		}
	}
	return nil
}

// checkPublished reads the published tally from the chain and compares it
// with this trustee's own combine.
func (T *TrusteeService) checkPublished(v *LiveElectionView) {
	T.mu.Lock()
	p := T.p
	known := p.TallyPublished
	T.mu.Unlock()
	if known || liveStateIndex(v.State) < liveStateIndex(LiveTallied) {
		return
	}
	c, err := T.getChain()
	if err != nil {
		return
	}
	tally, err := c.GetTally(p.ElectionID)
	if err != nil || tally == "" {
		return
	}
	totals, err := decodeTallyTotals(tally)
	if err != nil {
		return
	}
	_ = T.update(func(p *trusteeProgress) { p.TallyPublished, p.TallyTotals = true, totals })
	if len(p.Totals) > 0 && !slices.Equal(totals, p.Totals) {
		T.raise("tally-differs", fmt.Sprintf("the tally on the chain %v is not this trustee's own combine %v", totals, p.Totals))
	}
}

// --- ops ---------------------------------------------------------------------------

func (T *TrusteeService) opRaw(ctx context.Context, op string, in any) ([]byte, error) {
	data, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, trusteeOpTimeout)
	defer cancel()
	return T.run(ctx, op, data)
}

func (T *TrusteeService) op(ctx context.Context, op string, in, out any) error {
	raw, err := T.opRaw(ctx, op, in)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s: unreadable output", op)
	}
	return nil
}

// ExecLiveRunner is the production LiveRunner over the saksi-demo binary.
func ExecLiveRunner(bin string) LiveRunner { return execLiveRunner(bin) }

// TrusteeFabricDial opens the trustee's own read connection to the ledger.
func TrusteeFabricDial(cfg FabricConfig) func() (trusteeChain, error) {
	return func() (trusteeChain, error) {
		conn, err := cfg.Connect()
		if err != nil {
			return nil, err
		}
		return conn.Bulletin, nil
	}
}

// ProbeConsole checks at start-up that the console answers on this URL.
func (T *TrusteeService) ProbeConsole(ctx context.Context) error { return T.console.Probe(ctx) }
