package campaign

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// Live mode: the console as election authority, credential issuer and ballot
// relay for one real election (docs/live/http-api.md).
//
// Every cryptographic step is `saksi-demo live <op>` with JSON on stdin and
// JSON on stdout (docs/live/wire-format.md). The console holds one secret, the
// issuer key, by file path under the run's private folder; it never decrypts,
// never runs a trustee's op, and relays the phones' ballots and the trustees'
// masked shares unchanged.
//
// State lives in <run>/live.json, rewritten atomically at every transition and
// after every recorded item; a restart loads it and reconciles with the chain
// (resume). Secrets live in <run>/private/ (0700; files 0600), which no public
// route, export or log line ever reads out.

// ModeLive is the ElectionConfig.Mode recorded in a live run's run.json. It is
// never accepted from a posted study config (Validate refuses it): live runs
// are made only by POST /api/live/elections.
const ModeLive = "live"

// Live election states, in order.
const (
	LiveSetup    = "setup"
	LiveCeremony = "ceremony"
	LiveOpen     = "open"
	LiveClosed   = "closed"
	LiveTallied  = "tallied"
	LiveVerified = "verified"
	// LiveAbandoned is terminal and outside the order above: an election the
	// presenter gave up in setup or ceremony, before any credential or ballot
	// existed (POST /api/live/abandon). It is never tallied or verified.
	LiveAbandoned = "abandoned"
)

const (
	liveStateFile   = "live.json"
	livePrivateDir  = "private"
	liveIssuerKey   = "issuer.key"
	liveSessionsDir = "sessions"
	// LiveVerifyFile is the verifier's JSON for the last POST /api/live/verify.
	LiveVerifyFile  = "live-verify.json"
	liveStateSchema = "saksi-live-console-state-v1"

	liveSessionTTL    = 10 * time.Minute
	liveMaxSessions   = 8
	liveMaxBallotBody = 256 << 10
	liveMaxTitle      = 200
)

// LivePosition is one race: its wire id and its candidates' wire ids.
type LivePosition struct {
	ID         string   `json:"id"`
	Candidates []string `json:"candidates"`
}

// LiveTx is one recorded transaction.
type LiveTx struct {
	TxID        string `json:"tx_id"`
	BlockNumber uint64 `json:"block_number"`
}

func txOf(r clientsdk.Receipt) LiveTx { return LiveTx{TxID: r.TxID, BlockNumber: r.BlockNumber} }

// liveDeal is one dealer's posted deal. MaskedShares[k] is for recipient k+1,
// exactly the JSON object the dealer posted.
type liveDeal struct {
	Commitments  []string          `json:"commitments"`
	MaskedShares []json.RawMessage `json:"masked_shares"`
}

// liveAck is the public half of a trustee's dkg-receive output.
type liveAck struct {
	VerificationKey     string `json:"verification_key"`
	Fingerprint         string `json:"fingerprint"`
	JointPublicKey      string `json:"joint_public_key"`
	JointKeyFingerprint string `json:"joint_key_fingerprint"`
	RosterDigest        string `json:"roster_digest"`
}

// liveSig is one trustee's signature over the totals it combined itself.
type liveSig struct {
	Totals    []uint64  `json:"totals"`
	Signature string    `json:"signature"`
	At        time.Time `json:"at"`
}

// liveState is <run>/live.json. Nothing in it is secret, and nothing in it
// names a voter or links a ballot to one.
type liveState struct {
	Schema     string         `json:"schema"`
	RunID      string         `json:"run_id"`
	ElectionID string         `json:"election_id"`
	Title      string         `json:"title"`
	Positions  []LivePosition `json:"positions"`
	Trustees   int            `json:"trustees"`
	Threshold  int            `json:"threshold"`
	State      string         `json:"state"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`

	Params          string   `json:"params"`
	ContestIDs      []string `json:"contest_ids"`
	IssuerPublicKey string   `json:"issuer_public_key"`

	Lifecycle map[string]LiveTx `json:"lifecycle"`

	ReceiveKeys  map[string]string   `json:"receive_keys"`
	Roster       json.RawMessage     `json:"roster,omitempty"`
	RosterDigest string              `json:"roster_digest,omitempty"`
	Deals        map[string]liveDeal `json:"deals"`
	Acks         map[string]liveAck  `json:"acks"`
	// Transcript is the dkg-transcript output; DKG its PublishDKGTranscript
	// argument.
	Transcript          json.RawMessage `json:"transcript,omitempty"`
	DKG                 string          `json:"dkg,omitempty"`
	JointPublicKey      string          `json:"joint_public_key,omitempty"`
	JointKeyFingerprint string          `json:"joint_key_fingerprint,omitempty"`
	CeremonyError       string          `json:"ceremony_error,omitempty"`

	Ballots int `json:"ballots"`
	Issued  int `json:"credentials_issued"`

	// The voter list's public facts: the precinct, the fingerprint and the
	// number of entries. The list itself is in private/ (live_checkin.go).
	Precinct             string `json:"precinct,omitempty"`
	VoterListFingerprint string `json:"voter_list_fingerprint,omitempty"`
	VotersOnList         int    `json:"voters_on_list,omitempty"`

	Partials   map[string]map[string]LiveTx `json:"partials"`
	Signatures map[string]liveSig           `json:"signatures"`

	Tally         string          `json:"tally,omitempty"`
	Totals        []uint64        `json:"totals,omitempty"`
	VerifyOverall string          `json:"verify_overall,omitempty"`
	Verify        json.RawMessage `json:"verify,omitempty"`
}

func (st *liveState) stateIndex() int { return liveStateIndex(st.State) }

// minBallotRecords is the console's figure for the fewest ballot records an
// election with these contest ids can be decrypted over: --live-min-ballots
// for each position (a voter's ballot is one record per position), the same
// rule the trustee process applies with its own --min-ballots. It is shown
// from open on (0, left out of the JSON, before that and when abandoned).
//
// The positions are counted from the contest ids with positionsOf, literally
// the trustee process's count (TrusteeService.minBallotRecords).
func (L *liveService) minBallotRecords(state string, contestIDs []string) int {
	if liveStateIndex(state) < liveStateIndex(LiveOpen) {
		return 0
	}
	return L.minBallots * len(positionsOf(contestIDs))
}

// CheckLiveMinBallots refuses a --live-min-ballots value below 1, in one
// sentence. The command checks the flag with it before EnableLive.
func CheckLiveMinBallots(n int) error {
	if n < 1 {
		return fmt.Errorf("--live-min-ballots is %d; it must be at least 1, the fewest ballot records per position decryption can need", n)
	}
	return nil
}

func liveStateIndex(s string) int {
	for i, x := range []string{LiveSetup, LiveCeremony, LiveOpen, LiveClosed, LiveTallied, LiveVerified} {
		if x == s {
			return i
		}
	}
	return -1
}

// trusteeIDs is "1".."n".
func trusteeIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = strconv.Itoa(i + 1)
	}
	return ids
}

// LiveRunner runs `saksi-demo live <op>` with input on stdin and returns its
// stdout. A failure's error is the op's own message (which never carries
// secret material); tests inject a fake.
type LiveRunner func(ctx context.Context, op string, input []byte) ([]byte, error)

// liveOpError is a `saksi-demo live` op that refused or failed.
type liveOpError struct {
	Op  string
	Msg string
}

func (e *liveOpError) Error() string { return e.Op + ": " + e.Msg }

// liveRunError is a `saksi-demo live` op that did not run to an answer: it
// crashed, was killed, timed out or could not be started, so stderr carries
// no JSON {"error"}. It says nothing about the input: callers never turn it
// into a refusal or an alarm, and a retry may succeed.
type liveRunError struct {
	Op  string
	Msg string
}

func (e *liveRunError) Error() string { return e.Op + " did not run to an answer: " + e.Msg }

// isRunFailure reports whether err is an op that did not run to an answer.
func isRunFailure(err error) bool {
	var r *liveRunError
	return errors.As(err, &r)
}

// execLiveRunner is the production LiveRunner over the saksi-demo binary.
func execLiveRunner(bin string) LiveRunner {
	return func(ctx context.Context, op string, input []byte) ([]byte, error) {
		cmd := exec.CommandContext(ctx, bin, "live", op)
		cmd.Stdin = bytes.NewReader(input)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			var body struct {
				Error string `json:"error"`
			}
			if json.Unmarshal(stderr.Bytes(), &body) == nil && body.Error != "" {
				// The op answered: it refused this input.
				return nil, &liveOpError{Op: op, Msg: body.Error}
			}
			msg := err.Error()
			if ctx.Err() != nil {
				msg = ctx.Err().Error()
			}
			if t := strings.TrimSpace(stderr.String()); t != "" {
				msg += " (" + truncateErr(t) + ")"
			}
			return nil, &liveRunError{Op: op, Msg: msg}
		}
		return stdout.Bytes(), nil
	}
}

// liveChain is what the live election needs from the bulletin chaincode.
type liveChain interface {
	// Submit submits fn and waits for its commit, returning its receipt. A
	// chaincode refusal comes back with the endorsers' messages reachable
	// through clientsdk.ErrorText.
	Submit(fn string, args ...string) (clientsdk.Receipt, error)
	GetElection(electionID string) (string, error)
	GetElectionStatus(electionID string) (string, error)
	GetDKGTranscript(electionID string) (string, error)
	GetTally(electionID string) (string, error)
	ListNullifiers(electionID string, pageSize int, bookmark string) (clientsdk.NullifierPage, error)
	GetBallot(electionID, nullifier string) (string, error)
	GetBallots(electionID string, nullifiers []string) ([]string, error)
	GetPartialDecryption(electionID, contestID, trusteeID string) (string, error)
}

// fabricLiveChain is liveChain over a gateway connection.
type fabricLiveChain struct {
	*clientsdk.BulletinClient
	led clientsdk.Ledger
}

func (c fabricLiveChain) Submit(fn string, args ...string) (clientsdk.Receipt, error) {
	_, rc, err := c.led.SubmitWithReceipt(fn, args...)
	return rc, err
}

// absentRe matches the chaincode's "no <thing> found" answer to a getter.
var absentRe = regexp.MustCompile(`no [a-zA-Z ]+ found`)

func chainAbsent(err error) bool {
	return err != nil && absentRe.MatchString(clientsdk.ErrorText(err))
}

// LiveOptions configures live mode.
type LiveOptions struct {
	// TrusteeTokens is the --trustee-tokens file.
	TrusteeTokens string
	// Runner runs the live ops; nil = the executor's saksi-demo binary.
	Runner LiveRunner
	// Dial opens the chain; nil = the configured Fabric network.
	Dial func() (liveChain, error)
	// Now is the clock; nil = time.Now.
	Now func() time.Time
	// Precinct is --live-precinct; "" = DefaultLivePrecinct.
	Precinct string
	// MinBallots is --live-min-ballots. 0 (an unset field, for callers
	// other than the command) = DefaultMinBallots; below 0 is refused.
	MinBallots int
}

// liveService is the console's one live election.
type liveService struct {
	s      *Server
	root   string
	tokens *trusteeTokens
	run    LiveRunner
	dial   func() (liveChain, error)
	now    func() time.Time
	limit  *rateLimiter
	// ledgerLimit is GET /api/live/ledger's own bucket: a client looping the
	// ledger cannot use up the ballots' tokens.
	ledgerLimit *rateLimiter

	chainMu sync.Mutex
	chain   liveChain

	// mu guards st and every write to the run folder.
	mu  sync.Mutex
	st  *liveState
	dir string

	// partialBusy marks a trustee whose partials are in flight (guarded by mu).
	partialBusy map[string]bool

	// snap is the public view, rebuilt under mu at every save (live_snapshot.go).
	// Readers that must not wait on mu read it instead of st.
	snap atomic.Pointer[liveSnapshot]

	// issueMu serializes issuance: one issue-presign or issue-sign at a time,
	// across all list entries. A desk refuse or reset takes it too.
	issueMu sync.Mutex

	// precinct is the --live-precinct value new elections are set up with.
	precinct string
	// minBallots is --live-min-ballots: the console's own figure for the
	// fewest ballot records per position decryption needs. The trustee
	// processes apply their own --min-ballots; nothing checks the two agree.
	minBallots int
	// ckMu guards ck, the current election's voter list and check-in record
	// (live_checkin.go). Lock order: issueMu, then mu, then ckMu; ckMu is
	// never held while taking another.
	ckMu sync.Mutex
	ck   *checkinBook
	// ckView is the published check-in counts, read without ckMu.
	ckView atomic.Pointer[checkinView]
	// findLimit limits find and declare per caller address.
	findLimit *addrLimiter
	// counts is the chain count the public reads share (live_tally.go).
	counts chainCountCache

	// verifyMu guards verifyCall and auto (live_tally.go). Lock order: mu,
	// then verifyMu; verifyMu is never held while taking another lock.
	verifyMu sync.Mutex
	// verifyCall is the verify-live run in flight, or nil: a press that
	// arrives during a run waits for it and answers its result.
	verifyCall *liveVerifyCall
	// auto is the automatic verification's status for the run autoRun.
	auto    LiveAutoVerify
	autoRun string
	// bg counts background work (the automatic verification).
	bg sync.WaitGroup
}

// EnableLive turns on the live routes. Call it after EnableAuth: the
// presenter is an account. It loads the newest live election from
// the run store, if any, and resumes it from disk and the chain.
func (s *Server) EnableLive(o LiveOptions) error {
	if s.auth == nil {
		return errors.New("live mode needs --auth-file: the presenter's account is in it")
	}
	if o.TrusteeTokens == "" {
		return errors.New("live mode needs --trustee-tokens: each trustee process authenticates with its own token")
	}
	tokens, err := LoadTrusteeTokens(o.TrusteeTokens)
	if err != nil {
		return err
	}
	precinct := o.Precinct
	if precinct == "" {
		precinct = DefaultLivePrecinct
	}
	if !ValidPrecinct(precinct) {
		return fmt.Errorf("--live-precinct %q: a precinct is four digits and a capital letter, like %s", precinct, DefaultLivePrecinct)
	}
	minBallots := o.MinBallots
	if minBallots == 0 {
		minBallots = DefaultMinBallots
	}
	if err := CheckLiveMinBallots(minBallots); err != nil {
		return err
	}
	L := &liveService{
		s: s, root: s.store.Root(), tokens: tokens,
		run: o.Runner, dial: o.Dial, now: o.Now,
		limit:       newRateLimiter(5, 30),
		ledgerLimit: newRateLimiter(2, 10),
		precinct:    precinct,
		minBallots:  minBallots,
		findLimit:   newAddrLimiter(findPerSec, findBurst, findMaxAddrs),
	}
	if L.run == nil {
		L.run = execLiveRunner(s.exec.demoBin)
	}
	if L.dial == nil {
		fabric := s.fabric
		L.dial = func() (liveChain, error) {
			if !fabric.Enabled() {
				return nil, errors.New("no Fabric network is configured (--fabric-tls-cert, --fabric-cert, --fabric-key)")
			}
			conn, err := fabric.Connect()
			if err != nil {
				return nil, err
			}
			return fabricLiveChain{BulletinClient: conn.Bulletin, led: conn.Ledger()}, nil
		}
	}
	if L.now == nil {
		L.now = time.Now
	}
	if err := L.load(); err != nil {
		return err
	}
	s.live = L
	if L.st != nil {
		if err := L.resume(context.Background()); err != nil {
			// Not fatal: the chain may come up after the console. Nothing
			// reconciles until the next start; a stuck setup is retried by
			// POST elections.
			log.Printf("live: resume %s: %v", L.st.RunID, err)
		}
		// Tallied with no verification result (the console stopped before
		// or during the automatic run, or the run failed to give a verdict):
		// start it again, once.
		L.mu.Lock()
		if L.st.State == LiveTallied && L.st.VerifyOverall == "" {
			L.startAutoVerifyLocked()
		}
		L.mu.Unlock()
	}
	return nil
}

// getChain dials once and caches the connection; a failure is never cached.
func (L *liveService) getChain() (liveChain, error) {
	L.chainMu.Lock()
	defer L.chainMu.Unlock()
	if L.chain != nil {
		return L.chain, nil
	}
	c, err := L.dial()
	if err != nil {
		return nil, err
	}
	L.chain = c
	return c, nil
}

func (L *liveService) privateDir() string  { return filepath.Join(L.dir, livePrivateDir) }
func (L *liveService) sessionsDir() string { return filepath.Join(L.privateDir(), liveSessionsDir) }

// load finds the newest live run and reads its state.
func (L *liveService) load() error {
	recs, err := L.s.store.List()
	if err != nil {
		return err
	}
	for _, rec := range recs { // newest first
		if rec.Config.Mode != ModeLive {
			continue
		}
		dir, err := L.s.store.Dir(rec.RunID)
		if err != nil {
			continue
		}
		var st liveState
		if err := readJSON(filepath.Join(dir, liveStateFile), &st); err != nil {
			continue // a run whose setup never got as far as its first state write
		}
		if st.Schema != liveStateSchema {
			return fmt.Errorf("live run %s: state schema %q, want %q", rec.RunID, st.Schema, liveStateSchema)
		}
		book, err := loadCheckinBook(dir)
		if err != nil {
			return fmt.Errorf("live run %s: %v", rec.RunID, err)
		}
		L.st, L.dir = &st, dir
		L.publishSnapshotLocked()
		L.ckMu.Lock()
		L.ck = book
		L.publishCheckinLocked()
		L.ckMu.Unlock()
		if err := sweepClaimed(L.sessionsDir()); err != nil {
			log.Printf("live: sweep sessions: %v", err)
		}
		return nil
	}
	return nil
}

// save writes the state atomically and republishes the public snapshot.
// Caller holds mu.
func (L *liveService) save() error {
	L.st.UpdatedAt = L.now().UTC()
	return L.saveUntimed()
}

// saveUntimed is save without touching updated_at: an issuance is saved this
// way, so no issuance time reaches live.json or the public view. Caller holds
// mu.
func (L *liveService) saveUntimed() error {
	L.syncIssuedLocked()
	L.publishSnapshotLocked()
	data, err := json.MarshalIndent(L.st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(L.dir, liveStateFile), data, 0o644)
}

// syncIssuedLocked copies the issued count from the published check-in
// counts, the issuance record's own (live_issue.go). Caller holds mu.
func (L *liveService) syncIssuedLocked() {
	if L.st == nil {
		return
	}
	if v := L.ckView.Load(); v != nil && v.RunID == L.st.RunID {
		L.st.Issued = v.Counts.Issued
	}
}

// writeFileAtomic writes data to path through a temporary file in the same
// folder, fsynced and renamed into place, then fsyncs the folder: a crash
// leaves either the old file or the new one, never a torn one.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // a no-op once renamed
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// opJSON runs op with in marshalled as its input and decodes its output.
func (L *liveService) opJSON(ctx context.Context, op string, in, out any) error {
	data, err := json.Marshal(in)
	if err != nil {
		return err
	}
	res, err := L.run(ctx, op, data)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(res, out); err != nil {
		return fmt.Errorf("%s: unreadable output: %v", op, err)
	}
	return nil
}

// newLiveRunID is a fresh election id: the ledger persists across consoles,
// so it carries the time and 32 random bits.
func newLiveRunID(now time.Time) (string, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("live-%s-%s", now.UTC().Format("20060102-150405"), hex.EncodeToString(buf)), nil
}

// --- setup -------------------------------------------------------------------

// LiveElectionRequest is POST /api/live/elections.
type LiveElectionRequest struct {
	Title     string         `json:"title"`
	Positions []LivePosition `json:"positions"`
	Trustees  int            `json:"trustees"`
	Threshold int            `json:"threshold"`
	// VoterList is the CSV text of the precinct's list; VoterListFingerprint
	// the fingerprint the presenter confirmed in the preview. The election is
	// not created unless the list is valid, non-empty and has that
	// fingerprint.
	VoterList            string `json:"voter_list"`
	VoterListFingerprint string `json:"voter_list_fingerprint"`
}

// errConflict is a request in the wrong state: 409 with this reason.
type errConflict struct{ msg string }

func (e errConflict) Error() string { return e.msg }

func conflictf(format string, args ...any) error { return errConflict{fmt.Sprintf(format, args...)} }

// errBadRequest is a malformed request: 400 with this reason, and a stable
// short code when one is set.
type errBadRequest struct {
	msg  string
	code string
}

func (e errBadRequest) Error() string { return e.msg }

func badRequestf(format string, args ...any) error {
	return errBadRequest{msg: fmt.Sprintf(format, args...)}
}

// errRefused is the chaincode refusing a transaction: 422 with its own words.
type errRefused struct {
	Fn     string
	Gate   string
	Reason string
}

func (e errRefused) Error() string { return e.Fn + " refused by the chain: " + e.Reason }

// errChain is the chain unreachable or failing for a reason that is not a
// refusal: 502.
type errChain struct{ err error }

func (e errChain) Error() string { return "the chain did not answer: " + clientsdk.ErrorText(e.err) }

// chainSubmit submits fn and classifies a failure as a refusal (the endorsers
// said why) or a chain fault.
func (L *liveService) chainSubmit(fn string, args ...string) (clientsdk.Receipt, error) {
	c, err := L.getChain()
	if err != nil {
		return clientsdk.Receipt{}, errChain{err}
	}
	rc, err := c.Submit(fn, args...)
	if err == nil {
		return rc, nil
	}
	text := clientsdk.ErrorText(err)
	if code := refusalCode(fn, text); code != "" {
		return clientsdk.Receipt{}, errRefused{Fn: fn, Gate: code, Reason: text}
	}
	return clientsdk.Receipt{}, errChain{err}
}

// refusalCode is a stable short code for which check refused fn, or "" when
// text is not a chaincode refusal at all. The chaincode's own "gate=<id>:"
// marker wins; PublishTally's checks carry none, so they are named here.
func refusalCode(fn, text string) string {
	if m := gateID.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	switch {
	case strings.Contains(text, "valid trustee signatures, threshold is"),
		strings.Contains(text, "carries no trustee signatures"):
		return "threshold"
	case strings.Contains(text, "does not verify"):
		return "signature"
	case strings.Contains(text, "already published"):
		return "already-published"
	case strings.Contains(text, "is not closed"):
		return "election-closed"
	case strings.Contains(text, "already exists"):
		return "already-exists"
	case strings.Contains(text, "already closed"):
		return "already-closed"
	case strings.Contains(text, "is not a trustee"), strings.Contains(text, "more than one signature"):
		return "signature"
	case strings.Contains(text, "chaincode response"), strings.Contains(text, "failed to endorse"):
		return "refused"
	}
	return ""
}

// createElection runs setup: the issuer key, the parameters, the run folder,
// then CreateElection. The state is written in setup before the transaction,
// so a crash in between resumes by finishing setup. While the current
// election is still in setup, the call retries its CreateElection instead
// (the posted fields are not used) and answers 200; a new election answers
// 201.
func (L *liveService) createElection(ctx context.Context, req LiveElectionRequest) (int, error) {
	L.mu.Lock()
	defer L.mu.Unlock()
	if L.st != nil && L.st.State == LiveSetup {
		log.Printf("live: %s retrying setup", L.st.RunID)
		return http.StatusOK, L.finishSetupLocked()
	}
	if L.st != nil && L.st.State != LiveVerified && L.st.State != LiveAbandoned {
		return 0, conflictf("live election %s is %s; one live election at a time (start the next once it is verified, or abandon it in setup or ceremony)", L.st.ElectionID, L.st.State)
	}
	req.Title = strings.TrimSpace(req.Title)
	if req.Title == "" || len(req.Title) > liveMaxTitle {
		return 0, badRequestf("title must be 1 to %d bytes", liveMaxTitle)
	}
	if req.Trustees == 0 {
		req.Trustees = 5
	}
	if req.Threshold == 0 {
		req.Threshold = 3
	}
	if req.Trustees < 1 || req.Trustees > MaxTrustees || req.Threshold < 1 || req.Threshold > req.Trustees {
		return 0, badRequestf("trustees must be 1..%d and threshold 1..trustees (got %d of %d)", MaxTrustees, req.Threshold, req.Trustees)
	}
	for i := 1; i <= req.Trustees; i++ {
		if !L.tokens.has(strconv.Itoa(i)) {
			return 0, badRequestf("trustee %d has no token in the trustee tokens file; the ceremony could never finish", i)
		}
	}
	now := L.now().UTC()
	if strings.TrimSpace(req.VoterList) == "" {
		return 0, errBadRequest{msg: "the election needs its voter list (voter_list, the CSV text)", code: "voter-list-missing"}
	}
	list := parseVoterList(req.VoterList, L.precinct, now)
	if !list.Valid() {
		return 0, errBadRequest{msg: fmt.Sprintf("the voter list has %d error(s); preview it to see them", len(list.Errors)), code: "voter-list-invalid"}
	}
	switch req.VoterListFingerprint {
	case list.Fingerprint:
	case "":
		return 0, errBadRequest{msg: "confirm the voter list: send the fingerprint the preview gave (voter_list_fingerprint)", code: "voter-list-unconfirmed"}
	default:
		return 0, errBadRequest{msg: "the voter list is not the one confirmed in the preview (its fingerprint differs); preview it again", code: "voter-list-changed"}
	}

	runID, err := newLiveRunID(now)
	if err != nil {
		return 0, err
	}
	dir, err := L.s.store.Dir(runID)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	priv := filepath.Join(dir, livePrivateDir)
	if err := os.Mkdir(priv, 0o700); err != nil {
		return 0, err
	}
	if err := os.Mkdir(filepath.Join(priv, liveSessionsDir), 0o700); err != nil {
		return 0, err
	}

	var key struct {
		PublicKey string `json:"public_key"`
	}
	if err := L.opJSON(ctx, "issuer-keygen", map[string]string{"key_file": filepath.Join(priv, liveIssuerKey)}, &key); err != nil {
		return 0, badRequestf("%v", err)
	}
	var params struct {
		Params     string   `json:"params"`
		ElectionID string   `json:"election_id"`
		ContestIDs []string `json:"contest_ids"`
		Threshold  int      `json:"threshold"`
	}
	if err := L.opJSON(ctx, "election-params", map[string]any{
		"election_id": runID, "positions": req.Positions,
		"trustees": req.Trustees, "threshold": req.Threshold,
		"issuer_public_key": key.PublicKey,
	}, &params); err != nil {
		// The refused election's folder holds only an unused key; drop it.
		_ = os.RemoveAll(dir)
		return 0, badRequestf("%v", err)
	}

	maxCands := 0
	for _, p := range req.Positions {
		maxCands = max(maxCands, len(p.Candidates))
	}
	trustees := make([]Trustee, req.Trustees)
	for i := range trustees {
		trustees[i] = Trustee{Name: fmt.Sprintf("Trustee %d", i+1)}
	}
	rec := RunRecord{RunID: runID, CreatedAt: now, Config: ElectionConfig{
		Name: req.Title, Mode: ModeLive, Trustees: trustees, Threshold: req.Threshold,
		Positions: len(req.Positions), Candidates: maxCands, Voters: len(list.Rows),
	}}
	if err := writeJSON(filepath.Join(dir, RunFile), rec); err != nil {
		return 0, err
	}
	prevSt, prevDir := L.st, L.dir
	L.st = &liveState{
		Schema: liveStateSchema, RunID: runID, ElectionID: params.ElectionID, Title: req.Title,
		Positions: req.Positions, Trustees: req.Trustees, Threshold: req.Threshold,
		State: LiveSetup, CreatedAt: now,
		Params: params.Params, ContestIDs: params.ContestIDs, IssuerPublicKey: key.PublicKey,
		Lifecycle: map[string]LiveTx{}, ReceiveKeys: map[string]string{},
		Deals: map[string]liveDeal{}, Acks: map[string]liveAck{},
		Partials: map[string]map[string]LiveTx{}, Signatures: map[string]liveSig{},
		Precinct: L.precinct, VoterListFingerprint: list.Fingerprint, VotersOnList: len(list.Rows),
	}
	// The list and its check-in record are written before live.json: a run
	// with a live.json always has its list.
	// If either write fails, the new run folder is removed with the list in
	// it (no folder holding dates of birth is left behind without a
	// live.json), and the console keeps the election it had.
	undo := func(err error) (int, error) {
		L.st, L.dir = prevSt, prevDir
		L.publishSnapshotLocked()
		_ = os.RemoveAll(dir)
		return 0, err
	}
	book, err := newCheckinBook(dir, params.ElectionID, list)
	if err != nil {
		return undo(err)
	}
	L.dir = dir
	if err := L.save(); err != nil {
		return undo(err)
	}
	L.ckMu.Lock()
	L.ck = book
	L.publishCheckinLocked()
	L.ckMu.Unlock()
	log.Printf("live: %s created (setup)", runID)
	return http.StatusCreated, L.finishSetupLocked()
}

// finishSetupLocked records CreateElection and moves to ceremony. Caller holds
// mu; the state is setup.
func (L *liveService) finishSetupLocked() error {
	rc, err := L.chainSubmit("CreateElection", L.st.Params)
	var ref errRefused
	if errors.As(err, &ref) && ref.Gate == "already-exists" {
		// A resume after a crash between the transaction and the state write.
		err = nil
	}
	if err != nil {
		return err
	}
	if rc.TxID != "" {
		L.st.Lifecycle["CreateElection"] = txOf(rc)
		L.appendLifecycleLocked("CreateElection", "", rc)
	}
	L.st.State = LiveCeremony
	log.Printf("live: %s ceremony", L.st.RunID)
	return L.save()
}

// --- resume ------------------------------------------------------------------

// resume reconciles the loaded state with the chain: a transaction that
// committed before a crash cut off its state write is taken as done, and
// ballots the chain holds but the run folder lacks are appended.
func (L *liveService) resume(ctx context.Context) error {
	L.mu.Lock()
	defer L.mu.Unlock()
	st := L.st
	c, err := L.getChain()
	if err != nil {
		return err
	}
	if st.State == LiveSetup {
		if err := L.finishSetupLocked(); err != nil {
			return err
		}
	}
	if st.State == LiveCeremony && len(st.Acks) == st.Trustees {
		if _, err := c.GetDKGTranscript(st.ElectionID); err == nil && st.DKG != "" {
			st.State = LiveOpen
			if err := L.save(); err != nil {
				return err
			}
		} else if err := L.finishCeremonyLocked(ctx); err != nil {
			return err
		}
	}
	if st.State == LiveOpen {
		if status, err := c.GetElectionStatus(st.ElectionID); err == nil && status == "closed" {
			st.State = LiveClosed
			if err := L.save(); err != nil {
				return err
			}
		}
	}
	if st.State == LiveClosed {
		if tally, err := c.GetTally(st.ElectionID); err == nil && tally != "" && !L.signedEnough(tally) {
			// A tally on the chain that fewer than threshold trustees signed
			// (a chain without the threshold gate took the presenter's
			// unsigned demonstration tally) is never the result.
			log.Printf("live: %s ALARM: the chain holds a tally with fewer than %d trustee signatures; it is not taken as the result and the election stays closed", st.RunID, st.Threshold)
		} else if err == nil && tally != "" {
			st.Tally = tally
			st.State = LiveTallied
			if t, derr := decodeTallyTotals(tally); derr == nil {
				st.Totals = t
			}
			if err := L.save(); err != nil {
				return err
			}
		}
	}
	if st.stateIndex() >= liveStateIndex(LiveClosed) {
		if err := L.reconcilePartialsLocked(c); err != nil {
			return err
		}
	}
	if st.stateIndex() >= liveStateIndex(LiveOpen) {
		return L.reconcileBallotsLocked(c)
	}
	return nil
}

// signedEnough reports whether a tally's encoding carries at least threshold
// signatures from distinct trustees. It counts; the chain's gate verified
// them, and verify-live checks them again.
func (L *liveService) signedEnough(tallyHex string) bool {
	raw, err := hex.DecodeString(tallyHex)
	if err != nil {
		return false
	}
	var t pb.TallyResult
	if err := proto.Unmarshal(raw, &t); err != nil {
		return false
	}
	ids := map[string]bool{}
	for _, s := range t.Signatures {
		ids[s.TrusteeId] = true
	}
	return len(ids) >= L.st.Threshold
}

func decodeTallyTotals(tallyHex string) ([]uint64, error) {
	raw, err := hex.DecodeString(tallyHex)
	if err != nil {
		return nil, err
	}
	var t pb.TallyResult
	if err := proto.Unmarshal(raw, &t); err != nil {
		return nil, err
	}
	return t.Totals, nil
}

// reconcileBallotsLocked appends every ballot the chain holds for this
// election that the run folder does not, with no receipt (the tracking-code
// check then confirms it against the chain). Caller holds mu.
func (L *liveService) reconcileBallotsLocked(c liveChain) error {
	onChain, err := allNullifiers(c, L.st.ElectionID)
	if err != nil {
		return err
	}
	local, err := localNullifiers(L.dir)
	if err != nil {
		return err
	}
	var missing []string
	for _, n := range onChain {
		if !local[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) == 0 {
		if L.st.Ballots != len(local) {
			L.st.Ballots = len(local)
			return L.save()
		}
		return nil
	}
	hexes, err := getBallots(c, L.st.ElectionID, missing)
	if err != nil {
		return err
	}
	L.st.Ballots = len(local)
	for _, h := range hexes {
		raw, err := hex.DecodeString(h)
		if err != nil {
			return fmt.Errorf("chain ballot is not hex: %w", err)
		}
		if err := L.appendBallotLocked(raw, nil); err != nil {
			return err
		}
	}
	log.Printf("live: %s resumed %d ballot(s) from the chain", L.st.RunID, len(missing))
	return L.save()
}

// ballotLister is the part of the chain the ballot reads need; the console's
// liveChain and the trustee's read-only chain both have it.
type ballotLister interface {
	ListNullifiers(electionID string, pageSize int, bookmark string) (clientsdk.NullifierPage, error)
	GetBallots(electionID string, nullifiers []string) ([]string, error)
}

func allNullifiers(c ballotLister, electionID string) ([]string, error) {
	var out []string
	bookmark := ""
	for {
		page, err := c.ListNullifiers(electionID, 10000, bookmark)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Nullifiers...)
		if page.NextBookmark == "" {
			return out, nil
		}
		bookmark = page.NextBookmark
	}
}

func getBallots(c ballotLister, electionID string, nullifiers []string) ([]string, error) {
	var out []string
	for start := 0; start < len(nullifiers); start += clientsdk.BallotBatchSize {
		end := min(start+clientsdk.BallotBatchSize, len(nullifiers))
		page, err := c.GetBallots(electionID, nullifiers[start:end])
		if err != nil {
			return nil, err
		}
		for i, h := range page {
			if h == "" {
				return nil, fmt.Errorf("the chain lists nullifier %s but holds no ballot for it", nullifiers[start+i])
			}
		}
		out = append(out, page...)
	}
	return out, nil
}

// localNullifiers is the set of nullifiers in the run's ballots.csv.
func localNullifiers(dir string) (map[string]bool, error) {
	out := map[string]bool{}
	f, err := os.Open(filepath.Join(dir, BallotsCSV))
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", BallotsCSV, err)
	}
	if len(rows) == 0 {
		return out, nil
	}
	idx := columnIndex(rows[0])
	for _, r := range rows[1:] {
		out[strings.ToLower(field(r, idx, "nullifier"))] = true
	}
	return out, nil
}

// --- ballots in the run folder ----------------------------------------------

// ballotFingerprint is the wire format's ballot_fingerprint of raw record
// bytes: the first 16 bytes of their SHA-256, upper-case hex in eight groups
// of four.
func ballotFingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return groupFingerprint(hex.EncodeToString(sum[:16]))
}

// groupFingerprint formats 32 hex digits as XXXX-XXXX-...-XXXX.
func groupFingerprint(h string) string {
	h = strings.ToUpper(h)
	var parts []string
	for i := 0; i+4 <= len(h); i += 4 {
		parts = append(parts, h[i:i+4])
	}
	return strings.Join(parts, "-")
}

// appendBallotLocked appends one recorded ballot to the run folder in the
// layout the board and /api/verify-code/ read: a ballots.ndjson line, a
// ballots.csv row and, when rc is set, its SubmitBallot receipt. raw are the
// bytes the chain holds. Nothing written names an account or an address.
// Caller holds mu.
//
// The ndjson line, the CSV row and the receipt row go in together or not at
// all: if either append or the receipt fails, ballots.ndjson, ballots.csv and
// receipts.csv are cut back to their earlier length, so the next ballot's
// index still names the same line in each and no receipt index repeats.
func (L *liveService) appendBallotLocked(raw []byte, rc *clientsdk.Receipt) (err error) {
	index := L.st.Ballots
	row, err := ballotsCSVRow(index, raw)
	if err != nil {
		return err
	}
	ndjson, csvPath := filepath.Join(L.dir, BallotsFile), filepath.Join(L.dir, BallotsCSV)
	ndMark, err := markLength(ndjson)
	if err != nil {
		return err
	}
	csvMark, err := markLength(csvPath)
	if err != nil {
		return err
	}
	rcMark, err := markLength(filepath.Join(L.dir, "receipts.csv"))
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if rerr := errors.Join(ndMark.restore(), csvMark.restore(), rcMark.restore()); rerr != nil {
				err = fmt.Errorf("%w (and the ballot files could not be cut back: %v)", err, rerr)
			}
		}
	}()
	if err := appendSynced(ndjson, []byte(hex.EncodeToString(raw)+"\n")); err != nil {
		return err
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if !csvMark.existed {
		_ = w.Write(ballotsCSVHeader)
	}
	_ = w.Write(row)
	w.Flush()
	if err := appendSynced(csvPath, buf.Bytes()); err != nil {
		return err
	}
	if rc != nil {
		rw, err := openReceipts(L.dir)
		if err != nil {
			return err
		}
		err = rw.Append(TrailEvent{Event: "SubmitBallot", Ref: strconv.Itoa(index), Receipt: *rc})
		if cerr := rw.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	L.st.Ballots = index + 1
	return nil
}

// fileMark is a file's length before an append, to cut it back to.
type fileMark struct {
	path    string
	existed bool
	size    int64
}

func markLength(path string) (fileMark, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileMark{path: path}, nil
	}
	if err != nil {
		return fileMark{}, err
	}
	return fileMark{path: path, existed: true, size: info.Size()}, nil
}

// restore cuts the file back to its marked length (removes it if it did not
// exist), fsynced.
func (m fileMark) restore() error {
	if !m.existed {
		if err := os.Remove(m.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	info, err := os.Stat(m.path)
	if err != nil {
		return err
	}
	if info.Size() == m.size {
		return nil
	}
	if err := os.Truncate(m.path, m.size); err != nil {
		return err
	}
	f, err := os.OpenFile(m.path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// appendLifecycleLocked records a lifecycle transaction's receipt in
// receipts.csv and trail.ndjson, as the study runs do. Caller holds mu.
func (L *liveService) appendLifecycleLocked(event, ref string, rc clientsdk.Receipt) {
	rw, err := openReceipts(L.dir)
	if err != nil {
		log.Printf("live: %s receipts: %v", L.st.RunID, err)
		return
	}
	if err := rw.Lifecycle(TrailEvent{Event: event, Ref: ref, Receipt: rc}); err != nil {
		log.Printf("live: %s receipts: %v", L.st.RunID, err)
	}
	_ = rw.Close()
}

func appendSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// --- rate limit ----------------------------------------------------------------

// rateLimiter is a token bucket across all callers. It is global on purpose:
// a per-address limit would have to hold the callers' addresses, and the
// ballot route keeps none.
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newRateLimiter(perSecond, burst float64) *rateLimiter {
	return &rateLimiter{rate: perSecond, burst: burst, tokens: burst, now: time.Now}
}

func (l *rateLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !l.last.IsZero() {
		l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
