package campaign

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

// The R11 blackout-and-recovery test (tools/r11-blackout-test.sh).
//
// One on-chain election runs through the console executor's own lifecycle
// (Generate, then Submit: CreateElection, RegisterPrecinctMachine,
// PublishDKGTranscript and the ballot window). When BlackoutAt of its ballot
// records have committed, the worker that saw that commit SIGKILLs the whole
// network at once (docker kill on the orderer, both peers and the chaincode
// containers) and the window is cancelled, so no further ballot is dispatched.
// After Downtime the orderer and the peers are started again, and the test
// waits until the chain answers a query.
//
// It then checks, in order:
//
//  1. before the blackout: each ballot record is classified C (its submit
//     returned a valid commit status), U (its submit or commit status failed)
//     or N (never sent), and the block height is read;
//  2. the blackout: every container killed, held down for the downtime,
//     started again, and the first successful query after the restart;
//  3. after the restart: the height is at least the height before, and every
//     C record's nullifier is on the ledger;
//  4. the recovery: a deliberate resubmission of one C record is refused by the
//     nullifier gate, then the executor's own journal-based resume
//     (resumeAndClose: ListNullifiers intersected with the run decides what is
//     on chain) submits only the records the chain lacks and closes;
//  5. after the partial decryptions and the tally: the chain holds exactly the
//     election's records (count = N, no nullifier twice, none missing, none
//     extra), and the auditor finds E = 0 on every contest over the ledger dump.
//
// Everything that touches the chain goes through BlackoutConfig.Dial, and every
// docker call through BlackoutConfig.Run, so the whole sequence runs against a
// fake chain in the unit tests.

// Ballot record classes at the blackout.
const (
	R11Committed = "C"
	R11Uncertain = "U"
	R11NotSent   = "N"
)

// R11CoreContainers are the containers the blackout kills and the harness
// starts again: the orderer and both peers. The chaincode containers are
// killed too, but the peers relaunch them.
var R11CoreContainers = []string{"orderer.example.com", "peer0.org1.example.com", "peer0.org2.example.com"}

// Phases a recorded transaction belongs to.
const (
	r11PhaseWindow    = "window"
	r11PhaseDuplicate = "duplicate"
	r11PhaseResume    = "resume"
	r11PhaseCeremony  = "ceremony"
)

// r11MaxResumes bounds the resume attempts: a resume whose ballots or close
// fail (an orderer still electing its leader) stays resumable, and the
// executor's own contract is to resume again.
const r11MaxResumes = 3

// BlackoutReader is the chain's read side the test needs.
// *clientsdk.BulletinClient satisfies it.
type BlackoutReader interface {
	ledgerReader
	CountCommittedBallots(electionID string) (int, error)
}

var _ BlackoutReader = (*clientsdk.BulletinClient)(nil)

// BlackoutConn is one connection to the network: the ledger the lifecycle
// signs with (each function routed to its role) and the reader.
type BlackoutConn struct {
	Ledger clientsdk.Ledger
	Reader BlackoutReader
	Close  func()
}

// BlackoutConfig is everything the test needs.
type BlackoutConfig struct {
	OutDir       string
	DemoBin      string
	Stamp        string
	Voters       int
	Positions    int
	Candidates   int
	Trustees     int
	Threshold    int
	Distribution string
	Concurrency  int
	// BlackoutAt is the fraction of the ballot records committed when the
	// network is killed.
	BlackoutAt float64
	// Downtime is how long the network stays down after the kill.
	Downtime time.Duration
	// ReadyTimeout bounds the wait for the first successful query after the
	// restart (default 5 minutes).
	ReadyTimeout time.Duration
	// ChaincodeGrace is how long the peers get to relaunch the killed
	// chaincode containers themselves once the chain answers (default 60 s).
	// A chaincode container still down after it is started by the harness,
	// and the evidence says so.
	ChaincodeGrace time.Duration
	// ResumeRetryWait is the pause before a resume is retried (default 5 s).
	ResumeRetryWait time.Duration
	// ComposeProject is the compose project the core containers must carry
	// (com.docker.compose.project); the test refuses to kill anything else.
	ComposeProject string
	// Chaincode is the chaincode name in the dev-peer container names.
	Chaincode string
	// Dial opens a connection to the network.
	Dial func() (BlackoutConn, error)
	// Run shells saksi-demo and docker. nil means execRunner.
	Run Runner
	// Provenance copied into the evidence.
	Commit   string
	Network  map[string]string
	Binaries map[string]string
	// Log receives progress lines. nil discards them.
	Log io.Writer
}

// Records is the election's ballot records: one per voter per position.
func (c BlackoutConfig) Records() int { return c.Voters * c.Positions }

// TriggerCount is the number of committed records that fires the blackout.
func (c BlackoutConfig) TriggerCount() int {
	n := int(c.BlackoutAt * float64(c.Records()))
	if n < 1 {
		n = 1
	}
	return n
}

// ElectionName is the run's election name; the run id (and so the election
// id) is minted from it by the run store.
func (c BlackoutConfig) ElectionName() string { return "R11 blackout " + c.Stamp }

// Validate refuses a configuration the test cannot run.
func (c BlackoutConfig) Validate() error {
	switch {
	case c.Stamp == "":
		return errors.New("stamp is required")
	case c.Voters < 1:
		return errors.New("--voters must be at least 1")
	case c.Positions < 1 || c.Candidates < 2:
		return errors.New("--positions must be at least 1 and --candidates at least 2")
	case c.Threshold < 1 || c.Threshold > c.Trustees:
		return fmt.Errorf("--threshold %d must be between 1 and --trustees %d", c.Threshold, c.Trustees)
	case !(c.BlackoutAt > 0 && c.BlackoutAt < 1):
		return fmt.Errorf("--blackout-at must be between 0 and 1, exclusive (got %v)", c.BlackoutAt)
	case c.Downtime <= 0:
		return fmt.Errorf("--downtime must be positive (got %v)", c.Downtime)
	case c.Concurrency < 1:
		return fmt.Errorf("--concurrency must be at least 1 (got %d)", c.Concurrency)
	case c.ComposeProject == "":
		return errors.New("the compose project is required: the blackout kills only that project's containers")
	case c.Chaincode == "":
		return errors.New("the chaincode name is required")
	}
	if t := c.TriggerCount(); t >= c.Records() {
		return fmt.Errorf("--blackout-at %v of %d records fires at %d: at least one record must be left for the resume", c.BlackoutAt, c.Records(), t)
	}
	return nil
}

// chaincodeContainerRE matches the peers' chaincode containers for cc.
func chaincodeContainerRE(cc string) *regexp.Regexp {
	return regexp.MustCompile(`^dev-peer0\.org[12]\.example\.com-` + regexp.QuoteMeta(cc) + `_`)
}

// R11DryRun writes the plan. It touches neither the network nor the
// generator.
func R11DryRun(w io.Writer, c BlackoutConfig) {
	fmt.Fprintf(w, "R11 blackout-and-recovery test plan (dry run: nothing is contacted)\n\n")
	fmt.Fprintf(w, "election: %q, %d voters x %d positions x %d candidates = %d ballot records, %d-of-%d trustees, %s\n",
		c.ElectionName(), c.Voters, c.Positions, c.Candidates, c.Records(), c.Threshold, c.Trustees, c.Distribution)
	fmt.Fprintf(w, "ballots in flight: %d\n", c.Concurrency)
	fmt.Fprintf(w, "blackout: when %d of %d records (%.0f%%) have committed; down for %s; ready within %s\n",
		c.TriggerCount(), c.Records(), c.BlackoutAt*100, c.Downtime, c.ReadyTimeout)
	fmt.Fprintf(w, "compose project %q; chaincode containers match %s\n\n", c.ComposeProject, chaincodeContainerRE(c.Chaincode))
	steps := []string{
		"preflight  docker ps: " + strings.Join(R11CoreContainers, ", ") + " running, labelled com.docker.compose.project=" + c.ComposeProject,
		"generate   Executor.Generate: saksi-demo gen --stream <out>/runs/<run>",
		"window     Executor.Submit: CreateElection (admin), RegisterPrecinctMachine (admin), PublishDKGTranscript, SubmitBallot x N (machine)",
		fmt.Sprintf("blackout   at commit %d: ChainInfo (height before), docker kill <core + running chaincode containers> in one call, cancel the window", c.TriggerCount()),
		"classify   each record C (commit status valid), U (submit or commit-status error) or N (not sent)",
		fmt.Sprintf("downtime   %s from the kill; inspect: every killed container still down", c.Downtime),
		"restart    docker start " + strings.Join(R11CoreContainers, " "),
		"ready      CountCommittedBallots(<election>) until it answers; time from start to ready",
		fmt.Sprintf("chaincode  up to %s for the peers to relaunch the chaincode containers; any still down: docker start (recorded)", c.ChaincodeGrace),
		"after      ChainInfo (height after >= before); ListNullifiers: every C record on the ledger",
		"duplicate  SubmitBallot(one C record) again: refused at gate nullifier",
		"resume     Executor.resumeAndClose: ListNullifiers ∩ run decides; submits only the rest, then CloseElection (retried up to 3 times)",
		"ceremony   SubmitPartialDecryption x each, PublishTally (the bundle's, as the console's submit path)",
		"verify     Executor.verify (ledger dump + local audit), audit-stream over the ledger dump, CountCommittedBallots, ListNullifiers walk",
		"events     docker events over the run, filtered to the killed containers",
	}
	for i, s := range steps {
		fmt.Fprintf(w, "%3d  %s\n", i+1, s)
	}
	fmt.Fprintf(w, "\nchecks (each with expected, observed, PASS/FAIL in r11-evidence.json):\n")
	for _, ch := range r11CheckNames {
		fmt.Fprintf(w, "  %-26s %s\n", ch[0], ch[1])
	}
}

// r11CheckNames lists every check, in order, with what it expects.
var r11CheckNames = [][2]string{
	{"pre.classified", "C + U + N = records; C >= 1 and U + N >= 1 (the blackout fell mid-election)"},
	{"pre.height", "block height read just before the kill"},
	{"blackout.killed", "every target container killed (orderer, both peers, the chaincode containers)"},
	{"blackout.down", "every killed container still down at the end of the downtime"},
	{"blackout.downtime", "downtime >= the configured downtime"},
	{"blackout.ready", "a query succeeds after the restart"},
	{"blackout.restarted", "every killed container running again"},
	{"after.height", "height after the restart >= height before the blackout"},
	{"after.committed_kept", "every C record's nullifier on the ledger after the restart"},
	{"resume.duplicate_refused", "resubmitting one C record is refused at gate nullifier"},
	{"resume.only_missing", "each resume attempt submits exactly the records the chain lacks"},
	{"resume.done", "the resume landed every record and closed the election"},
	{"final.tally", "partial decryptions and the tally committed"},
	{"final.count", "CountCommittedBallots = records"},
	{"final.no_duplicates", "ListNullifiers: records entries, all distinct, none missing, none extra"},
	{"final.audit", "auditor: local and ledger pass, E = 0 on every contest, ledger matches generated"},
}

// R11Check is one check's evidence.
type R11Check struct {
	ID       string `json:"id"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Pass     bool   `json:"pass"`
}

// R11Container is one killed container's evidence.
type R11Container struct {
	Name string `json:"name"`
	Role string `json:"role"` // orderer | peer | chaincode
	// RunningAtDowntimeEnd is the inspect just before the restart.
	RunningAtDowntimeEnd *bool `json:"running_at_downtime_end,omitempty"`
	// StartedBy is who brought it back: harness (docker start) or peer (the
	// peer relaunched its chaincode), or "" when it did not come back.
	StartedBy    string `json:"started_by,omitempty"`
	RunningAtEnd bool   `json:"running_at_end"`
	State        string `json:"state,omitempty"` // docker inspect, at the end
}

// R11Blackout is the blackout's timeline.
type R11Blackout struct {
	TriggerCount   int            `json:"trigger_committed"`
	Fired          bool           `json:"fired"`
	HeightBefore   uint64         `json:"height_before"`
	HeightBeforeOK bool           `json:"height_before_ok"`
	KillIssued     string         `json:"kill_issued,omitempty"`
	KillDone       string         `json:"kill_done,omitempty"`
	KillCommand    []string       `json:"kill_command,omitempty"`
	KillOK         bool           `json:"kill_ok"`
	KillOutput     string         `json:"kill_output,omitempty"`
	Containers     []R11Container `json:"containers"`
	StartIssued    string         `json:"start_issued,omitempty"`
	StartDone      string         `json:"start_done,omitempty"`
	StartCommand   []string       `json:"start_command,omitempty"`
	StartOK        bool           `json:"start_ok"`
	DowntimeMs     int64          `json:"downtime_ms"`
	ConfiguredMs   int64          `json:"configured_downtime_ms"`
	Ready          bool           `json:"ready"`
	ReadyAt        string         `json:"ready_at,omitempty"`
	TimeToReadyMs  int64          `json:"time_to_ready_ms"`
	ReadyAttempts  int            `json:"ready_attempts"`
	FirstQuery     string         `json:"first_query,omitempty"`
	HeightAfter    uint64         `json:"height_after"`
	HeightAfterOK  bool           `json:"height_after_ok"`
	Errors         []string       `json:"errors,omitempty"`
}

// R11Classification counts the records by class at the blackout, and what
// the chain held of each class once it was back.
type R11Classification struct {
	Records   int `json:"records"`
	Committed int `json:"committed_C"`
	Uncertain int `json:"uncertain_U"`
	NotSent   int `json:"not_sent_N"`
	// CommittedAfterKill counts C records whose valid commit status came back
	// after the kill was issued (already committed, answer still in flight).
	CommittedAfterKill int `json:"committed_answer_after_kill"`
	// After the restart, before the resume.
	OnChainAfterRestart    int    `json:"on_chain_after_restart"`
	CommittedMissing       int    `json:"committed_missing_after_restart"`
	UncertainOnChain       int    `json:"uncertain_on_chain_after_restart"`
	UncertainNotOnChain    int    `json:"uncertain_not_on_chain_after_restart"`
	NotSentOnChain         int    `json:"not_sent_on_chain_after_restart"`
	FirstUncertainError    string `json:"first_uncertain_error,omitempty"`
	CommittedMissingSample []int  `json:"committed_missing_indices,omitempty"`
}

// R11Duplicate is the deliberate resubmission of one C record.
type R11Duplicate struct {
	Index     int    `json:"index"`
	Nullifier string `json:"nullifier"`
	Outcome   string `json:"outcome"` // accept | refuse | error
	Gate      string `json:"gate,omitempty"`
	Error     string `json:"error,omitempty"`
	TxID      string `json:"tx_id,omitempty"`
}

// R11ResumeAttempt is one call of the executor's resume.
type R11ResumeAttempt struct {
	Attempt       int `json:"attempt"`
	OnChainBefore int `json:"on_chain_before"`
	Submitted     int `json:"submitted"`
	Accepted      int `json:"accepted"`
	// SubmittedAlreadyOnChain counts submissions of records the chain held
	// when the attempt started: the resume must never send one.
	SubmittedAlreadyOnChain int    `json:"submitted_already_on_chain"`
	DistinctSubmitted       int    `json:"distinct_submitted"`
	Error                   string `json:"error,omitempty"`
}

// R11Final is the end state.
type R11Final struct {
	TallyError         string               `json:"tally_error,omitempty"`
	CountCommitted     int                  `json:"count_committed"`
	CountError         string               `json:"count_error,omitempty"`
	ListedNullifiers   int                  `json:"listed_nullifiers"`
	DistinctNullifiers int                  `json:"distinct_nullifiers"`
	MissingFromLedger  int                  `json:"missing_from_ledger"`
	ExtraOnLedger      int                  `json:"extra_on_ledger"`
	ListError          string               `json:"list_error,omitempty"`
	LocalOverall       string               `json:"local_overall"`
	LedgerOverall      string               `json:"ledger_overall"`
	LedgerMatchLocal   bool                 `json:"ledger_matches_generated"`
	Contests           []ContestCorrectness `json:"contests"`
	MaxAbsE            int64                `json:"max_abs_e"`
	VerifyError        string               `json:"verify_error,omitempty"`
}

// R11Evidence is r11-evidence.json.
type R11Evidence struct {
	Schema         string             `json:"schema"`
	Started        string             `json:"started"`
	Finished       string             `json:"finished"`
	Commit         string             `json:"commit"`
	Binaries       map[string]string  `json:"binary_sha256"`
	Network        map[string]string  `json:"network"`
	Election       map[string]any     `json:"election"`
	RunID          string             `json:"run_id,omitempty"`
	RunDir         string             `json:"run_dir,omitempty"`
	ResumePath     string             `json:"resume_path"`
	Classification R11Classification  `json:"classification"`
	Blackout       R11Blackout        `json:"blackout"`
	Duplicate      *R11Duplicate      `json:"duplicate,omitempty"`
	Resume         []R11ResumeAttempt `json:"resume"`
	Final          *R11Final          `json:"final,omitempty"`
	Checks         []R11Check         `json:"checks"`
	Aborted        string             `json:"aborted,omitempty"`
	Pass           bool               `json:"pass"`
}

// r11Call is one recorded transaction.
type r11Call struct {
	Time      string `json:"time"`
	Phase     string `json:"phase"`
	Fn        string `json:"fn"`
	Nullifier string `json:"nullifier,omitempty"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	Gate      string `json:"gate,omitempty"`
	TxID      string `json:"tx_id,omitempty"`
	Block     uint64 `json:"block,omitempty"`
	done      time.Time
}

type r11Run struct {
	cfg   BlackoutConfig
	run   Runner
	e     *Executor
	runID string
	dir   string
	elec  string
	calls *os.File

	mu        sync.Mutex
	phase     string
	recorded  []r11Call
	committed int // window commits seen

	winLed    clientsdk.Ledger // the window's ledger, unwrapped
	winCancel context.CancelFunc
	fire      sync.Once
	restarted chan struct{}

	bo        R11Blackout
	boMu      sync.Mutex
	killAt    time.Time
	killed    []string // every container the kill named
	post      *BlackoutConn
	coreKill  bool // the core containers were killed and not yet started
	coreStart sync.Once
}

func (r *r11Run) logf(format string, a ...any) {
	if r.cfg.Log != nil {
		fmt.Fprintf(r.cfg.Log, "%s "+format+"\n", append([]any{time.Now().UTC().Format("15:04:05.000")}, a...)...)
	}
}

func (r *r11Run) setPhase(p string) {
	r.mu.Lock()
	r.phase = p
	r.mu.Unlock()
}

// r11Ledger records every transaction the executor makes through it and, in
// the window, fires the blackout from the worker that saw the trigger commit.
type r11Ledger struct {
	clientsdk.Ledger
	r *r11Run
}

func (l r11Ledger) Submit(fn string, args ...string) (string, uint64, error) {
	tx, blk, err := l.Ledger.Submit(fn, args...)
	l.r.note(fn, args, tx, blk, err)
	return tx, blk, err
}

func (l r11Ledger) SubmitWithReceipt(fn string, args ...string) ([]byte, clientsdk.Receipt, error) {
	out, rec, err := l.Ledger.SubmitWithReceipt(fn, args...)
	l.r.note(fn, args, rec.TxID, rec.BlockNumber, err)
	return out, rec, err
}

func (r *r11Run) note(fn string, args []string, tx string, blk uint64, err error) {
	c := r11Call{Time: time.Now().UTC().Format(time.RFC3339Nano), Fn: fn, OK: err == nil, TxID: tx, Block: blk, done: time.Now()}
	if fn == "SubmitBallot" && len(args) == 1 {
		c.Nullifier = r14NullifierOf(args[0])
	}
	if err != nil {
		c.Error = clientsdk.ErrorText(err)
		c.Gate = refusalCode(fn, c.Error)
	}
	fire := false
	r.mu.Lock()
	c.Phase = r.phase
	r.recorded = append(r.recorded, c)
	if c.Phase == r11PhaseWindow && fn == "SubmitBallot" && c.OK {
		r.committed++
		fire = r.committed == r.cfg.TriggerCount()
	}
	line, _ := json.Marshal(c)
	_, _ = r.calls.Write(append(line, '\n'))
	r.mu.Unlock()
	if fire {
		r.fire.Do(r.blackout)
	}
}

// callsIn returns the recorded calls of a phase.
func (r *r11Run) callsIn(phase string) []r11Call {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []r11Call
	for _, c := range r.recorded {
		if c.Phase == phase {
			out = append(out, c)
		}
	}
	return out
}

func (r *r11Run) docker(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, faultDockerTimeout)
	defer cancel()
	out, err := r.run(ctx, "docker", args...)
	return strings.TrimSpace(string(out)), err
}

// runningContainers maps each running container's name to its compose
// project label.
func (r *r11Run) runningContainers(ctx context.Context) (map[string]string, error) {
	out, err := r.docker(ctx, "ps", "--format", `{{.Names}}|{{.Label "com.docker.compose.project"}}`)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		name, project, _ := strings.Cut(strings.TrimSpace(line), "|")
		if name != "" {
			m[name] = project
		}
	}
	return m, nil
}

// preflight refuses to start unless the core containers run under the
// configured compose project.
func (r *r11Run) preflight(ctx context.Context) error {
	running, err := r.runningContainers(ctx)
	if err != nil {
		return fmt.Errorf("docker ps: %w", err)
	}
	for _, name := range R11CoreContainers {
		project, ok := running[name]
		switch {
		case !ok:
			return fmt.Errorf("%s is not running", name)
		case project != r.cfg.ComposeProject:
			return fmt.Errorf("%s belongs to compose project %q, not %q: refusing to kill it", name, project, r.cfg.ComposeProject)
		}
	}
	return nil
}

// inspect returns whether name is running and its state line.
func (r *r11Run) inspect(ctx context.Context, name string) (bool, string) {
	out, err := r.docker(ctx, "inspect", "-f", "{{.State.Running}}|{{.State.Status}}|started {{.State.StartedAt}}|finished {{.State.FinishedAt}}|exit {{.State.ExitCode}}", name)
	if err != nil {
		return false, "inspect failed: " + err.Error()
	}
	running, _, _ := strings.Cut(out, "|")
	return running == "true", out
}

func (r *r11Run) boError(format string, a ...any) {
	r.boMu.Lock()
	r.bo.Errors = append(r.bo.Errors, fmt.Sprintf(format, a...))
	r.boMu.Unlock()
}

// blackout is the kill. It runs once, in the window worker whose commit
// reached the trigger, so ballots are in flight when it lands.
func (r *r11Run) blackout() {
	ctx := context.Background()
	h, _, herr := r.winLed.ChainInfo()
	targets := append([]string(nil), R11CoreContainers...)
	running, err := r.runningContainers(ctx)
	if err != nil {
		r.boError("docker ps before the kill: %v", err)
	}
	re := chaincodeContainerRE(r.cfg.Chaincode)
	var chaincode []string
	for name := range running {
		if re.MatchString(name) {
			chaincode = append(chaincode, name)
		}
	}
	sort.Strings(chaincode)
	targets = append(targets, chaincode...)
	cmd := append([]string{"kill"}, targets...)

	r.boMu.Lock()
	r.bo.Fired = true
	r.bo.HeightBefore, r.bo.HeightBeforeOK = h, herr == nil
	r.bo.KillCommand = append([]string{"docker"}, cmd...)
	r.killAt = time.Now()
	r.bo.KillIssued = r.killAt.UTC().Format(time.RFC3339Nano)
	r.coreKill = true
	r.boMu.Unlock()
	if herr != nil {
		r.boError("ChainInfo before the kill: %v", herr)
	}

	out, kerr := r.docker(ctx, cmd...)
	// The window stops dispatching: what was not sent stays N.
	r.winCancel()
	done := time.Now()

	r.boMu.Lock()
	r.bo.KillDone = done.UTC().Format(time.RFC3339Nano)
	r.bo.KillOK = kerr == nil
	r.bo.KillOutput = out
	if kerr != nil {
		r.bo.Errors = append(r.bo.Errors, "docker kill: "+kerr.Error())
	}
	r.killed = targets
	for _, name := range targets {
		role := "chaincode"
		switch {
		case strings.HasPrefix(name, "orderer"):
			role = "orderer"
		case strings.HasPrefix(name, "peer"):
			role = "peer"
		}
		r.bo.Containers = append(r.bo.Containers, R11Container{Name: name, Role: role})
	}
	r.boMu.Unlock()
	r.logf("BLACKOUT: killed %s at %d committed (height before %d)", strings.Join(targets, ", "), r.cfg.TriggerCount(), h)
	go r.restore(done)
}

// startCore starts the orderer and the peers, once.
func (r *r11Run) startCore() {
	r.coreStart.Do(func() {
		cmd := append([]string{"start"}, R11CoreContainers...)
		t := time.Now()
		out, err := r.docker(context.Background(), cmd...)
		r.boMu.Lock()
		r.bo.StartIssued = t.UTC().Format(time.RFC3339Nano)
		r.bo.StartDone = time.Now().UTC().Format(time.RFC3339Nano)
		r.bo.StartCommand = append([]string{"docker"}, cmd...)
		r.bo.StartOK = err == nil
		r.bo.DowntimeMs = t.Sub(r.killAt).Milliseconds()
		r.coreKill = false
		if err != nil {
			r.bo.Errors = append(r.bo.Errors, fmt.Sprintf("docker start: %v (%s)", err, out))
		}
		r.boMu.Unlock()
		r.logf("restart: docker start %s (ok %v)", strings.Join(R11CoreContainers, " "), err == nil)
	})
}

// restore holds the network down for the downtime, starts it, and waits until
// it answers. It always starts the core containers, whatever happened.
func (r *r11Run) restore(killDone time.Time) {
	defer close(r.restarted)
	defer r.startCore()
	if wait := time.Until(killDone.Add(r.cfg.Downtime)); wait > 0 {
		time.Sleep(wait)
	}
	ctx := context.Background()
	r.boMu.Lock()
	names := append([]string(nil), r.killed...)
	r.boMu.Unlock()
	for i, name := range names {
		up, _ := r.inspect(ctx, name)
		r.boMu.Lock()
		r.bo.Containers[i].RunningAtDowntimeEnd = &up
		r.boMu.Unlock()
	}
	r.startCore()
	r.boMu.Lock()
	startIssued, _ := time.Parse(time.RFC3339Nano, r.bo.StartIssued)
	r.boMu.Unlock()

	deadline := time.Now().Add(r.cfg.ReadyTimeout)
	attempts := 0
	for {
		attempts++
		if r.post == nil {
			if conn, err := r.cfg.Dial(); err == nil {
				r.post = &conn
			}
		}
		if r.post != nil {
			n, err := r.post.Reader.CountCommittedBallots(r.elec)
			if err == nil {
				now := time.Now()
				r.boMu.Lock()
				r.bo.Ready = true
				r.bo.ReadyAt = now.UTC().Format(time.RFC3339Nano)
				r.bo.TimeToReadyMs = now.Sub(startIssued).Milliseconds()
				r.bo.ReadyAttempts = attempts
				r.bo.FirstQuery = fmt.Sprintf("CountCommittedBallots(%s) = %d", r.elec, n)
				r.boMu.Unlock()
				r.logf("ready: %s after %d ms (%d attempts)", r.bo.FirstQuery, r.bo.TimeToReadyMs, attempts)
				break
			}
		}
		if time.Now().After(deadline) {
			r.boMu.Lock()
			r.bo.ReadyAttempts = attempts
			r.boMu.Unlock()
			r.boError("no successful query within %s of the restart", r.cfg.ReadyTimeout)
			return
		}
		time.Sleep(time.Second)
	}

	// The chaincode containers: the peers relaunch them on demand. Any still
	// down after the grace is started here, and recorded as such.
	graceEnd := time.Now().Add(r.cfg.ChaincodeGrace)
	for {
		pending := 0
		for i, name := range names {
			if r.bo.Containers[i].Role != "chaincode" || r.bo.Containers[i].StartedBy != "" {
				continue
			}
			if up, _ := r.inspect(ctx, name); up {
				r.boMu.Lock()
				r.bo.Containers[i].StartedBy = "peer"
				r.boMu.Unlock()
				continue
			}
			pending++
		}
		if pending == 0 || time.Now().After(graceEnd) {
			break
		}
		time.Sleep(time.Second)
	}
	for i, name := range names {
		c := &r.bo.Containers[i]
		switch {
		case c.Role != "chaincode":
			c.StartedBy = "harness"
		case c.StartedBy == "":
			if out, err := r.docker(ctx, "start", name); err != nil {
				r.boError("docker start %s: %v (%s)", name, err, out)
			} else {
				r.boMu.Lock()
				c.StartedBy = "harness"
				r.boMu.Unlock()
				r.logf("chaincode container %s was not relaunched by its peer: started by the harness", name)
			}
		}
	}
	if h, _, err := r.post.Ledger.ChainInfo(); err == nil {
		r.boMu.Lock()
		r.bo.HeightAfter, r.bo.HeightAfterOK = h, true
		r.boMu.Unlock()
	} else {
		r.boError("ChainInfo after the restart: %v", err)
	}
}

// RunBlackoutTest runs the whole sequence and writes r11-evidence.json and
// the raw logs into cfg.OutDir. The error is non-nil only when the evidence
// could not be written; a failed check is ev.Pass == false.
func RunBlackoutTest(ctx context.Context, cfg BlackoutConfig) (R11Evidence, error) {
	if cfg.ReadyTimeout <= 0 {
		cfg.ReadyTimeout = 5 * time.Minute
	}
	if cfg.ChaincodeGrace <= 0 {
		cfg.ChaincodeGrace = time.Minute
	}
	if cfg.ResumeRetryWait <= 0 {
		cfg.ResumeRetryWait = 5 * time.Second
	}
	started := time.Now()
	ev := R11Evidence{
		Schema:   "saksi-r11-blackout-test/v1",
		Started:  started.UTC().Format(time.RFC3339),
		Commit:   cfg.Commit,
		Binaries: map[string]string{},
		Network:  cfg.Network,
		Election: map[string]any{
			"name": cfg.ElectionName(), "voters": cfg.Voters, "positions": cfg.Positions,
			"candidates": cfg.Candidates, "trustees": cfg.Trustees, "threshold": cfg.Threshold,
			"distribution": cfg.Distribution, "concurrency": cfg.Concurrency, "records": cfg.Records(),
			"blackout_at": cfg.BlackoutAt, "downtime_s": cfg.Downtime.Seconds(),
		},
		ResumePath: "Executor.resumeAndClose, the body of the console's Resume (POST /api/runs/<id>/resume), " +
			"called in process: journal checkpoint + ListNullifiers ∩ run nullifiers, then CloseElection",
	}
	for name, path := range cfg.Binaries {
		ev.Binaries[name] = fileSHA256(path)
	}
	if err := cfg.Validate(); err != nil {
		return ev, err
	}
	if cfg.Dial == nil {
		return ev, errors.New("no Dial: nothing to connect to")
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return ev, err
	}
	calls, err := os.Create(filepath.Join(cfg.OutDir, "calls.ndjson"))
	if err != nil {
		return ev, err
	}
	defer calls.Close()

	r := &r11Run{cfg: cfg, run: cfg.Run, calls: calls, restarted: make(chan struct{})}
	if r.run == nil {
		r.run = execRunner
	}
	r.bo.TriggerCount = cfg.TriggerCount()
	r.bo.ConfiguredMs = cfg.Downtime.Milliseconds()

	ev.Aborted = r.drive(ctx, &ev)
	// A kill that happened must always be followed by a start.
	r.boMu.Lock()
	pendingStart := r.coreKill
	r.boMu.Unlock()
	if pendingStart {
		r.startCore()
	}
	if r.post != nil && r.post.Close != nil {
		r.post.Close()
	}
	r.inspectAtEnd()
	r.boMu.Lock()
	ev.Blackout = r.bo
	r.boMu.Unlock()
	r.writeEvents(started)

	ev.Checks = r11Checks(ev)
	ev.Pass = ev.Aborted == "" && len(ev.Checks) > 0
	for _, c := range ev.Checks {
		ev.Pass = ev.Pass && c.Pass
	}
	ev.Finished = time.Now().UTC().Format(time.RFC3339)
	if err := writeJSON(filepath.Join(cfg.OutDir, "r11-evidence.json"), ev); err != nil {
		return ev, err
	}
	return ev, nil
}

// drive runs the sequence; it returns why it stopped early, or "".
func (r *r11Run) drive(ctx context.Context, ev *R11Evidence) string {
	cfg := r.cfg
	if err := r.preflight(ctx); err != nil {
		return "preflight: " + err.Error()
	}
	r.logf("preflight: %s running under compose project %q", strings.Join(R11CoreContainers, ", "), cfg.ComposeProject)

	store := NewRunStore(filepath.Join(cfg.OutDir, "runs"))
	e := NewExecutor(store, nil, cfg.DemoBin, "", FabricConfig{})
	e.run = r.run
	r.e = e
	names := make([]Trustee, cfg.Trustees)
	for i := range names {
		names[i] = Trustee{Name: "Trustee " + strconv.Itoa(i+1)}
	}
	c := ElectionConfig{
		Name: cfg.ElectionName(), Trustees: names, Threshold: cfg.Threshold,
		Positions: cfg.Positions, Candidates: cfg.Candidates, Voters: cfg.Voters,
		Distribution: cfg.Distribution, Mode: "onchain", Concurrency: cfg.Concurrency,
		SkipAttacks: true,
	}
	runID, dir, err := store.Create(c, time.Now())
	if err != nil {
		return "create run: " + err.Error()
	}
	r.runID, r.dir, r.elec = runID, dir, e.electionID(runID)
	ev.RunID, ev.RunDir = runID, dir
	ev.Election["election_id"] = r.elec
	r.logf("run %s (election %s) in %s", runID, r.elec, dir)

	r.logf("generate: %d voters x %d positions", cfg.Voters, cfg.Positions)
	if err := e.Generate(ctx, runID, c); err != nil {
		return "generate: " + err.Error()
	}
	var h electionHeader
	if err := readJSON(filepath.Join(dir, headerFile), &h); err != nil {
		return "read header: " + err.Error()
	}
	if h.N != cfg.Records() {
		return fmt.Sprintf("the generator wrote %d records, want %d", h.N, cfg.Records())
	}

	// The window's ledger: one connection, recorded, firing the blackout.
	winCtx, winCancel := context.WithCancel(ctx)
	defer winCancel()
	r.winCancel = winCancel
	e.dialLedger = func() (clientsdk.Ledger, func(), error) {
		conn, err := cfg.Dial()
		if err != nil {
			return nil, nil, err
		}
		r.winLed = conn.Ledger
		closeFn := conn.Close
		if closeFn == nil {
			closeFn = func() {}
		}
		return r11Ledger{Ledger: conn.Ledger, r: r}, closeFn, nil
	}
	// Submit's setup transactions (CreateElection, RegisterPrecinctMachine,
	// PublishDKGTranscript) are recorded under the window phase too; only its
	// SubmitBallot calls are classified.
	r.setPhase(r11PhaseWindow)
	r.logf("submit: setup, then %d records, %d in flight; blackout at %d committed", cfg.Records(), cfg.Concurrency, cfg.TriggerCount())
	subErr := e.Submit(winCtx, runID, c)
	r.logf("submit returned: %v", subErr)
	fired := false
	r.boMu.Lock()
	fired = r.bo.Fired
	r.boMu.Unlock()
	if !fired {
		if subErr == nil {
			return "the ballot window finished before the blackout fired"
		}
		return "submit failed before the blackout fired: " + subErr.Error()
	}
	select {
	case <-r.restarted:
	case <-ctx.Done():
		return "cancelled while the network was down: " + ctx.Err().Error()
	}
	r.boMu.Lock()
	ready := r.bo.Ready
	r.boMu.Unlock()

	// 1. Classification, from the window's own calls.
	byNullifier, err := nullifierIndex(dir, h.N)
	if err != nil {
		return "index nullifiers: " + err.Error()
	}
	status, cls := classifyRecords(h.N, byNullifier, r.callsIn(r11PhaseWindow), r.killAt)
	ev.Classification = cls
	r.logf("classified: C %d, U %d, N %d (of %d)", cls.Committed, cls.Uncertain, cls.NotSent, cls.Records)
	if !ready || r.post == nil {
		return "the chain did not answer after the restart"
	}

	bundlePath, err := e.bundlePath(runID)
	if err != nil {
		return err.Error()
	}
	b, err := loadBundle(bundlePath)
	if err != nil {
		return err.Error()
	}
	post := r11Ledger{Ledger: r.post.Ledger, r: r}
	reader := r.post.Reader

	// 3. What the chain holds after the restart.
	onChain, err := chainCommitted(byNullifier, b, reader)
	if err != nil {
		return "list nullifiers after the restart: " + err.Error()
	}
	afterRestart(&ev.Classification, status, onChain)
	r.logf("after restart: %d on chain; C missing %d; U on chain %d", ev.Classification.OnChainAfterRestart,
		ev.Classification.CommittedMissing, ev.Classification.UncertainOnChain)

	// 4a. The duplicate: one C record again, while the election is open.
	r.setPhase(r11PhaseDuplicate)
	ev.Duplicate = r.duplicate(dir, status)
	if ev.Duplicate != nil {
		r.logf("duplicate: record %d -> %s gate %q", ev.Duplicate.Index, ev.Duplicate.Outcome, ev.Duplicate.Gate)
	}

	// 4b. The executor's resume.
	for attempt := 1; attempt <= r11MaxResumes; attempt++ {
		before, err := chainCommitted(byNullifier, b, reader)
		if err != nil {
			ev.Resume = append(ev.Resume, R11ResumeAttempt{Attempt: attempt, Error: "list nullifiers: " + err.Error()})
			time.Sleep(cfg.ResumeRetryWait)
			continue
		}
		phase := fmt.Sprintf("%s-%d", r11PhaseResume, attempt)
		r.setPhase(phase)
		rerr := e.resumeAndClose(ctx, runID, c, post, reader, bundlePath)
		a := resumeAttempt(attempt, before, byNullifier, r.callsIn(phase))
		if rerr != nil {
			a.Error = rerr.Error()
		}
		ev.Resume = append(ev.Resume, a)
		r.logf("resume %d: %d on chain before, %d submitted, %d accepted, %d already on chain; err %v",
			attempt, a.OnChainBefore, a.Submitted, a.Accepted, a.SubmittedAlreadyOnChain, rerr)
		if rerr == nil || ctx.Err() != nil {
			break
		}
		time.Sleep(cfg.ResumeRetryWait)
	}
	if n := len(ev.Resume); n == 0 || ev.Resume[n-1].Error != "" {
		return "the resume did not finish"
	}

	// 5. Ceremony and verification.
	fin := &R11Final{}
	ev.Final = fin
	r.setPhase(r11PhaseCeremony)
	if err := r.ceremony(ctx, post, bundlePath); err != nil {
		fin.TallyError = err.Error()
		return "ceremony: " + err.Error()
	}
	r.finalChecks(ctx, c, byNullifier, reader, fin)
	return ""
}

// duplicate resubmits the first C record.
func (r *r11Run) duplicate(dir string, status []string) *R11Duplicate {
	idx := -1
	for i, s := range status {
		if s == R11Committed {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil
	}
	var line string
	_ = scanBallotLines(dir, func(i int, l string) error {
		if i == idx {
			line = l
		}
		return nil
	})
	d := &R11Duplicate{Index: idx, Nullifier: r14NullifierOf(line)}
	_, rec, err := r11Ledger{Ledger: r.post.Ledger, r: r}.SubmitWithReceipt("SubmitBallot", line)
	o := observe("SubmitBallot", rec, err)
	d.Outcome, d.Gate, d.Error, d.TxID = o.Outcome, o.Gate, o.Error, o.TxID
	return d
}

// ceremony commits the bundle's partial decryptions and the tally through
// the executor's lifecycle step, as its all-in-one submit path does.
func (r *r11Run) ceremony(ctx context.Context, led clientsdk.Ledger, bundlePath string) error {
	b, step, err := r.e.lifecycle(r.runID, led, bundlePath, "ceremony")
	if err != nil {
		return err
	}
	defer r.e.closeReceipts(r.runID)
	if err := submitPartials(ctx, b, step); err != nil {
		return err
	}
	return step(ctx, "PublishTally", "", "PublishTally", b.Tally)
}

// finalChecks reads the end state and audits it.
func (r *r11Run) finalChecks(ctx context.Context, c ElectionConfig,
	byNullifier map[[32]byte]int, reader BlackoutReader, fin *R11Final) {
	if n, err := reader.CountCommittedBallots(r.elec); err != nil {
		fin.CountError = err.Error()
	} else {
		fin.CountCommitted = n
	}
	listed, err := listAllNullifiers(reader, r.elec)
	if err != nil {
		fin.ListError = err.Error()
	}
	fin.ListedNullifiers, fin.DistinctNullifiers, fin.MissingFromLedger, fin.ExtraOnLedger = nullifierSetStats(listed, byNullifier)

	local, err := r.e.verify(ctx, r.runID, c, reader)
	if err != nil {
		fin.VerifyError = err.Error()
	}
	fin.LocalOverall = local.Overall
	out, runErr := r.run(ctx, r.cfg.DemoBin, "audit-stream", filepath.Join(r.dir, LedgerDir), "--json")
	_ = os.WriteFile(filepath.Join(r.cfg.OutDir, "audit-ledger.json"), out, 0o644)
	var ledger StreamAudit
	if err := json.Unmarshal(out, &ledger); err != nil {
		fin.VerifyError = strings.TrimSpace(fin.VerifyError + "; ledger audit-stream: no valid result: " + fmt.Sprint(err, " ", runErr))
		return
	}
	fin.LedgerOverall = ledger.Overall
	for _, ct := range ledger.Contests {
		ct.Source = "ledger"
		fin.Contests = append(fin.Contests, ct)
		if e := abs64(ct.E); e > fin.MaxAbsE {
			fin.MaxAbsE = e
		}
	}
	if fin.LedgerMatchLocal, err = compareLedger(r.dir, local, ledger); err != nil {
		fin.VerifyError = strings.TrimSpace(fin.VerifyError + "; compare ledger: " + err.Error())
	}
}

// inspectAtEnd records each killed container's state at the end of the run.
func (r *r11Run) inspectAtEnd() {
	r.boMu.Lock()
	names := append([]string(nil), r.killed...)
	r.boMu.Unlock()
	for i, name := range names {
		up, state := r.inspect(context.Background(), name)
		r.boMu.Lock()
		r.bo.Containers[i].RunningAtEnd, r.bo.Containers[i].State = up, state
		r.boMu.Unlock()
	}
}

// writeEvents saves the docker events of the killed containers over the run.
func (r *r11Run) writeEvents(started time.Time) {
	r.boMu.Lock()
	names := append([]string(nil), r.killed...)
	r.boMu.Unlock()
	if len(names) == 0 {
		return
	}
	out, err := r.docker(context.Background(), "events",
		"--since", strconv.FormatInt(started.Add(-5*time.Second).Unix(), 10),
		"--until", strconv.FormatInt(time.Now().Add(time.Second).Unix(), 10),
		"--filter", "type=container", "--format", "{{json .}}")
	if err != nil {
		r.boError("docker events: %v", err)
	}
	_ = os.WriteFile(filepath.Join(r.cfg.OutDir, "docker-events.ndjson"), []byte(filterEvents(out, names)), 0o644)
}

// filterEvents keeps the event lines naming one of names.
func filterEvents(out string, names []string) string {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var b strings.Builder
	for _, line := range strings.Split(out, "\n") {
		var ev struct {
			Actor struct {
				Attributes map[string]string `json:"Attributes"`
			} `json:"Actor"`
		}
		if json.Unmarshal([]byte(line), &ev) != nil || !want[ev.Actor.Attributes["name"]] {
			continue
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// classifyRecords puts each ballot record in C, U or N from the window's
// SubmitBallot calls. A record with several calls is C if any of them
// returned a valid commit status. killAt splits C records by when their
// answer came back.
func classifyRecords(records int, byNullifier map[[32]byte]int, calls []r11Call, killAt time.Time) ([]string, R11Classification) {
	status := make([]string, records)
	for i := range status {
		status[i] = R11NotSent
	}
	cls := R11Classification{Records: records}
	afterKill := map[int]bool{}
	for _, c := range calls {
		if c.Fn != "SubmitBallot" {
			continue
		}
		key, ok := nullifierKey(c.Nullifier)
		if !ok {
			continue
		}
		i, ok := byNullifier[key]
		if !ok || i >= records {
			continue
		}
		switch {
		case c.OK:
			status[i] = R11Committed
			afterKill[i] = !killAt.IsZero() && c.done.After(killAt)
		case status[i] != R11Committed:
			status[i] = R11Uncertain
			if cls.FirstUncertainError == "" {
				cls.FirstUncertainError = c.Error
			}
		}
	}
	for i, s := range status {
		switch s {
		case R11Committed:
			cls.Committed++
			if afterKill[i] {
				cls.CommittedAfterKill++
			}
		case R11Uncertain:
			cls.Uncertain++
		default:
			cls.NotSent++
		}
	}
	return status, cls
}

// afterRestart fills in what the chain held of each class after the restart.
func afterRestart(cls *R11Classification, status []string, onChain []bool) {
	for i, s := range status {
		on := i < len(onChain) && onChain[i]
		if on {
			cls.OnChainAfterRestart++
		}
		switch s {
		case R11Committed:
			if !on {
				cls.CommittedMissing++
				if len(cls.CommittedMissingSample) < 20 {
					cls.CommittedMissingSample = append(cls.CommittedMissingSample, i)
				}
			}
		case R11Uncertain:
			if on {
				cls.UncertainOnChain++
			} else {
				cls.UncertainNotOnChain++
			}
		default:
			if on {
				cls.NotSentOnChain++
			}
		}
	}
}

// resumeAttempt summarises one resume's SubmitBallot calls against what the
// chain held when it started.
func resumeAttempt(attempt int, before []bool, byNullifier map[[32]byte]int, calls []r11Call) R11ResumeAttempt {
	a := R11ResumeAttempt{Attempt: attempt}
	for _, on := range before {
		if on {
			a.OnChainBefore++
		}
	}
	distinct := map[int]bool{}
	for _, c := range calls {
		if c.Fn != "SubmitBallot" {
			continue
		}
		a.Submitted++
		if c.OK {
			a.Accepted++
		}
		key, ok := nullifierKey(c.Nullifier)
		if !ok {
			continue
		}
		if i, ok := byNullifier[key]; ok {
			distinct[i] = true
			if i < len(before) && before[i] {
				a.SubmittedAlreadyOnChain++
			}
		}
	}
	a.DistinctSubmitted = len(distinct)
	return a
}

// listAllNullifiers walks every ListNullifiers page of an election.
func listAllNullifiers(nl nullifierLister, electionID string) ([]string, error) {
	var all []string
	bookmark := ""
	for {
		page, err := nl.ListNullifiers(electionID, nullifierPageSize, bookmark)
		if err != nil {
			return all, err
		}
		all = append(all, page.Nullifiers...)
		if page.NextBookmark == "" || page.NextBookmark == bookmark {
			return all, nil
		}
		bookmark = page.NextBookmark
	}
}

// nullifierSetStats compares the chain's listing with the run's records.
func nullifierSetStats(listed []string, byNullifier map[[32]byte]int) (total, distinct, missing, extra int) {
	seen := map[string]bool{}
	for _, n := range listed {
		n = strings.ToLower(n)
		total++
		if seen[n] {
			continue
		}
		seen[n] = true
		distinct++
		if key, ok := nullifierKey(n); !ok || !inIndex(byNullifier, key) {
			extra++
		}
	}
	for key := range byNullifier {
		if !seen[hex.EncodeToString(key[:])] {
			missing++
		}
	}
	return total, distinct, missing, extra
}

func inIndex(m map[[32]byte]int, k [32]byte) bool { _, ok := m[k]; return ok }

// r11Checks turns the evidence into the checks. It reads only ev, so a test
// can drive every verdict from a hand-built evidence document.
func r11Checks(ev R11Evidence) []R11Check {
	cls, bo := ev.Classification, ev.Blackout
	var out []R11Check
	add := func(id, observed string, pass bool) {
		exp := ""
		for _, n := range r11CheckNames {
			if n[0] == id {
				exp = n[1]
			}
		}
		out = append(out, R11Check{ID: id, Expected: exp, Observed: observed, Pass: pass})
	}
	add("pre.classified", fmt.Sprintf("C %d + U %d + N %d = %d of %d records", cls.Committed, cls.Uncertain, cls.NotSent,
		cls.Committed+cls.Uncertain+cls.NotSent, cls.Records),
		bo.Fired && cls.Records > 0 && cls.Committed+cls.Uncertain+cls.NotSent == cls.Records &&
			cls.Committed >= 1 && cls.Uncertain+cls.NotSent >= 1)
	add("pre.height", fmt.Sprintf("height %d (read ok %v)", bo.HeightBefore, bo.HeightBeforeOK), bo.HeightBeforeOK && bo.HeightBefore > 0)

	killedRoles := map[string]int{}
	for _, c := range bo.Containers {
		killedRoles[c.Role]++
	}
	add("blackout.killed", fmt.Sprintf("kill ok %v: %d orderer, %d peers, %d chaincode containers", bo.KillOK,
		killedRoles["orderer"], killedRoles["peer"], killedRoles["chaincode"]),
		bo.Fired && bo.KillOK && killedRoles["orderer"] == 1 && killedRoles["peer"] == 2 && killedRoles["chaincode"] >= 1)
	down, inspected := 0, 0
	for _, c := range bo.Containers {
		if c.RunningAtDowntimeEnd != nil {
			inspected++
			if !*c.RunningAtDowntimeEnd {
				down++
			}
		}
	}
	add("blackout.down", fmt.Sprintf("%d of %d killed containers down at the end of the downtime", down, len(bo.Containers)),
		len(bo.Containers) > 0 && inspected == len(bo.Containers) && down == len(bo.Containers))
	add("blackout.downtime", fmt.Sprintf("down %d ms (configured %d ms)", bo.DowntimeMs, bo.ConfiguredMs),
		bo.StartOK && bo.ConfiguredMs > 0 && bo.DowntimeMs >= bo.ConfiguredMs)
	add("blackout.ready", fmt.Sprintf("ready %v after %d ms (%d attempts): %s", bo.Ready, bo.TimeToReadyMs, bo.ReadyAttempts, bo.FirstQuery), bo.Ready)
	up := 0
	var by []string
	for _, c := range bo.Containers {
		if c.RunningAtEnd {
			up++
		}
		if c.Role == "chaincode" {
			by = append(by, c.Name+" by "+orNone(c.StartedBy))
		}
	}
	add("blackout.restarted", fmt.Sprintf("%d of %d running; %s", up, len(bo.Containers), strings.Join(by, "; ")),
		len(bo.Containers) > 0 && up == len(bo.Containers))

	add("after.height", fmt.Sprintf("after %d (ok %v) vs before %d", bo.HeightAfter, bo.HeightAfterOK, bo.HeightBefore),
		bo.HeightAfterOK && bo.HeightBeforeOK && bo.HeightAfter >= bo.HeightBefore)
	add("after.committed_kept", fmt.Sprintf("%d of %d C records missing; %d on chain in all (U on chain %d, U not %d)",
		cls.CommittedMissing, cls.Committed, cls.OnChainAfterRestart, cls.UncertainOnChain, cls.UncertainNotOnChain),
		bo.Ready && cls.Committed >= 1 && cls.CommittedMissing == 0 && cls.OnChainAfterRestart >= cls.Committed)

	if d := ev.Duplicate; d != nil {
		add("resume.duplicate_refused", fmt.Sprintf("record %d: %s gate %q", d.Index, d.Outcome, d.Gate),
			d.Outcome == r14Refuse && d.Gate == "nullifier")
	} else {
		add("resume.duplicate_refused", "not run", false)
	}
	only := len(ev.Resume) > 0
	var parts []string
	for _, a := range ev.Resume {
		parts = append(parts, fmt.Sprintf("attempt %d: on chain %d, submitted %d (%d distinct), already on chain %d",
			a.Attempt, a.OnChainBefore, a.Submitted, a.DistinctSubmitted, a.SubmittedAlreadyOnChain))
		// Every record the chain lacked is sent once, and nothing it held.
		if a.SubmittedAlreadyOnChain != 0 || a.DistinctSubmitted != a.Submitted ||
			(a.Error == "" && a.Submitted != cls.Records-a.OnChainBefore) {
			only = false
		}
	}
	add("resume.only_missing", strings.Join(parts, "; "), only)
	last := R11ResumeAttempt{Error: "no resume"}
	if n := len(ev.Resume); n > 0 {
		last = ev.Resume[n-1]
	}
	add("resume.done", fmt.Sprintf("%d attempt(s); last error %q", len(ev.Resume), last.Error), len(ev.Resume) > 0 && last.Error == "")

	fin := ev.Final
	if fin == nil {
		fin = &R11Final{TallyError: "not reached"}
	}
	add("final.tally", "tally error "+strconv.Quote(fin.TallyError), ev.Final != nil && fin.TallyError == "")
	add("final.count", fmt.Sprintf("CountCommittedBallots %d of %d %s", fin.CountCommitted, cls.Records, fin.CountError),
		ev.Final != nil && fin.CountError == "" && fin.CountCommitted == cls.Records)
	add("final.no_duplicates", fmt.Sprintf("listed %d, distinct %d, missing %d, extra %d %s",
		fin.ListedNullifiers, fin.DistinctNullifiers, fin.MissingFromLedger, fin.ExtraOnLedger, fin.ListError),
		ev.Final != nil && fin.ListError == "" && fin.ListedNullifiers == cls.Records &&
			fin.DistinctNullifiers == cls.Records && fin.MissingFromLedger == 0 && fin.ExtraOnLedger == 0)
	add("final.audit", fmt.Sprintf("local %s, ledger %s, %d contests, max |E| %d, ledger matches generated %v %s",
		orNone(fin.LocalOverall), orNone(fin.LedgerOverall), len(fin.Contests), fin.MaxAbsE, fin.LedgerMatchLocal, fin.VerifyError),
		ev.Final != nil && fin.VerifyError == "" && fin.LocalOverall == "pass" && fin.LedgerOverall == "pass" &&
			len(fin.Contests) > 0 && fin.MaxAbsE == 0 && fin.LedgerMatchLocal)
	return out
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
