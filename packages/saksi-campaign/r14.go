package campaign

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// The R14 precinct-machine test (tools/r14-machine-test.sh).
//
// It checks, against a live network running the chaincode with the admin gate
// and the per-precinct machine binding, that:
//
//	case 1  the registered machine (User1, precinct A) submits ballots into A: accepted
//	case 2  an unregistered Org1 client (User3) submits a valid A ballot: refused at gate caller
//	case 3  precinct B's machine (User2) submits a valid A ballot: refused at gate caller
//	case 4  a non-admin (User1) cannot create an election, register a machine or close
//	        one (gate admin), and the administrator cannot re-register or swap A's machine
//	case 5  after the normal close, partial decryptions and tally, the verifier finds E = 0
//	        on every contest, and the ledger holds exactly case 1's accepted ballots
//
// The ballot refused in cases 2 and 3 is A's last generated ballot, held back
// from case 1's first batch. Once both refusals are recorded, User1 submits it
// and it is accepted: the refusal was the caller, not the ballot. Every other
// piece (generator, DKG transcript, partial decryptions, tally, ledger dump,
// auditor) is the console's own on-chain path; nothing here reimplements
// crypto.

// The four identities the test acts as, keyed as in MachineTestConfig.Identities.
const (
	R14Admin = "admin"
	R14User1 = "user1"
	R14User2 = "user2"
	R14User3 = "user3"
)

// R14Identities lists the identity keys in a fixed order, with the
// test-network user each one is and the role it plays.
var R14Identities = []struct{ Key, User, Role string }{
	{R14Admin, "Admin", "administrator (Org1MSP, OU admin)"},
	{R14User1, "User1", "precinct A's registered machine"},
	{R14User2, "User2", "precinct B's registered machine"},
	{R14User3, "User3", "valid Org1 client registered for no precinct"},
}

// MachineTestActor submits one chaincode transaction signed by a single fixed
// identity. A clientsdk.Ledger from a connection with only a default identity
// satisfies it.
type MachineTestActor interface {
	SubmitWithReceipt(fn string, args ...string) ([]byte, clientsdk.Receipt, error)
}

// MachineTestReader is the read side the test needs: the ledger dump's reads
// plus the precinct-machine registry and the committed-ballot count.
// *clientsdk.BulletinClient satisfies it.
type MachineTestReader interface {
	ledgerReader
	GetPrecinctMachine(electionID string) (string, error)
	CountCommittedBallots(electionID string) (int, error)
}

var _ MachineTestReader = (*clientsdk.BulletinClient)(nil)

// MachineTestChain is the network as the test sees it: one actor per
// identity, and a reader.
type MachineTestChain struct {
	Actors map[string]MachineTestActor
	Reader MachineTestReader
}

// MachineTestIdentity is one identity's evidence: who it is, and the
// fingerprint the chaincode computes for it.
type MachineTestIdentity struct {
	User        string `json:"user"`
	Role        string `json:"role"`
	Cert        string `json:"cert"`
	Fingerprint string `json:"fingerprint"`
}

// MachineTestConfig is everything the test needs besides the chain.
type MachineTestConfig struct {
	OutDir       string
	DemoBin      string
	Stamp        string
	Voters       int
	Positions    int
	Candidates   int
	Trustees     int
	Threshold    int
	Distribution string
	// Concurrency bounds case 1's ballots in flight.
	Concurrency int
	Identities  map[string]MachineTestIdentity
	// Run shells the generator and the auditor. nil means execRunner.
	Run Runner
	// Provenance copied into the evidence.
	Commit   string
	Network  map[string]string
	Binaries map[string]string // name -> path; each is SHA-256 digested
	// Log receives progress lines. nil discards them.
	Log io.Writer
}

// ElectionA and ElectionB are the two precinct elections' ids.
func (c MachineTestConfig) ElectionA() string { return "r14-" + c.Stamp + "-p01" }
func (c MachineTestConfig) ElectionB() string { return "r14-" + c.Stamp + "-p02" }

// Validate refuses a configuration the test cannot run.
func (c MachineTestConfig) Validate() error {
	switch {
	case c.Stamp == "":
		return errors.New("stamp is required")
	case c.Voters < 1:
		return errors.New("--voters must be at least 1")
	case c.Positions < 1 || c.Candidates < 2:
		return errors.New("--positions must be at least 1 and --candidates at least 2")
	case c.Threshold < 1 || c.Threshold > c.Trustees:
		return fmt.Errorf("--threshold %d must be between 1 and --trustees %d", c.Threshold, c.Trustees)
	}
	for _, id := range R14Identities {
		if c.Identities[id.Key].Fingerprint == "" {
			return fmt.Errorf("identity %s (%s) has no certificate fingerprint", id.Key, id.User)
		}
	}
	return nil
}

// Expected outcomes.
const (
	r14Accept = "accept"
	r14Refuse = "refuse"
	r14Absent = "absent"
)

// Step kinds. A call is one transaction; the rest are reads, bulk
// submissions, or the verifier.
const (
	r14KindCall     = "call"
	r14KindAbsent   = "absent"
	r14KindMachine  = "machine"
	r14KindBallots  = "ballots"
	r14KindPartials = "partials"
	r14KindVerify   = "verify"
)

// R14Step is one planned step: who does what, and what must happen.
type R14Step struct {
	ID    int    `json:"step"`
	Case  string `json:"case"` // setup, case1..case5
	Kind  string `json:"kind"`
	Actor string `json:"actor,omitempty"` // identity key
	Fn    string `json:"fn,omitempty"`
	// Args are symbolic ($A, $B, $A.params, $B.params, $A.dkg, $B.dkg,
	// $A.tally, $fp.<key>, $held), resolved when the step runs.
	Args   []string `json:"args,omitempty"`
	Expect string   `json:"expect"`         // accept | refuse | absent
	Gate   string   `json:"gate,omitempty"` // the refusal gate expected
	Note   string   `json:"note"`
	// Abort stops the run when the step does not go as expected: the steps
	// after it would measure nothing.
	Abort bool `json:"-"`
}

// R14Plan is the fixed order of calls. Cases 2 and 3 run between case 1's two
// submissions so the ballot they offer is one case 1 then lands.
func R14Plan() []R14Step {
	s := []R14Step{
		{Case: "case4", Kind: r14KindCall, Actor: R14User1, Fn: "CreateElection", Args: []string{"$B.params"},
			Expect: r14Refuse, Gate: "admin", Note: "B1 retest: a non-admin Org1 client creates precinct B's election"},
		{Case: "case4", Kind: r14KindAbsent, Actor: R14Admin, Fn: "GetElection", Args: []string{"$B"},
			Expect: r14Absent, Note: "the refused CreateElection left no election B behind", Abort: true},
		{Case: "setup", Kind: r14KindCall, Actor: R14Admin, Fn: "CreateElection", Args: []string{"$A.params"},
			Expect: r14Accept, Note: "administrator creates precinct A", Abort: true},
		{Case: "setup", Kind: r14KindCall, Actor: R14Admin, Fn: "CreateElection", Args: []string{"$B.params"},
			Expect: r14Accept, Note: "administrator creates precinct B", Abort: true},
		{Case: "case4", Kind: r14KindCall, Actor: R14User1, Fn: "RegisterPrecinctMachine", Args: []string{"$A", "$fp.user1"},
			Expect: r14Refuse, Gate: "admin", Note: "B1 retest: a non-admin registers itself as A's machine"},
		{Case: "setup", Kind: r14KindCall, Actor: R14Admin, Fn: "RegisterPrecinctMachine", Args: []string{"$A", "$fp.user1"},
			Expect: r14Accept, Note: "administrator binds A to User1", Abort: true},
		{Case: "setup", Kind: r14KindCall, Actor: R14Admin, Fn: "RegisterPrecinctMachine", Args: []string{"$B", "$fp.user2"},
			Expect: r14Accept, Note: "administrator binds B to User2", Abort: true},
		{Case: "case4", Kind: r14KindCall, Actor: R14Admin, Fn: "RegisterPrecinctMachine", Args: []string{"$A", "$fp.user1"},
			Expect: r14Refuse, Gate: "machine-duplicate", Note: "administrator re-registers A (same machine)"},
		{Case: "case4", Kind: r14KindCall, Actor: R14Admin, Fn: "RegisterPrecinctMachine", Args: []string{"$A", "$fp.user3"},
			Expect: r14Refuse, Gate: "machine-duplicate", Note: "administrator tries to swap A's machine to User3 before any ballot"},
		{Case: "setup", Kind: r14KindMachine, Actor: R14Admin, Fn: "GetPrecinctMachine", Args: []string{"$A", "$fp.user1"},
			Expect: r14Accept, Note: "A is bound to User1's fingerprint", Abort: true},
		{Case: "setup", Kind: r14KindMachine, Actor: R14Admin, Fn: "GetPrecinctMachine", Args: []string{"$B", "$fp.user2"},
			Expect: r14Accept, Note: "B is bound to User2's fingerprint", Abort: true},
		{Case: "setup", Kind: r14KindCall, Actor: R14User1, Fn: "PublishDKGTranscript", Args: []string{"$A.dkg"},
			Expect: r14Accept, Note: "A's DKG transcript (the console's default identity publishes it)", Abort: true},
		{Case: "setup", Kind: r14KindCall, Actor: R14User1, Fn: "PublishDKGTranscript", Args: []string{"$B.dkg"},
			Expect: r14Accept, Note: "B's DKG transcript", Abort: true},
		{Case: "case1", Kind: r14KindBallots, Actor: R14User1, Fn: "SubmitBallot",
			Expect: r14Accept, Note: "A's machine submits every generated ballot but the held one", Abort: true},
		{Case: "case2", Kind: r14KindCall, Actor: R14User3, Fn: "SubmitBallot", Args: []string{"$held"},
			Expect: r14Refuse, Gate: "caller", Note: "unregistered Org1 client submits A's held ballot"},
		{Case: "case3", Kind: r14KindCall, Actor: R14User2, Fn: "SubmitBallot", Args: []string{"$held"},
			Expect: r14Refuse, Gate: "caller", Note: "precinct B's machine submits A's held ballot"},
		{Case: "case1", Kind: r14KindCall, Actor: R14User1, Fn: "SubmitBallot", Args: []string{"$held"},
			Expect: r14Accept, Note: "A's machine submits the held ballot that cases 2 and 3 offered"},
		{Case: "case4", Kind: r14KindCall, Actor: R14User1, Fn: "CloseElection", Args: []string{"$A"},
			Expect: r14Refuse, Gate: "admin", Note: "a non-admin (A's own machine) closes A"},
		{Case: "case4", Kind: r14KindCall, Actor: R14Admin, Fn: "RegisterPrecinctMachine", Args: []string{"$A", "$fp.user3"},
			Expect: r14Refuse, Gate: "machine-window", Note: "administrator tries to swap A's machine after ballots"},
		{Case: "case5", Kind: r14KindCall, Actor: R14Admin, Fn: "CloseElection", Args: []string{"$A"},
			Expect: r14Accept, Note: "administrator closes A", Abort: true},
		{Case: "case5", Kind: r14KindPartials, Actor: R14User1, Fn: "SubmitPartialDecryption",
			Expect: r14Accept, Note: "the threshold trustees' partial decryptions for A", Abort: true},
		{Case: "case5", Kind: r14KindCall, Actor: R14User1, Fn: "PublishTally", Args: []string{"$A.tally"},
			Expect: r14Accept, Note: "A's tally", Abort: true},
		{Case: "case5", Kind: r14KindVerify, Actor: R14Admin,
			Expect: r14Accept, Note: "ledger dump of A audited: E = 0 on every contest, ledger ballots = case 1 accepted, ledger matches the generated set"},
	}
	for i := range s {
		s[i].ID = i + 1
	}
	return s
}

// R14CaseTitles names each case in the evidence.
var R14CaseTitles = map[string]string{
	"setup": "Setup: two precinct elections, each bound to its machine, DKG published",
	"case1": "Registered machine (User1) submits valid ballots into precinct A: accepted",
	"case2": "Unregistered Org1 client (User3) submits a valid A ballot: refused at gate caller",
	"case3": "Precinct B's machine (User2) submits a valid A ballot: refused at gate caller",
	"case4": "Non-admin create/register/close refused at gate admin (B1 retest); re-registering A refused",
	"case5": "Close, partial decryptions, tally; verifier E = 0 and ledger ballots = case 1 accepted",
}

// R14CaseOrder is the evidence's case order.
var R14CaseOrder = []string{"setup", "case1", "case2", "case3", "case4", "case5"}

// R14DryRun writes the plan: every call, who makes it, and what must happen.
// It touches neither the network nor the generator.
func R14DryRun(w io.Writer, c MachineTestConfig) {
	fmt.Fprintf(w, "R14 precinct-machine test plan (dry run: nothing is contacted)\n\n")
	fmt.Fprintf(w, "election A: %s  (%d voters x %d positions x %d candidates, %d-of-%d trustees)\n",
		c.ElectionA(), c.Voters, c.Positions, c.Candidates, c.Threshold, c.Trustees)
	fmt.Fprintf(w, "election B: %s  (1 voter, same shape; created and bound only)\n\n", c.ElectionB())
	fmt.Fprintf(w, "identities:\n")
	for _, id := range R14Identities {
		mi := c.Identities[id.Key]
		fp := mi.Fingerprint
		if fp == "" {
			fp = "(certificate not found)"
		}
		fmt.Fprintf(w, "  %-6s %-6s %-46s %s\n", id.Key, id.User, id.Role, fp)
		if mi.Cert != "" {
			fmt.Fprintf(w, "         cert %s\n", mi.Cert)
		}
	}
	fmt.Fprintf(w, "\n  0  setup  local  saksi-demo gen --stream <out>/A (%d voters) and <out>/B (1 voter)\n", c.Voters)
	for _, s := range R14Plan() {
		want := s.Expect
		if s.Gate != "" {
			want += " gate=" + s.Gate
		}
		call := s.Fn + "(" + strings.Join(s.Args, ", ") + ")"
		switch s.Kind {
		case r14KindBallots:
			call = fmt.Sprintf("SubmitBallot x (records-1) (A's records 0..records-2, %d in flight)", c.Concurrency)
		case r14KindPartials:
			call = "SubmitPartialDecryption x each (A's bundle)"
		case r14KindVerify:
			call = "dump ledger(A) + saksi-demo audit-stream (local and ledger) + compare"
		case r14KindAbsent:
			call += " (read)"
		case r14KindMachine:
			call = fmt.Sprintf("GetPrecinctMachine(%s) == %s", s.Args[0], s.Args[1])
		}
		fmt.Fprintf(w, "%3d  %-5s  %-6s %-62s -> %s\n", s.ID, s.Case, s.Actor, call, want)
		fmt.Fprintf(w, "                     %s\n", s.Note)
	}
	fmt.Fprintf(w, "\nA ballot record is one voter's choice for one position, with its own nullifier:\n"+
		"A has about %d x %d = %d records (the header's n is authoritative).\n"+
		"$held is A's last generated record; case 1's bulk step submits all the others.\n",
		c.Voters, c.Positions, c.Voters*c.Positions)
}

// R14Observed is what happened.
type R14Observed struct {
	Outcome string `json:"outcome"` // accept | refuse | error
	Gate    string `json:"gate,omitempty"`
	Error   string `json:"error,omitempty"`
	TxID    string `json:"tx_id,omitempty"`
	Block   uint64 `json:"block,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// R14CallArg is one argument as evidence: short hex args are kept, long ones
// are summarised by length and digest.
type R14CallArg struct {
	Value  string `json:"value,omitempty"`
	Bytes  int    `json:"hex_bytes,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Symbol string `json:"symbol"`
}

// R14StepResult is one step's evidence.
type R14StepResult struct {
	Step     int                 `json:"step"`
	Case     string              `json:"case"`
	Identity MachineTestIdentity `json:"identity"`
	IdentKey string              `json:"identity_key"`
	Call     struct {
		Fn   string       `json:"fn"`
		Args []R14CallArg `json:"args,omitempty"`
	} `json:"call"`
	Expected struct {
		Outcome string `json:"outcome"`
		Gate    string `json:"gate,omitempty"`
	} `json:"expected"`
	Observed R14Observed    `json:"observed"`
	Counts   map[string]int `json:"counts,omitempty"`
	Note     string         `json:"note"`
	Pass     bool           `json:"pass"`
}

// R14Case groups a case's steps.
type R14Case struct {
	ID    string          `json:"id"`
	Title string          `json:"title"`
	Pass  bool            `json:"pass"`
	Steps []R14StepResult `json:"steps"`
}

// R14Evidence is r14-evidence.json.
type R14Evidence struct {
	Schema     string                         `json:"schema"`
	Started    string                         `json:"started"`
	Finished   string                         `json:"finished"`
	Commit     string                         `json:"commit"`
	Binaries   map[string]string              `json:"binary_sha256"`
	Network    map[string]string              `json:"network"`
	Election   map[string]any                 `json:"election"`
	Identities map[string]MachineTestIdentity `json:"identities"`
	Cases      []R14Case                      `json:"cases"`
	Verify     *R14Verify                     `json:"verify,omitempty"`
	Aborted    string                         `json:"aborted,omitempty"`
	Pass       bool                           `json:"pass"`
}

// R14Verify is case 5's verifier result.
type R14Verify struct {
	LedgerBallots    int                  `json:"ledger_ballots"`
	CommittedCount   int                  `json:"committed_count"`
	Case1Accepted    int                  `json:"case1_accepted"`
	Generated        int                  `json:"generated_records"`
	LocalOverall     string               `json:"local_overall"`
	LedgerOverall    string               `json:"ledger_overall"`
	LedgerMatchLocal bool                 `json:"ledger_matches_generated"`
	Contests         []ContestCorrectness `json:"contests"`
	MaxAbsE          int64                `json:"max_abs_e"`
}

// r14Election is one generated precinct election.
type r14Election struct {
	dir string
	h   electionHeader
}

type r14Run struct {
	cfg   MachineTestConfig
	chain MachineTestChain
	run   Runner
	calls *os.File
	mu    sync.Mutex
	a, b  r14Election
	held  string
	// records is A's generated ballot records: one per voter per position
	// (the ballot model submits each position as its own record, with its
	// own nullifier).
	records int
	n1      int // case 1 accepted
}

// RunMachineTest runs the plan against chain and writes r14-evidence.json and
// the raw logs into cfg.OutDir. The error is non-nil only when the evidence
// could not be written; a failed case is ev.Pass == false.
func RunMachineTest(ctx context.Context, cfg MachineTestConfig, chain MachineTestChain) (R14Evidence, error) {
	ev := R14Evidence{
		Schema:     "saksi-r14-machine-test/v1",
		Started:    time.Now().UTC().Format(time.RFC3339),
		Commit:     cfg.Commit,
		Binaries:   map[string]string{},
		Network:    cfg.Network,
		Identities: cfg.Identities,
		Election: map[string]any{
			"a": cfg.ElectionA(), "b": cfg.ElectionB(), "voters": cfg.Voters,
			"positions": cfg.Positions, "candidates": cfg.Candidates,
			"trustees": cfg.Trustees, "threshold": cfg.Threshold, "distribution": cfg.Distribution,
		},
	}
	for name, path := range cfg.Binaries {
		ev.Binaries[name] = fileSHA256(path)
	}
	if err := cfg.Validate(); err != nil {
		return ev, err
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return ev, err
	}
	calls, err := os.Create(filepath.Join(cfg.OutDir, "calls.ndjson"))
	if err != nil {
		return ev, err
	}
	defer calls.Close()
	r := &r14Run{cfg: cfg, chain: chain, run: cfg.Run, calls: calls}
	if r.run == nil {
		r.run = execRunner
	}

	results := map[string][]R14StepResult{}
	if err := r.generate(ctx); err != nil {
		ev.Aborted = "generate: " + err.Error()
	} else {
		ev.Election["ballot_records"] = r.records
		ev.Election["held_ballot_index"] = r.records - 1
		ev.Election["held_nullifier"] = r14NullifierOf(r.held)
		for _, s := range R14Plan() {
			if err := ctx.Err(); err != nil {
				ev.Aborted = "cancelled: " + err.Error()
				break
			}
			res := r.step(ctx, s, &ev)
			results[s.Case] = append(results[s.Case], res)
			r.logf("step %2d %-5s %-6s %-26s expect %-6s %-17s observed %-6s %-17s %s",
				s.ID, s.Case, s.Actor, s.Fn, s.Expect, s.Gate, res.Observed.Outcome, res.Observed.Gate, passWord(res.Pass))
			if !res.Pass && s.Abort {
				ev.Aborted = fmt.Sprintf("step %d (%s %s) did not go as expected; later steps would measure nothing", s.ID, s.Actor, s.Fn)
				break
			}
		}
	}

	ev.Pass = ev.Aborted == ""
	for _, id := range R14CaseOrder {
		c := R14Case{ID: id, Title: R14CaseTitles[id], Steps: results[id], Pass: len(results[id]) > 0}
		for _, s := range c.Steps {
			c.Pass = c.Pass && s.Pass
		}
		ev.Pass = ev.Pass && c.Pass
		ev.Cases = append(ev.Cases, c)
	}
	ev.Finished = time.Now().UTC().Format(time.RFC3339)
	if err := writeJSON(filepath.Join(cfg.OutDir, "r14-evidence.json"), ev); err != nil {
		return ev, err
	}
	return ev, nil
}

func passWord(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func (r *r14Run) logf(format string, a ...any) {
	if r.cfg.Log != nil {
		fmt.Fprintf(r.cfg.Log, format+"\n", a...)
	}
}

// generate runs saksi-demo gen for both precincts and holds back A's last
// ballot.
func (r *r14Run) generate(ctx context.Context) error {
	gen := func(id, sub string, voters int) (r14Election, error) {
		dir := filepath.Join(r.cfg.OutDir, sub)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return r14Election{}, err
		}
		names := make([]string, r.cfg.Trustees)
		for i := range names {
			names[i] = "Trustee " + strconv.Itoa(i+1)
		}
		args := []string{
			"gen", "--stream", dir,
			"--voters", strconv.Itoa(voters),
			"--positions", strconv.Itoa(r.cfg.Positions),
			"--candidates", strconv.Itoa(r.cfg.Candidates),
			"--trustees", strconv.Itoa(r.cfg.Trustees),
			"--threshold", strconv.Itoa(r.cfg.Threshold),
			"--election-id", id,
			"--election-name", "R14 precinct " + sub,
			"--trustee-names", strings.Join(names, ","),
			"--distribution", r.cfg.Distribution,
		}
		r.logf("generate %s: %s %s", id, r.cfg.DemoBin, strings.Join(args, " "))
		out, err := r.run(ctx, r.cfg.DemoBin, args...)
		_ = os.WriteFile(filepath.Join(r.cfg.OutDir, "gen-"+sub+".log"), out, 0o644)
		if err != nil {
			return r14Election{}, err
		}
		var e r14Election
		e.dir = dir
		if err := readJSON(filepath.Join(dir, headerFile), &e.h); err != nil {
			return r14Election{}, fmt.Errorf("read %s header: %w", sub, err)
		}
		if e.h.ElectionID != id {
			return r14Election{}, fmt.Errorf("%s header names election %q, want %q", sub, e.h.ElectionID, id)
		}
		return e, nil
	}
	var err error
	if r.a, err = gen(r.cfg.ElectionA(), "A", r.cfg.Voters); err != nil {
		return err
	}
	if r.b, err = gen(r.cfg.ElectionB(), "B", 1); err != nil {
		return err
	}
	n, err := validateBallots(r.a.dir)
	if err != nil {
		return err
	}
	if n < 2 || r.a.h.N != n {
		return fmt.Errorf("A holds %d ballot records (header n=%d); need the two to agree and at least 2", n, r.a.h.N)
	}
	r.records = n
	return scanBallotLines(r.a.dir, func(i int, line string) error {
		if i == n-1 {
			r.held = line
		}
		return nil
	})
}

// resolve turns a symbolic argument into its value.
func (r *r14Run) resolve(sym string) string {
	switch sym {
	case "$A":
		return r.a.h.ElectionID
	case "$B":
		return r.b.h.ElectionID
	case "$A.params":
		return r.a.h.Params
	case "$B.params":
		return r.b.h.Params
	case "$A.dkg":
		return r.a.h.Dkg
	case "$B.dkg":
		return r.b.h.Dkg
	case "$A.tally":
		return r.a.h.Tally
	case "$held":
		return r.held
	}
	if key, ok := strings.CutPrefix(sym, "$fp."); ok {
		return r.cfg.Identities[key].Fingerprint
	}
	return sym
}

func callArg(sym, v string) R14CallArg {
	if len(v) <= 80 {
		return R14CallArg{Symbol: sym, Value: v}
	}
	a := R14CallArg{Symbol: sym, Value: v[:32] + "...", Bytes: len(v) / 2}
	if raw, err := hex.DecodeString(v); err == nil {
		sum := sha256.Sum256(raw)
		a.SHA256 = hex.EncodeToString(sum[:])
	}
	return a
}

// observe classifies a transaction's outcome.
func observe(fn string, rec clientsdk.Receipt, err error) R14Observed {
	if err == nil {
		return R14Observed{Outcome: r14Accept, TxID: rec.TxID, Block: rec.BlockNumber}
	}
	text := clientsdk.ErrorText(err)
	o := R14Observed{Error: text, Gate: refusalCode(fn, text), Outcome: r14Refuse}
	if o.Gate == "" || o.Gate == "refused" {
		// Not a named chaincode gate: transport, timeout, MVCC, or an
		// endorsement failure with no gate marker. Never counted as the
		// refusal a case expects.
		o.Outcome = "error"
	}
	return o
}

func matches(s R14Step, o R14Observed) bool {
	if o.Outcome != s.Expect {
		return false
	}
	return s.Expect != r14Refuse || o.Gate == s.Gate
}

// record appends one raw call line to calls.ndjson.
func (r *r14Run) record(step int, actor, fn string, args []string, o R14Observed) {
	short := make([]R14CallArg, len(args))
	for i, a := range args {
		short[i] = callArg("", a)
	}
	entry := map[string]any{
		"time": time.Now().UTC().Format(time.RFC3339Nano), "step": step, "actor": actor,
		"fingerprint": r.cfg.Identities[actor].Fingerprint, "fn": fn, "args": short, "observed": o,
	}
	if fn == "SubmitBallot" && len(args) == 1 {
		entry["nullifier"] = r14NullifierOf(args[0])
	}
	line, _ := json.Marshal(entry)
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _ = r.calls.Write(append(line, '\n'))
}

func (r *r14Run) submit(step int, actor, fn string, args ...string) R14Observed {
	a, ok := r.chain.Actors[actor]
	if !ok {
		o := R14Observed{Outcome: "error", Error: "no actor for identity " + actor}
		r.record(step, actor, fn, args, o)
		return o
	}
	_, rec, err := a.SubmitWithReceipt(fn, args...)
	o := observe(fn, rec, err)
	r.record(step, actor, fn, args, o)
	return o
}

func (r *r14Run) step(ctx context.Context, s R14Step, ev *R14Evidence) R14StepResult {
	res := R14StepResult{Step: s.ID, Case: s.Case, IdentKey: s.Actor, Identity: r.cfg.Identities[s.Actor], Note: s.Note}
	res.Call.Fn = s.Fn
	res.Expected.Outcome, res.Expected.Gate = s.Expect, s.Gate
	args := make([]string, len(s.Args))
	for i, sym := range s.Args {
		args[i] = r.resolve(sym)
		res.Call.Args = append(res.Call.Args, callArg(sym, args[i]))
	}

	switch s.Kind {
	case r14KindCall:
		res.Observed = r.submit(s.ID, s.Actor, s.Fn, args...)
		res.Pass = matches(s, res.Observed)
		if res.Pass && s.Case == "case1" && s.Fn == "SubmitBallot" {
			r.n1++
		}
	case r14KindAbsent:
		_, err := r.chain.Reader.GetElection(args[0])
		if err == nil {
			res.Observed = R14Observed{Outcome: "present", Detail: "election exists on the ledger"}
		} else {
			res.Observed = R14Observed{Outcome: r14Absent, Detail: clientsdk.ErrorText(err)}
			res.Pass = true
		}
	case r14KindMachine:
		got, err := r.chain.Reader.GetPrecinctMachine(args[0])
		res.Observed = R14Observed{Outcome: r14Accept, Detail: "registered " + got}
		if err != nil {
			res.Observed = R14Observed{Outcome: "error", Error: clientsdk.ErrorText(err)}
		}
		res.Pass = err == nil && got == args[1]
	case r14KindBallots:
		res.Counts, res.Observed = r.ballots(ctx, s)
		res.Pass = res.Counts["accepted"] == res.Counts["submitted"] && res.Counts["submitted"] == r.records-1
	case r14KindPartials:
		res.Counts = map[string]int{"submitted": 0, "accepted": 0}
		res.Observed = R14Observed{Outcome: r14Accept}
		for _, pd := range r.a.h.PartialDecryptions {
			res.Counts["submitted"]++
			o := r.submit(s.ID, s.Actor, s.Fn, r.a.h.ElectionID, pd)
			if o.Outcome == r14Accept {
				res.Counts["accepted"]++
			} else if res.Observed.Outcome == r14Accept {
				res.Observed = o
			}
		}
		res.Pass = len(r.a.h.PartialDecryptions) > 0 && res.Counts["accepted"] == res.Counts["submitted"]
	case r14KindVerify:
		v, err := r.verify(ctx)
		ev.Verify = &v
		res.Observed = R14Observed{Outcome: r14Accept, Detail: fmt.Sprintf(
			"ledger %d ballots, committed %d, case 1 accepted %d; local %s, ledger %s, max |E| %d, ledger matches generated %v",
			v.LedgerBallots, v.CommittedCount, v.Case1Accepted, v.LocalOverall, v.LedgerOverall, v.MaxAbsE, v.LedgerMatchLocal)}
		if err != nil {
			res.Observed.Outcome, res.Observed.Error = "error", err.Error()
		}
		res.Pass = err == nil && v.LocalOverall == "pass" && v.LedgerOverall == "pass" && v.MaxAbsE == 0 &&
			v.LedgerBallots == v.Case1Accepted && v.CommittedCount == v.Case1Accepted &&
			v.Case1Accepted == v.Generated && v.LedgerMatchLocal && len(v.Contests) > 0
	}
	return res
}

// ballots submits A's ballots 0..N-2 as the actor, bounded in flight.
func (r *r14Run) ballots(ctx context.Context, s R14Step) (map[string]int, R14Observed) {
	lines := make(chan string)
	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		submitted  int
		accepted   int
		refused    int
		firstOther R14Observed
	)
	workers := r.cfg.Concurrency
	if workers < 1 {
		workers = 1
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range lines {
				o := r.submit(s.ID, s.Actor, s.Fn, line)
				mu.Lock()
				submitted++
				if o.Outcome == r14Accept {
					accepted++
				} else {
					refused++
					if firstOther.Outcome == "" {
						firstOther = o
					}
				}
				mu.Unlock()
			}
		}()
	}
	n := r.records
	err := scanBallotLines(r.a.dir, func(i int, line string) error {
		if i >= n-1 {
			return nil
		}
		select {
		case lines <- line:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	close(lines)
	wg.Wait()
	r.n1 += accepted
	counts := map[string]int{"submitted": submitted, "accepted": accepted, "not_accepted": refused}
	switch {
	case err != nil:
		return counts, R14Observed{Outcome: "error", Error: err.Error()}
	case refused > 0:
		firstOther.Detail = fmt.Sprintf("%d of %d not accepted; first shown", refused, submitted)
		return counts, firstOther
	}
	return counts, R14Observed{Outcome: r14Accept, Detail: fmt.Sprintf("%d of %d accepted", accepted, submitted)}
}

// verify dumps A's ledger, audits it and the generated folder with the same
// auditor, and compares them.
func (r *r14Run) verify(ctx context.Context) (R14Verify, error) {
	v := R14Verify{Case1Accepted: r.n1, Generated: r.records}
	audit := func(dir, name string) (StreamAudit, error) {
		out, runErr := r.run(ctx, r.cfg.DemoBin, "audit-stream", dir, "--json")
		_ = os.WriteFile(filepath.Join(r.cfg.OutDir, name), out, 0o644)
		var sa StreamAudit
		if err := json.Unmarshal(out, &sa); err != nil {
			return sa, fmt.Errorf("audit-stream %s: no valid result: %v (%v)", dir, err, runErr)
		}
		return sa, nil
	}
	n, _, err := dumpLedger(r.a.dir, r.a.h.ElectionID, r.chain.Reader)
	if err != nil {
		return v, fmt.Errorf("dump ledger: %w", err)
	}
	v.LedgerBallots = n
	if v.CommittedCount, err = r.chain.Reader.CountCommittedBallots(r.a.h.ElectionID); err != nil {
		return v, fmt.Errorf("count committed ballots: %w", err)
	}
	local, err := audit(r.a.dir, "audit-local.json")
	if err != nil {
		return v, err
	}
	ledger, err := audit(filepath.Join(r.a.dir, LedgerDir), "audit-ledger.json")
	if err != nil {
		return v, err
	}
	v.LocalOverall, v.LedgerOverall = local.Overall, ledger.Overall
	for _, c := range ledger.Contests {
		c.Source = "ledger"
		v.Contests = append(v.Contests, c)
		if e := abs64(c.E); e > v.MaxAbsE {
			v.MaxAbsE = e
		}
	}
	if v.LedgerMatchLocal, err = compareLedger(r.a.dir, local, ledger); err != nil {
		return v, fmt.Errorf("compare ledger: %w", err)
	}
	return v, nil
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "unavailable: " + err.Error()
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "unavailable: " + err.Error()
	}
	return hex.EncodeToString(h.Sum(nil))
}

// r14NullifierOf is a ballot's nullifier hex, or "".
func r14NullifierOf(ballotHex string) string {
	raw, err := hex.DecodeString(ballotHex)
	if err != nil {
		return ""
	}
	var b pb.Ballot
	if proto.Unmarshal(raw, &b) != nil {
		return ""
	}
	return hex.EncodeToString(b.GetCredentialPresentation().GetNullifier().GetValue())
}
