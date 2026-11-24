package campaign

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// r14Chain is an in-memory model of the chaincode's identity gates: the admin
// gate on CreateElection, RegisterPrecinctMachine and CloseElection, the
// registry's window and duplicate checks, and SubmitBallot's caller gate ahead
// of the existing election-open and nullifier gates. noAdminGate and
// noCallerGate switch a gate off, the regression the test must catch.
type r14Chain struct {
	mu           sync.Mutex
	adminFP      string
	noAdminGate  bool
	noCallerGate bool
	elections    map[string]*r14FakeElection
	tx           int
}

type r14FakeElection struct {
	params, status, dkg, tally, machine string
	contests, trustees                  []string
	ballots                             map[string]string
	order                               []string
	partials                            []string
}

type r14Actor struct {
	c  *r14Chain
	fp string
}

func newR14Chain(adminFP string) *r14Chain {
	return &r14Chain{adminFP: adminFP, elections: map[string]*r14FakeElection{}}
}

func (a r14Actor) SubmitWithReceipt(fn string, args ...string) ([]byte, clientsdk.Receipt, error) {
	c := a.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.apply(a.fp, fn, args); err != nil {
		return nil, clientsdk.Receipt{}, err
	}
	c.tx++
	return nil, clientsdk.Receipt{TxID: fmt.Sprintf("tx%d", c.tx), BlockNumber: uint64(c.tx)}, nil
}

func (c *r14Chain) admin(fp, action string) error {
	if c.noAdminGate || fp == c.adminFP {
		return nil
	}
	return fmt.Errorf("gate=admin: %s needs an administrator of Org1MSP (OU \"admin\"); caller is MSP \"Org1MSP\" with OUs [client]", action)
}

func (c *r14Chain) apply(fp, fn string, args []string) error {
	switch fn {
	case "CreateElection":
		if err := c.admin(fp, fn); err != nil {
			return err
		}
		raw, _ := hex.DecodeString(args[0])
		var p pb.ElectionParameters
		if err := proto.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("gate=decode: %v", err)
		}
		if c.elections[p.GetElectionId()] != nil {
			return fmt.Errorf("election %q already exists", p.GetElectionId())
		}
		c.elections[p.GetElectionId()] = &r14FakeElection{params: args[0], status: "open",
			contests: p.GetContestIds(), trustees: p.GetTrusteeIds(), ballots: map[string]string{}}
	case "RegisterPrecinctMachine":
		if err := c.admin(fp, fn); err != nil {
			return err
		}
		e := c.elections[args[0]]
		switch {
		case e == nil:
			return fmt.Errorf("gate=election-exists: no election found with id %q", args[0])
		case e.status != "open" || len(e.ballots) > 0:
			return fmt.Errorf("gate=machine-window: election %q already has ballots", args[0])
		case e.machine != "":
			return fmt.Errorf("gate=machine-duplicate: a precinct machine is already registered for election %q", args[0])
		}
		e.machine = args[1]
	case "PublishDKGTranscript":
		raw, _ := hex.DecodeString(args[0])
		var d pb.DKGTranscript
		if err := proto.Unmarshal(raw, &d); err != nil || c.elections[d.GetElectionId()] == nil {
			return fmt.Errorf("gate=dkg: no election for transcript (%v)", err)
		}
		c.elections[d.GetElectionId()].dkg = args[0]
	case "SubmitBallot":
		raw, _ := hex.DecodeString(args[0])
		var b pb.Ballot
		if err := proto.Unmarshal(raw, &b); err != nil {
			return fmt.Errorf("gate=decode: %v", err)
		}
		e := c.elections[b.GetElectionId()]
		if !c.noCallerGate {
			if e == nil || e.machine == "" {
				return fmt.Errorf("gate=caller: no precinct machine is registered for election %q", b.GetElectionId())
			}
			if fp != e.machine {
				return fmt.Errorf("gate=caller: caller is not this precinct's machine for election %q (certificate %s)", b.GetElectionId(), fp)
			}
		}
		if e == nil || e.status != "open" {
			return fmt.Errorf("gate=election-open: election %q is not open", b.GetElectionId())
		}
		nul := hex.EncodeToString(b.GetCredentialPresentation().GetNullifier().GetValue())
		if _, dup := e.ballots[nul]; dup {
			return fmt.Errorf("gate=nullifier: nullifier already used")
		}
		e.ballots[nul] = args[0]
		e.order = append(e.order, nul)
	case "CloseElection":
		if err := c.admin(fp, fn); err != nil {
			return err
		}
		e := c.elections[args[0]]
		if e == nil {
			return fmt.Errorf("no election %q", args[0])
		}
		e.status = "closed"
	case "SubmitPartialDecryption":
		e := c.elections[args[0]]
		if e == nil || e.status != "closed" {
			return fmt.Errorf("election %q is not closed", args[0])
		}
		e.partials = append(e.partials, args[1])
	case "PublishTally":
		raw, _ := hex.DecodeString(args[0])
		var tr pb.TallyResult
		if err := proto.Unmarshal(raw, &tr); err != nil || c.elections[tr.GetElectionId()] == nil {
			return fmt.Errorf("no election for tally (%v)", err)
		}
		c.elections[tr.GetElectionId()].tally = args[0]
	default:
		return fmt.Errorf("unknown function %s", fn)
	}
	return nil
}

// The reader side (MachineTestReader).

func (c *r14Chain) election(id string) (*r14FakeElection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.elections[id]; e != nil {
		return e, nil
	}
	return nil, fmt.Errorf("no election found with id %q", id)
}

func (c *r14Chain) ListNullifiers(id string, pageSize int, bookmark string) (clientsdk.NullifierPage, error) {
	e, err := c.election(id)
	if err != nil {
		return clientsdk.NullifierPage{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	list := append([]string(nil), e.order...)
	sort.Strings(list)
	off, _ := strconv.Atoi(bookmark)
	end := off + pageSize
	if pageSize <= 0 || end > len(list) {
		end = len(list)
	}
	page := clientsdk.NullifierPage{Nullifiers: list[off:end]}
	if end < len(list) {
		page.NextBookmark = strconv.Itoa(end)
	}
	return page, nil
}

func (c *r14Chain) GetBallot(id, nul string) (string, error) {
	e, err := c.election(id)
	if err != nil {
		return "", err
	}
	if b, ok := e.ballots[nul]; ok {
		return b, nil
	}
	return "", errors.New("no ballot")
}

func (c *r14Chain) GetBallots(id string, nuls []string) ([]string, error) {
	out := make([]string, len(nuls))
	for i, n := range nuls {
		out[i], _ = c.GetBallot(id, n)
	}
	return out, nil
}

func (c *r14Chain) GetElection(id string) (string, error) {
	e, err := c.election(id)
	if err != nil {
		return "", err
	}
	return e.params, nil
}

func (c *r14Chain) GetDKGTranscript(id string) (string, error) {
	e, err := c.election(id)
	if err != nil {
		return "", err
	}
	return e.dkg, nil
}

func (c *r14Chain) GetTally(id string) (string, error) {
	e, err := c.election(id)
	if err != nil {
		return "", err
	}
	return e.tally, nil
}

func (c *r14Chain) GetPartialDecryption(id, contest, trustee string) (string, error) {
	e, err := c.election(id)
	if err != nil {
		return "", err
	}
	for i, ct := range e.contests {
		for j, tr := range e.trustees {
			if ct == contest && tr == trustee {
				if k := i*len(e.trustees) + j; k < len(e.partials) {
					return e.partials[k], nil
				}
			}
		}
	}
	return "", errors.New("no partial")
}

func (c *r14Chain) GetPrecinctMachine(id string) (string, error) {
	e, err := c.election(id)
	if err != nil {
		return "", err
	}
	if e.machine == "" {
		return "", fmt.Errorf("no precinct machine registered for election %q", id)
	}
	return e.machine, nil
}

func (c *r14Chain) CountCommittedBallots(id string) (int, error) {
	e, err := c.election(id)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(e.ballots), nil
}

// r14FakeRunner stands in for saksi-demo. gen writes a stream folder: a header
// whose ground truth is the voter count, and one decodable ballot per voter.
// audit-stream scores a folder by that ground truth: E is the folder's ballot
// count minus it, so a ledger missing or holding extra ballots fails.
func r14FakeRunner(t *testing.T) Runner {
	return func(_ context.Context, _ string, args ...string) ([]byte, error) {
		switch args[0] {
		case "gen":
			flags := map[string]string{}
			for i := 1; i+1 < len(args); i += 2 {
				flags[args[i]] = args[i+1]
			}
			return nil, r14FakeGen(flags)
		case "audit-stream":
			return r14FakeAudit(args[1])
		}
		t.Errorf("unexpected saksi-demo call %v", args)
		return nil, errors.New("unexpected")
	}
}

func r14FakeGen(f map[string]string) error {
	dir, id := f["--stream"], f["--election-id"]
	voters, _ := strconv.Atoi(f["--voters"])
	positions, _ := strconv.Atoi(f["--positions"])
	trustees, _ := strconv.Atoi(f["--trustees"])
	threshold, _ := strconv.Atoi(f["--threshold"])
	p := &pb.ElectionParameters{ElectionId: id}
	for i := 0; i < positions; i++ {
		p.ContestIds = append(p.ContestIds, fmt.Sprintf("pos-%d", i))
	}
	for i := 0; i < trustees; i++ {
		p.TrusteeIds = append(p.TrusteeIds, fmt.Sprintf("t%d", i))
	}
	raw, _ := proto.Marshal(p)
	params := hex.EncodeToString(raw)
	var partials []string
	for range p.ContestIds {
		for j := 0; j < threshold; j++ {
			partials = append(partials, fmt.Sprintf("%02x", j))
		}
	}
	h := map[string]any{
		"election_id": id, "params": params, "dkg": r14Hex(&pb.DKGTranscript{ElectionId: id}),
		"tally":               r14Hex(&pb.TallyResult{ElectionId: id}),
		"partial_decryptions": partials, "n": voters * positions, "ground_truth": []int{voters * positions},
		"positions": positions, "voter_ids": make([]string, voters*positions),
	}
	if err := writeJSON(filepath.Join(dir, headerFile), h); err != nil {
		return err
	}
	var lines bytes.Buffer
	for i := 0; i < voters*positions; i++ {
		nul := make([]byte, 32)
		_, _ = rand.Read(nul)
		b := &pb.Ballot{ElectionId: id, CredentialPresentation: &pb.CredentialPresentation{Nullifier: &pb.Nullifier{Value: nul}}}
		raw, _ := proto.Marshal(b)
		lines.WriteString(hex.EncodeToString(raw) + "\n")
	}
	return os.WriteFile(filepath.Join(dir, BallotsFile), lines.Bytes(), 0o644)
}

func r14Hex(m proto.Message) string {
	raw, _ := proto.Marshal(m)
	return hex.EncodeToString(raw)
}

func r14FakeAudit(dir string) ([]byte, error) {
	var h struct {
		GroundTruth []int `json:"ground_truth"`
	}
	if err := readJSON(filepath.Join(dir, headerFile), &h); err != nil {
		return nil, err
	}
	n := 0
	_ = scanBallotLines(dir, func(int, string) error { n++; return nil })
	e := int64(n - h.GroundTruth[0])
	overall := "pass"
	if e != 0 {
		overall = "fail"
	}
	return json.Marshal(StreamAudit{Overall: overall, Contests: []ContestCorrectness{
		{Contest: "pos-0", GroundTruth: uint64(h.GroundTruth[0]), Decoded: uint64(n), E: e, Pass: e == 0, AggregateCiphertext: "agg"},
	}})
}

// r14Setup is a chain with the four identities and a config to run on it.
func r14Setup(t *testing.T, voters int) (MachineTestConfig, MachineTestChain, *r14Chain) {
	t.Helper()
	fps := map[string]string{}
	ids := map[string]MachineTestIdentity{}
	for i, id := range R14Identities {
		fps[id.Key] = strings.Repeat(strconv.Itoa(i+1), 64)
		ids[id.Key] = MachineTestIdentity{User: id.User + "@org1.example.com", Role: id.Role, Fingerprint: fps[id.Key]}
	}
	fc := newR14Chain(fps[R14Admin])
	chain := MachineTestChain{Actors: map[string]MachineTestActor{}, Reader: fc}
	for k, fp := range fps {
		chain.Actors[k] = r14Actor{c: fc, fp: fp}
	}
	cfg := MachineTestConfig{
		OutDir: t.TempDir(), DemoBin: "saksi-demo", Stamp: "t1",
		Voters: voters, Positions: 3, Candidates: 4, Trustees: 5, Threshold: 3,
		Distribution: "uniform", Concurrency: 4, Identities: ids, Run: r14FakeRunner(t),
		Commit: "abc123", Binaries: map[string]string{"missing": filepath.Join(t.TempDir(), "nope")},
	}
	return cfg, chain, fc
}

func r14CaseByID(ev R14Evidence, id string) R14Case {
	for _, c := range ev.Cases {
		if c.ID == id {
			return c
		}
	}
	return R14Case{}
}

func TestMachineTestPassesOnTheGatedChaincode(t *testing.T) {
	cfg, chain, fc := r14Setup(t, 20)
	ev, err := RunMachineTest(context.Background(), cfg, chain)
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Pass || ev.Aborted != "" {
		out, _ := json.MarshalIndent(ev.Cases, "", " ")
		t.Fatalf("want every case to pass, aborted=%q\n%s", ev.Aborted, out)
	}
	for _, id := range R14CaseOrder {
		if c := r14CaseByID(ev, id); !c.Pass || len(c.Steps) == 0 {
			t.Errorf("case %s: pass=%v steps=%d", id, c.Pass, len(c.Steps))
		}
	}
	// Cases 2 and 3 name the gate and the identity that was refused.
	for _, id := range []string{"case2", "case3"} {
		s := r14CaseByID(ev, id).Steps[0]
		if s.Observed.Outcome != "refuse" || s.Observed.Gate != "caller" || !strings.Contains(s.Observed.Error, s.Identity.Fingerprint) {
			t.Errorf("%s observed %+v for %s", id, s.Observed, s.Identity.Fingerprint)
		}
	}
	if v := ev.Verify; v == nil || v.LedgerBallots != 60 || v.Case1Accepted != 60 || v.CommittedCount != 60 || v.MaxAbsE != 0 || !v.LedgerMatchLocal {
		t.Errorf("verify = %+v", ev.Verify)
	}
	a := fc.elections[cfg.ElectionA()]
	if a.machine != cfg.Identities[R14User1].Fingerprint || a.status != "closed" || a.tally == "" {
		t.Errorf("election A on the fake chain: machine %s status %s tally %q", a.machine, a.status, a.tally)
	}
	if b := fc.elections[cfg.ElectionB()]; b == nil || b.machine != cfg.Identities[R14User2].Fingerprint || len(b.ballots) != 0 {
		t.Errorf("election B on the fake chain: %+v", b)
	}

	// The evidence and the raw logs are on disk.
	var onDisk R14Evidence
	if err := readJSON(filepath.Join(cfg.OutDir, "r14-evidence.json"), &onDisk); err != nil || !onDisk.Pass || onDisk.Commit != "abc123" {
		t.Fatalf("r14-evidence.json: %v pass=%v commit=%q", err, onDisk.Pass, onDisk.Commit)
	}
	if !strings.HasPrefix(onDisk.Binaries["missing"], "unavailable") {
		t.Errorf("a missing binary must be recorded as unavailable, got %q", onDisk.Binaries["missing"])
	}
	calls, _ := os.ReadFile(filepath.Join(cfg.OutDir, "calls.ndjson"))
	// 59 bulk records + 9 partials + every single call in the plan.
	single := 0
	for _, s := range R14Plan() {
		if s.Kind == r14KindCall {
			single++
		}
	}
	if got, want := bytes.Count(calls, []byte("\n")), 59+9+single; got != want {
		t.Errorf("calls.ndjson has %d lines, want %d", got, want)
	}
	for _, f := range []string{"audit-local.json", "audit-ledger.json", "gen-A.log", "gen-B.log"} {
		if _, err := os.Stat(filepath.Join(cfg.OutDir, f)); err != nil {
			t.Errorf("missing raw log %s", f)
		}
	}
}

func TestMachineTestFailsWithoutTheCallerGate(t *testing.T) {
	cfg, chain, fc := r14Setup(t, 6)
	fc.noCallerGate = true
	ev, err := RunMachineTest(context.Background(), cfg, chain)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Pass {
		t.Fatal("a chaincode that takes ballots from any certificate must fail the test")
	}
	for _, id := range []string{"case2", "case3"} {
		if r14CaseByID(ev, id).Pass {
			t.Errorf("%s passed without the caller gate", id)
		}
	}
}

func TestMachineTestFailsWithoutTheAdminGate(t *testing.T) {
	cfg, chain, fc := r14Setup(t, 6)
	fc.noAdminGate = true
	ev, err := RunMachineTest(context.Background(), cfg, chain)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Pass || r14CaseByID(ev, "case4").Pass {
		t.Fatal("a chaincode that lets User1 create elections must fail case 4")
	}
	// User1's CreateElection went through, so B exists: the run stops there
	// rather than measuring cases on a chain it no longer understands.
	if !strings.Contains(ev.Aborted, "step 2") {
		t.Errorf("aborted = %q, want the stop at step 2", ev.Aborted)
	}
	if _, err := os.Stat(filepath.Join(cfg.OutDir, "r14-evidence.json")); err != nil {
		t.Error("an aborted run must still write its evidence")
	}
}

func TestMachineTestWrongGateIsAFail(t *testing.T) {
	s := R14Step{Expect: r14Refuse, Gate: "caller"}
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{errors.New("gate=caller: caller is not this precinct's machine"), true},
		{errors.New("gate=election-open: election is closed"), false},
		{errors.New("rpc error: code = Unavailable desc = connection refused"), false},
		{errors.New("failed to endorse transaction, see attached details for more info"), false},
		{nil, false},
	} {
		o := observe("SubmitBallot", clientsdk.Receipt{TxID: "x"}, tc.err)
		if got := matches(s, o); got != tc.want {
			t.Errorf("%v: matches = %v (observed %+v), want %v", tc.err, got, o, tc.want)
		}
	}
	if o := observe("SubmitBallot", clientsdk.Receipt{}, errors.New("connection refused")); o.Outcome != "error" {
		t.Errorf("a transport failure is an error, not a refusal: %+v", o)
	}
}

func TestMachineTestDryRunNamesEveryCallAndIdentity(t *testing.T) {
	cfg, _, _ := r14Setup(t, 20)
	var out bytes.Buffer
	R14DryRun(&out, cfg)
	text := out.String()
	for _, want := range []string{
		"r14-t1-p01", "r14-t1-p02", cfg.Identities[R14User3].Fingerprint,
		"SubmitBallot x (records-1)", "20 x 3 = 60", "gate=caller", "gate=admin", "gate=machine-duplicate", "gate=machine-window",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("dry run lacks %q", want)
		}
	}
	if n := len(R14Plan()); !strings.Contains(text, fmt.Sprintf("%3d  case5", n)) {
		t.Errorf("dry run does not list the last step %d", n)
	}
	if entries, _ := os.ReadDir(cfg.OutDir); len(entries) != 0 {
		t.Errorf("dry run wrote %d files", len(entries))
	}
}

func TestMachineTestConfigValidate(t *testing.T) {
	cfg, _, _ := r14Setup(t, 20)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := cfg
	bad.Voters = 0
	if bad.Validate() == nil {
		t.Error("no voters accepted")
	}
	bad = cfg
	bad.Threshold = 6
	if bad.Validate() == nil {
		t.Error("threshold above trustees accepted")
	}
	bad = cfg
	bad.Identities = map[string]MachineTestIdentity{}
	if bad.Validate() == nil {
		t.Error("missing identities accepted")
	}
}

// TestMachineTestWithTheRealGeneratorAndAuditor runs the test on the fake
// chain with the real saksi-demo: the generator's stream folders, the ledger
// dump rebuilt from what the fake chain holds, and the real auditor over both.
// The fake chain checks no proofs, so this proves the harness's plumbing
// (headers, held ballot, partials, dump, audit), not the chaincode. Set
// R14_SAKSI_DEMO to the binary to run it.
func TestMachineTestWithTheRealGeneratorAndAuditor(t *testing.T) {
	bin := os.Getenv("R14_SAKSI_DEMO")
	if bin == "" {
		t.Skip("R14_SAKSI_DEMO is not set")
	}
	cfg, chain, _ := r14Setup(t, 8)
	cfg.DemoBin, cfg.Run = bin, nil
	ev, err := RunMachineTest(context.Background(), cfg, chain)
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Pass {
		out, _ := json.MarshalIndent(ev, "", " ")
		t.Fatalf("aborted=%q\n%s", ev.Aborted, out)
	}
	if v := ev.Verify; len(v.Contests) != 12 || v.LedgerBallots != 24 {
		t.Errorf("verify = %+v", v)
	}
}
