package campaign

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

// r11Net is a fake network for the blackout test: the r14 chaincode model
// behind a switch that docker kill and docker start flip, and the containers
// docker ps and inspect report.
type r11Net struct {
	chain      *r14Chain
	adminFP    string
	machineFP  string
	mu         sync.Mutex
	running    map[string]bool
	project    map[string]string
	ccOrg1     string
	ccOrg2     string
	dockerLog  []string
	loseOnKill bool // the kill also drops the last committed ballot: a lost C record
	lastTx     string
}

func newR11Net() *r11Net {
	admin, machine := strings.Repeat("a1", 32), strings.Repeat("b2", 32)
	n := &r11Net{
		chain: newR14Chain(admin), adminFP: admin, machineFP: machine,
		running: map[string]bool{}, project: map[string]string{},
		ccOrg1: "dev-peer0.org1.example.com-saksi-bulletin_1.0-abc",
		ccOrg2: "dev-peer0.org2.example.com-saksi-bulletin_1.0-abc",
	}
	for _, c := range R11CoreContainers {
		n.running[c], n.project[c] = true, "r14"
	}
	n.running[n.ccOrg1], n.running[n.ccOrg2] = true, true
	n.running["saksilive_peer0"], n.project["saksilive_peer0"] = true, "saksilive"
	return n
}

// up is the network answering: the orderer and the gateway peer running.
// A query while up relaunches org1's chaincode container, as the peer does.
func (n *r11Net) up(query bool) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	ok := n.running["orderer.example.com"] && n.running["peer0.org1.example.com"]
	if ok && query {
		n.running[n.ccOrg1] = true
	}
	return ok
}

var errR11Down = errors.New("rpc error: code = Unavailable desc = connection refused")

func (n *r11Net) docker(args []string) ([]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dockerLog = append(n.dockerLog, strings.Join(args, " "))
	switch args[0] {
	case "ps":
		var b strings.Builder
		for name, up := range n.running {
			if up {
				fmt.Fprintf(&b, "%s|%s\n", name, n.project[name])
			}
		}
		return []byte(b.String()), nil
	case "kill":
		for _, name := range args[1:] {
			n.running[name] = false
		}
		if n.loseOnKill && n.lastTx != "" {
			for _, e := range n.chain.elections {
				delete(e.ballots, n.lastTx)
				for i, x := range e.order {
					if x == n.lastTx {
						e.order = append(e.order[:i], e.order[i+1:]...)
						break
					}
				}
			}
		}
		return nil, nil
	case "start":
		for _, name := range args[1:] {
			n.running[name] = true
		}
		return nil, nil
	case "inspect":
		name := args[len(args)-1]
		return []byte(fmt.Sprintf("%v|status|started x|finished y|exit 137", n.running[name])), nil
	case "events":
		return []byte(`{"status":"kill","Actor":{"Attributes":{"name":"orderer.example.com"}}}` + "\n" +
			`{"status":"start","Actor":{"Attributes":{"name":"saksilive_peer0"}}}` + "\n"), nil
	}
	return nil, fmt.Errorf("unexpected docker %v", args)
}

// r11FakeLedger signs admin functions as the administrator and the rest as
// the machine, like a routed connection.
type r11FakeLedger struct{ n *r11Net }

func (l r11FakeLedger) fp(fn string) string {
	switch fn {
	case "CreateElection", "RegisterPrecinctMachine", "CloseElection":
		return l.n.adminFP
	}
	return l.n.machineFP
}

func (l r11FakeLedger) SubmitWithReceipt(fn string, args ...string) ([]byte, clientsdk.Receipt, error) {
	if !l.n.up(true) {
		return nil, clientsdk.Receipt{}, errR11Down
	}
	out, rec, err := r14Actor{c: l.n.chain, fp: l.fp(fn)}.SubmitWithReceipt(fn, args...)
	if err == nil && fn == "SubmitBallot" {
		l.n.mu.Lock()
		l.n.lastTx = r14NullifierOf(args[0])
		l.n.mu.Unlock()
	}
	return out, rec, err
}

func (l r11FakeLedger) Submit(fn string, args ...string) (string, uint64, error) {
	_, rec, err := l.SubmitWithReceipt(fn, args...)
	return rec.TxID, rec.BlockNumber, err
}
func (l r11FakeLedger) LedgerReceipt(string) (clientsdk.Receipt, error) {
	return clientsdk.Receipt{}, nil
}
func (l r11FakeLedger) GetBlockByNumber(n uint64) (*common.Block, error) {
	return &common.Block{Header: &common.BlockHeader{Number: n}}, nil
}
func (l r11FakeLedger) ReceiptsForBlock(n uint64, txIDs []string) ([]clientsdk.Receipt, error) {
	if !l.n.up(true) {
		return nil, errR11Down
	}
	return nil, nil
}
func (l r11FakeLedger) ChainInfo() (uint64, []byte, error) {
	if !l.n.up(true) {
		return 0, nil, errR11Down
	}
	l.n.chain.mu.Lock()
	defer l.n.chain.mu.Unlock()
	return uint64(l.n.chain.tx + 1), nil, nil
}
func (l r11FakeLedger) VerifyChain(from, to uint64, _ []clientsdk.Receipt) (clientsdk.ChainReport, error) {
	return clientsdk.ChainReport{Linked: true, Status: "PASS"}, nil
}
func (l r11FakeLedger) MachineFingerprint() string { return l.n.machineFP }

// r11FakeReader is the chain's reads, failing while the network is down.
type r11FakeReader struct {
	*r14Chain
	n *r11Net
}

func (r r11FakeReader) CountCommittedBallots(id string) (int, error) {
	if !r.n.up(true) {
		return 0, errR11Down
	}
	return r.r14Chain.CountCommittedBallots(id)
}

func (r r11FakeReader) ListNullifiers(id string, size int, bm string) (clientsdk.NullifierPage, error) {
	if !r.n.up(true) {
		return clientsdk.NullifierPage{}, errR11Down
	}
	return r.r14Chain.ListNullifiers(id, size, bm)
}

func r11Setup(t *testing.T, voters int) (BlackoutConfig, *r11Net, *bytes.Buffer) {
	t.Helper()
	n := newR11Net()
	gen := r14FakeRunner(t)
	var log bytes.Buffer
	cfg := BlackoutConfig{
		OutDir: t.TempDir(), DemoBin: "saksi-demo", Stamp: "t1",
		Voters: voters, Positions: 3, Candidates: 4, Trustees: 5, Threshold: 3,
		Distribution: "uniform", Concurrency: 4, BlackoutAt: 0.4,
		Downtime: 20 * time.Millisecond, ReadyTimeout: 3 * time.Second,
		ChaincodeGrace: 50 * time.Millisecond, ResumeRetryWait: 10 * time.Millisecond,
		ComposeProject: "r14", Chaincode: "saksi-bulletin", Commit: "abc",
		Dial: func() (BlackoutConn, error) {
			return BlackoutConn{Ledger: r11FakeLedger{n}, Reader: r11FakeReader{n.chain, n}, Close: func() {}}, nil
		},
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "docker" {
				return n.docker(args)
			}
			return gen(ctx, name, args...)
		},
		Log: &log,
	}
	return cfg, n, &log
}

func r11Check(ev R11Evidence, id string) R11Check {
	for _, c := range ev.Checks {
		if c.ID == id {
			return c
		}
	}
	return R11Check{ID: id, Observed: "missing"}
}

func TestBlackoutRecoversEveryCommittedRecord(t *testing.T) {
	cfg, n, log := r11Setup(t, 20)
	ev, err := RunBlackoutTest(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Pass || ev.Aborted != "" {
		t.Fatalf("want a pass, aborted %q\nchecks %+v\nlog:\n%s", ev.Aborted, ev.Checks, log)
	}
	if len(ev.Checks) != len(r11CheckNames) {
		t.Errorf("%d checks, want %d", len(ev.Checks), len(r11CheckNames))
	}
	cls := ev.Classification
	if cls.Records != 60 || cls.Committed < cfg.TriggerCount() || cls.Committed+cls.Uncertain+cls.NotSent != 60 || cls.NotSent == 0 {
		t.Errorf("classification %+v", cls)
	}
	// Only the r14 project's containers and the chaincode containers were
	// killed, in one call; the other project's container never was.
	kills := 0
	for _, l := range n.dockerLog {
		if strings.HasPrefix(l, "kill") {
			kills++
			if strings.Contains(l, "saksilive") {
				t.Errorf("killed another project's container: %s", l)
			}
			for _, c := range append(R11CoreContainers, n.ccOrg1, n.ccOrg2) {
				if !strings.Contains(l, c) {
					t.Errorf("kill %q misses %s", l, c)
				}
			}
		}
	}
	if kills != 1 {
		t.Errorf("%d kill calls, want 1", kills)
	}
	// org1's chaincode came back through its peer; org2's peer was never
	// asked, so the harness started it and says so.
	by := map[string]string{}
	for _, c := range ev.Blackout.Containers {
		by[c.Name] = c.StartedBy
		if !c.RunningAtEnd {
			t.Errorf("%s not running at the end", c.Name)
		}
	}
	if by[n.ccOrg1] != "peer" || by[n.ccOrg2] != "harness" || by["orderer.example.com"] != "harness" {
		t.Errorf("started by %v", by)
	}
	if ev.Duplicate == nil || ev.Duplicate.Gate != "nullifier" {
		t.Errorf("duplicate %+v", ev.Duplicate)
	}
	if len(ev.Resume) != 1 || ev.Resume[0].Submitted != 60-ev.Resume[0].OnChainBefore || ev.Resume[0].SubmittedAlreadyOnChain != 0 {
		t.Errorf("resume %+v", ev.Resume)
	}
	e := n.chain.elections[ev.RunID]
	if e == nil || e.status != "closed" || e.tally == "" || len(e.ballots) != 60 {
		t.Fatalf("election on the fake chain: %+v", e)
	}
	ev2 := readFile(t, cfg.OutDir+"/docker-events.ndjson")
	if !strings.Contains(ev2, "orderer.example.com") || strings.Contains(ev2, "saksilive") {
		t.Errorf("docker events not filtered to the killed containers:\n%s", ev2)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// A committed record the chain no longer holds after the restart is the
// finding the test exists for: it must fail, not be resubmitted away.
func TestBlackoutReportsALostCommittedRecord(t *testing.T) {
	cfg, n, _ := r11Setup(t, 20)
	n.loseOnKill = true
	ev, err := RunBlackoutTest(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Pass {
		t.Fatal("a lost C record must fail the run")
	}
	if c := r11Check(ev, "after.committed_kept"); c.Pass || ev.Classification.CommittedMissing != 1 {
		t.Errorf("after.committed_kept %+v, missing %d", c, ev.Classification.CommittedMissing)
	}
}

// The preflight refuses to kill an orderer that belongs to another project.
func TestBlackoutRefusesAnotherProjectsNetwork(t *testing.T) {
	cfg, n, _ := r11Setup(t, 20)
	n.project["orderer.example.com"] = "compose"
	ev, err := RunBlackoutTest(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Pass || !strings.Contains(ev.Aborted, "refusing to kill") {
		t.Fatalf("aborted %q", ev.Aborted)
	}
	for _, l := range n.dockerLog {
		if strings.HasPrefix(l, "kill") || strings.HasPrefix(l, "start") {
			t.Errorf("docker %s after a refused preflight", l)
		}
	}
}

func TestClassifyRecords(t *testing.T) {
	nul := func(i int) string { return testNullifierHex(i) }
	idx := map[[32]byte]int{}
	for i := 0; i < 6; i++ {
		k, _ := nullifierKey(nul(i))
		idx[k] = i
	}
	kill := time.Now()
	calls := []r11Call{
		{Fn: "CreateElection", OK: true},
		{Fn: "SubmitBallot", Nullifier: nul(0), OK: true, done: kill.Add(-time.Second)},
		{Fn: "SubmitBallot", Nullifier: nul(1), OK: true, done: kill.Add(time.Millisecond)},
		{Fn: "SubmitBallot", Nullifier: nul(2), OK: false, Error: "commit status: unavailable"},
		{Fn: "SubmitBallot", Nullifier: nul(3), OK: false, Error: "first"},
		{Fn: "SubmitBallot", Nullifier: nul(3), OK: true, done: kill.Add(-time.Second)},
		{Fn: "SubmitBallot", Nullifier: "zz", OK: true},
	}
	status, cls := classifyRecords(6, idx, calls, kill)
	want := []string{"C", "C", "U", "C", "N", "N"}
	for i := range want {
		if status[i] != want[i] {
			t.Errorf("record %d = %s, want %s", i, status[i], want[i])
		}
	}
	if cls.Committed != 3 || cls.Uncertain != 1 || cls.NotSent != 2 || cls.CommittedAfterKill != 1 ||
		cls.FirstUncertainError != "commit status: unavailable" {
		t.Errorf("classification %+v", cls)
	}
	afterRestart(&cls, status, []bool{true, true, true, false, false, true})
	if cls.CommittedMissing != 1 || cls.CommittedMissingSample[0] != 3 || cls.UncertainOnChain != 1 ||
		cls.NotSentOnChain != 1 || cls.OnChainAfterRestart != 4 {
		t.Errorf("after restart %+v", cls)
	}
}

func TestResumeAttemptCountsResubmissionsOfOnChainRecords(t *testing.T) {
	idx := map[[32]byte]int{}
	for i := 0; i < 4; i++ {
		k, _ := nullifierKey(testNullifierHex(i))
		idx[k] = i
	}
	before := []bool{true, false, false, false}
	calls := []r11Call{
		{Fn: "SubmitBallot", Nullifier: testNullifierHex(1), OK: true},
		{Fn: "SubmitBallot", Nullifier: testNullifierHex(2), OK: true},
		{Fn: "SubmitBallot", Nullifier: testNullifierHex(0), OK: false},
		{Fn: "CloseElection", OK: true},
	}
	a := resumeAttempt(1, before, idx, calls)
	if a.OnChainBefore != 1 || a.Submitted != 3 || a.Accepted != 2 || a.SubmittedAlreadyOnChain != 1 || a.DistinctSubmitted != 3 {
		t.Errorf("attempt %+v", a)
	}
}

func TestNullifierSetStats(t *testing.T) {
	idx := map[[32]byte]int{}
	for i := 0; i < 3; i++ {
		k, _ := nullifierKey(testNullifierHex(i))
		idx[k] = i
	}
	listed := []string{testNullifierHex(0), testNullifierHex(1), testNullifierHex(1), hex.EncodeToString(make([]byte, 32))}
	total, distinct, missing, extra := nullifierSetStats(listed, idx)
	if total != 4 || distinct != 3 || missing != 1 || extra != 1 {
		t.Errorf("total %d distinct %d missing %d extra %d", total, distinct, missing, extra)
	}
}

// r11PassingEvidence is a hand-built evidence document every check passes on.
func r11PassingEvidence() R11Evidence {
	f := false
	cs := []R11Container{
		{Name: "orderer.example.com", Role: "orderer", RunningAtDowntimeEnd: &f, StartedBy: "harness", RunningAtEnd: true},
		{Name: "peer0.org1.example.com", Role: "peer", RunningAtDowntimeEnd: &f, StartedBy: "harness", RunningAtEnd: true},
		{Name: "peer0.org2.example.com", Role: "peer", RunningAtDowntimeEnd: &f, StartedBy: "harness", RunningAtEnd: true},
		{Name: "dev-peer0.org1.example.com-cc_1", Role: "chaincode", RunningAtDowntimeEnd: &f, StartedBy: "peer", RunningAtEnd: true},
	}
	return R11Evidence{
		Classification: R11Classification{Records: 100, Committed: 40, Uncertain: 30, NotSent: 30, OnChainAfterRestart: 45},
		Blackout: R11Blackout{Fired: true, HeightBefore: 10, HeightBeforeOK: true, KillOK: true, Containers: cs,
			StartOK: true, DowntimeMs: 30001, ConfiguredMs: 30000, Ready: true, HeightAfter: 12, HeightAfterOK: true},
		Duplicate: &R11Duplicate{Outcome: "refuse", Gate: "nullifier"},
		Resume:    []R11ResumeAttempt{{Attempt: 1, OnChainBefore: 45, Submitted: 55, DistinctSubmitted: 55, Accepted: 55}},
		Final: &R11Final{CountCommitted: 100, ListedNullifiers: 100, DistinctNullifiers: 100,
			LocalOverall: "pass", LedgerOverall: "pass", LedgerMatchLocal: true,
			Contests: []ContestCorrectness{{Contest: "p0"}}},
	}
}

func TestR11ChecksVerdicts(t *testing.T) {
	for _, c := range r11Checks(r11PassingEvidence()) {
		if !c.Pass {
			t.Errorf("baseline: %s failed: %s", c.ID, c.Observed)
		}
	}
	tr := true
	cases := []struct {
		check string
		mut   func(*R11Evidence)
	}{
		{"pre.classified", func(e *R11Evidence) { e.Classification.Uncertain, e.Classification.NotSent = 0, 0 }},
		{"pre.height", func(e *R11Evidence) { e.Blackout.HeightBeforeOK = false }},
		{"blackout.killed", func(e *R11Evidence) { e.Blackout.Containers = e.Blackout.Containers[:3] }},
		{"blackout.down", func(e *R11Evidence) { e.Blackout.Containers[1].RunningAtDowntimeEnd = &tr }},
		{"blackout.downtime", func(e *R11Evidence) { e.Blackout.DowntimeMs = 29000 }},
		{"blackout.ready", func(e *R11Evidence) { e.Blackout.Ready = false }},
		{"blackout.restarted", func(e *R11Evidence) { e.Blackout.Containers[3].RunningAtEnd = false }},
		{"after.height", func(e *R11Evidence) { e.Blackout.HeightAfter = 9 }},
		{"after.committed_kept", func(e *R11Evidence) { e.Classification.CommittedMissing = 1 }},
		{"resume.duplicate_refused", func(e *R11Evidence) { e.Duplicate.Gate = "caller" }},
		{"resume.duplicate_refused", func(e *R11Evidence) { e.Duplicate = nil }},
		{"resume.only_missing", func(e *R11Evidence) { e.Resume[0].SubmittedAlreadyOnChain = 1 }},
		{"resume.only_missing", func(e *R11Evidence) { e.Resume[0].Submitted, e.Resume[0].DistinctSubmitted = 54, 54 }},
		{"resume.done", func(e *R11Evidence) { e.Resume[0].Error = "close failed" }},
		{"final.tally", func(e *R11Evidence) { e.Final.TallyError = "boom" }},
		{"final.count", func(e *R11Evidence) { e.Final.CountCommitted = 99 }},
		{"final.no_duplicates", func(e *R11Evidence) { e.Final.ListedNullifiers = 101 }},
		{"final.no_duplicates", func(e *R11Evidence) { e.Final.MissingFromLedger = 1 }},
		{"final.audit", func(e *R11Evidence) { e.Final.MaxAbsE = 1 }},
		{"final.audit", func(e *R11Evidence) { e.Final.LedgerMatchLocal = false }},
	}
	for _, tc := range cases {
		ev := r11PassingEvidence()
		tc.mut(&ev)
		for _, c := range r11Checks(ev) {
			if c.ID == tc.check && c.Pass {
				t.Errorf("%s still passes after its failure was injected: %s", tc.check, c.Observed)
			}
		}
	}
}

func TestBlackoutConfigValidate(t *testing.T) {
	cfg, _, _ := r11Setup(t, 20)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*BlackoutConfig){
		"at 0":       func(c *BlackoutConfig) { c.BlackoutAt = 0 },
		"at 1":       func(c *BlackoutConfig) { c.BlackoutAt = 1 },
		"no project": func(c *BlackoutConfig) { c.ComposeProject = "" },
		"downtime":   func(c *BlackoutConfig) { c.Downtime = 0 },
		"tiny":       func(c *BlackoutConfig) { c.Voters, c.Positions, c.BlackoutAt = 1, 1, 0.5 },
	} {
		c := cfg
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
	var out bytes.Buffer
	R11DryRun(&out, cfg)
	for _, want := range []string{"24 of 60", "docker kill", "resumeAndClose", "final.audit"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run lacks %q", want)
		}
	}
}
