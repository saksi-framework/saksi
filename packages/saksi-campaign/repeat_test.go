package campaign

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk/bench"
)

// fakeConsole is the minimum of the console's HTTP API that the --repeat
// driver actually touches. The driver is HTTP-only by contract, so this is
// the whole seam: nothing here shares state with the real Server.
type fakeConsole struct {
	mu sync.Mutex
	n  int
	// reps records the rep tag each created run carried, by run id; cfgs
	// records the config it was created with.
	reps map[string]RepTag
	cfgs map[string]ElectionConfig
	// perf returns the perf.csv data row for a run (nil = 404, i.e. the run
	// never got as far as Verify).
	perf func(runID string, rep RepTag) map[string]string
	// end returns the run.end journal event for a run.
	end func(runID string, rep RepTag) map[string]any
}

func newFakeConsole() *fakeConsole {
	return &fakeConsole{reps: map[string]RepTag{}, cfgs: map[string]ElectionConfig{}}
}

func (f *fakeConsole) start(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return srv.URL
}

func (f *fakeConsole) rep(runID string) RepTag {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reps[runID]
}

// config returns the config a given run was created with.
func (f *fakeConsole) config(runID string) ElectionConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfgs[runID]
}

// configFor returns the config of the first run created with the given rep kind.
func (f *fakeConsole) configFor(kind string) (ElectionConfig, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, rep := range f.reps {
		if rep.Kind == kind {
			return f.cfgs[id], true
		}
	}
	return ElectionConfig{}, false
}

func (f *fakeConsole) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/generate":
		var c ElectionConfig
		_ = json.NewDecoder(r.Body).Decode(&c)
		f.mu.Lock()
		f.n++
		id := fmt.Sprintf("run-%d", f.n)
		if c.Rep != nil {
			f.reps[id] = *c.Rep
		}
		f.cfgs[id] = c
		f.mu.Unlock()
		writeJSONResp(w, http.StatusAccepted, map[string]string{"run_id": id})
	case strings.HasPrefix(p, "/api/runs/") && strings.HasSuffix(p, "/status"):
		writeJSONResp(w, http.StatusOK, map[string]any{"busy": false})
	case strings.HasPrefix(p, "/api/check/"):
		writeJSONResp(w, http.StatusOK, CheckReport{Pass: true, Rows: 1})
	case strings.HasPrefix(p, "/api/ceremony/"):
		writeJSONResp(w, http.StatusOK, CeremonyState{
			Threshold: 2,
			Trustees:  []CeremonyTrustee{{ID: "1"}, {ID: "2"}, {ID: "3"}},
		})
	case p == "/submit" || p == "/verify" ||
		p == "/ceremony/start" || p == "/ceremony/submit" || p == "/ceremony/publish":
		writeJSONResp(w, http.StatusAccepted, map[string]string{"run_id": "ok"})
	case strings.HasPrefix(p, "/export/"):
		id, artifact, _ := strings.Cut(strings.TrimPrefix(p, "/export/"), "/")
		f.serveExport(w, id, artifact)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeConsole) serveExport(w http.ResponseWriter, id, artifact string) {
	rep := f.rep(id)
	switch artifact {
	case PerfCSV:
		cells := f.perf(id, rep)
		if cells == nil {
			http.NotFound(w, nil)
			return
		}
		row := make([]string, len(perfColumns))
		for i, col := range perfColumns {
			if col == "run_id" {
				row[i] = id
				continue
			}
			row[i] = cells[col]
		}
		fmt.Fprintln(w, strings.Join(perfColumns, ","))
		fmt.Fprintln(w, strings.Join(csvEscape(row), ","))
	case JournalFile:
		ev := map[string]any{"event": "run.end"}
		for k, v := range f.end(id, rep) {
			ev[k] = v
		}
		line, _ := json.Marshal(ev)
		fmt.Fprintf(w, "{\"event\":\"env\"}\n%s\n", line)
	default:
		http.NotFound(w, nil)
	}
}

// readSummary parses summary.csv into metric -> {column: cell}.
func readSummary(t *testing.T, path string) map[string]map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open summary: %v", err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if len(rows) < 2 {
		t.Fatalf("summary has no data rows: %v", rows)
	}
	head := rows[0]
	out := map[string]map[string]string{}
	for _, row := range rows[1:] {
		cells := map[string]string{}
		for i, h := range head {
			if i < len(row) {
				cells[h] = row[i]
			}
		}
		out[row[0]] = cells
	}
	return out
}

func testRepeatOpts(t *testing.T, base string) RepeatOpts {
	t.Helper()
	return RepeatOpts{
		BaseURL: base,
		Config:  good(),
		Out:     filepath.Join(t.TempDir(), "summary.csv"),
		Poll:    time.Millisecond,
		Log:     io.Discard,
	}
}

// One warm-up and three measured reps, one of the measured reps failed: the
// summary must cover the measured reps only, and every throughput statistic
// must exclude the failed one.
func TestRepeatSummaryExcludesWarmupsAndFailedRuns(t *testing.T) {
	fake := newFakeConsole()
	// tps by rep: warm-up 999 (must never appear), measured 10/20/30 —
	// measured #2 (tps 20) is the failed one.
	fake.perf = func(_ string, rep RepTag) map[string]string {
		v := float64(rep.Index * 10)
		if rep.Kind == "warmup" {
			v = 999
		}
		return map[string]string{
			"mode": "offline", "voters": "10", "dropped": "0",
			"committed_tps":  fmt.Sprintf("%.3f", v),
			"latency_p99_ms": fmt.Sprintf("%.3f", v),
		}
	}
	fake.end = func(_ string, rep RepTag) map[string]any {
		if rep.Kind == "measured" && rep.Index == 2 {
			return map[string]any{"failed": true, "reason": "dropped: 7"}
		}
		return map[string]any{"failed": false, "reason": ""}
	}

	o := testRepeatOpts(t, fake.start(t))
	o.Warmups, o.Reps = 1, 3
	if err := Repeat(context.Background(), o); err != nil {
		t.Fatalf("Repeat: %v", err)
	}

	sum := readSummary(t, o.Out)
	row, ok := sum["committed_tps"]
	if !ok {
		t.Fatalf("no committed_tps row: %v", sum)
	}
	if row["n"] != "2" {
		t.Errorf("committed_tps n = %q, want 2 (3 measured minus 1 failed)", row["n"])
	}
	// 10 and 30 survive; the warm-up's 999 and the failed rep's 20 do not.
	if row["min"] != "10" || row["p99"] != "30" || row["mean"] != "20" {
		t.Errorf("committed_tps stats = %v, want min 10 / p99 30 / mean 20", row)
	}
	if got := sum["runs_measured"]["mean"]; got != "3" {
		t.Errorf("runs_measured = %q, want 3", got)
	}
	if got := sum["runs_failed"]["mean"]; got != "1" {
		t.Errorf("runs_failed = %q, want 1", got)
	}
	if got := sum["failure_rate"]["mean"]; got != "0.333" {
		t.Errorf("failure_rate = %q, want 0.333", got)
	}
	if got := sum["runs_failed"]["failed_reasons"]; !strings.Contains(got, "dropped: 7") {
		t.Errorf("failed_reasons = %q, want it to list the failure", got)
	}
}

// The sweep raises the offered rate until throughput stops improving; the
// plateau is the last step that still improved.
func TestRepeatSweepPlateauIsLastGoodStep(t *testing.T) {
	fake := newFakeConsole()
	// step 1: 10 tps, step 2: 20 tps, step 3: 15 tps (degraded) -> plateau 20.
	byStep := map[int]float64{1: 10, 2: 20, 3: 15}
	fake.perf = func(_ string, rep RepTag) map[string]string {
		v, ok := byStep[rep.Index]
		if !ok {
			v = 1 // any further step keeps degrading
		}
		return map[string]string{
			"mode": "onchain", "dropped": "0",
			"committed_tps":  fmt.Sprintf("%.3f", v),
			"latency_p99_ms": "500.000",
		}
	}
	fake.end = func(string, RepTag) map[string]any {
		return map[string]any{"failed": false, "reason": ""}
	}

	o := testRepeatOpts(t, fake.start(t))
	o.Reps = 0
	o.Sweep = 2
	o.Window = 5 * time.Second
	if err := Repeat(context.Background(), o); err != nil {
		t.Fatalf("Repeat: %v", err)
	}
	sum := readSummary(t, o.Out)
	if got := sum["plateau_tps"]["mean"]; got != "20" {
		t.Errorf("plateau_tps = %q, want 20 (step 2)", got)
	}
	// Step 2's concurrency must be ceil(rate x p99_prev_seconds) + 4, never
	// the config's, and every step is a bounded window.
	if got := fake.rep("run-2"); got.Kind != "sweep" || got.Index != 2 {
		t.Fatalf("run-2 rep tag = %+v, want sweep step 2", got)
	}
	step2 := fake.config("run-2")
	// step 1 offers 10/s (the config's rate is 0); step 2 offers 10 x 2 = 20/s
	// against step 1's p99 of 500 ms: ceil(20 x 0.5) + 4 = 14.
	if step2.SendRate != 20 || step2.Concurrency != 14 {
		t.Errorf("step 2 = rate %v / concurrency %d, want 20 / 14", step2.SendRate, step2.Concurrency)
	}
	if step2.WindowS != 5 {
		t.Errorf("step 2 window = %v s, want 5", step2.WindowS)
	}
}

// The burst is its own run: N ballots offered as fast as the driver can push
// them (no rate cap), tagged so the journal segment can be found later.
func TestRepeatBurstIsItsOwnTaggedRun(t *testing.T) {
	fake := newFakeConsole()
	fake.perf = func(string, RepTag) map[string]string {
		return map[string]string{"mode": "onchain", "dropped": "0", "committed_tps": "5.000"}
	}
	fake.end = func(string, RepTag) map[string]any {
		return map[string]any{"failed": false}
	}
	o := testRepeatOpts(t, fake.start(t))
	o.Reps = 1
	o.Burst = 42
	if err := Repeat(context.Background(), o); err != nil {
		t.Fatalf("Repeat: %v", err)
	}
	burstCfg, ok := fake.configFor("burst")
	if !ok {
		t.Fatal("no run was created with rep kind burst")
	}
	if burstCfg.Voters != 42 || burstCfg.SendRate != 0 {
		t.Errorf("burst config = %d voters / rate %v, want 42 / 0", burstCfg.Voters, burstCfg.SendRate)
	}
}

// --- admission gates --------------------------------------------------------

// gateServer is a console whose git head and free-space probe are fixed, so the
// gates can be exercised without depending on the machine the tests run on.
func gateServer(t *testing.T, fabric FabricConfig, head string, free uint64) (*Server, string) {
	t.Helper()
	root := t.TempDir()
	store := NewRunStore(root)
	hub := NewHub()
	exec := NewExecutor(store, hub, "saksi-demo", "", fabric)
	exec.run = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	s := NewServer(store, exec, hub, fabric, nil, time.Minute)
	s.gitHead = func() (string, bool) { return head, head != "" }
	s.freeSpace = func(string) (uint64, error) { return free, nil }
	return s, root
}

func writeLadder(t *testing.T, root, commit string) {
	t.Helper()
	if err := writeJSON(filepath.Join(root, LadderFile),
		ladderRecord{Commit: commit, RanAt: time.Now(), Runs: []string{"a"}}); err != nil {
		t.Fatalf("write ladder.json: %v", err)
	}
}

func postConfig(t *testing.T, s *Server, c ElectionConfig) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, postJSON("/generate", c))
	return rec
}

// A tier above the ladder ceiling may only run on a build the ladder has
// actually passed on.
func TestLadderGate(t *testing.T) {
	big := good()
	big.Voters = 2000 // offline, over LadderVoterCeiling, under OfflineVoterCeiling

	t.Run("refused with no ladder.json", func(t *testing.T) {
		s, _ := gateServer(t, FabricConfig{}, "abc123", 1<<62)
		rec := postConfig(t, s, big)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), errLadderNotRun) {
			t.Fatalf("want 400 %q, got %d: %s", errLadderNotRun, rec.Code, rec.Body)
		}
	})
	t.Run("allowed with a matching commit", func(t *testing.T) {
		s, root := gateServer(t, FabricConfig{}, "abc123", 1<<62)
		writeLadder(t, root, "abc123")
		if rec := postConfig(t, s, big); rec.Code != http.StatusAccepted {
			t.Fatalf("want 202, got %d: %s", rec.Code, rec.Body)
		}
	})
	t.Run("refused with a stale commit", func(t *testing.T) {
		s, root := gateServer(t, FabricConfig{}, "abc123", 1<<62)
		writeLadder(t, root, "deadbeef") // ladder ran, but on another build
		rec := postConfig(t, s, big)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), errLadderNotRun) {
			t.Fatalf("want 400 %q, got %d: %s", errLadderNotRun, rec.Code, rec.Body)
		}
	})
	t.Run("ground truth is exempt", func(t *testing.T) {
		s, _ := gateServer(t, FabricConfig{}, "abc123", 1<<62)
		gt := good()
		gt.Mode, gt.Voters = ModeGroundTruth, 3_524_078
		if rec := postConfig(t, s, gt); rec.Code != http.StatusAccepted {
			t.Fatalf("ground truth should be exempt; got %d: %s", rec.Code, rec.Body)
		}
	})
	t.Run("small tiers never need the ladder", func(t *testing.T) {
		s, _ := gateServer(t, FabricConfig{}, "abc123", 1<<62)
		small := good()
		small.Voters = LadderVoterCeiling
		if rec := postConfig(t, s, small); rec.Code != http.StatusAccepted {
			t.Fatalf("want 202, got %d: %s", rec.Code, rec.Body)
		}
	})
}

// liveFabric is a FabricConfig that Enabled() accepts. Nothing connects in
// these tests — the gates refuse before any dial.
func liveFabric() FabricConfig {
	return FabricConfig{
		PeerEndpoint: "localhost:7051", GatewayPeer: "peer0", TLSCert: "tls.pem",
		MSPID: "Org1MSP", Cert: "c.pem", Key: "k.pem",
		Channel: "saksi", Chaincode: "saksi-bulletin",
	}
}

// An on-chain tier the disk cannot hold is refused before a run folder exists,
// with the numbers that make the refusal actionable.
func TestDiskGuardRefusesWhenProjectedExceedsFree(t *testing.T) {
	c := good()
	c.Mode, c.Voters, c.Positions = "onchain", 100, 3
	need := uint64(100 * 3 * LedgerBytesPerBallot)

	s, root := gateServer(t, liveFabric(), "abc123", need-1)
	writeLadder(t, root, "abc123")
	rec := postConfig(t, s, c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{
		strconv.FormatUint(need, 10),
		strconv.FormatUint(need-1, 10),
		"100 voters", "3 positions",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("refusal should name %q; got %s", want, body)
		}
	}

	// Exactly enough is enough.
	s2, root2 := gateServer(t, liveFabric(), "abc123", need)
	writeLadder(t, root2, "abc123")
	if rec := postConfig(t, s2, c); rec.Code != http.StatusAccepted {
		t.Fatalf("a run that fits should be accepted; got %d: %s", rec.Code, rec.Body)
	}
}

// A probe that cannot read the volume must not block the run: losing the
// instrument is not a reason to refuse a measurement.
func TestDiskGuardIgnoresAnUnreadableVolume(t *testing.T) {
	c := good()
	c.Mode, c.Voters, c.Positions = "onchain", 100, 3
	s, _ := gateServer(t, liveFabric(), "abc123", 0)
	s.freeSpace = func(string) (uint64, error) { return 0, errors.New("no such volume") }
	if rec := postConfig(t, s, c); rec.Code != http.StatusAccepted {
		t.Fatalf("want 202 when the probe fails, got %d: %s", rec.Code, rec.Body)
	}
}

// The per-run status probe is what lets the --repeat driver sequence phases
// over HTTP alone.
func TestRunStatusReportsBusy(t *testing.T) {
	s, _ := gateServer(t, FabricConfig{}, "abc123", 1<<62)
	rec := postConfig(t, s, good())
	var body struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.RunID == "" {
		t.Fatalf("no run id: %v %s", err, rec.Body)
	}
	got := httptest.NewRecorder()
	s.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/api/runs/"+body.RunID+"/status", nil))
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"busy"`) {
		t.Fatalf("status = %d %s", got.Code, got.Body)
	}
	unknown := httptest.NewRecorder()
	s.ServeHTTP(unknown, httptest.NewRequest(http.MethodGet, "/api/runs/NOPE/status", nil))
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("bad run id should be 400, got %d", unknown.Code)
	}
}

// --- T3: verify-only ---------------------------------------------------------

// countingLedger adds the chaincode's own committed-ballot count to the
// on-chain fake, which is the number verify-only reconciles against.
type countingLedger struct {
	*fakeLedger
	count int
	err   error
}

func (c countingLedger) CountCommittedBallots(string) (int, error) { return c.count, c.err }

// After a peer restart mid-window, verify-only must say what the chain
// actually holds and mark the run interrupted — WITHOUT submitting anything.
func TestVerifyOnlyReconcilesAndMarksInterrupted(t *testing.T) {
	e, led, c, runDir, _ := crashedRun(t, 40, 20)
	landed := len(led.acceptedIndices())
	before := led.callNames()

	rr := countingLedger{fakeLedger: led, count: landed}
	if err := e.verifyOnly("run-1", rr, led); err != nil {
		t.Fatalf("verifyOnly: %v", err)
	}

	if got := journalEventsOfType(t, runDir, "interrupted_at"); len(got) != 1 {
		t.Fatalf("want one interrupted_at stamp, got %d", len(got))
	}
	rec := journalEventsOfType(t, runDir, "verify_only.reconcile")
	if len(rec) != 1 {
		t.Fatalf("want one verify_only.reconcile, got %d", len(rec))
	}
	if got := jint(rec[0], "committed_local"); got != landed {
		t.Errorf("committed_local = %d, want %d", got, landed)
	}
	if ok, _ := rec[0]["reconciled"].(bool); !ok {
		t.Errorf("chain count %d and committed set %d should reconcile: %v", landed, landed, rec[0])
	}
	if got := jint(rec[0], "missing"); got != c.Voters-landed {
		t.Errorf("missing = %d, want %d", got, c.Voters-landed)
	}
	if chain := journalEventsOfType(t, runDir, "verify_only.chain"); len(chain) != 1 {
		t.Fatalf("want one verify_only.chain, got %d", len(chain))
	} else if jstring(chain[0], "status") != "PASS" {
		t.Errorf("chain status = %q, want PASS", jstring(chain[0], "status"))
	}

	// Nothing new was submitted: verify-only audits, it does not fill the gap.
	for i, name := range led.callNames() {
		if i < len(before) && name == before[i] {
			continue
		}
		if name == "SubmitBallot" {
			t.Fatalf("verify-only submitted a ballot")
		}
	}

	// The run is now recorded as interrupted, which is what a later resume reads.
	if plan, err := planResume(runDir, c); err != nil {
		t.Fatalf("planResume after verify-only: %v", err)
	} else if !plan.stamped {
		t.Error("verify-only should have stamped interrupted_at for a later resume")
	}
}

// A chain that cannot answer must surface the error, not a fabricated count.
func TestVerifyOnlyReportsAChainThatCannotAnswer(t *testing.T) {
	e, led, _, runDir, _ := crashedRun(t, 10, 5)
	rr := countingLedger{fakeLedger: led, err: errors.New("peer unavailable")}
	if err := e.verifyOnly("run-1", rr, led); err == nil {
		t.Fatal("want the chain's error surfaced")
	}
	rec := journalEventsOfType(t, runDir, "verify_only.reconcile")
	if len(rec) != 1 || jstring(rec[0], "chain_count_error") == "" {
		t.Fatalf("want the count error recorded, got %v", rec)
	}
	if _, ok := rec[0]["committed_local"]; ok {
		t.Error("no count means no reconciliation: committed_local must be absent")
	}
}

// --- rep tagging + the bounded window ---------------------------------------

// WindowS is the wire form of a bench.RunOpts.MaxDuration: seconds, with zero
// meaning "run until every ballot is dispatched".
func TestConfigWindow(t *testing.T) {
	for _, tc := range []struct {
		s    float64
		want time.Duration
	}{{0, 0}, {-1, 0}, {120, 2 * time.Minute}, {0.25, 250 * time.Millisecond}} {
		c := good()
		c.WindowS = tc.s
		if got := c.Window(); got != tc.want {
			t.Errorf("WindowS %v -> %v, want %v", tc.s, got, tc.want)
		}
	}
}

// A repetition's run folder must say which repetition it is, and a tagged
// repetition's ballot window must say so on its own segment — that is what
// separates a burst window from the measured one when both are read back.
func TestRepTagReachesTheJournal(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	e.run = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }

	c := good()
	c.Rep = &RepTag{Index: 7, Kind: "burst"}
	// Generation shells a fake saksi-demo that writes nothing, so the derived
	// CSVs fail — after run.start and rep.start are already on disk.
	_ = e.Generate(context.Background(), "run-1", c)

	rep := journalEventsOfType(t, runDir, "rep.start")
	if len(rep) != 1 {
		t.Fatalf("want one rep.start, got %d", len(rep))
	}
	if jint(rep[0], "index") != 7 || jstring(rep[0], "kind") != "burst" {
		t.Errorf("rep.start = %v, want index 7 / kind burst", rep[0])
	}

	// The ballot window carries the same tag on its segment.
	onchain := ElectionConfig{Mode: "onchain", Voters: 4, Positions: 1, Candidates: 2,
		Concurrency: 2, Rep: &RepTag{Index: 7, Kind: "burst"}}
	path := writeRealBallotStream(t, runDir, 4)
	if err := e.submitOnChain(context.Background(), "run-1", onchain, &fakeLedger{}, path); err != nil {
		t.Fatalf("submitOnChain: %v", err)
	}
	starts := journalEventsOfType(t, runDir, "segment.start")
	if len(starts) != 1 || jstring(starts[0], "tag") != "burst" {
		t.Fatalf("segment.start = %v, want one tagged burst", starts)
	}
}

// --- the bounded window ------------------------------------------------------

// slowLedger makes every submit take long enough that a short window closes
// before the whole population is dispatched — which is what a sweep step does
// on purpose.
type slowLedger struct {
	*fakeLedger
	delay time.Duration
}

func (s slowLedger) Submit(fn string, args ...string) (string, uint64, error) {
	time.Sleep(s.delay)
	return s.fakeLedger.Submit(fn, args...)
}

// A window that closed because it reached its own time bound ended as
// instructed. It is not a failed run, and it is not left open for a resume to
// "finish" — otherwise every sweep step would be recorded as a failure and the
// campaign's failure rate would measure the sweep instead of the network.
func TestBoundedWindowIsNotAFailedRun(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeRealBallotStream(t, runDir, 400)

	c := ElectionConfig{
		Mode: "onchain", Voters: 400, Positions: 1, Candidates: 2,
		Concurrency: 2, WindowS: 0.15,
		Rep: &RepTag{Index: 1, Kind: "sweep"},
	}
	led := slowLedger{fakeLedger: &fakeLedger{}, delay: 10 * time.Millisecond}
	if err := e.submitOnChain(context.Background(), "run-1", c, led, path); err != nil {
		t.Fatalf("submitOnChain: %v", err)
	}

	var sm submitMetrics
	if err := readJSON(filepath.Join(runDir, submitMetricsFile), &sm); err != nil {
		t.Fatalf("read submit metrics: %v", err)
	}
	if !sm.Stopped || !sm.Bounded {
		t.Fatalf("want a bounded stop, got stopped=%v bounded=%v", sm.Stopped, sm.Bounded)
	}
	if sm.Dropped != 0 {
		t.Fatalf("a bounded window should drop nothing, got %d", sm.Dropped)
	}
	if sm.Submitted >= c.Voters {
		t.Fatalf("the window dispatched all %d ballots, so it was never bounded", sm.Submitted)
	}

	// The window is CLOSED: a resume must not offer to finish it.
	if got := journalEventsOfType(t, runDir, "stage.ballots.interrupted"); len(got) != 0 {
		t.Errorf("a bounded window must not be stamped interrupted: %v", got)
	}
	if got := journalEventsOfType(t, runDir, "stage.ballots.end"); len(got) != 1 {
		t.Errorf("want one stage.ballots.end, got %d", len(got))
	}
	if _, err := planResume(runDir, c); err == nil {
		t.Error("a bounded window is not resumable: planResume should refuse it")
	}

	// And the verdict: not a failure.
	in := finaliseInput(runDir, c, StreamAudit{}, nil, nil)
	if !in.Bounded || !in.ReconcileOK {
		t.Fatalf("finaliseInput = bounded %v / reconcileOK %v (%v), want true/true",
			in.Bounded, in.ReconcileOK, in.ReconcileErr)
	}
	j := e.journalFor("run-1")
	fin := Finalise(j, in)
	_ = j.Close()
	if fin.Failed || fin.Reason != "" {
		t.Fatalf("bounded run recorded as failed: %v %q", fin.Failed, fin.Reason)
	}
	// A bounded window is still not a sustained measurement.
	if fin.Sustained {
		t.Error("a bounded window must not be reported as sustained")
	}

	end := journalEventsOfType(t, runDir, "run.end")
	if len(end) != 1 {
		t.Fatalf("want one run.end, got %d", len(end))
	}
	if failed, _ := end[0]["failed"].(bool); failed {
		t.Errorf("run.end.failed = true for a bounded window: %v", end[0])
	}
	if jstring(end[0], "reason") != "" {
		t.Errorf("run.end.reason = %q, want empty", jstring(end[0], "reason"))
	}
	if b, _ := end[0]["bounded"].(bool); !b {
		t.Errorf("run.end should stamp bounded=true: %v", end[0])
	}
}

// An interrupted window (context cancelled) is still a failure — the bounded
// carve-out must not swallow the case it was carved out of.
func TestCancelledWindowIsStillInterrupted(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeRealBallotStream(t, runDir, 400)

	ctx, cancel := context.WithCancel(context.Background())
	c := ElectionConfig{Mode: "onchain", Voters: 400, Positions: 1, Candidates: 2,
		Concurrency: 2, WindowS: 30}
	led := slowLedger{fakeLedger: &fakeLedger{cancel: cancel, FailAt: 5}, delay: time.Millisecond}
	_ = e.submitOnChain(ctx, "run-1", c, led, path)

	var sm submitMetrics
	if err := readJSON(filepath.Join(runDir, submitMetricsFile), &sm); err != nil {
		t.Skipf("no submit metrics written (the window failed before writing): %v", err)
	}
	if sm.Bounded {
		t.Fatal("a cancelled window must not be recorded as a bounded stop")
	}
}

// windowWasBounded is the whole carve-out, so each of its three conditions
// gets a row: no bound, a live bound reached, a cancelled context, a drop.
func TestWindowWasBounded(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	stoppedClean := bench.RunResult{Stopped: true}
	cases := []struct {
		name    string
		ctx     context.Context
		windowS float64
		res     bench.RunResult
		want    bool
	}{
		{"bound reached", context.Background(), 120, stoppedClean, true},
		{"no bound configured", context.Background(), 0, stoppedClean, false},
		{"not stopped at all", context.Background(), 120, bench.RunResult{}, false},
		{"context cancelled", cancelled, 120, stoppedClean, false},
		{"a ballot dropped", context.Background(), 120, bench.RunResult{Stopped: true, Dropped: 1}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := ElectionConfig{WindowS: c.windowS}
			if got := windowWasBounded(c.ctx, cfg, c.res); got != c.want {
				t.Fatalf("windowWasBounded = %v, want %v", got, c.want)
			}
		})
	}
}
