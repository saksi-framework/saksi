package campaign

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// writeStreamBundle writes a bundle.json that REFERENCES ballots.ndjson
// instead of carrying the population inline.
func writeStreamBundle(t *testing.T, runDir string, count int) string {
	t.Helper()
	data, err := json.Marshal(onChainBundle{
		ElectionID: "run-1", Params: "aa", DKG: "bb", Tally: "tt",
		BallotsFile: BallotsFile, BallotCount: count,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(runDir, "bundle.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeBallotStream writes n hex ballot lines plus the matching bundle.
func writeBallotStream(t *testing.T, runDir string, n int) string {
	t.Helper()
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%08x\n", i)
	}
	if err := os.WriteFile(filepath.Join(runDir, BallotsFile), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return writeStreamBundle(t, runDir, n)
}

// TestSubmitBallotsFetchesReceiptsPerBlockNotPerBallot is the qscc-cost gate:
// 1,000 ballots at concurrency 8 must cost at most one receipt fetch per
// DISTINCT block (plus the handful of non-ballot lifecycle steps), never one
// per ballot. The fake batches 10 transactions per block, so a per-ballot
// fetch overshoots the bound by ~10x.
func TestSubmitBallotsFetchesReceiptsPerBlockNotPerBallot(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeBallotStream(t, runDir, 1000)
	led := &fakeLedger{blockSize: 10}

	if err := e.submitOnChain(context.Background(), "run-1", ElectionConfig{Concurrency: 8}, led, path); err != nil {
		t.Fatal(err)
	}

	blocks := led.distinctBlocks()
	if blocks >= 1000 {
		t.Fatalf("fake ledger should batch ballots into blocks, got %d distinct blocks", blocks)
	}
	if got, want := led.qsccCalls(), blocks+6; got > want {
		t.Fatalf("qscc calls = %d, want <= %d (distinct blocks %d + 6)", got, want, blocks)
	}
}

// TestSubmitBallotsAbortsOnTruncatedBallotLine: a truncated / non-hex ballot
// line must abort the whole submission naming its line number, never be
// counted as a single dropped ballot and scrolled past.
func TestSubmitBallotsAbortsOnTruncatedBallotLine(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	if err := os.WriteFile(filepath.Join(runDir, BallotsFile),
		[]byte("aabb\nccdd\nzzz\naabb\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := writeStreamBundle(t, runDir, 4)

	err := e.submitOnChain(context.Background(), "run-1", ElectionConfig{Concurrency: 4}, &fakeLedger{}, path)
	if err == nil {
		t.Fatal("want an error for the truncated ballot line")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("error must name the offending line number, got: %v", err)
	}
}

// TestSubmitBallotsRejectsBallotCountMismatch: bundle.json and ballots.ndjson
// must agree. A bundle that promises more ballots than the file holds would
// otherwise create the election and fill it with a silent undercount.
func TestSubmitBallotsRejectsBallotCountMismatch(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	writeBallotLinesFile(t, runDir, 3)
	path := writeStreamBundle(t, runDir, 5) // bundle claims 5, file holds 3

	err := e.submitOnChain(context.Background(), "run-1", ElectionConfig{}, &fakeLedger{}, path)
	if err == nil {
		t.Fatal("want an error when ballot_count disagrees with the stream")
	}
	if !strings.Contains(err.Error(), "5") || !strings.Contains(err.Error(), "3") {
		t.Fatalf("error must name both counts, got: %v", err)
	}
}

// TestSubmitBallotsRejectsBundleWithoutBallotsFile: an old bundle that inlined
// its ballots names the missing field, so the fix is obvious.
func TestSubmitBallotsRejectsBundleWithoutBallotsFile(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := filepath.Join(runDir, "bundle.json")
	if err := os.WriteFile(path,
		[]byte(`{"election_id":"run-1","params":"aa","dkg":"bb","tally":"tt"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	err := e.submitOnChain(context.Background(), "run-1", ElectionConfig{}, &fakeLedger{}, path)
	if err == nil || !strings.Contains(err.Error(), "ballots_file") {
		t.Fatalf("want an error naming ballots_file, got: %v", err)
	}
}

// perfCells reads perf.csv's single data row as column -> cell.
func perfCells(t *testing.T, dir string) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, PerfCSV))
	if err != nil {
		t.Fatalf("perf.csv not written: %v", err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("perf.csv unparseable: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("perf.csv should be a header + one run row, got %d rows", len(rows))
	}
	if !reflect.DeepEqual(rows[0], perfColumns) {
		t.Fatalf("perf.csv header = %v", rows[0])
	}
	cells := map[string]string{}
	for i, name := range rows[0] {
		cells[name] = rows[1][i]
	}
	return cells
}

// auditJSON is a passing audit document carrying the auditor's in-process
// stage timings.
const auditJSON = `{"overall":"pass","timings_ms":{"verify_ballots":41,"aggregate":7,` +
	`"combine":3,"decode":12,"verify_threads":16},"contests":[{"contest":"president/cand0",` +
	`"ground_truth":3,"decoded":3,"E":0,"pass":true}]}`

// TestVerifyWritesPerfRowForOnChainRun: the submitted run's row carries the
// measured window, and every column WITHOUT a producer on this box (no docker
// sampler, no peer volume) is EMPTY — a fabricated 0 would read as "we
// measured the peer and it used no CPU".
func TestVerifyWritesPerfRowForOnChainRun(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeBallotStream(t, runDir, 20)
	c := ElectionConfig{Mode: "onchain", Voters: 20, Positions: 1, Candidates: 2,
		Distribution: "realistic", Concurrency: 4}

	if err := e.submitOnChain(context.Background(), "run-1", c, &fakeLedger{blockSize: 5}, path); err != nil {
		t.Fatal(err)
	}
	e.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(auditJSON), nil
	}
	if _, err := e.Verify(context.Background(), "run-1", c); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	cells := perfCells(t, runDir)
	if cells["committed"] != "20" || cells["dropped"] != "0" {
		t.Fatalf("committed/dropped = %q/%q", cells["committed"], cells["dropped"])
	}
	if cells["committed_tps"] == "" {
		t.Fatal("committed_tps must be measured for a run that submitted ballots")
	}
	// The auditor's own timings, not zeros.
	for col, want := range map[string]string{
		"proof_verify_inproc_ms": "41", "aggregate_inproc_ms": "7",
		"combine_inproc_ms": "3", "decrypt_inproc_ms": "12",
		"verify_threads": "16",
	} {
		if cells[col] != want {
			t.Fatalf("%s = %q, want %q", col, cells[col], want)
		}
	}
	// Nothing sampled these, so they are blank rather than zero.
	for _, col := range []string{
		"peak_cpu_pct_peer", "peak_cpu_pct_orderer", "peak_cpu_pct_client",
		"peak_mem_mb_peer", "peak_mem_mb_orderer", "peak_mem_mb_client",
		"ledger_bytes_delta",
	} {
		if cells[col] != "" {
			t.Fatalf("%s = %q, want an empty cell (nothing produced it)", col, cells[col])
		}
	}
	// latencies.csv carries one row per submitted ballot.
	lat, err := os.ReadFile(filepath.Join(runDir, LatenciesCSV))
	if err != nil {
		t.Fatalf("latencies.csv: %v", err)
	}
	rows := strings.Split(strings.TrimSpace(string(lat)), "\n")
	if rows[0] != "index,segment,ms,ok" {
		t.Fatalf("latencies.csv header = %q", rows[0])
	}
	if len(rows) != 21 {
		t.Fatalf("latencies.csv has %d lines, want header + 20", len(rows))
	}
	if _, err := os.Stat(filepath.Join(runDir, PerfSchemaFile)); err != nil {
		t.Fatalf("%s not written: %v", PerfSchemaFile, err)
	}
}

// TestVerifyWritesPerfRowForOfflineRun: an offline run never opens a
// submission window, so every submit column is empty — not zero.
func TestVerifyWritesPerfRowForOfflineRun(t *testing.T) {
	e, runID, dir := newRun(t, "offline")
	e.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(auditJSON), nil
	}
	if _, err := e.Verify(context.Background(), runID, good()); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	cells := perfCells(t, dir)
	for _, col := range []string{
		"submit_window_ms", "committed", "dropped", "committed_tps", "driver_ceiling_tps",
		"latency_min_ms", "latency_p50_ms", "latency_mean_ms", "latency_p95_ms",
		"latency_p99_ms", "latency_stddev_ms", "ledger_bytes_delta",
	} {
		if cells[col] != "" {
			t.Fatalf("offline run's %s = %q, want an empty cell", col, cells[col])
		}
	}
	if cells["run_id"] != runID || cells["mode"] != "offline" {
		t.Fatalf("run_id/mode = %q/%q", cells["run_id"], cells["mode"])
	}
	if cells["failed"] != "false" {
		t.Fatalf("failed = %q, want false", cells["failed"])
	}
}

// TestSubmitBallotsLatenciesRecordEverySubmission is the 1,000-row gate the
// per-ballot latency record exists for.
func TestSubmitBallotsLatenciesRecordEverySubmission(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	path := writeBallotStream(t, runDir, 1000)

	if err := e.submitOnChain(context.Background(), "run-1",
		ElectionConfig{Concurrency: 8}, &fakeLedger{blockSize: 10}, path); err != nil {
		t.Fatal(err)
	}
	lat, err := os.ReadFile(filepath.Join(runDir, LatenciesCSV))
	if err != nil {
		t.Fatalf("latencies.csv: %v", err)
	}
	rows := strings.Split(strings.TrimSpace(string(lat)), "\n")
	if len(rows) != 1001 {
		t.Fatalf("latencies.csv has %d lines, want header + 1000", len(rows))
	}
	for i, row := range rows[1:] {
		if !strings.HasPrefix(row, strconv.Itoa(i)+",0,") || !strings.HasSuffix(row, ",commit") {
			t.Fatalf("row %d = %q, want index %d, segment 0, ok=commit", i, row, i)
		}
	}
}

// TestVerifyReplacesThePerfRowOnReAudit: perf.csv is one row per run_id and
// the latest Verify wins. Re-auditing must REPLACE the run's row, never append
// a second one — a duplicated row would double-count the run in anything that
// concatenates these files.
func TestVerifyReplacesThePerfRowOnReAudit(t *testing.T) {
	e, runID, dir := newRun(t, "offline")
	e.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(auditJSON), nil
	}
	if _, err := e.Verify(context.Background(), runID, good()); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if cells := perfCells(t, dir); cells["decrypt_inproc_ms"] != "12" {
		t.Fatalf("first row decrypt_inproc_ms = %q", cells["decrypt_inproc_ms"])
	}

	// Re-audit: same run, a different verdict and different timings.
	e.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(`{"overall":"fail","timings_ms":{"verify_ballots":99,"aggregate":1,` +
			`"combine":2,"decode":77},"contests":[{"contest":"president/cand0",` +
			`"ground_truth":3,"decoded":4,"E":1,"pass":false}]}`), nil
	}
	if _, err := e.Verify(context.Background(), runID, good()); err != nil {
		t.Fatalf("second Verify: %v", err)
	}

	// perfCells fails unless the file is exactly a header + ONE data row.
	cells := perfCells(t, dir)
	if cells["run_id"] != runID {
		t.Fatalf("run_id = %q, want %q", cells["run_id"], runID)
	}
	if cells["decrypt_inproc_ms"] != "77" || cells["proof_verify_inproc_ms"] != "99" {
		t.Fatalf("the surviving row is not the second audit's: %v", cells)
	}
	// The second document (an older auditor's) reports no thread count: the
	// cell is empty, never a fabricated 0.
	if cells["verify_threads"] != "" {
		t.Fatalf("verify_threads = %q, want empty for an audit that did not report it", cells["verify_threads"])
	}
	if cells["failed"] != "true" || !strings.Contains(cells["fail_reason"], "e_nonzero") {
		t.Fatalf("failed/fail_reason = %q/%q", cells["failed"], cells["fail_reason"])
	}
}

// TestWritePerfRowKeepsOtherRuns: replacing this run's row must not disturb
// rows belonging to other run ids sharing the file.
func TestWritePerfRowKeepsOtherRuns(t *testing.T) {
	dir := t.TempDir()
	other := make([]string, len(perfColumns))
	other[0] = "run-other"
	reasonCol := slices.Index(perfColumns, "fail_reason") // the free-text column
	other[reasonCol] = `boom, "quoted"`
	if err := os.WriteFile(filepath.Join(dir, PerfCSV),
		[]byte(strings.Join(perfColumns, ",")+"\n"+
			strings.Join(csvEscape(other), ",")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ { // twice: the second write replaces the first
		if err := writePerfRow(dir, "run-1", ElectionConfig{Mode: "offline"}, FinaliseResult{}); err != nil {
			t.Fatalf("writePerfRow: %v", err)
		}
	}

	f, err := os.Open(filepath.Join(dir, PerfCSV))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("perf.csv unparseable: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("want header + run-other + run-1, got %d rows", len(rows))
	}
	if rows[1][0] != "run-other" || rows[1][reasonCol] != `boom, "quoted"` {
		t.Fatalf("the other run's row was disturbed: %q", rows[1])
	}
	if rows[2][0] != "run-1" {
		t.Fatalf("this run's row = %q", rows[2][0])
	}
}
