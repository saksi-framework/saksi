package campaign

import (
	"context"
	"encoding/csv"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// findDemo locates the saksi-demo binary; the scenario integration test needs
// the real auditor. Skips (not fails) when it cannot be found.
func findDemo(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SAKSI_DEMO_BIN"); p != "" {
		return p
	}
	// ".exe" as well: on Windows the cargo build lands as saksi-demo.exe, and
	// target/ is not on PATH for LookPath to find it.
	for _, rel := range []string{
		"../../target/release/saksi-demo",
		"../../target/debug/saksi-demo",
	} {
		for _, cand := range []string{rel, rel + ".exe"} {
			if abs, err := filepath.Abs(cand); err == nil {
				if _, err := os.Stat(abs); err == nil {
					return abs
				}
			}
		}
	}
	if p, err := exec.LookPath("saksi-demo"); err == nil {
		return p
	}
	t.Skip("saksi-demo binary not found; set SAKSI_DEMO_BIN or build it")
	return ""
}

func TestScenariosRejectTheirMutations(t *testing.T) {
	demo := findDemo(t)
	ctx := context.Background()

	store := NewRunStore(t.TempDir())
	c := good()
	c.Voters, c.Positions, c.Candidates = 6, 1, 2
	runID, srcDir, err := store.Create(c, time.Now())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	e := NewExecutor(store, NewHub(), demo, "", FabricConfig{})

	if err := e.Generate(ctx, runID, c); err != nil {
		t.Fatalf("generate: %v", err)
	}
	// Real ballots flatten into ballots.csv: header + one row per (voter, position).
	bc, err := os.ReadFile(filepath.Join(srcDir, BallotsCSV))
	if err != nil {
		t.Fatalf("ballots.csv: %v", err)
	}
	if got := len(strings.Split(strings.TrimSpace(string(bc)), "\n")); got != 1+c.Voters*c.Positions {
		t.Fatalf("ballots.csv rows = %d, want %d", got, 1+c.Voters*c.Positions)
	}
	// The evidence columns carry the actual encrypted values + hashes.
	if !strings.Contains(string(bc), "ballot_sha256,ballot_json") {
		t.Fatal("ballots.csv missing evidence columns (ballot_sha256, ballot_json)")
	}
	if !strings.Contains(string(bc), "ciphertexts") || !strings.Contains(string(bc), "well_formedness_proofs") {
		t.Fatal("ballots.csv ballot_json must contain the actual ciphertexts + proofs")
	}
	ec, err := os.ReadFile(filepath.Join(srcDir, ElectionCSV))
	if err != nil {
		t.Fatalf("election.csv not written: %v", err)
	}
	if !strings.Contains(string(ec), "ballots_sha256") || !strings.Contains(string(ec), "dkg_sha256") {
		t.Fatal("election.csv must carry provenance digests")
	}

	// Sanity: the clean run audits pass.
	if sa, err := e.Verify(ctx, runID, c); err != nil || sa.Overall != "pass" {
		t.Fatalf("clean run must verify pass: %v %+v", err, sa)
	}
	// correctness.csv is the proof: carries the recovered point, aggregate
	// ciphertext, and artifact hashes — not just the verdict.
	cc, err := os.ReadFile(filepath.Join(srcDir, CorrectnessFile))
	if err != nil {
		t.Fatalf("correctness.csv: %v", err)
	}
	ccs := string(cc)
	for _, col := range []string{"recovered_point", "aggregate_ciphertext", "dkg_sha256", "tally_sha256", "ballots_sha256"} {
		if !strings.Contains(ccs, col) {
			t.Fatalf("correctness.csv missing proof column %q", col)
		}
	}
	// At least one contest row, and it carries a 64-hex recovered point.
	ccLines := strings.Split(strings.TrimSpace(ccs), "\n")
	if len(ccLines) < 2 {
		t.Fatalf("correctness.csv has no data rows:\n%s", ccs)
	}
	cols := strings.Split(ccLines[1], ",")
	if len(cols) != 13 || len(cols[6]) != 64 {
		t.Fatalf("correctness row missing 64-hex recovered_point: %q", ccLines[1])
	}

	if err := e.RunScenarios(ctx, runID, nil); err != nil {
		t.Fatalf("run scenarios: %v", err)
	}

	// Every offline scenario must have PASSED (attack rejected).
	rows := readCSVRows(t, srcDir)
	if len(rows) < 2 {
		t.Fatalf("expected scenario rows, got: %v", rows)
	}
	// Look columns up by name: hardcoding indices means a schema change reads
	// the wrong field instead of failing honestly.
	layerCol, verdictCol := csvCol(t, rows[0], "layer"), csvCol(t, rows[0], "verdict")
	offlineCount := 0
	for _, cols := range rows[1:] {
		if cols[layerCol] == "offline" {
			offlineCount++
			if v := cols[verdictCol]; v != "PASS" {
				t.Fatalf("offline scenario %q must PASS (be rejected), got %q — a gate that should have rejected did not",
					cols[0], v)
			}
		}
	}
	if offlineCount < 5 {
		t.Fatalf("expected the offline attack catalog, got only %d offline scenarios", offlineCount)
	}
}

func TestSelectScenariosFilters(t *testing.T) {
	got := selectScenarios([]string{"dropped-ballot", "reordered-ballots"})
	if len(got) != 2 {
		t.Fatalf("expected 2 selected, got %d", len(got))
	}
	if len(selectScenarios(nil)) != len(Registry()) {
		t.Fatal("empty selection must return the full registry")
	}
}

func TestBallotLineRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := writeBallotLines(dir, []string{"aa", "bb", "cc"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	lines, err := readBallotLines(dir)
	if err != nil || len(lines) != 3 || lines[1] != "bb" {
		t.Fatalf("round-trip failed: %v %v", err, lines)
	}
}

func TestFlipHexStringChangesValue(t *testing.T) {
	for _, s := range []string{"", "0a", "ff", "deadbeef0"} {
		if flipHexString(s) == s {
			t.Fatalf("flipHexString(%q) did not change the value", s)
		}
	}
}

// readCSVRows returns negative-tests.csv as records, header included.
func readCSVRows(t *testing.T, dir string) [][]string {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, NegativeTestsFile))
	if err != nil {
		t.Fatalf("open %s: %v", NegativeTestsFile, err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("parse %s: %v", NegativeTestsFile, err)
	}
	return rows
}

// csvCol returns the index of a named column, failing loudly when the schema
// no longer has it — a positional read would silently pick a neighbour.
func csvCol(t *testing.T, header []string, name string) int {
	t.Helper()
	for i, h := range header {
		if h == name {
			return i
		}
	}
	t.Fatalf("negative-tests.csv has no %q column: %v", name, header)
	return -1
}

// The header and the row writer are two separate literals in
// writeNegativeTestsCSV: if one gains a column and the other does not, every
// reader silently reads the wrong field. Sentinel values catch that without
// needing saksi-demo on PATH.
func TestNegativeTestsCSVRowsMatchTheirHeader(t *testing.T) {
	dir := t.TempDir()
	exportOnce(t, dir, ScenarioResult{
		Scenario: "dropped-ballot", Stage: StageClose, Layer: LayerOffline.String(),
		Action: "act", Expected: "exp", Actual: "actual", Verdict: "PASS",
		Property: "prop", OnChain: false,
	})
	rows := readCSVRows(t, dir)
	if len(rows) != 3 {
		t.Fatalf("csv rows = %d, want header + 1 + summary: %v", len(rows), rows)
	}
	for col, want := range map[string]string{
		"scenario": "dropped-ballot", "stage": StageClose, "layer": "offline",
		"action": "act", "expected": "exp", "actual": "actual",
		"verdict": "PASS", "property": "prop", "on_chain": "false",
		"attempted": "1", "rejected": "1", "rate": "1.00",
	} {
		if got := rows[1][csvCol(t, rows[0], col)]; got != want {
			t.Errorf("column %q = %q, want %q — header and row writer are out of step", col, got, want)
		}
	}
}

// exportOnce merges one result and rewrites the CSV, mimicking what
// RunScenarios does at the end of a single-scenario call.
func exportOnce(t *testing.T, dir string, res ScenarioResult) {
	t.Helper()
	merged, err := mergeScenarioResults(dir, []ScenarioResult{res})
	if err != nil {
		t.Fatalf("merge %s: %v", res.Scenario, err)
	}
	if err := writeNegativeTestsCSV(filepath.Join(dir, NegativeTestsFile), merged); err != nil {
		t.Fatalf("write csv: %v", err)
	}
}

// The wizard runs one attack per step, so each call to RunScenarios carries a
// single scenario. Before the accumulator existed the CSV was recreated from
// only that call's results, so the export ended up holding whichever scenario
// ran last and silently lost the other six.
func TestScenarioResultsAccumulateAcrossSeparateRuns(t *testing.T) {
	dir := t.TempDir()

	exportOnce(t, dir, ScenarioResult{Scenario: "reused-nullifier", Verdict: "PASS", Actual: "rejected"})
	exportOnce(t, dir, ScenarioResult{Scenario: "dropped-ballot", Verdict: "PASS", Actual: "rejected"})

	rows := readCSVRows(t, dir)
	if len(rows) != 4 { // header + 2 + summary
		t.Fatalf("csv rows = %d, want 4 (header + both scenarios + summary): %v", len(rows), rows)
	}
	got := map[string]bool{rows[1][0]: true, rows[2][0]: true}
	for _, want := range []string{"reused-nullifier", "dropped-ballot"} {
		if !got[want] {
			t.Errorf("csv missing %q after running it in its own call; rows=%v", want, rows)
		}
	}

	// Rows follow Registry order regardless of the order the calls arrived in.
	if rows[1][0] != "reused-nullifier" || rows[2][0] != "dropped-ballot" {
		t.Errorf("rows not in Registry order: %v, %v", rows[1][0], rows[2][0])
	}
}

func TestScenarioRerunUpdatesRowInPlace(t *testing.T) {
	dir := t.TempDir()

	exportOnce(t, dir, ScenarioResult{Scenario: "dropped-ballot", Verdict: "FAIL", Actual: "not rejected"})
	exportOnce(t, dir, ScenarioResult{Scenario: "dropped-ballot", Verdict: "PASS", Actual: "rejected"})

	rows := readCSVRows(t, dir)
	if len(rows) != 3 { // header + 1 + summary
		t.Fatalf("re-running a scenario appended a duplicate row: %v", rows)
	}
	// Look the column up by name: hardcoding an index means a schema change
	// silently reads the wrong field instead of failing honestly.
	if verdict := rows[1][csvCol(t, rows[0], "verdict")]; verdict != "PASS" {
		t.Errorf("verdict = %q, want PASS (the re-run should replace the earlier FAIL)", verdict)
	}
}

func TestScenarioListingsJoinVerdicts(t *testing.T) {
	dir := t.TempDir()

	before, err := ScenarioListings(dir)
	if err != nil {
		t.Fatalf("listings on a fresh run: %v", err)
	}
	if len(before) != len(Registry()) {
		t.Fatalf("listings = %d, want %d (the full catalog)", len(before), len(Registry()))
	}
	for _, l := range before {
		if l.Verdict != "" {
			t.Errorf("%s has verdict %q before being run", l.ID, l.Verdict)
		}
		if l.Action == "" || l.Expected == "" || l.Property == "" {
			t.Errorf("%s is missing briefing text the wizard renders: %+v", l.ID, l)
		}
	}

	exportOnce(t, dir, ScenarioResult{Scenario: "reused-nullifier", Verdict: "PASS", Actual: "rejected"})

	after, err := ScenarioListings(dir)
	if err != nil {
		t.Fatalf("listings after a run: %v", err)
	}
	var seen bool
	for _, l := range after {
		if l.ID != "reused-nullifier" {
			if l.Verdict != "" {
				t.Errorf("%s gained a verdict it never earned", l.ID)
			}
			continue
		}
		seen = true
		if l.Verdict != "PASS" {
			t.Errorf("verdict = %q, want PASS", l.Verdict)
		}
	}
	if !seen {
		t.Error("reused-nullifier missing from the listings")
	}
}

// The rejection-rate columns are what the paper reports: how many attacks were
// mounted and how many the system refused. A SKIPPED scenario was never
// mounted, so it must not dilute the rate with a phantom attempt.
func TestNegativeTestsCSVRejectionRates(t *testing.T) {
	dir := t.TempDir()

	exportOnce(t, dir, ScenarioResult{Scenario: "tamper-ballot-proof", Verdict: "PASS", OnChain: true})
	exportOnce(t, dir, ScenarioResult{Scenario: "reused-nullifier", Verdict: "FAIL"})
	exportOnce(t, dir, ScenarioResult{Scenario: "dropped-ballot", Verdict: "SKIPPED"})

	rows := readCSVRows(t, dir)
	if len(rows) != 5 { // header + 3 + summary
		t.Fatalf("csv rows = %d, want header + 3 + summary: %v", len(rows), rows)
	}
	scenarioCol := csvCol(t, rows[0], "scenario")
	attempted, rejected, rate := csvCol(t, rows[0], "attempted"), csvCol(t, rows[0], "rejected"), csvCol(t, rows[0], "rate")

	want := map[string][3]string{
		"tamper-ballot-proof": {"1", "1", "1.00"},
		"reused-nullifier":    {"1", "0", "0.00"},
		"dropped-ballot":      {"0", "0", ""}, // never mounted — no rate to report
		"summary":             {"2", "1", "0.50"},
	}
	for _, cols := range rows[1:] {
		w, ok := want[cols[scenarioCol]]
		if !ok {
			t.Fatalf("unexpected row %q", cols[scenarioCol])
		}
		got := [3]string{cols[attempted], cols[rejected], cols[rate]}
		if got != w {
			t.Errorf("%s: attempted/rejected/rate = %v, want %v", cols[scenarioCol], got, w)
		}
		delete(want, cols[scenarioCol])
	}
	if len(want) != 0 {
		t.Errorf("rows missing from the export: %v", want)
	}
	if rows[len(rows)-1][scenarioCol] != "summary" {
		t.Errorf("summary must be the last row, got %q", rows[len(rows)-1][scenarioCol])
	}
}
