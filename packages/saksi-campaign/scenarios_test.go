package campaign

import (
	"context"
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
	for _, rel := range []string{
		"../../target/release/saksi-demo",
		"../../target/debug/saksi-demo",
	} {
		if abs, err := filepath.Abs(rel); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
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
	if sa, err := e.Verify(ctx, runID); err != nil || sa.Overall != "pass" {
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
	if len(cols) != 11 || len(cols[6]) != 64 {
		t.Fatalf("correctness row missing 64-hex recovered_point: %q", ccLines[1])
	}

	if err := e.RunScenarios(ctx, runID, nil); err != nil {
		t.Fatalf("run scenarios: %v", err)
	}

	// Every offline scenario must have PASSED (attack rejected).
	data, err := os.ReadFile(filepath.Join(srcDir, NegativeTestsFile))
	if err != nil {
		t.Fatalf("negative-tests.csv: %v", err)
	}
	rows := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(rows) < 2 {
		t.Fatalf("expected scenario rows, got: %s", data)
	}
	offlineCount := 0
	for _, line := range rows[1:] {
		cols := strings.Split(line, ",")
		// scenario,layer,action,expected,actual,verdict,property
		if len(cols) < 6 {
			t.Fatalf("bad csv row: %q", line)
		}
		layer, verdict := cols[1], cols[5]
		if layer == "offline" {
			offlineCount++
			if verdict != "PASS" {
				t.Fatalf("offline scenario %q must PASS (be rejected), got %q — a gate that should have rejected did not",
					cols[0], verdict)
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
