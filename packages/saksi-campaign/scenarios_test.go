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
	e := NewExecutor(store, NewHub(), demo, "")

	if err := e.Generate(ctx, runID, c); err != nil {
		t.Fatalf("generate: %v", err)
	}
	// Sanity: the clean run audits pass.
	if sa, err := e.Verify(ctx, runID); err != nil || sa.Overall != "pass" {
		t.Fatalf("clean run must verify pass: %v %+v", err, sa)
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
