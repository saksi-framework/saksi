package campaign

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Preflight estimates the longest phase from the per-record costs and holds it
// against --phase-timeout: a block above it, a warning above 75 % of it, and
// both name the flag.
func TestPreflightPhaseTimeout(t *testing.T) {
	fakeHostProbes(t, "", nil)
	for _, tc := range []struct {
		name     string
		in       PreflightInput
		timeout  time.Duration
		code     string // "" = neither finding fires
		phase    string
		estimate float64
	}{
		// SP-3.5M on-chain: 3,524,078 records x 1.24 ms = 4,370 s, over an hour.
		{"capstone blocks at the default", PreflightInput{Mode: "onchain", Voters: 3_524_078, Positions: 1},
			time.Hour, "phase_timeout_short", "ballot submission", 4369.85672},
		// SP-50K x 3 on-chain: 186 s is 77.5 % of four minutes.
		{"tight warns", PreflightInput{Mode: "onchain", Voters: 50_000, Positions: 3},
			4 * time.Minute, "phase_timeout_tight", "ballot submission", 186},
		{"fits", PreflightInput{Mode: "onchain", Voters: 50_000, Positions: 3},
			time.Hour, "", "ballot submission", 186},
		// MP-3.5M offline: generation (0.18 ms) outlasts the audit (0.16 ms).
		{"offline row 8 fits", PreflightInput{Mode: "offline", Voters: 3_524_078, Positions: 3, Candidates: 4},
			time.Hour, "", "generate", 1903.00212},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, root := gateServer(t, FabricConfig{}, "abc", 1<<60)
			writeLadder(t, root, "abc")
			fakeMeminfo(t, 1<<40)
			s.timeout = tc.timeout
			rep := s.preflight(tc.in)
			got := findings(rep.Warnings)
			for _, code := range []string{"phase_timeout_short", "phase_timeout_tight"} {
				if fires := got[code].Code != ""; fires != (code == tc.code) {
					t.Errorf("%s fired=%v, want code %q (all %+v)", code, fires, tc.code, rep.Warnings)
				}
			}
			if f := got[tc.code]; tc.code != "" && (!strings.Contains(f.Message, "--phase-timeout") || f.Forceable) {
				t.Errorf("finding must name the flag and not be forceable: %+v", f)
			}
			pt := rep.PhaseTimeout
			if pt.Seconds != tc.timeout.Seconds() || pt.LongestPhase != tc.phase || pt.EstimatedS == nil ||
				*pt.EstimatedS < tc.estimate-0.01 || *pt.EstimatedS > tc.estimate+0.01 {
				t.Errorf("phase_timeout = %+v (estimate %v), want %s at %v s", pt, pt.EstimatedS, tc.phase, tc.estimate)
			}
		})
	}

	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<60)
	if rep := s.preflight(PreflightInput{Mode: ModeGroundTruth, Voters: 3_524_078, Positions: 3}); rep.PhaseTimeout.EstimatedS != nil {
		t.Fatalf("ground truth runs no cryptography, so no estimate: %+v", rep.PhaseTimeout)
	}
}

// Journal line 1 records the phase timeout the run was started under.
func TestJournalRecordsPhaseTimeout(t *testing.T) {
	s, _, exec := testServer(t, nil)
	runID, dir := seedRun(t, s, nil)
	_ = exec.Generate(context.Background(), runID, good())
	lines := journalLines(t, dir)
	if len(lines) == 0 || lines[0]["phase_timeout_s"] != float64(60) {
		t.Fatalf("journal line 1 = %v, want phase_timeout_s 60", lines)
	}
}
