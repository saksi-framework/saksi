package campaign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// plantGroundTruth writes a small, internally consistent pair of ground-truth
// tables: 4 voters, 2 positions, 2 candidates, alternating selections.
func plantGroundTruth(t *testing.T, dir string) {
	t.Helper()
	ballots := "voter_id,scale_group,ballot_complexity,PRESIDENT,VICE_PRESIDENT\n" +
		"V-000001,4,multi,CAND_PRES_01,CAND_VICE_01\n" +
		"V-000002,4,multi,CAND_PRES_02,CAND_VICE_02\n" +
		"V-000003,4,multi,CAND_PRES_01,CAND_VICE_01\n" +
		"V-000004,4,multi,CAND_PRES_02,CAND_VICE_02\n"
	summary := "position,candidate,ground_truth_count\n" +
		"PRESIDENT,CAND_PRES_01,2\nPRESIDENT,CAND_PRES_02,2\n" +
		"VICE_PRESIDENT,CAND_VICE_01,2\nVICE_PRESIDENT,CAND_VICE_02,2\n"
	if err := os.WriteFile(filepath.Join(dir, GroundTruthBallotsCSV), []byte(ballots), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, GroundTruthSummaryCSV), []byte(summary), 0o644); err != nil {
		t.Fatal(err)
	}
}

func checkConfig() ElectionConfig {
	c := good()
	c.Voters, c.Positions, c.Candidates = 4, 2, 2
	return c
}

func runCheckOn(t *testing.T, mutate func(dir string)) CheckReport {
	t.Helper()
	s, _, exec := testServer(t, nil)
	c := checkConfig()
	runID, dir, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	plantGroundTruth(t, dir)
	if mutate != nil {
		mutate(dir)
	}
	rep, err := exec.RunCheck(runID, c)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func failedCheck(rep CheckReport, name string) *Check {
	for i := range rep.Checks {
		if strings.Contains(rep.Checks[i].Name, name) && !rep.Checks[i].Pass {
			return &rep.Checks[i]
		}
	}
	return nil
}

func TestCheckPassesOnConsistentData(t *testing.T) {
	rep := runCheckOn(t, nil)
	if !rep.Pass {
		for _, c := range rep.Checks {
			if !c.Pass {
				t.Errorf("unexpected failure: %s — %s", c.Name, c.Detail)
			}
		}
		t.Fatal("consistent data must pass every check")
	}
	if rep.Rows != 4 {
		t.Fatalf("audited %d rows, want 4", rep.Rows)
	}
	if rep.BallotsSHA256 == "" || rep.SummarySHA256 == "" {
		t.Fatal("both tables must be fingerprinted")
	}
}

// The check exists to catch a tally that disagrees with the ballots it claims
// to summarise. If it cannot catch that, it is decoration.
func TestCheckCatchesTallyDisagreeingWithBallots(t *testing.T) {
	rep := runCheckOn(t, func(dir string) {
		p := filepath.Join(dir, GroundTruthSummaryCSV)
		b, _ := os.ReadFile(p)
		// Claim 3 votes for the first candidate where the ballots show 2.
		_ = os.WriteFile(p, []byte(strings.Replace(string(b),
			"PRESIDENT,CAND_PRES_01,2", "PRESIDENT,CAND_PRES_01,3", 1)), 0o644)
	})
	if rep.Pass {
		t.Fatal("a summary that disagrees with the ballots must fail the gate")
	}
	if c := failedCheck(rep, "Recount matches"); c == nil {
		t.Fatal("the recount check specifically must be the one that fails")
	}
}

// A truncated file — a torn write, an interrupted copy — must not read as valid.
func TestCheckCatchesMissingVoters(t *testing.T) {
	rep := runCheckOn(t, func(dir string) {
		p := filepath.Join(dir, GroundTruthBallotsCSV)
		b, _ := os.ReadFile(p)
		lines := strings.SplitAfter(string(b), "\n")
		_ = os.WriteFile(p, []byte(strings.Join(lines[:3], "")), 0o644) // header + 2 voters
	})
	if rep.Pass {
		t.Fatal("a truncated ballot table must fail the gate")
	}
	if c := failedCheck(rep, "Every voter accounted for"); c == nil {
		t.Fatal("the voter-count check must fail on a truncated table")
	}
}

// A selection naming a candidate outside the declared set is malformed input,
// not a valid vote.
func TestCheckCatchesOutOfRangeSelection(t *testing.T) {
	rep := runCheckOn(t, func(dir string) {
		p := filepath.Join(dir, GroundTruthBallotsCSV)
		b, _ := os.ReadFile(p)
		_ = os.WriteFile(p, []byte(strings.Replace(string(b),
			"CAND_PRES_02,CAND_VICE_02", "CAND_PRES_09,CAND_VICE_02", 1)), 0o644)
	})
	if rep.Pass {
		t.Fatal("a selection outside the candidate set must fail the gate")
	}
	if c := failedCheck(rep, "real candidate"); c == nil {
		t.Fatal("the candidate-range check must fail")
	}
}

// A duplicated voter id means someone voted twice, or a row was copied.
func TestCheckCatchesDuplicateVoterID(t *testing.T) {
	rep := runCheckOn(t, func(dir string) {
		p := filepath.Join(dir, GroundTruthBallotsCSV)
		b, _ := os.ReadFile(p)
		_ = os.WriteFile(p, []byte(strings.Replace(string(b),
			"V-000003", "V-000002", 1)), 0o644)
	})
	if rep.Pass {
		t.Fatal("a duplicate voter id must fail the gate")
	}
	if c := failedCheck(rep, "unique and sequential"); c == nil {
		t.Fatal("the voter-id check must fail")
	}
}
