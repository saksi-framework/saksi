package campaign

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The data-validation gate, made visible.
//
// The paper's methodology (Figure 3.1) puts a "Data Validation: all records
// valid?" decision between Stage 4 (synthetic data generation) and Stage 5
// (the encrypted demonstration): only data confirmed complete, well-formed, and
// internally consistent proceeds. The Rust generator already enforces a
// fail-closed structural gate over the ballots it builds, but nothing ever
// showed that to the operator, and nothing at all re-checked the ground-truth
// CSVs after they were written.
//
// RunCheck audits the generated population against itself: it recounts the
// per-voter ballot table from scratch and holds the result against the
// published summary. A writer bug, a truncated file, or a torn write shows up
// here as a disagreement rather than as a clean-looking tally downstream.
//
// It also digests both files, which is what lets a published ground-truth table
// later be shown to be the same population an encrypted run was built from —
// the encryption is randomized, so the ciphertexts cannot serve as that link.

// Check is one validation rule and its outcome.
type Check struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

// CheckReport is the /api/check/<runID> body.
type CheckReport struct {
	Pass   bool    `json:"pass"`
	Checks []Check `json:"checks"`
	// Rows is the number of voter rows audited.
	Rows int `json:"rows"`
	// Digests bind this exact population to a later encrypted run.
	BallotsSHA256 string `json:"ground_truth_ballots_sha256"`
	SummarySHA256 string `json:"ground_truth_summary_sha256"`
	// Params records what the population claims to be, so a published table
	// carries its own provenance rather than relying on the run folder's name.
	Voters       int    `json:"voters"`
	Positions    int    `json:"positions"`
	Candidates   int    `json:"candidates"`
	Distribution string `json:"distribution"`
	ElectionID   string `json:"election_id"`
}

// CheckFile is where the report is persisted in the run folder.
const CheckFile = "ground-truth-check.json"

func pass(name, detail string) Check { return Check{Name: name, Pass: true, Detail: detail} }
func fail(name, detail string) Check { return Check{Name: name, Pass: false, Detail: detail} }

// RunCheck audits a run's ground-truth tables and writes the report into the
// run folder. It streams the ballot table a line at a time, so the capstone
// tiers (3.5M rows, ~217 MB) audit in bounded memory.
func (e *Executor) RunCheck(runID string, c ElectionConfig) (CheckReport, error) {
	dir, err := e.store.Dir(runID)
	if err != nil {
		return CheckReport{}, err
	}
	rep := CheckReport{
		Voters: c.Voters, Positions: c.Positions, Candidates: c.Candidates,
		Distribution: c.Distribution, ElectionID: runID,
	}

	ballotsPath := filepath.Join(dir, GroundTruthBallotsCSV)
	summaryPath := filepath.Join(dir, GroundTruthSummaryCSV)

	// Recount the per-voter table from scratch. counts[position][candidate].
	counts, rows, structural := recountBallots(ballotsPath, c)
	rep.Checks = append(rep.Checks, structural...)
	rep.Rows = rows

	// Every voter must appear exactly once, in order, with no gaps.
	if rows == c.Voters {
		rep.Checks = append(rep.Checks, pass("Every voter accounted for",
			fmt.Sprintf("%s rows, one per configured voter", withCommas(rows))))
	} else {
		rep.Checks = append(rep.Checks, fail("Every voter accounted for",
			fmt.Sprintf("found %s rows, expected %s", withCommas(rows), withCommas(c.Voters))))
	}

	// The independent recount must agree with the published summary — this is
	// the check the whole step exists for.
	rep.Checks = append(rep.Checks, compareToSummary(summaryPath, counts, c))

	// No position may lose or gain a vote.
	if counts != nil {
		balanced := true
		var offender string
		for p := 0; p < c.Positions && p < len(counts); p++ {
			total := 0
			for _, n := range counts[p] {
				total += n
			}
			if total != rows {
				balanced = false
				offender = fmt.Sprintf("position %d totals %s, expected %s",
					p+1, withCommas(total), withCommas(rows))
				break
			}
		}
		if balanced {
			rep.Checks = append(rep.Checks, pass("No votes lost or invented",
				fmt.Sprintf("each of the %d positions totals exactly %s", c.Positions, withCommas(rows))))
		} else {
			rep.Checks = append(rep.Checks, fail("No votes lost or invented", offender))
		}
	}

	rep.BallotsSHA256 = fileDigest(ballotsPath)
	rep.SummarySHA256 = fileDigest(summaryPath)
	if rep.BallotsSHA256 != "" && rep.SummarySHA256 != "" {
		rep.Checks = append(rep.Checks, pass("Population fingerprinted",
			"sha256 recorded for both tables — a later encrypted run can be shown to use this exact population"))
	}

	rep.Pass = true
	for _, ch := range rep.Checks {
		if !ch.Pass {
			rep.Pass = false
		}
	}
	_ = writeJSON(filepath.Join(dir, CheckFile), rep)
	return rep, nil
}

// recountBallots streams the wide ballot table, verifying each row's shape as
// it goes and tallying selections independently of the published summary.
func recountBallots(path string, c ElectionConfig) ([][]int, int, []Check) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, []Check{fail("Ballot table readable",
			"ground-truth-ballots.csv is missing or unreadable")}
	}
	defer f.Close()

	counts := make([][]int, c.Positions)
	for i := range counts {
		counts[i] = make([]int, c.Candidates)
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 256*1024), 4*1024*1024)
	if !sc.Scan() {
		return nil, 0, []Check{fail("Ballot table readable", "file is empty")}
	}
	header := strings.Split(sc.Text(), ",")
	// voter_id, scale_group, ballot_complexity, then one column per position.
	const fixedCols = 3
	if len(header) != fixedCols+c.Positions {
		return nil, 0, []Check{fail("Ballot table shape",
			fmt.Sprintf("header has %d columns, expected %d (3 fixed + %d positions)",
				len(header), fixedCols+c.Positions, c.Positions))}
	}

	rows, ordered, inRange := 0, true, true
	var firstBad string
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		rows++
		fields := strings.Split(line, ",")
		if len(fields) != len(header) {
			if firstBad == "" {
				firstBad = fmt.Sprintf("row %d has %d fields, expected %d", rows, len(fields), len(header))
			}
			inRange = false
			continue
		}
		// Voter ids are V-%06d and strictly sequential; checking the ordinal
		// against the row number catches a duplicate or a gap in O(1) memory,
		// which a set of 3.5M ids would not afford.
		if n, err := strconv.Atoi(strings.TrimPrefix(fields[0], "V-")); err != nil || n != rows {
			if ordered && firstBad == "" {
				firstBad = fmt.Sprintf("row %d carries voter id %q", rows, fields[0])
			}
			ordered = false
		}
		for p := 0; p < c.Positions; p++ {
			k, ok := candidateOrdinal(fields[fixedCols+p])
			if !ok || k < 1 || k > c.Candidates {
				if inRange && firstBad == "" {
					firstBad = fmt.Sprintf("row %d, position %d: %q is not one of %d candidates",
						rows, p+1, fields[fixedCols+p], c.Candidates)
				}
				inRange = false
				continue
			}
			counts[p][k-1]++
		}
	}
	if err := sc.Err(); err != nil {
		return counts, rows, []Check{fail("Ballot table readable", "read error: "+err.Error())}
	}

	checks := []Check{pass("Ballot table shape",
		fmt.Sprintf("%d columns: voter, scale, complexity, and one per position", len(header)))}
	if ordered {
		checks = append(checks, pass("Voter ids unique and sequential",
			"V-000001 through V-"+strconv.Itoa(rows)+", no duplicates or gaps"))
	} else {
		checks = append(checks, fail("Voter ids unique and sequential", firstBad))
	}
	if inRange {
		checks = append(checks, pass("Every selection is a real candidate",
			fmt.Sprintf("all selections fall within the %d declared candidates", c.Candidates)))
	} else {
		checks = append(checks, fail("Every selection is a real candidate", firstBad))
	}
	return counts, rows, checks
}

// compareToSummary holds the independent recount against the published tally.
func compareToSummary(path string, counts [][]int, c ElectionConfig) Check {
	const name = "Recount matches the published tally"
	if counts == nil {
		return fail(name, "no recount available")
	}
	f, err := os.Open(path)
	if err != nil {
		return fail(name, "ground-truth-summary.csv is missing or unreadable")
	}
	defer f.Close()

	rows, err := csv.NewReader(f).ReadAll()
	if err != nil || len(rows) < 2 {
		return fail(name, "ground-truth-summary.csv is empty or malformed")
	}
	want := c.Positions * c.Candidates
	if got := len(rows) - 1; got != want {
		return fail(name, fmt.Sprintf("summary has %d contest rows, expected %d", got, want))
	}
	for i, r := range rows[1:] {
		if len(r) < 3 {
			return fail(name, fmt.Sprintf("summary row %d is malformed", i+1))
		}
		published, err := strconv.Atoi(strings.TrimSpace(r[2]))
		if err != nil {
			return fail(name, fmt.Sprintf("summary row %d has a non-numeric count", i+1))
		}
		p, k := i/c.Candidates, i%c.Candidates
		if recounted := counts[p][k]; recounted != published {
			return fail(name, fmt.Sprintf("%s / %s: summary says %s, recount says %s",
				r[0], r[1], withCommas(published), withCommas(recounted)))
		}
	}
	return pass(name, fmt.Sprintf("all %d contests agree, recounted from the ballot table", want))
}

// candidateOrdinal pulls NN out of a CAND_PREFIX_NN label.
func candidateOrdinal(label string) (int, bool) {
	i := strings.LastIndex(label, "_")
	if i < 0 || i == len(label)-1 {
		return 0, false
	}
	n, err := strconv.Atoi(label[i+1:])
	if err != nil {
		return 0, false
	}
	return n, true
}

func fileDigest(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// withCommas groups an integer for display: 3524078 -> "3,524,078".
func withCommas(n int) string {
	s := strconv.Itoa(n)
	if n < 0 {
		return s
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return b.String()
}
