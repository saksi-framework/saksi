// Package bench holds the pure metric machinery for the Saksi benchmark harness
// (thesis Appendix C): latency percentiles, throughput, and the Appendix-C CSV
// schema. It is deliberately network-free so the math and the CSV columns can
// be unit-tested without a live bulletin board — the live run (saksi-console
// --auto / the campaign wizard) fills the same structs with measured durations.
package bench

import (
	"fmt"
	"io"
	"math"
	"sort"
	"time"
)

// PhaseTimings splits one ballot's commit latency across Fabric's execute-order-
// validate stages (kept separate because lumping them "makes the numbers mush",
// per the plan). Endorse includes on-chain CDS verification; CDSVerify isolates
// that sub-cost — the axis of comparison against the Galal baseline, which had no
// on-chain proof verification.
type PhaseTimings struct {
	Endorse   time.Duration // gateway endorsement (includes CDS verify below)
	CDSVerify time.Duration // sub-split of Endorse: the CDS well-formedness check
	Order     time.Duration // ordering-service sequencing
	Validate  time.Duration // VSCC/MVCC validation at commit
	Commit    time.Duration // ledger write + commit event
}

// Total is the end-to-end submit→commit latency. CDSVerify is NOT added: it is a
// component of Endorse, not a separate stage.
func (p PhaseTimings) Total() time.Duration {
	return p.Endorse + p.Order + p.Validate + p.Commit
}

// Percentiles returns the p50/p95/p99 of durs using the nearest-rank method.
// The input is copied before sorting (the caller's slice is left untouched). An
// empty input yields three zeros. p50 <= p95 <= p99 always holds.
func Percentiles(durs []time.Duration) (p50, p95, p99 time.Duration) {
	if len(durs) == 0 {
		return 0, 0, 0
	}
	sorted := make([]time.Duration, len(durs))
	copy(sorted, durs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return percentile(sorted, 50), percentile(sorted, 95), percentile(sorted, 99)
}

// percentile picks the nearest-rank value from an already-sorted slice:
// rank = ceil(p/100 * n), clamped to [1, n]; index = rank-1. This is the same
// rule Summary uses for Median/P95/P99 — for small N it can differ from the
// textbook "average the two middle values" median (e.g. N=10, p50: rank =
// ceil(0.5*10) = 5, index 4, i.e. the 5th-smallest value, not an average of
// the 5th and 6th).
func percentile(sorted []time.Duration, p int) time.Duration {
	n := len(sorted)
	rank := (p*n + 99) / 100 // ceil(p*n/100)
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}

// ThroughputTPS is committed ballots per wall-clock second over the submission
// window. Returns 0 for a non-positive window (avoids a divide-by-zero on an
// instantaneous or unmeasured run).
func ThroughputTPS(committed int, window time.Duration) float64 {
	if window <= 0 {
		return 0
	}
	return float64(committed) / window.Seconds()
}

// Stats is the full latency summary the thesis commits to: min/median/mean/
// p95/p99/stddev over a set of durations, plus the sample size.
type Stats struct {
	Min, Median, Mean, P95, P99, StdDev time.Duration
	N                                   int
}

// Summary computes Stats over durs. Percentiles (including Median = the p50
// nearest-rank value) use the same nearest-rank rule as Percentiles/percentile.
// StdDev is the population standard deviation (divides by N, not N-1) since
// durs is the full set of observations for the run, not a sample of a larger
// population.
//
// N == 0 returns a zero-value Stats (N: 0). Callers must not print zeros for
// N == 0 — a run with nothing committed has no latency to report, and printing
// 0ms would read as "the fastest possible commit" rather than "unmeasured"
// (see Row.fields, which emits an empty CSV cell instead).
func Summary(durs []time.Duration) Stats {
	n := len(durs)
	if n == 0 {
		return Stats{}
	}
	sorted := make([]time.Duration, n)
	copy(sorted, durs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var sum float64
	for _, d := range sorted {
		sum += float64(d)
	}
	meanF := sum / float64(n)

	var sqDiffSum float64
	for _, d := range sorted {
		diff := float64(d) - meanF
		sqDiffSum += diff * diff
	}
	stddev := math.Sqrt(sqDiffSum / float64(n))

	return Stats{
		Min:    sorted[0],
		Median: percentile(sorted, 50),
		Mean:   time.Duration(math.Round(meanF)),
		P95:    percentile(sorted, 95),
		P99:    percentile(sorted, 99),
		StdDev: time.Duration(math.Round(stddev)),
		N:      n,
	}
}

// Row is one Appendix-C record: a tier × ballot-axis measurement (or the Galal
// baseline row). Durations are reported in milliseconds in the CSV.
//
// DecryptTime, PeakCPUPct, and PeakMemMB are pointers because nothing in this
// package's own code path produces them — they are filled by an external
// measurement (a docker-stats sampler, a decrypt-ceremony timer) that may not
// run for a given row. A nil pointer serialises as an empty CSV cell, never a
// fabricated 0 (see fields()).
type Row struct {
	Tier       int    // voter count (1k, 10k, ... 1M)
	BallotAxis string // "single" | "multi" | "galal-baseline"
	Positions  int
	Candidates int

	SendRateReq float64 // requested send rate (tps); 0 = unbounded/serial
	Submitted   int
	Committed   int
	Dropped     int // submitted - committed (endorsement timeout / MVCC conflict)

	ThroughputTPS float64
	// End-to-end commit latency stats. Empty CSV cells when Committed == 0
	// (see fields()) — there is nothing to summarise.
	LatencyMin, LatencyP50, LatencyMean, LatencyP95, LatencyP99, LatencyStdDev time.Duration

	DecryptTime *time.Duration // threshold decryption wall-clock; nil if unmeasured
	PeakCPUPct  *float64       // peak peer/orderer CPU % (docker stats); nil if unmeasured
	PeakMemMB   *float64       // peak peer/orderer memory MB (docker stats); nil if unmeasured
}

// csvHeader is the fixed Appendix-C column order. Kept next to fields so they
// never drift.
var csvHeader = []string{
	"tier", "ballot_axis", "positions", "candidates",
	"send_rate_req", "submitted", "committed", "dropped",
	"throughput_tps",
	"latency_min_ms", "latency_p50_ms", "latency_mean_ms", "latency_p95_ms", "latency_p99_ms", "latency_stddev_ms",
	"decrypt_ms", "peak_cpu_pct", "peak_mem_mb",
}

// WriteCSV writes the Appendix-C header followed by one line per row to w.
func WriteCSV(w io.Writer, rows []Row) error {
	if err := writeLine(w, csvHeader); err != nil {
		return err
	}
	for _, r := range rows {
		if err := writeLine(w, r.fields()); err != nil {
			return err
		}
	}
	return nil
}

// WriteRow appends a single data row (no header) to w — used to append to an
// existing Appendix-C CSV across a multi-tier campaign.
func WriteRow(w io.Writer, row Row) error {
	return writeLine(w, row.fields())
}

// Header returns a copy of the Appendix-C column order (for tests / external
// consumers that need to validate a CSV they did not write).
func Header() []string {
	out := make([]string, len(csvHeader))
	copy(out, csvHeader)
	return out
}

func (r Row) fields() []string {
	ms := func(d time.Duration) string { return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000.0) }
	// latency emits an empty cell rather than a fabricated 0ms when nothing
	// committed — there is no latency to report for zero commits.
	latency := func(d time.Duration) string {
		if r.Committed == 0 {
			return ""
		}
		return ms(d)
	}
	durPtr := func(d *time.Duration) string {
		if d == nil {
			return ""
		}
		return ms(*d)
	}
	pctPtr := func(v *float64) string {
		if v == nil {
			return ""
		}
		return fmt.Sprintf("%.2f", *v)
	}
	return []string{
		fmt.Sprintf("%d", r.Tier), r.BallotAxis, fmt.Sprintf("%d", r.Positions), fmt.Sprintf("%d", r.Candidates),
		fmt.Sprintf("%.3f", r.SendRateReq), fmt.Sprintf("%d", r.Submitted), fmt.Sprintf("%d", r.Committed), fmt.Sprintf("%d", r.Dropped),
		fmt.Sprintf("%.3f", r.ThroughputTPS),
		latency(r.LatencyMin), latency(r.LatencyP50), latency(r.LatencyMean), latency(r.LatencyP95), latency(r.LatencyP99), latency(r.LatencyStdDev),
		durPtr(r.DecryptTime), pctPtr(r.PeakCPUPct), pctPtr(r.PeakMemMB),
	}
}

func writeLine(w io.Writer, fields []string) error {
	for i, f := range fields {
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, f); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\n")
	return err
}
