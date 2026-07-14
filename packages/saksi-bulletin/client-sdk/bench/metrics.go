// Package bench holds the pure metric machinery for the Saksi benchmark harness
// (thesis Appendix C): latency percentiles, Fabric phase timings, throughput,
// and the Appendix-C CSV schema. It is deliberately network-free so the math and
// the CSV columns can be unit-tested without a live bulletin board — the live
// run (saksi-console --auto) fills the same structs with measured durations.
package bench

import (
	"fmt"
	"io"
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

// percentile picks the nearest-rank value from an already-sorted slice.
// rank = ceil(p/100 * n), clamped to [1, n]; index = rank-1.
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

// Row is one Appendix-C record: a tier × ballot-axis measurement (or the Galal
// baseline row). Durations are reported in milliseconds in the CSV.
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
	// End-to-end commit latency percentiles.
	LatencyP50, LatencyP95, LatencyP99 time.Duration
	// Median of each Fabric phase (endorse incl. CDS, then the CDS sub-split).
	EndorseP50, CDSVerifyP50, OrderP50, ValidateP50, CommitP50 time.Duration

	DecryptTime time.Duration // threshold decryption wall-clock
	PeakCPUPct  float64       // peak peer/orderer CPU % (docker stats)
	PeakMemMB   float64       // peak peer/orderer memory MB (docker stats)
}

// csvHeader is the fixed Appendix-C column order. Kept next to writeRow so they
// never drift.
var csvHeader = []string{
	"tier", "ballot_axis", "positions", "candidates",
	"send_rate_req", "submitted", "committed", "dropped",
	"throughput_tps", "latency_p50_ms", "latency_p95_ms", "latency_p99_ms",
	"endorse_p50_ms", "cds_verify_p50_ms", "order_p50_ms", "validate_p50_ms", "commit_p50_ms",
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
	return []string{
		fmt.Sprintf("%d", r.Tier), r.BallotAxis, fmt.Sprintf("%d", r.Positions), fmt.Sprintf("%d", r.Candidates),
		fmt.Sprintf("%.3f", r.SendRateReq), fmt.Sprintf("%d", r.Submitted), fmt.Sprintf("%d", r.Committed), fmt.Sprintf("%d", r.Dropped),
		fmt.Sprintf("%.3f", r.ThroughputTPS), ms(r.LatencyP50), ms(r.LatencyP95), ms(r.LatencyP99),
		ms(r.EndorseP50), ms(r.CDSVerifyP50), ms(r.OrderP50), ms(r.ValidateP50), ms(r.CommitP50),
		ms(r.DecryptTime), fmt.Sprintf("%.2f", r.PeakCPUPct), fmt.Sprintf("%.2f", r.PeakMemMB),
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
