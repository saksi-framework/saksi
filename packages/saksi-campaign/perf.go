package campaign

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk/bench"
)

// The run's performance record.
//
// perf.csv is one row per run, written by Verify. Every column names its own
// provenance (`_inproc_ms` = measured inside the auditor process, `gen_` = the
// generator's own sidecar, peaks = docker stats), and a column with no
// producer for this run is EMPTY — never a fabricated 0. An offline run has no
// submission window, so its submit/peak/ledger columns are blank rather than
// zeroed, which would read as "measured, and it was nothing".
//
// The submission numbers are measured during the ballot stage but reported by
// Verify, a separate phase and a separate HTTP request, so they travel through
// the run folder in submit-metrics.json.

const (
	// PerfCSV is the per-run performance row.
	PerfCSV = "perf.csv"
	// PerfSchemaFile documents every perf.csv column and where it came from.
	PerfSchemaFile = "perf-schema.md"
	// LatenciesCSV is the per-ballot submit latency record.
	LatenciesCSV = "latencies.csv"
	// TimingsFile holds the auditor's per-stage in-process timings.
	TimingsFile = "timings.json"
	// GenTimingsFile is the generator's own CPU/wall sidecar (written by
	// `saksi-demo gen --stream`).
	GenTimingsFile = "gen-timings.json"
	// submitMetricsFile carries the ballot window's measurements from the
	// submission phase to Verify.
	submitMetricsFile = "submit-metrics.json"
)

// TimingsMs mirrors the `timings_ms` object of `saksi-demo audit-stream --json`
// (saksi-auditor/src/demo.rs TimingsMs) — milliseconds spent in each measured
// audit stage, in-process, with no I/O in between.
//
// VerifyBallots is the WALL time of the parallel ballot-verification phase on
// VerifyThreads threads, not CPU summed across them. VerifyThreads is 0 when
// the auditor did not report it (an older binary, or no ballot phase ran), and
// is then omitted from timings.json rather than written as a measured zero.
type TimingsMs struct {
	VerifyBallots uint64 `json:"verify_ballots"`
	Aggregate     uint64 `json:"aggregate"`
	Combine       uint64 `json:"combine"`
	Decode        uint64 `json:"decode"`
	VerifyThreads uint64 `json:"verify_threads,omitempty"`
}

// genTimings mirrors gen-timings.json (saksi-auditor/src/stream.rs GenTimings).
// The `_cpu_ms` fields are CPU sums across worker threads, so on a parallel run
// they legitimately exceed wall_ms.
type genTimings struct {
	CredentialCPUMs uint64 `json:"credential_cpu_ms"`
	EncryptCPUMs    uint64 `json:"encrypt_cpu_ms"`
	CDSProveCPUMs   uint64 `json:"cds_prove_cpu_ms"`
	WallMs          uint64 `json:"wall_ms"`
	Chunks          int    `json:"chunks"`
	ChunkVoters     int    `json:"chunk_voters"`
}

// submitMetrics is everything the timed ballot window measured.
type submitMetrics struct {
	WindowMs         int64   `json:"window_ms"`
	Submitted        int     `json:"submitted"`
	Committed        int     `json:"committed"`
	Dropped          int     `json:"dropped"`
	Expected         int     `json:"expected"`
	CommittedTPS     float64 `json:"committed_tps"`
	DriverCeilingTPS float64 `json:"driver_ceiling_tps"`
	Concurrency      int     `json:"concurrency"`
	SendRate         float64 `json:"send_rate"`
	// Stopped reports that the window closed before every ballot was
	// dispatched — either ctx was cancelled (interrupted) or the window's own
	// time bound elapsed (see Bounded).
	Stopped bool `json:"stopped"`
	// Bounded distinguishes the second of those: the window stopped because
	// MaxDuration elapsed, with the context still live and nothing dropped.
	// That is a window that ended as instructed, not a failed run.
	Bounded bool `json:"bounded"`

	LatencyMinMs    float64 `json:"latency_min_ms"`
	LatencyP50Ms    float64 `json:"latency_p50_ms"`
	LatencyMeanMs   float64 `json:"latency_mean_ms"`
	LatencyP95Ms    float64 `json:"latency_p95_ms"`
	LatencyP99Ms    float64 `json:"latency_p99_ms"`
	LatencyStdDevMs float64 `json:"latency_stddev_ms"`

	// PeakCPUPct / PeakMemMB are keyed by role ("peer", "orderer", "client").
	// A role absent from the map was never sampled and stays an empty cell.
	PeakCPUPct map[string]float64 `json:"peak_cpu_pct"`
	PeakMemMB  map[string]float64 `json:"peak_mem_mb"`
	// LedgerBytesDelta is nil unless a peer volume path was configured.
	LedgerBytesDelta *int64 `json:"ledger_bytes_delta"`

	// JournalError is set when the run journal failed DURING this window. The
	// journal cannot carry its own failure — a failed journal refuses every
	// later write, run.end included — and Verify finalises the run from a
	// fresh journal, so this file is where the reason has to survive. Empty
	// for every healthy run; see journalWindowErr.
	JournalError string `json:"journal_error,omitempty"`
}

// perfColumns is the exact perf.csv column order.
var perfColumns = []string{
	"run_id", "mode", "voters", "positions", "candidates", "profile",
	"gen_wall_ms", "gen_cpu_ms", "proof_gen_cpu_ms",
	"proof_verify_inproc_ms", "aggregate_inproc_ms", "combine_inproc_ms", "decrypt_inproc_ms",
	"submit_window_ms", "committed", "dropped", "committed_tps", "driver_ceiling_tps",
	"latency_min_ms", "latency_p50_ms", "latency_mean_ms", "latency_p95_ms", "latency_p99_ms", "latency_stddev_ms",
	"peak_cpu_pct_peer", "peak_cpu_pct_orderer", "peak_cpu_pct_client",
	"peak_mem_mb_peer", "peak_mem_mb_orderer", "peak_mem_mb_client",
	"ledger_bytes_delta", "sustained", "scaling_limit", "failed", "fail_reason",
	"verify_threads",
}

// millis renders a duration measured in milliseconds; ms3 renders a float with
// 3 decimals. Both return "" when the producer did not run.
func ms3(have bool, v float64) string {
	if !have {
		return ""
	}
	return strconv.FormatFloat(v, 'f', 3, 64)
}

func uintCell(have bool, v uint64) string {
	if !have {
		return ""
	}
	return strconv.FormatUint(v, 10)
}

func intCell(have bool, v int) string {
	if !have {
		return ""
	}
	return strconv.Itoa(v)
}

func roleCell(m map[string]float64, role string) string {
	v, ok := m[role]
	return ms3(ok, v)
}

// perfRow assembles one run's row from the four producers that exist in the
// run folder. Anything missing stays empty.
func perfRow(dir, runID string, c ElectionConfig, fin FinaliseResult) []string {
	var gt genTimings
	haveGen := readJSON(filepath.Join(dir, GenTimingsFile), &gt) == nil
	var tm TimingsMs
	haveTimings := readJSON(filepath.Join(dir, TimingsFile), &tm) == nil
	var sm submitMetrics
	haveSubmit := readJSON(filepath.Join(dir, submitMetricsFile), &sm) == nil

	ledgerDelta := ""
	if haveSubmit && sm.LedgerBytesDelta != nil {
		ledgerDelta = strconv.FormatInt(*sm.LedgerBytesDelta, 10)
	}

	return []string{
		runID, c.Mode,
		strconv.Itoa(c.Voters), strconv.Itoa(c.Positions), strconv.Itoa(c.Candidates), c.Distribution,
		uintCell(haveGen, gt.WallMs),
		uintCell(haveGen, gt.CredentialCPUMs+gt.EncryptCPUMs+gt.CDSProveCPUMs),
		uintCell(haveGen, gt.CDSProveCPUMs),
		uintCell(haveTimings, tm.VerifyBallots),
		uintCell(haveTimings, tm.Aggregate),
		uintCell(haveTimings, tm.Combine),
		uintCell(haveTimings, tm.Decode),
		intCell(haveSubmit, int(sm.WindowMs)),
		intCell(haveSubmit, sm.Committed),
		intCell(haveSubmit, sm.Dropped),
		ms3(haveSubmit, sm.CommittedTPS),
		ms3(haveSubmit, sm.DriverCeilingTPS),
		ms3(haveSubmit, sm.LatencyMinMs),
		ms3(haveSubmit, sm.LatencyP50Ms),
		ms3(haveSubmit, sm.LatencyMeanMs),
		ms3(haveSubmit, sm.LatencyP95Ms),
		ms3(haveSubmit, sm.LatencyP99Ms),
		ms3(haveSubmit, sm.LatencyStdDevMs),
		roleCell(sm.PeakCPUPct, "peer"), roleCell(sm.PeakCPUPct, "orderer"), roleCell(sm.PeakCPUPct, "client"),
		roleCell(sm.PeakMemMB, "peer"), roleCell(sm.PeakMemMB, "orderer"), roleCell(sm.PeakMemMB, "client"),
		ledgerDelta,
		strconv.FormatBool(fin.Sustained), fin.ScalingLimit,
		strconv.FormatBool(fin.Failed), fin.Reason,
		uintCell(haveTimings && tm.VerifyThreads > 0, tm.VerifyThreads),
	}
}

// writePerfRow writes the run's row to perf.csv (header once, no comment
// lines) and drops perf-schema.md beside it.
//
// One row per run_id, latest Verify wins: re-auditing a run REPLACES its row
// rather than appending a second one, so a re-verified run is never counted
// twice by anything that concatenates these files. The rewrite goes to a temp
// file and renames, so an interrupted write cannot leave a half-written CSV
// where a complete one used to be.
func writePerfRow(dir, runID string, c ElectionConfig, fin FinaliseResult) error {
	if err := writePerfSchema(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, PerfCSV)
	kept, err := perfRowsExcept(path, runID)
	if err != nil {
		return err
	}
	kept = append(kept, perfRow(dir, runID, c, fin))

	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("open %s: %w", PerfCSV, err)
	}
	w := bufio.NewWriter(f)
	_, err = fmt.Fprintln(w, strings.Join(perfColumns, ","))
	for _, row := range kept {
		if err != nil {
			break
		}
		_, err = fmt.Fprintln(w, strings.Join(csvEscape(row), ","))
	}
	if err == nil {
		err = w.Flush()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %w", PerfCSV, err)
	}
	return os.Rename(tmp, path)
}

// perfRowsExcept reads perf.csv's data rows, dropping the header and any row
// belonging to runID. A missing file is simply no rows; an unreadable one is an
// error rather than a silent overwrite of results somebody may still want.
func perfRowsExcept(path, runID string) ([][]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", PerfCSV, err)
	}
	var kept [][]string
	for i, row := range rows {
		if i == 0 && len(row) > 0 && row[0] == perfColumns[0] {
			continue // header
		}
		if len(row) > 0 && row[0] == runID {
			continue // superseded by this run's new row
		}
		kept = append(kept, row)
	}
	return kept, nil
}

// csvEscape quotes any cell containing a comma or quote — fail_reason is free
// text and can carry either.
func csvEscape(row []string) []string {
	out := make([]string, len(row))
	for i, cell := range row {
		if strings.ContainsAny(cell, `,"`+"\n") {
			cell = `"` + strings.ReplaceAll(cell, `"`, `""`) + `"`
		}
		out[i] = cell
	}
	return out
}

// writeLatenciesCSV records every dispatched index's submit latency. segment is
// 0 for a single-window run (multi-segment ramps set it from the segment
// index); ok is "commit" or "drop" ("replay" is written by the replay driver).
func writeLatenciesCSV(dir string, res bench.RunResult, segment int) error {
	f, err := os.Create(filepath.Join(dir, LatenciesCSV))
	if err != nil {
		return fmt.Errorf("create %s: %w", LatenciesCSV, err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	if _, err := w.WriteString("index,segment,ms,ok\n"); err != nil {
		return err
	}
	for i := 0; i <= res.LastIndex && i < len(res.ByIndex); i++ {
		status := "drop"
		if res.OK[i] {
			status = "commit"
		}
		if _, err := fmt.Fprintf(w, "%d,%d,%.3f,%s\n",
			i, segment, float64(res.ByIndex[i].Microseconds())/1000.0, status); err != nil {
			return err
		}
	}
	return w.Flush()
}

// appendLatenciesCSV appends one resumed segment's rows to latencies.csv,
// keeping the rows segment 0 already wrote. index maps the compact slot k
// bench.Run dispatched back to the ballot index it carried; replay reports
// whether slot k's rejection was the chain telling us the ballot was already
// committed (ok=replay) rather than a drop.
func appendLatenciesCSV(dir string, res bench.RunResult, segment int, index func(k int) int, replay func(k int) bool) error {
	f, err := os.OpenFile(filepath.Join(dir, LatenciesCSV), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", LatenciesCSV, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", LatenciesCSV, err)
	}
	w := bufio.NewWriter(f)
	if info.Size() == 0 {
		if _, err := w.WriteString("index,segment,ms,ok\n"); err != nil {
			return err
		}
	}
	for k := 0; k <= res.LastIndex && k < len(res.ByIndex); k++ {
		status := "drop"
		switch {
		case res.OK[k]:
			status = "commit"
		case replay(k):
			status = "replay"
		}
		if _, err := fmt.Fprintf(w, "%d,%d,%.3f,%s\n",
			index(k), segment, float64(res.ByIndex[k].Microseconds())/1000.0, status); err != nil {
			return err
		}
	}
	return w.Flush()
}

// perfSchema documents every perf.csv column and its producer. Written once per
// run folder so a downloaded CSV carries its own definitions — perf.csv itself
// stays comment-free so it loads straight into a spreadsheet.
const perfSchema = `# perf.csv — column reference

One row per run, appended by the Verify phase. **An empty cell means the column
has no producer for this run** (e.g. an offline run never opens a submission
window) — it is never a measured zero.

| Column | Units | Produced by |
| --- | --- | --- |
| ` + "`run_id`" + ` | — | the run folder's id |
| ` + "`mode`" + ` | offline\|onchain\|groundtruth | run config |
| ` + "`voters`, `positions`, `candidates`" + ` | count | run config |
| ` + "`profile`" + ` | uniform\|skewed\|realistic | run config (` + "`distribution`" + `) |
| ` + "`gen_wall_ms`" + ` | ms | ` + "`gen-timings.json` `wall_ms`" + ` — generator wall time |
| ` + "`gen_cpu_ms`" + ` | ms | ` + "`gen-timings.json`" + `: credential + encrypt + CDS-prove CPU, summed across worker threads (may exceed wall) |
| ` + "`proof_gen_cpu_ms`" + ` | ms | ` + "`gen-timings.json` `cds_prove_cpu_ms`" + ` |
| ` + "`proof_verify_inproc_ms`" + ` | ms | ` + "`timings.json` `verify_ballots`" + ` — in-auditor-process CDS + credential verification of every ballot. **Wall-clock** time of the parallel verify phase on ` + "`verify_threads`" + ` threads, not CPU time summed across them; compare runs only at the same thread count |
| ` + "`aggregate_inproc_ms`" + ` | ms | ` + "`timings.json` `aggregate`" + ` |
| ` + "`combine_inproc_ms`" + ` | ms | ` + "`timings.json` `combine`" + ` — Lagrange recombination |
| ` + "`decrypt_inproc_ms`" + ` | ms | ` + "`timings.json` `decode`" + ` — discrete-log tally recovery |
| ` + "`submit_window_ms`" + ` | ms | wall clock of the timed ballot window (submit→commit only; no receipt fetch, no file write inside it) |
| ` + "`committed`, `dropped`" + ` | count | ballot window outcome |
| ` + "`committed_tps`" + ` | tx/s | committed ÷ window |
| ` + "`driver_ceiling_tps`" + ` | tx/s | concurrency ÷ median submit latency — the harness's own ceiling. A ` + "`committed_tps`" + ` near it means the driver, not the network, was the limit |
| ` + "`latency_*_ms`" + ` | ms | per-ballot submit→commit latency stats (nearest-rank percentiles, population stddev) |
| ` + "`peak_cpu_pct_{peer,orderer,client}`" + ` | % | ` + "`docker stats`" + ` sampler peak (` + "`client`" + ` is this console's own process) |
| ` + "`peak_mem_mb_{peer,orderer,client}`" + ` | MB | same sampler |
| ` + "`ledger_bytes_delta`" + ` | bytes | on-disk ledger growth over the ballot window; empty unless a peer volume path is configured |
| ` + "`sustained`" + ` | bool | the run was one uninterrupted window |
| ` + "`scaling_limit`" + ` | true\|false\|inconclusive | sustained TPS vs. the arrival rate the tier demands; ` + "`inconclusive`" + ` when the driver was the ceiling |
| ` + "`failed`, `fail_reason`" + ` | bool, text | the run-failed predicate: stage error, any drop, reconcile mismatch, nonzero E, or interruption |
| ` + "`verify_threads`" + ` | count | ` + "`timings.json` `verify_threads`" + ` — threads the auditor verified ballots on (all cores by default; ` + "`SAKSI_AUDIT_THREADS`" + ` pins it). Empty when the auditor did not report it |

A window that closed because it reached its own configured time bound
(` + "`window_s`" + `, as a rate sweep's steps do) is **not** an interruption and not a
failure: it ended as instructed, and it still owes that every ballot it
dispatched committed. Such a run is stamped ` + "`bounded`" + ` in ` + "`journal.ndjson`" + `'s
` + "`run.end`" + `. It is not a sustained measurement either — ` + "`sustained`" + ` is false and
` + "`scaling_limit`" + ` inconclusive — because it covers a slice of the population,
not all of it.

Per-ballot latencies are in ` + "`latencies.csv`" + ` (` + "`index,segment,ms,ok`" + `);
the full event log with the environment snapshot is ` + "`journal.ndjson`" + `.

A run that was RESUMED after an interrupted ballot window has more than one
window. Its ` + "`committed`, `dropped`, `failed`" + ` cells cover the whole run, but the
window and latency cells (` + "`submit_window_ms`, `committed_tps`, `driver_ceiling_tps`, `latency_*_ms`" + `)
describe only the FIRST window — they measure one window, and a resumed run is
not a sustained measurement (` + "`sustained`" + ` is false, ` + "`scaling_limit`" + ` inconclusive).
The per-window figures are the ` + "`segment.end`" + ` events in ` + "`journal.ndjson`" + `,
and each window's rows carry its segment number in ` + "`latencies.csv`" + `.
`

func writePerfSchema(dir string) error {
	path := filepath.Join(dir, PerfSchemaFile)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return os.WriteFile(path, []byte(perfSchema), 0o644)
}
