package campaign

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The repeated-measures driver.
//
// A single run is one observation, and one observation is not a measurement:
// the paper reports medians and dispersion over repetitions, which means the
// console has to be able to run the same election many times and summarise the
// spread. This file is that driver.
//
// It drives a RUNNING console over its HTTP API and never reaches into a run
// folder or calls the executor directly. That is deliberate: the numbers a
// campaign reports must come from the same path an operator's clicks take, so
// nothing can be measured through a shortcut the real console does not have.
//
// Every repetition is its own run folder, tagged in the journal with
// rep {index, kind}, so a campaign is auditable one run at a time.
//
// summary.csv covers MEASURED repetitions only. Warm-ups are discarded (they
// pay for page cache, JIT-warm connections and a cold ledger), and failed runs
// are excluded from every statistic — a run that dropped ballots did not
// measure throughput, it measured a failure, and averaging the two produces a
// number that describes neither.

// SummaryCSV is the campaign-level summary the --repeat driver writes.
const SummaryCSV = "summary.csv"

// summaryColumns is summary.csv's column order. Every row is a one-metric
// sample: the scalar rows (runs_measured, runs_failed, failure_rate,
// plateau_tps) are single-observation samples, so min == median == mean ==
// p95 == p99 == the value, stddev == 0 and n == 1. That keeps one shape for
// the whole file instead of a special case a reader has to know about.
var summaryColumns = []string{"metric", "min", "median", "mean", "p95", "p99", "stddev", "n", "failed_reasons"}

// defaultSweepRate is the first sweep step's offered rate when the config does
// not set one (SendRate 0 means "as fast as the workers drain", which is not a
// rate a sweep can multiply).
const defaultSweepRate = 10.0

// sweepHeadroom is the extra in-flight capacity every sweep step gets on top of
// the Little's-law estimate (rate x p99), so a step is never starved of workers
// by a latency estimate that was a little optimistic.
const sweepHeadroom = 4

// maxSweepSteps bounds a sweep that never degrades.
//
// ponytail: a fixed cap, not an adaptive stop. Ten doublings is ~1000x the
// starting rate; if a real network ever climbs past that, raise it.
const maxSweepSteps = 12

// DefaultWindow is a sweep step's wall-clock window when --window is not given.
const DefaultWindow = 120 * time.Second

// RepeatOpts configures one repeated-measures campaign.
type RepeatOpts struct {
	// BaseURL is the running console, e.g. http://127.0.0.1:8090.
	BaseURL string
	// Config is the election every repetition runs.
	Config ElectionConfig
	// Warmups run first and are discarded; Reps are the measured repetitions.
	Warmups, Reps int
	// Sweep, when > 1, raises the offered rate by that factor per step until
	// throughput stops improving.
	Sweep float64
	// Window bounds each sweep step's ballot window (default DefaultWindow).
	Window time.Duration
	// Burst, when > 0, submits that many ballots with no rate cap as its own
	// tagged run after the measured repetitions.
	Burst int
	// Out is where summary.csv is written (default ./summary.csv).
	Out string
	// Log receives the progress lines (default os.Stdout).
	Log io.Writer
	// Poll is how often the driver checks whether a phase has finished.
	Poll time.Duration
}

// repResult is one repetition's outcome as the API reported it.
type repResult struct {
	RunID  string
	Rep    RepTag
	Perf   map[string]string // perf.csv column -> cell
	Failed bool
	Reason string
	// GatePass is the data-validation gate's verdict (/api/check). False also
	// when the gate could not be read at all — the ladder must not pass a tier
	// whose gate never answered.
	GatePass bool
}

// num reads a perf.csv cell as a float. An empty or unparseable cell reads as
// absent, never as zero.
func (r repResult) num(col string) (float64, bool) {
	v, err := strconv.ParseFloat(strings.TrimSpace(r.Perf[col]), 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// Repeat runs a campaign against the console at o.BaseURL and writes
// summary.csv. A repetition that fails is recorded, not fatal: a failure rate
// is one of the things the campaign exists to report.
func Repeat(ctx context.Context, o RepeatOpts) error {
	d, err := newRepeatDriver(o)
	if err != nil {
		return err
	}
	for i := 1; i <= o.Warmups; i++ {
		if _, err := d.once(ctx, o.Config, RepTag{Index: i, Kind: "warmup"}); err != nil {
			return err
		}
	}
	measured := make([]repResult, 0, o.Reps)
	for i := 1; i <= o.Reps; i++ {
		r, err := d.once(ctx, o.Config, RepTag{Index: i, Kind: "measured"})
		if err != nil {
			return err
		}
		measured = append(measured, r)
	}

	var plateau *float64
	if o.Sweep > 1 {
		tps, err := d.sweep(ctx, o.Config)
		if err != nil {
			return err
		}
		plateau = &tps
	}
	if o.Burst > 0 {
		burst := o.Config
		burst.Voters = o.Burst
		burst.SendRate = 0 // a burst is uncapped by definition
		burst.WindowS = 0
		if _, err := d.once(ctx, burst, RepTag{Index: 1, Kind: "burst"}); err != nil {
			return err
		}
	}
	return writeSummaryCSV(d.out, measured, plateau)
}

// repeatDriver is the HTTP client half of a campaign.
type repeatDriver struct {
	base   string
	http   *http.Client
	log    io.Writer
	poll   time.Duration
	window time.Duration
	factor float64 // --sweep k: the per-step rate multiplier
	out    string
}

func newRepeatDriver(o RepeatOpts) (*repeatDriver, error) {
	if strings.TrimSpace(o.BaseURL) == "" {
		return nil, fmt.Errorf("--base-url is required: --repeat drives a RUNNING console over its HTTP API")
	}
	d := &repeatDriver{
		base:   strings.TrimSuffix(o.BaseURL, "/"),
		http:   &http.Client{Timeout: 0}, // phases are polled, not waited on
		log:    o.Log,
		poll:   o.Poll,
		window: o.Window,
		factor: o.Sweep,
		out:    o.Out,
	}
	if d.log == nil {
		d.log = os.Stdout
	}
	if d.poll <= 0 {
		d.poll = 250 * time.Millisecond
	}
	if d.window <= 0 {
		d.window = DefaultWindow
	}
	if d.out == "" {
		d.out = SummaryCSV
	}
	return d, nil
}

func (d *repeatDriver) printf(format string, args ...any) {
	fmt.Fprintf(d.log, format+"\n", args...)
}

// once drives one repetition end to end: generate -> check -> submit ->
// ceremony -> verify, then reads back the run's perf.csv row and run.end.
//
// A phase that fails does not abort the campaign — the run's own run.end says
// it failed, which is exactly what the summary needs to count.
func (d *repeatDriver) once(ctx context.Context, c ElectionConfig, rep RepTag) (repResult, error) {
	c.Rep = &rep
	runID, err := d.create(ctx, c)
	if err != nil {
		return repResult{}, err
	}
	d.printf("rep %d (%s): run %s", rep.Index, rep.Kind, runID)

	// The check gate is read for its verdict but never aborts: a failed gate is
	// recorded by the run itself, and the ladder is what turns it into a stop.
	var gate CheckReport
	if err := d.getJSON(ctx, "/api/check/"+runID, &gate); err != nil {
		d.printf("  check unavailable: %v", err)
	} else if !gate.Pass {
		d.printf("  check gate FAILED")
	}

	if err := d.phase(ctx, runID, "/submit", map[string]string{"run_id": runID}); err != nil {
		d.printf("  submit: %v", err)
	}
	if err := d.ceremony(ctx, runID); err != nil {
		d.printf("  ceremony: %v", err)
	}
	if err := d.phase(ctx, runID, "/verify", map[string]string{"run_id": runID}); err != nil {
		d.printf("  verify: %v", err)
	}
	r, err := d.collect(ctx, runID, rep)
	r.GatePass = gate.Pass
	return r, err
}

// create posts the config and waits for the generate phase to finish.
func (d *repeatDriver) create(ctx context.Context, c ElectionConfig) (string, error) {
	var body struct {
		RunID string `json:"run_id"`
	}
	if err := d.postJSON(ctx, "/generate", c, &body); err != nil {
		return "", err
	}
	if body.RunID == "" {
		return "", fmt.Errorf("console accepted the run but returned no run_id")
	}
	return body.RunID, d.waitIdle(ctx, body.RunID)
}

// phase posts one phase and waits for it to finish.
func (d *repeatDriver) phase(ctx context.Context, runID, path string, body any) error {
	if err := d.postJSON(ctx, path, body, nil); err != nil {
		return err
	}
	return d.waitIdle(ctx, runID)
}

// ceremony runs the trustee ceremony: start, every trustee contributes, then
// publish. The roster comes from the console, so the trustee ids are the wire
// ids the bundle actually carries.
func (d *repeatDriver) ceremony(ctx context.Context, runID string) error {
	if err := d.phase(ctx, runID, "/ceremony/start", map[string]string{"run_id": runID}); err != nil {
		return err
	}
	var state CeremonyState
	if err := d.getJSON(ctx, "/api/ceremony/"+runID, &state); err != nil {
		return err
	}
	for _, t := range state.Trustees {
		if err := d.phase(ctx, runID, "/ceremony/submit",
			map[string]string{"run_id": runID, "trustee_id": t.ID}); err != nil {
			return err
		}
	}
	return d.phase(ctx, runID, "/ceremony/publish", map[string]string{"run_id": runID})
}

// collect reads back what the run recorded: its perf.csv row and its run.end
// verdict. A run with no perf.csv never reached Verify, which is itself a
// failure with a reason.
func (d *repeatDriver) collect(ctx context.Context, runID string, rep RepTag) (repResult, error) {
	r := repResult{RunID: runID, Rep: rep}

	perf, err := d.export(ctx, runID, PerfCSV)
	if err == nil {
		r.Perf, err = perfRowCells(perf, runID)
	}
	if err != nil {
		r.Failed, r.Reason = true, "no perf.csv: "+err.Error()
	}

	journal, jerr := d.export(ctx, runID, JournalFile)
	if jerr != nil {
		if r.Reason == "" {
			r.Failed, r.Reason = true, "no journal: "+jerr.Error()
		}
		return r, nil
	}
	end, ok := runEndEvent(journal)
	if !ok {
		if r.Reason == "" {
			r.Failed, r.Reason = true, "run never reached run.end"
		}
		return r, nil
	}
	// run.end is the authority on whether the run failed — perf.csv mirrors it,
	// but a run can end without ever writing one.
	if failed, _ := end["failed"].(bool); failed {
		r.Failed = true
		r.Reason = jstring(end, "reason")
		if r.Reason == "" {
			r.Reason = "failed"
		}
	}
	return r, nil
}

// sweep raises the offered rate by o.Sweep per step until committed throughput
// stops improving (or a step drops a ballot) and returns the plateau: the last
// step's throughput that was still an improvement.
//
// Each step is a fixed wall-clock window, so the steps are comparable: the same
// slice of time at a different offered rate. Concurrency per step is Little's
// law over the previous step's tail latency — enough workers in flight to
// actually offer the rate — plus a little headroom.
func (d *repeatDriver) sweep(ctx context.Context, c ElectionConfig) (float64, error) {
	rate := c.SendRate
	if rate <= 0 {
		rate = defaultSweepRate
	}
	concurrency := c.submitConcurrency()
	plateau := 0.0

	for step := 1; step <= maxSweepSteps; step++ {
		sc := c
		sc.SendRate = rate
		sc.Concurrency = concurrency
		sc.WindowS = d.window.Seconds()
		r, err := d.once(ctx, sc, RepTag{Index: step, Kind: "sweep"})
		if err != nil {
			return plateau, err
		}
		tps, haveTPS := r.num("committed_tps")
		dropped, _ := r.num("dropped")
		d.printf("  sweep step %d: offered %.3f/s, committed %.3f/s, dropped %.0f", step, rate, tps, dropped)

		if dropped > 0 {
			return plateau, nil // the network shed load: the previous step was the plateau
		}
		if !haveTPS {
			return plateau, nil // nothing measured: do not climb on a number we do not have
		}
		if step > 1 && tps < plateau {
			return plateau, nil
		}
		plateau = tps

		p99Ms, ok := r.num("latency_p99_ms")
		rate *= d.factor
		if ok {
			concurrency = int(math.Ceil(rate*(p99Ms/1000.0))) + sweepHeadroom
		}
		if concurrency < 1 {
			concurrency = 1
		}
	}
	return plateau, nil
}

// --- HTTP ------------------------------------------------------------------

// waitIdle blocks until the run has no phase running. The console claims its
// per-run lock BEFORE answering 202, so once a phase has been accepted this is
// exact rather than a guess about scheduling.
func (d *repeatDriver) waitIdle(ctx context.Context, runID string) error {
	for {
		var st struct {
			Busy bool `json:"busy"`
		}
		if err := d.getJSON(ctx, "/api/runs/"+runID+"/status", &st); err != nil {
			return err
		}
		if !st.Busy {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d.poll):
		}
	}
}

func (d *repeatDriver) postJSON(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return d.do(req, out)
}

func (d *repeatDriver) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+path, nil)
	if err != nil {
		return err
	}
	return d.do(req, out)
}

func (d *repeatDriver) do(req *http.Request, out any) error {
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s: %s", req.Method, req.URL.Path, resp.Status, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

// export downloads one of a run's artifacts.
func (d *repeatDriver) export(ctx context.Context, runID, artifact string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		d.base+"/export/"+runID+"/"+artifact, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: %s", artifact, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// --- parsing ---------------------------------------------------------------

// perfRowCells reads a downloaded perf.csv and returns the named run's row as
// column -> cell.
func perfRowCells(data []byte, runID string) (map[string]string, error) {
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", PerfCSV, err)
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("%s has no data row", PerfCSV)
	}
	head := rows[0]
	for _, row := range rows[1:] {
		if len(row) == 0 || row[0] != runID {
			continue
		}
		cells := make(map[string]string, len(head))
		for i, h := range head {
			if i < len(row) {
				cells[h] = row[i]
			}
		}
		return cells, nil
	}
	return nil, fmt.Errorf("%s has no row for run %s", PerfCSV, runID)
}

// runEndEvent finds the run.end event in a downloaded journal.ndjson.
func runEndEvent(data []byte) (map[string]any, bool) {
	var found map[string]any
	ok := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev map[string]any
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue // a torn last line is exactly what the journal tolerates
		}
		if jstring(ev, "event") == "run.end" {
			found, ok = ev, true
		}
	}
	return found, ok
}

// --- summary ---------------------------------------------------------------

// writeSummaryCSV summarises the measured repetitions. Failed runs contribute
// to runs_failed and failed_reasons and to nothing else.
func writeSummaryCSV(path string, measured []repResult, plateau *float64) error {
	var good []repResult
	var reasons []string
	for _, r := range measured {
		if r.Failed {
			if r.Reason != "" {
				reasons = append(reasons, r.Reason)
			}
			continue
		}
		good = append(good, r)
	}
	failed := len(measured) - len(good)

	rows := [][]string{}
	for _, col := range numericPerfColumns(good) {
		var xs []float64
		for _, r := range good {
			if v, ok := r.num(col); ok {
				xs = append(xs, v)
			}
		}
		rows = append(rows, summaryRow(col, xs, ""))
	}
	rate := 0.0
	if len(measured) > 0 {
		rate = float64(failed) / float64(len(measured))
	}
	rows = append(rows,
		scalarRow("runs_measured", float64(len(measured)), ""),
		scalarRow("runs_failed", float64(failed), strings.Join(reasons, "; ")),
		scalarRow("failure_rate", rate, ""))
	if plateau != nil {
		rows = append(rows, scalarRow("plateau_tps", *plateau, ""))
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	var b strings.Builder
	fmt.Fprintln(&b, strings.Join(summaryColumns, ","))
	for _, row := range rows {
		fmt.Fprintln(&b, strings.Join(csvEscape(row), ","))
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// numericPerfColumns is the set of perf.csv columns that carry numbers in this
// campaign's rows, in perf.csv's own order. A column is numeric when every
// non-empty cell parses as a float and at least one does — so `mode` and
// `scaling_limit` are excluded by their content rather than by a hardcoded
// list that would drift as perf.csv grows.
func numericPerfColumns(rs []repResult) []string {
	var out []string
	for _, col := range perfColumns {
		if col == "run_id" {
			continue
		}
		seen, numeric := false, true
		for _, r := range rs {
			cell := strings.TrimSpace(r.Perf[col])
			if cell == "" {
				continue
			}
			if _, err := strconv.ParseFloat(cell, 64); err != nil {
				numeric = false
				break
			}
			seen = true
		}
		if seen && numeric {
			out = append(out, col)
		}
	}
	return out
}

// scalarRow is a one-observation sample: the same value at every percentile,
// no dispersion.
func scalarRow(name string, v float64, reasons string) []string {
	return summaryRow(name, []float64{v}, reasons)
}

// summaryRow reduces a sample to summary.csv's row. Percentiles use the same
// nearest-rank rule as bench.Summary (rank = ceil(p*n/100), clamped to 1..n)
// and the standard deviation is the population one, so a latency column
// summarised here and one summarised inside a run are the same statistic.
func summaryRow(name string, xs []float64, reasons string) []string {
	if len(xs) == 0 {
		return []string{name, "", "", "", "", "", "", "0", reasons}
	}
	sorted := append([]float64(nil), xs...)
	sort.Float64s(sorted)
	n := len(sorted)

	sum := 0.0
	for _, x := range sorted {
		sum += x
	}
	mean := sum / float64(n)
	sq := 0.0
	for _, x := range sorted {
		sq += (x - mean) * (x - mean)
	}
	return []string{
		name,
		num(sorted[0]),
		num(pctl(sorted, 50)),
		num(mean),
		num(pctl(sorted, 95)),
		num(pctl(sorted, 99)),
		num(math.Sqrt(sq / float64(n))),
		strconv.Itoa(n),
		reasons,
	}
}

// pctl is bench.Summary's nearest-rank percentile over float64s.
func pctl(sorted []float64, p int) float64 {
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

// num renders a statistic at millisecond/TPS precision without trailing noise:
// 3 decimals, trailing zeros trimmed, so a count reads as "3" and a rate as
// "0.333".
func num(v float64) string {
	s := strconv.FormatFloat(v, 'f', 3, 64)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(s, "0")
		s = strings.TrimSuffix(s, ".")
	}
	return s
}

// --- the validation ladder ---------------------------------------------------

// LadderTiers is the validation ladder: the same election at four sizes, each
// small enough to be checked exactly. A build that gets all four right is a
// build whose large tiers are worth the hours they cost.
var LadderTiers = []int{1, 10, 100, 1000}

// LadderOpts configures a ladder run.
type LadderOpts struct {
	// BaseURL is the running console.
	BaseURL string
	// DataDir is where ladder.json is written — the console's run-store root,
	// which is where its own gate reads it from.
	DataDir string
	Log     io.Writer
	Poll    time.Duration
}

// LadderConfig is one ladder tier's election: three positions, four candidates,
// realistic distribution, offline.
func LadderConfig(voters int) ElectionConfig {
	return ElectionConfig{
		Name:         "validation ladder",
		Trustees:     []Trustee{{Name: "Trustee 1"}, {Name: "Trustee 2"}, {Name: "Trustee 3"}},
		Threshold:    2,
		Positions:    3,
		Candidates:   4,
		Voters:       voters,
		Distribution: "realistic",
		Mode:         "offline",
		Concurrency:  DefaultConcurrency,
	}
}

// RunLadder runs every tier through the console's own API and, only if all of
// them pass, records that this build passed the ladder.
//
// "Pass" means two things at once: the data-validation gate accepted the
// generated population, and the run did not fail — which, via the run-failed
// predicate, is where E != 0 on any contest shows up. A single failing tier
// leaves no ladder.json, so the large-tier gate stays shut.
func RunLadder(ctx context.Context, o LadderOpts) error {
	d, err := newRepeatDriver(RepeatOpts{BaseURL: o.BaseURL, Log: o.Log, Poll: o.Poll})
	if err != nil {
		return err
	}
	if strings.TrimSpace(o.DataDir) == "" {
		return fmt.Errorf("--runs is required: ladder.json must be written where the console reads it")
	}
	runs := make([]string, 0, len(LadderTiers))
	for i, voters := range LadderTiers {
		r, err := d.once(ctx, LadderConfig(voters), RepTag{Index: i + 1, Kind: "ladder"})
		if err != nil {
			return fmt.Errorf("ladder tier %d voters: %w", voters, err)
		}
		if !r.GatePass {
			return fmt.Errorf("ladder tier %d voters: the data-validation gate did not pass (run %s)", voters, r.RunID)
		}
		if r.Failed {
			return fmt.Errorf("ladder tier %d voters FAILED: %s (run %s)", voters, r.Reason, r.RunID)
		}
		d.printf("  ladder tier %d voters: PASS (%s)", voters, r.RunID)
		runs = append(runs, r.RunID)
	}

	head, ok := consoleGitHead()
	if !ok {
		return fmt.Errorf("the ladder passed but this build's commit could not be resolved, " +
			"so the result cannot be pinned to it; run from a git checkout")
	}
	path := filepath.Join(o.DataDir, LadderFile)
	if err := writeJSON(path, ladderRecord{Commit: head, RanAt: time.Now().UTC(), Runs: runs}); err != nil {
		return err
	}
	d.printf("ladder PASSED on %s — recorded in %s", head, path)
	return nil
}

// consoleGitHead is the running binary's own commit.
func consoleGitHead() (string, bool) {
	p, err := os.Executable()
	if err != nil {
		return "", false
	}
	return gitHeadFor(p)
}
