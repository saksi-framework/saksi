package bench

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func TestPercentilesMonotonicAndCorrect(t *testing.T) {
	// 1..100 ms.
	var durs []time.Duration
	for i := 1; i <= 100; i++ {
		durs = append(durs, ms(i))
	}
	p50, p95, p99 := Percentiles(durs)
	if !(p50 <= p95 && p95 <= p99) {
		t.Fatalf("percentiles not monotonic: p50=%v p95=%v p99=%v", p50, p95, p99)
	}
	// Nearest-rank: p50 -> rank 50 -> 50ms, p95 -> 95ms, p99 -> 99ms.
	if p50 != ms(50) || p95 != ms(95) || p99 != ms(99) {
		t.Fatalf("got p50=%v p95=%v p99=%v, want 50/95/99ms", p50, p95, p99)
	}
}

func TestPercentilesEmptyIsZero(t *testing.T) {
	p50, p95, p99 := Percentiles(nil)
	if p50 != 0 || p95 != 0 || p99 != 0 {
		t.Fatalf("empty input must give zeros, got %v/%v/%v", p50, p95, p99)
	}
}

func TestPercentilesDoesNotMutateInput(t *testing.T) {
	durs := []time.Duration{ms(3), ms(1), ms(2)}
	_, _, _ = Percentiles(durs)
	if durs[0] != ms(3) || durs[1] != ms(1) || durs[2] != ms(2) {
		t.Fatalf("Percentiles mutated its input: %v", durs)
	}
}

func TestPhaseTimingsSumToTotal(t *testing.T) {
	p := PhaseTimings{
		Endorse:   ms(10), // includes CDSVerify
		CDSVerify: ms(4),
		Order:     ms(5),
		Validate:  ms(3),
		Commit:    ms(2),
	}
	// Total is endorse+order+validate+commit (CDSVerify is inside endorse).
	if got, want := p.Total(), ms(20); got != want {
		t.Fatalf("Total() = %v, want %v", got, want)
	}
	if p.CDSVerify >= p.Endorse {
		t.Fatalf("CDS verify (%v) must be a sub-cost of endorse (%v)", p.CDSVerify, p.Endorse)
	}
}

func TestThroughput(t *testing.T) {
	if got := ThroughputTPS(1000, 2*time.Second); got != 500 {
		t.Fatalf("throughput = %v, want 500", got)
	}
	if got := ThroughputTPS(10, 0); got != 0 {
		t.Fatalf("zero window must give 0 tps, got %v", got)
	}
}

// TestSummaryKnownVector pins the exact numbers from the task brief: 1..10ms
// gives min 1, median 5 (nearest-rank rule: rank=ceil(0.5*10)=5, index 4, the
// 5th-smallest value — not an average-of-middle-two 5.5), mean 5.5, p95 10,
// p99 10, population stddev ~2.872.
func TestSummaryKnownVector(t *testing.T) {
	var durs []time.Duration
	for i := 1; i <= 10; i++ {
		durs = append(durs, ms(i))
	}
	s := Summary(durs)
	if s.N != 10 {
		t.Fatalf("N = %d, want 10", s.N)
	}
	if s.Min != ms(1) {
		t.Fatalf("Min = %v, want 1ms", s.Min)
	}
	if s.Median != ms(5) {
		t.Fatalf("Median = %v, want 5ms", s.Median)
	}
	if s.Mean != time.Duration(5.5*float64(time.Millisecond)) {
		t.Fatalf("Mean = %v, want 5.5ms", s.Mean)
	}
	if s.P95 != ms(10) {
		t.Fatalf("P95 = %v, want 10ms", s.P95)
	}
	if s.P99 != ms(10) {
		t.Fatalf("P99 = %v, want 10ms", s.P99)
	}
	wantStdDevMs := 2.8722813232690143
	wantStdDev := time.Duration(wantStdDevMs * float64(time.Millisecond))
	if diff := s.StdDev - wantStdDev; diff > time.Microsecond || diff < -time.Microsecond {
		t.Fatalf("StdDev = %v, want ~%v", s.StdDev, wantStdDev)
	}
}

func TestSummaryEmptyIsZeroValue(t *testing.T) {
	s := Summary(nil)
	if s != (Stats{}) {
		t.Fatalf("empty input must give a zero-value Stats, got %+v", s)
	}
	if s.N != 0 {
		t.Fatalf("N = %d, want 0", s.N)
	}
}

func TestSummaryN1(t *testing.T) {
	s := Summary([]time.Duration{ms(7)})
	if s.N != 1 {
		t.Fatalf("N = %d, want 1", s.N)
	}
	for name, got := range map[string]time.Duration{
		"Min": s.Min, "Median": s.Median, "Mean": s.Mean, "P95": s.P95, "P99": s.P99,
	} {
		if got != ms(7) {
			t.Fatalf("%s = %v, want 7ms", name, got)
		}
	}
	if s.StdDev != 0 {
		t.Fatalf("StdDev = %v, want 0 for a single sample", s.StdDev)
	}
}

func TestSummaryN2(t *testing.T) {
	s := Summary([]time.Duration{ms(10), ms(20)})
	if s.N != 2 {
		t.Fatalf("N = %d, want 2", s.N)
	}
	if s.Min != ms(10) {
		t.Fatalf("Min = %v, want 10ms", s.Min)
	}
	if s.Mean != ms(15) {
		t.Fatalf("Mean = %v, want 15ms", s.Mean)
	}
	if s.StdDev != ms(5) {
		t.Fatalf("StdDev = %v, want 5ms (population stddev of {10,20})", s.StdDev)
	}
}

func TestSummaryAllEqualStdDevZero(t *testing.T) {
	durs := []time.Duration{ms(5), ms(5), ms(5), ms(5)}
	s := Summary(durs)
	if s.StdDev != 0 {
		t.Fatalf("StdDev = %v, want 0 for all-equal input", s.StdDev)
	}
	if s.Min != ms(5) || s.Median != ms(5) || s.Mean != ms(5) || s.P95 != ms(5) || s.P99 != ms(5) {
		t.Fatalf("all-equal stats should all read 5ms, got %+v", s)
	}
}

func TestWriteCSVHasAllColumnsPopulated(t *testing.T) {
	decrypt := ms(1500)
	cpu := 190.5
	mem := 512.25
	rows := []Row{
		{
			Tier: 1000, BallotAxis: "single", Positions: 1, Candidates: 2,
			SendRateReq: 200, Submitted: 1000, Committed: 1000, Dropped: 0,
			ThroughputTPS: 480.5,
			LatencyMin:    ms(5), LatencyP50: ms(40), LatencyMean: ms(42), LatencyP95: ms(80), LatencyP99: ms(120), LatencyStdDev: ms(15),
			DecryptTime: &decrypt, PeakCPUPct: &cpu, PeakMemMB: &mem,
		},
		// Galal baseline: nothing committed, no producers for the optional columns.
		{Tier: 1000, BallotAxis: "galal-baseline", Positions: 1, Candidates: 2, Committed: 1000, ThroughputTPS: 600},
	}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, rows); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected header + 2 rows, got %d lines:\n%s", len(lines), buf.String())
	}
	// Header column count must match every data row's field count (no missing cols).
	header := strings.Split(lines[0], ",")
	if len(header) != len(csvHeader) {
		t.Fatalf("header has %d cols, want %d", len(header), len(csvHeader))
	}
	for i, line := range lines[1:] {
		if got := len(strings.Split(line, ",")); got != len(csvHeader) {
			t.Fatalf("row %d has %d fields, want %d: %q", i, got, len(csvHeader), line)
		}
	}
	// Spot-check a couple of formatted values in the first data row.
	if !strings.Contains(lines[1], "1000,single,1,2") {
		t.Fatalf("row 1 missing expected leading fields: %q", lines[1])
	}
	if !strings.Contains(lines[1], "40.000") { // latency_p50_ms
		t.Fatalf("row 1 missing latency_p50_ms=40.000: %q", lines[1])
	}
}

// TestRowWithoutProducersEmitsEmptyCells is the regression guard for the
// original audit finding: a Row from ToRow with nothing to measure must never
// print a fabricated 0 for a column nothing produced. Checked per column (by
// header index), not by substring across the row — a substring check like
// `,0,` would miss a `0` that happens to land at the start/end of the row or
// be masked by an adjacent real value.
func TestRowWithoutProducersEmitsEmptyCells(t *testing.T) {
	res := RunResult{} // no Run, no submits: nothing committed, no ptr fields set.
	row := res.ToRow(1000, "single", 1, 2, 0)

	var buf bytes.Buffer
	if err := WriteCSV(&buf, []Row{row}); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	header := strings.Split(lines[0], ",")
	data := strings.Split(lines[1], ",")
	if len(header) != len(data) {
		t.Fatalf("header/data column count mismatch: %d vs %d", len(header), len(data))
	}

	empty := []string{
		"latency_min_ms", "latency_p50_ms", "latency_mean_ms", "latency_p95_ms", "latency_p99_ms", "latency_stddev_ms",
		"decrypt_ms", "peak_cpu_pct", "peak_mem_mb",
	}
	colIndex := make(map[string]int, len(header))
	for i, h := range header {
		colIndex[h] = i
	}
	for _, col := range empty {
		idx, ok := colIndex[col]
		if !ok {
			t.Fatalf("column %q not found in header %v", col, header)
		}
		if data[idx] != "" {
			t.Errorf("column %q = %q, want empty cell (no producer), got a value instead of a fabricated 0", col, data[idx])
		}
	}
}
