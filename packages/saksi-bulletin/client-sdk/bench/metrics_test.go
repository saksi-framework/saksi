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

func TestWriteCSVHasAllColumnsPopulated(t *testing.T) {
	rows := []Row{
		{
			Tier: 1000, BallotAxis: "single", Positions: 1, Candidates: 2,
			SendRateReq: 200, Submitted: 1000, Committed: 1000, Dropped: 0,
			ThroughputTPS: 480.5,
			LatencyP50:    ms(40), LatencyP95: ms(80), LatencyP99: ms(120),
			EndorseP50: ms(20), CDSVerifyP50: ms(8), OrderP50: ms(5), ValidateP50: ms(3), CommitP50: ms(2),
			DecryptTime: ms(1500), PeakCPUPct: 190.5, PeakMemMB: 512.25,
		},
		// Galal baseline: no on-chain proof verify.
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
