package bench

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunCountsCommitsAndDrops(t *testing.T) {
	// Odd indices "drop", even indices commit.
	res := Run(context.Background(), 10, func(i int) error {
		if i%2 == 1 {
			return fmt.Errorf("drop %d", i)
		}
		return nil
	}, RunOpts{Concurrency: 3})
	if res.Submitted != 10 {
		t.Fatalf("submitted = %d, want 10", res.Submitted)
	}
	if res.Committed != 5 || res.Dropped != 5 {
		t.Fatalf("committed=%d dropped=%d, want 5/5", res.Committed, res.Dropped)
	}
	if len(res.Latencies) != res.Committed {
		t.Fatalf("latencies len = %d, want %d (one per commit)", len(res.Latencies), res.Committed)
	}
	// committed + dropped must equal submitted — no silently lost ballot.
	if res.Committed+res.Dropped != res.Submitted {
		t.Fatalf("committed+dropped=%d != submitted=%d", res.Committed+res.Dropped, res.Submitted)
	}
	if res.Stopped {
		t.Fatalf("an uncancelled, unbounded run must not report Stopped")
	}
	if res.LastIndex != 9 {
		t.Fatalf("LastIndex = %d, want 9 (all dispatched)", res.LastIndex)
	}
}

func TestRunInvokesEverySubmitExactlyOnce(t *testing.T) {
	var calls int64
	seen := make([]int32, 20)
	res := Run(context.Background(), 20, func(i int) error {
		atomic.AddInt64(&calls, 1)
		atomic.AddInt32(&seen[i], 1)
		return nil
	}, RunOpts{Concurrency: 5})
	if calls != 20 {
		t.Fatalf("submit called %d times, want 20", calls)
	}
	for i, c := range seen {
		if c != 1 {
			t.Fatalf("index %d submitted %d times, want exactly 1", i, c)
		}
	}
	if res.Committed != 20 {
		t.Fatalf("committed = %d, want 20", res.Committed)
	}
}

func TestRunByIndexAndOKAreFullLength(t *testing.T) {
	res := Run(context.Background(), 6, func(i int) error {
		if i == 2 {
			return fmt.Errorf("drop")
		}
		return nil
	}, RunOpts{Concurrency: 2})
	if len(res.ByIndex) != 6 || len(res.OK) != 6 {
		t.Fatalf("ByIndex/OK must be length n=6, got %d/%d", len(res.ByIndex), len(res.OK))
	}
	for i, okVal := range res.OK {
		want := i != 2
		if okVal != want {
			t.Fatalf("OK[%d] = %v, want %v", i, okVal, want)
		}
	}
}

func TestRunRateLimitedStillCommitsAll(t *testing.T) {
	// High rate keeps the test fast; we assert correctness, not timing.
	res := Run(context.Background(), 5, func(i int) error { return nil }, RunOpts{Concurrency: 2, SendRate: 1000})
	if res.Committed != 5 || res.Dropped != 0 {
		t.Fatalf("committed=%d dropped=%d, want 5/0", res.Committed, res.Dropped)
	}
	row := res.ToRow(5, "single", 1, 2, 1000)
	if row.Submitted != 5 || row.Committed != 5 {
		t.Fatalf("row counts wrong: %+v", row)
	}
	if row.ThroughputTPS <= 0 {
		t.Fatalf("throughput should be positive, got %v", row.ThroughputTPS)
	}
}

func TestToRowStatsPopulated(t *testing.T) {
	res := RunResult{
		Submitted: 3, Committed: 3, Window: time.Second,
		Latencies: []time.Duration{ms(10), ms(20), ms(30)},
	}
	row := res.ToRow(1000, "multi", 3, 3, 0)
	if !(row.LatencyMin <= row.LatencyP50 && row.LatencyP50 <= row.LatencyP95 && row.LatencyP95 <= row.LatencyP99) {
		t.Fatalf("row stats not monotonic: min=%v p50=%v p95=%v p99=%v", row.LatencyMin, row.LatencyP50, row.LatencyP95, row.LatencyP99)
	}
	if row.LatencyMean != ms(20) {
		t.Fatalf("mean = %v, want 20ms", row.LatencyMean)
	}
	if row.ThroughputTPS != 3 {
		t.Fatalf("throughput = %v, want 3", row.ThroughputTPS)
	}
}

// TestRunCancelledContextStops crashes the run mid-flight via ctx cancellation
// at index 500 (concurrency 8) and asserts the dispatcher stopped handing out
// new indices: Stopped is set, LastIndex reflects real progress, and nothing
// past LastIndex (+ the in-flight concurrency window) was ever submitted.
func TestRunCancelledContextStops(t *testing.T) {
	const n = 5000
	const concurrency = 8
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var maxSubmitted int64
	var cancelledOnce int32
	res := Run(ctx, n, func(i int) error {
		// A tiny sleep keeps the dispatcher from racing to n=5000 before the
		// cancellation below has a chance to be noticed.
		time.Sleep(100 * time.Microsecond)
		for {
			cur := atomic.LoadInt64(&maxSubmitted)
			if int64(i) <= cur || atomic.CompareAndSwapInt64(&maxSubmitted, cur, int64(i)) {
				break
			}
		}
		if i >= 500 && atomic.CompareAndSwapInt32(&cancelledOnce, 0, 1) {
			cancel()
		}
		return nil
	}, RunOpts{Concurrency: concurrency})

	if !res.Stopped {
		t.Fatalf("Stopped = false, want true after ctx cancellation")
	}
	if res.LastIndex < 500 {
		t.Fatalf("LastIndex = %d, want >= 500", res.LastIndex)
	}
	if res.LastIndex >= n-1 {
		t.Fatalf("LastIndex = %d, run should have stopped well short of n-1=%d", res.LastIndex, n-1)
	}
	if int(maxSubmitted) > res.LastIndex+concurrency {
		t.Fatalf("a submit ran for index %d, past LastIndex(%d)+concurrency(%d)", maxSubmitted, res.LastIndex, concurrency)
	}
	// Nothing beyond LastIndex should have a recorded submit.
	for i := res.LastIndex + 1; i < n; i++ {
		if res.OK[i] || res.ByIndex[i] != 0 {
			t.Fatalf("index %d beyond LastIndex(%d) has a recorded submit", i, res.LastIndex)
		}
	}
}

func TestRunMaxDurationStops(t *testing.T) {
	const n = 100000
	res := Run(context.Background(), n, func(i int) error {
		time.Sleep(time.Millisecond)
		return nil
	}, RunOpts{Concurrency: 4, MaxDuration: 20 * time.Millisecond})

	if !res.Stopped {
		t.Fatalf("Stopped = false, want true after MaxDuration elapsed")
	}
	if res.LastIndex >= n-1 {
		t.Fatalf("LastIndex = %d, expected the run to stop well short of n-1=%d given MaxDuration", res.LastIndex, n-1)
	}
	if res.Submitted != res.LastIndex+1 {
		t.Fatalf("Submitted = %d, want LastIndex+1 = %d", res.Submitted, res.LastIndex+1)
	}
}

func TestRunOnProgressFiresAtThousandBoundaries(t *testing.T) {
	const n = 2500
	var calls []int
	res := Run(context.Background(), n, func(i int) error { return nil }, RunOpts{
		Concurrency: 4,
		OnProgress:  func(done int) { calls = append(calls, done) },
	})
	if res.Submitted != n {
		t.Fatalf("submitted = %d, want %d", res.Submitted, n)
	}
	if len(calls) < 2 {
		t.Fatalf("expected at least the 1000/2000 boundary calls plus a final call, got %v", calls)
	}
	if calls[0] != 1000 || calls[1] != 2000 {
		t.Fatalf("expected boundary calls 1000,2000 first, got %v", calls)
	}
	last := calls[len(calls)-1]
	if last != n {
		t.Fatalf("final OnProgress call = %d, want %d (n)", last, n)
	}
}

func TestDriverCeilingTPSZeroWhenNothingCommitted(t *testing.T) {
	res := RunResult{Concurrency: 8}
	if got := res.DriverCeilingTPS(); got != 0 {
		t.Fatalf("DriverCeilingTPS = %v, want 0 with no latencies", got)
	}
}

func TestDriverCeilingTPS(t *testing.T) {
	res := RunResult{
		Concurrency: 8,
		Latencies:   []time.Duration{ms(10), ms(20), ms(30)}, // median (nearest-rank p50 of 3) = 20ms
	}
	got := res.DriverCeilingTPS()
	want := 8.0 / 0.02
	if got != want {
		t.Fatalf("DriverCeilingTPS = %v, want %v", got, want)
	}
}
