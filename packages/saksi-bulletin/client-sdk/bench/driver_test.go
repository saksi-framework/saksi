package bench

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunCountsCommitsAndDrops(t *testing.T) {
	// Odd indices "drop", even indices commit.
	res := Run(10, 3, 0, func(i int) error {
		if i%2 == 1 {
			return fmt.Errorf("drop %d", i)
		}
		return nil
	})
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
}

func TestRunInvokesEverySubmitExactlyOnce(t *testing.T) {
	var calls int64
	seen := make([]int32, 20)
	res := Run(20, 5, 0, func(i int) error {
		atomic.AddInt64(&calls, 1)
		atomic.AddInt32(&seen[i], 1)
		return nil
	})
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

func TestRunRateLimitedStillCommitsAll(t *testing.T) {
	// High rate keeps the test fast; we assert correctness, not timing.
	res := Run(5, 2, 1000, func(i int) error { return nil })
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

func TestToRowPercentilesPopulated(t *testing.T) {
	res := RunResult{
		Submitted: 3, Committed: 3, Window: time.Second,
		Latencies: []time.Duration{ms(10), ms(20), ms(30)},
	}
	row := res.ToRow(1000, "multi", 3, 3, 0)
	if !(row.LatencyP50 <= row.LatencyP95 && row.LatencyP95 <= row.LatencyP99) {
		t.Fatalf("row percentiles not monotonic: %v/%v/%v", row.LatencyP50, row.LatencyP95, row.LatencyP99)
	}
	if row.ThroughputTPS != 3 {
		t.Fatalf("throughput = %v, want 3", row.ThroughputTPS)
	}
}
