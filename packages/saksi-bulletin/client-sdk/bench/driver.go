package bench

import (
	"context"
	"sync"
	"time"
)

// SubmitFunc submits the ballot at index i and returns nil on commit or an error
// on a drop (endorsement timeout, MVCC conflict, rejection). It must be safe to
// call concurrently.
type SubmitFunc func(i int) error

// RunOpts configures a Run. Concurrency < 1 is treated as 1. SendRate <= 0
// dispatches as fast as the workers drain (closed-loop); SendRate > 0
// rate-limits dispatch to that many submissions per second (open-loop load).
// MaxDuration == 0 means unbounded — Run only stops on ctx cancellation or
// after all n indices are dispatched. OnProgress, if non-nil, is called from
// the dispatcher goroutine (never concurrently with itself) every 1,000
// dispatched indices and once more at the end with the final count.
type RunOpts struct {
	Concurrency int
	SendRate    float64
	MaxDuration time.Duration
	OnProgress  func(done int)
}

// RunResult is the raw outcome of a submission run: per-index latencies plus
// the counts and wall-clock window needed to fill a Row.
type RunResult struct {
	Submitted int
	Committed int
	Dropped   int
	Latencies []time.Duration // one per committed ballot (drops excluded)
	Window    time.Duration   // total wall-clock of the submission window

	// Stopped is true when ctx was cancelled or MaxDuration elapsed before all
	// n indices were dispatched. LastIndex is the highest index actually
	// dispatched (handed to a worker); indices above it were never submitted.
	Stopped   bool
	LastIndex int

	// ByIndex and OK let a caller reconstruct a per-index record (e.g.
	// latencies.csv): ByIndex[i] is the submit latency for index i (zero if i
	// was never dispatched), OK[i] is whether submit(i) returned nil. Both are
	// always length n, dispatched or not.
	ByIndex []time.Duration
	OK      []bool

	// Concurrency is the worker count this run actually used (opts.Concurrency
	// clamped to >= 1), captured for DriverCeilingTPS.
	Concurrency int
}

// DriverCeilingTPS estimates the harness's own round-trip ceiling: concurrency
// workers each gated by the median per-submit latency. A measured throughput
// above this number reflects driver parallelism, not something the target
// system achieved, so it bounds how a tps figure should be read. Returns 0
// when nothing committed (p50 undefined) or p50 is 0.
func (r RunResult) DriverCeilingTPS() float64 {
	p50 := Summary(r.Latencies).Median
	if p50 <= 0 {
		return 0
	}
	return float64(r.Concurrency) / p50.Seconds()
}

// Run submits up to n ballots through submit with up to opts.Concurrency in
// flight. Serial submission measures the driver's round-trip ceiling, not
// Fabric throughput, so concurrency > 1 is mandatory for valid tps.
//
// Every submit result is recorded — a dropped ballot is counted, never silently
// swallowed (a silent drop at high tps would read as a clean undercount).
//
// ctx cancellation or opts.MaxDuration elapsing stops the dispatcher from
// handing out further indices; in-flight submits are allowed to finish before
// Run returns. The result then covers only the indices actually dispatched
// (RunResult.Stopped is set, LastIndex names the last one).
func Run(ctx context.Context, n int, submit SubmitFunc, opts RunOpts) RunResult {
	concurrency := opts.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}

	byIndex := make([]time.Duration, n)
	ok := make([]bool, n)
	jobs := make(chan int)

	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				t0 := time.Now()
				err := submit(i)
				byIndex[i] = time.Since(t0) // index i is owned by exactly one worker
				ok[i] = err == nil
			}
		}()
	}

	var deadline time.Time
	if opts.MaxDuration > 0 {
		deadline = start.Add(opts.MaxDuration)
	}

	var tick *time.Ticker
	if opts.SendRate > 0 {
		tick = time.NewTicker(time.Duration(float64(time.Second) / opts.SendRate))
		defer tick.Stop()
	}

	dispatched := 0
	lastReported := 0
	lastIndex := -1
	stopped := false

dispatchLoop:
	for i := 0; i < n; i++ {
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			stopped = true
			break dispatchLoop
		}
		if tick != nil {
			select {
			case <-ctx.Done():
				stopped = true
				break dispatchLoop
			case <-tick.C:
			}
		}
		select {
		case <-ctx.Done():
			stopped = true
			break dispatchLoop
		case jobs <- i:
			lastIndex = i
			dispatched++
			if opts.OnProgress != nil && dispatched%1000 == 0 {
				opts.OnProgress(dispatched)
				lastReported = dispatched
			}
		}
	}
	close(jobs)
	wg.Wait()
	window := time.Since(start)

	if opts.OnProgress != nil && dispatched != lastReported {
		opts.OnProgress(dispatched)
	}

	res := RunResult{
		Submitted:   dispatched,
		Window:      window,
		Stopped:     stopped,
		LastIndex:   lastIndex,
		ByIndex:     byIndex,
		OK:          ok,
		Concurrency: concurrency,
	}
	for i := 0; i <= lastIndex; i++ {
		if ok[i] {
			res.Committed++
			res.Latencies = append(res.Latencies, byIndex[i])
		} else {
			res.Dropped++
		}
	}
	return res
}

// ToRow folds a RunResult into an Appendix-C Row for the given tier/axis, filling
// throughput and the end-to-end latency stats. Decrypt time and docker-stats
// peaks are filled separately by the live run (nil here — see Row).
func (res RunResult) ToRow(tier int, axis string, positions, candidates int, sendRate float64) Row {
	stats := Summary(res.Latencies)
	return Row{
		Tier: tier, BallotAxis: axis, Positions: positions, Candidates: candidates,
		SendRateReq:   sendRate,
		Submitted:     res.Submitted,
		Committed:     res.Committed,
		Dropped:       res.Dropped,
		ThroughputTPS: ThroughputTPS(res.Committed, res.Window),
		LatencyMin:    stats.Min,
		LatencyP50:    stats.Median,
		LatencyMean:   stats.Mean,
		LatencyP95:    stats.P95,
		LatencyP99:    stats.P99,
		LatencyStdDev: stats.StdDev,
	}
}
