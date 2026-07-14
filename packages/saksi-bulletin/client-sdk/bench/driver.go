package bench

import (
	"sync"
	"time"
)

// SubmitFunc submits the ballot at index i and returns nil on commit or an error
// on a drop (endorsement timeout, MVCC conflict, rejection). It must be safe to
// call concurrently.
type SubmitFunc func(i int) error

// RunResult is the raw outcome of a submission run: per-committed-ballot
// latencies plus the counts and wall-clock window needed to fill a Row.
type RunResult struct {
	Submitted int
	Committed int
	Dropped   int
	Latencies []time.Duration // one per committed ballot (drops excluded)
	Window    time.Duration   // total wall-clock of the submission window
}

// Run submits n ballots through submit with up to `concurrency` in flight. Serial
// submission measures the driver's round-trip ceiling, not Fabric throughput, so
// concurrency > 1 is mandatory for valid tps. When sendRate > 0, dispatch is
// rate-limited to that many submissions per second (open-loop load); sendRate
// <= 0 dispatches as fast as the workers drain.
//
// Every submit result is recorded — a dropped ballot is counted, never silently
// swallowed (a silent drop at high tps would read as a clean undercount).
func Run(n, concurrency int, sendRate float64, submit SubmitFunc) RunResult {
	if concurrency < 1 {
		concurrency = 1
	}
	lat := make([]time.Duration, n)
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
				lat[i] = time.Since(t0) // index i is owned by exactly one worker
				ok[i] = err == nil
			}
		}()
	}

	if sendRate > 0 {
		interval := time.Duration(float64(time.Second) / sendRate)
		tick := time.NewTicker(interval)
		for i := 0; i < n; i++ {
			<-tick.C
			jobs <- i
		}
		tick.Stop()
	} else {
		for i := 0; i < n; i++ {
			jobs <- i
		}
	}
	close(jobs)
	wg.Wait()
	window := time.Since(start)

	res := RunResult{Submitted: n, Window: window}
	for i := 0; i < n; i++ {
		if ok[i] {
			res.Committed++
			res.Latencies = append(res.Latencies, lat[i])
		} else {
			res.Dropped++
		}
	}
	return res
}

// ToRow folds a RunResult into an Appendix-C Row for the given tier/axis, filling
// throughput and the end-to-end latency percentiles. Fabric phase splits,
// decrypt time, and docker-stats peaks are filled separately by the live run.
func (res RunResult) ToRow(tier int, axis string, positions, candidates int, sendRate float64) Row {
	p50, p95, p99 := Percentiles(res.Latencies)
	return Row{
		Tier: tier, BallotAxis: axis, Positions: positions, Candidates: candidates,
		SendRateReq:   sendRate,
		Submitted:     res.Submitted,
		Committed:     res.Committed,
		Dropped:       res.Dropped,
		ThroughputTPS: ThroughputTPS(res.Committed, res.Window),
		LatencyP50:    p50,
		LatencyP95:    p95,
		LatencyP99:    p99,
	}
}
