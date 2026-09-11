package campaign

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeTestBundleWithPartials writes a bundle with n partial decryptions (and
// no ballots) so the post-window half of the lifecycle — CloseElection, the
// partials, PublishTally — is the only interesting part of the run.
func writeTestBundleWithPartials(t *testing.T, runDir string, n int) string {
	t.Helper()
	writeBallotLinesFile(t, runDir, 0)
	pds := make([]string, n)
	for i := range pds {
		pds[i] = fmt.Sprintf("p%d", i)
	}
	data, err := json.Marshal(onChainBundle{
		ElectionID: "run-1", Params: "aa", DKG: "bb", Tally: "tt",
		BallotsFile: BallotsFile, BallotCount: 0, PartialDecryptions: pds,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(runDir, "bundle.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSubmitPartialsRunConcurrentlyWithinTheBound is the whole point of the
// change: the partial decryptions are in flight together, bounded, and still
// strictly between CloseElection and PublishTally.
//
// The fake ledger blocks every SubmitPartialDecryption until maxPartialsInFlight
// of them are waiting at once. Sequential submission can never reach that
// barrier, so the test fails (on the barrier timeout) rather than hanging; a
// bound that leaked would push the observed peak above maxPartialsInFlight.
func TestSubmitPartialsRunConcurrentlyWithinTheBound(t *testing.T) {
	dir := t.TempDir()
	const partials = maxPartialsInFlight*2 + 3

	var (
		mu       sync.Mutex
		inFlight int
		peak     int
	)
	gate := make(chan struct{})
	var once sync.Once
	led := &fakeLedger{}
	led.beforeCommit = func(fn string) {
		if fn != "SubmitPartialDecryption" {
			return
		}
		mu.Lock()
		inFlight++
		if inFlight > peak {
			peak = inFlight
		}
		full := inFlight >= maxPartialsInFlight
		mu.Unlock()
		if full {
			once.Do(func() { close(gate) })
		}
		select {
		case <-gate:
		case <-time.After(10 * time.Second):
		}
		mu.Lock()
		inFlight--
		mu.Unlock()
	}

	e := newTestExecutor(t, dir)
	path := writeTestBundleWithPartials(t, filepath.Join(dir, "run-1"), partials)
	if err := e.submitOnChain(context.Background(), "run-1", ElectionConfig{}, led, path); err != nil {
		t.Fatalf("submitOnChain: %v", err)
	}

	mu.Lock()
	gotPeak := peak
	mu.Unlock()
	if gotPeak != maxPartialsInFlight {
		t.Fatalf("peak partial decryptions in flight = %d, want exactly %d "+
			"(below means they are still serialised, above means the bound leaks)",
			gotPeak, maxPartialsInFlight)
	}

	calls := led.callNames()
	closeAt, tallyAt, partialCount := -1, -1, 0
	for i, fn := range calls {
		switch fn {
		case "CloseElection":
			closeAt = i
		case "PublishTally":
			tallyAt = i
		case "SubmitPartialDecryption":
			partialCount++
			if closeAt < 0 {
				t.Fatalf("a partial decryption was submitted before CloseElection: %v", calls)
			}
			if tallyAt >= 0 {
				t.Fatalf("a partial decryption was submitted after PublishTally: %v", calls)
			}
		}
	}
	if partialCount != partials {
		t.Fatalf("submitted %d partial decryptions, want %d", partialCount, partials)
	}
	if tallyAt != len(calls)-1 {
		t.Fatalf("PublishTally is not the last call: %v", calls)
	}

	// Every partial still has its receipt row, one per bundle index, whatever
	// order they committed in.
	csvData, err := os.ReadFile(filepath.Join(dir, "run-1", "receipts.csv"))
	if err != nil {
		t.Fatalf("receipts.csv not written: %v", err)
	}
	refs := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(csvData)), "\n") {
		if !strings.HasPrefix(line, "SubmitPartialDecryption,") {
			continue
		}
		refs[strings.Split(line, ",")[1]] = true
	}
	if len(refs) != partials {
		t.Fatalf("receipts.csv holds %d distinct partial-decryption refs, want %d", len(refs), partials)
	}
	for i := 0; i < partials; i++ {
		if !refs[fmt.Sprint(i)] {
			t.Fatalf("no receipt row for partial decryption %d", i)
		}
	}

	// trail.ndjson carries every lifecycle event too.
	trail, err := os.ReadFile(filepath.Join(dir, "run-1", "trail.ndjson"))
	if err != nil {
		t.Fatalf("trail.ndjson not written: %v", err)
	}
	if got := strings.Count(string(trail), `"SubmitPartialDecryption"`); got != partials {
		t.Fatalf("trail.ndjson holds %d partial-decryption events, want %d", got, partials)
	}
}

// TestSubmitPartialsFailLoud keeps the failure contract: one failing partial
// fails the whole lifecycle, with the same wording sequential submission gave,
// and PublishTally never runs.
func TestSubmitPartialsFailLoud(t *testing.T) {
	dir := t.TempDir()
	led := &fakeLedger{failOn: "SubmitPartialDecryption"}
	e := newTestExecutor(t, dir)
	path := writeTestBundleWithPartials(t, filepath.Join(dir, "run-1"), 5)

	err := e.submitOnChain(context.Background(), "run-1", ElectionConfig{}, led, path)
	if err == nil {
		t.Fatal("want an error when a partial decryption fails")
	}
	if !strings.HasPrefix(err.Error(), "SubmitPartialDecryption: ") {
		t.Fatalf("error wording changed: %v", err)
	}
	for _, fn := range led.callNames() {
		if fn == "PublishTally" {
			t.Fatalf("PublishTally ran after a failed partial decryption: %v", led.callNames())
		}
	}
}

// TestSubmitPartialsStopAfterAFailure is the other half of the failure
// contract, and the reason the fan-out carries a cancellable child context: a
// run whose first partial decryption fails must not go on to submit the rest
// of them into an election it is about to abandon.
//
// It is made deterministic by holding the fake: every partial after the first
// blocks inside the ledger until the watcher below has SEEN the first one
// commit-and-fail, so the failure is always observed before any further
// transaction can be attempted. The bound is the semaphore's: nothing beyond
// the maxPartialsInFlight already in flight when the failure landed may reach
// the chain, because a goroutine that takes a freed slot afterwards finds the
// context cancelled and returns at step's entry check without submitting.
func TestSubmitPartialsStopAfterAFailure(t *testing.T) {
	dir := t.TempDir()
	const partials = maxPartialsInFlight * 4

	var first sync.Once
	release := make(chan struct{})
	led := &fakeLedger{failOn: "SubmitPartialDecryption"}
	led.beforeCommit = func(fn string) {
		if fn != "SubmitPartialDecryption" {
			return
		}
		lead := false
		first.Do(func() { lead = true })
		if lead {
			return // this one commits, fails, and cancels the rest
		}
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	}
	// Release the held partials once the first has actually reached the ledger
	// and failed. commit() records the call before returning the failure, and
	// the goroutine records the error before freeing its semaphore slot, so a
	// visible call means the failure is in hand.
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			for _, fn := range led.callNames() {
				if fn == "SubmitPartialDecryption" {
					close(release)
					return
				}
			}
			time.Sleep(time.Millisecond)
		}
	}()

	e := newTestExecutor(t, dir)
	path := writeTestBundleWithPartials(t, filepath.Join(dir, "run-1"), partials)
	if err := e.submitOnChain(context.Background(), "run-1", ElectionConfig{}, led, path); err == nil {
		t.Fatal("want an error when a partial decryption fails")
	}

	attempted := 0
	for _, fn := range led.callNames() {
		if fn == "SubmitPartialDecryption" {
			attempted++
		}
	}
	if attempted >= partials {
		t.Fatalf("all %d partial decryptions were submitted after the first failed", partials)
	}
	if attempted > maxPartialsInFlight {
		t.Fatalf("%d partial decryptions reached the chain after the failure, "+
			"want at most the %d that were already in flight",
			attempted, maxPartialsInFlight)
	}
}
