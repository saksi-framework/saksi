package campaign

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

// outageLedger is a fakeLedger whose network goes away, with no cancel, once
// a number of ballots have committed: the console keeps sending, every
// later ballot fails at once, and the window runs to its end with drops.
type outageLedger struct {
	*fakeLedger
	mu       sync.Mutex
	after    int
	accepted int
}

func (l *outageLedger) Submit(fn string, args ...string) (string, uint64, error) {
	tx, blk, err := l.fakeLedger.Submit(fn, args...)
	if fn == "SubmitBallot" && err == nil {
		l.mu.Lock()
		l.accepted++
		down := l.accepted == l.after
		l.mu.Unlock()
		if down {
			l.fakeLedger.mu.Lock()
			l.fakeLedger.peerDown = true
			l.fakeLedger.mu.Unlock()
		}
	}
	return tx, blk, err
}

func (l *outageLedger) restore() {
	l.fakeLedger.mu.Lock()
	l.fakeLedger.peerDown = false
	l.fakeLedger.mu.Unlock()
}

var _ clientsdk.Ledger = (*outageLedger)(nil)

// TestResumeAfterANetworkOnlyOutage: the window sent every ballot and most of
// them failed (the network died under a console that kept running), so it
// ended with drops rather than being interrupted. The resume must take it and
// submit exactly the ballots the chain lacks, then close.
func TestResumeAfterANetworkOnlyOutage(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	e := newTestExecutor(t, dir)
	const n = 200
	path := writeRealBallotStream(t, runDir, n)
	c := ElectionConfig{Mode: "onchain", Voters: n, Positions: 1, Candidates: 2, Concurrency: 8}
	led := &outageLedger{fakeLedger: &fakeLedger{RejectDuplicates: true}, after: 60}

	if err := e.submitOnChain(context.Background(), "run-1", c, led, path); err == nil {
		t.Fatal("want the window's drops reported")
	}
	// The window ended (every ballot dispatched), not interrupted.
	ends := journalEventsOfType(t, runDir, "stage.ballots.end")
	if len(ends) != 1 || jint(ends[0], "dropped") == 0 || jint(ends[0], "unavailable") != jint(ends[0], "dropped") {
		t.Fatalf("want one stage.ballots.end whose drops are all unavailable, got %v", ends)
	}
	if got := journalEventsOfType(t, runDir, "stage.ballots.interrupted"); len(got) != 0 {
		t.Fatalf("the window was stamped interrupted: %v", got)
	}
	before := led.acceptedIndices()
	if len(before) < 60 || len(before) >= n {
		t.Fatalf("the outage left %d of %d on chain, want a partial window", len(before), n)
	}

	plan, err := planResume(runDir, c)
	if err != nil {
		t.Fatalf("planResume refused the outage run: %v", err)
	}
	if plan.CloseOnly || plan.Remaining != n-len(before) {
		t.Fatalf("plan %+v, want remaining %d", plan, n-len(before))
	}

	led.restore()
	if err := e.resumeAndClose(context.Background(), "run-1", c, led, led, path); err != nil {
		t.Fatalf("resume: %v", err)
	}
	rows := latencyRows(t, runDir, 1)
	if len(rows) != n-len(before) {
		t.Fatalf("segment 1 resubmitted %d ballots, want %d", len(rows), n-len(before))
	}
	for i := range rows {
		if before[i] {
			t.Fatalf("index %d was already on chain and was resubmitted", i)
		}
		if rows[i] != "commit" {
			t.Fatalf("index %d ok = %q, want commit", i, rows[i])
		}
	}
	if got := len(led.acceptedIndices()); got != n {
		t.Fatalf("chain holds %d ballots after the resume, want %d", got, n)
	}
	closes := 0
	for _, fn := range led.callNames() {
		if fn == "CloseElection" {
			closes++
		}
	}
	if closes != 1 {
		t.Fatalf("CloseElection committed %d times, want 1", closes)
	}
	// Closed now: nothing more to resume.
	if _, err := planResume(runDir, c); err == nil {
		t.Fatal("a resumed and closed run must not be resumable again")
	}
}

// TestPlanResumeEndedWindowWithDrops: an ended window is resumable only when
// every one of its drops was the network being unreachable (an outage) and
// the election was never closed. A window that lost a ballot to anything
// else, or that was journalled before the count existed, stays failed.
func TestPlanResumeEndedWindowWithDrops(t *testing.T) {
	c := ElectionConfig{Mode: "onchain"}
	start := `{"event":"stage.ballots.start","n":100}`
	outage := `{"event":"stage.ballots.end","committed":40,"dropped":60,"unavailable":60}`
	for _, tc := range []struct {
		name      string
		end       string
		closed    string // "", "ceremony" or "receipt"
		ok        bool
		remaining int
	}{
		{"outage, open election", outage, "", true, 60},
		{"outage, closed (ceremony file)", outage, "ceremony", false, 0},
		{"outage, closed (CloseElection receipt only)", outage, "receipt", false, 0},
		{"chaincode refusals", `{"event":"stage.ballots.end","committed":40,"dropped":60,"unavailable":0}`, "", false, 0},
		{"outage mixed with refusals", `{"event":"stage.ballots.end","committed":40,"dropped":60,"unavailable":59}`, "", false, 0},
		{"journalled before the count", `{"event":"stage.ballots.end","committed":40,"dropped":60}`, "", false, 0},
		{"no drops", `{"event":"stage.ballots.end","committed":100,"dropped":0}`, "", false, 0},
	} {
		dir := t.TempDir()
		writeJournalLines(t, dir, start, tc.end)
		switch tc.closed {
		case "ceremony":
			if err := os.WriteFile(filepath.Join(dir, CeremonyFile), []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
		case "receipt":
			w, err := openReceipts(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := w.Lifecycle(TrailEvent{Event: "CloseElection", Receipt: clientsdk.Receipt{TxID: "tx-close", BlockNumber: 9}}); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(dir, CeremonyFile)); err == nil {
				t.Fatal("the receipt case must have no ceremony file")
			}
		}
		plan, err := planResume(dir, c)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err %v, want ok %v", tc.name, err, tc.ok)
			continue
		}
		if tc.ok && (plan.CloseOnly || plan.Remaining != tc.remaining) {
			t.Errorf("%s: plan %+v, want remaining %d", tc.name, plan, tc.remaining)
		}
	}
}

// TestUnavailableTellsAnOutageFromARefusal: only the network being
// unreachable counts toward an outage.
func TestUnavailableTellsAnOutageFromARefusal(t *testing.T) {
	for text, want := range map[string]bool{
		"submit SubmitBallot: rpc error: code = Unavailable desc = connection error":                 true,
		"commit status for SubmitBallot: rpc error: code = Unavailable desc = error reading: EOF":    true,
		"rpc error: code = Aborted desc = failed to endorse transaction; gate=nullifier: spent":      false,
		"commit status for SubmitBallot: rpc error: code = DeadlineExceeded desc = context deadline": false,
		"tx did not validate (code 11)": false,
	} {
		if got := unavailable(errors.New(text)); got != want {
			t.Errorf("unavailable(%q) = %v, want %v", text, got, want)
		}
	}
	if unavailable(nil) {
		t.Error("unavailable(nil) = true")
	}
}
