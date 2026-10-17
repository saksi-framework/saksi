package campaign

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

// newPrecinctFolder writes genDir/precinct-01 as the generator does: a stream
// whose election id is <base>-p01, not the folder name. The fake chain serves
// the same ballots back.
func newPrecinctFolder(t *testing.T, n int) (*Executor, string, *fakeLedger) {
	t.Helper()
	genDir := t.TempDir()
	dir := filepath.Join(genDir, "precinct-01")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFakeStream(t, dir, n)
	var h map[string]any
	if err := readJSON(filepath.Join(dir, headerFile), &h); err != nil {
		t.Fatal(err)
	}
	h["election_id"] = "base-p01"
	h["params"] = paramsHexFor(t, "base-p01")
	h["dkg"], h["tally"] = "bb", "tt"
	h["partial_decryptions"] = []string{"p0"}
	if err := writeJSON(filepath.Join(dir, headerFile), h); err != nil {
		t.Fatal(err)
	}

	led := &fakeLedger{Ballots: map[string]string{}, Partials: map[string]string{"president/cand0|t0": "p0"}}
	led.Params, led.DKG, led.Tally = paramsHexFor(t, "base-p01"), "bb", "tt"
	for i := 0; i < n; i++ {
		led.Ballots[hex.EncodeToString([]byte{byte(i + 1)})] = ballotHexFor(t, []byte{byte(i + 1)})
	}
	e := NewExecutor(NewRunStore(genDir), nil, "saksi-demo", "", FabricConfig{})
	e.dialLedger = func() (clientsdk.Ledger, func(), error) { return led, func() {}, nil }
	e.run = passingAudit("")
	return e, dir, led
}

func TestPrecinctLifecycleRunsTheHookBetweenBallotsAndClose(t *testing.T) {
	e, dir, led := newPrecinctFolder(t, 3)
	var atHook, atTally []string
	tally, err := e.PrecinctLifecycle(context.Background(), "precinct-01", PrecinctHooks{
		BeforeClose: func(context.Context) error { atHook = led.callNames(); return nil },
		BeforeTally: func(context.Context) error { atTally = led.callNames(); return nil },
	})
	if err != nil || tally != TallyPublished {
		t.Fatal(tally, err)
	}
	want := []string{"CreateElection", "PublishDKGTranscript", "SubmitBallot", "SubmitBallot", "SubmitBallot",
		"CloseElection", "SubmitPartialDecryption", "PublishTally"}
	if got := led.callNames(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	if strings.Join(atHook, ",") != strings.Join(want[:5], ",") {
		t.Fatalf("hook ran after %v, want after the ballots and before CloseElection", atHook)
	}
	if strings.Join(atTally, ",") != strings.Join(want[:7], ",") {
		t.Fatalf("tally hook ran after %v, want after the partials and before PublishTally", atTally)
	}
	for _, f := range []string{"latencies.csv", submitMetricsFile, "receipts.csv", "bundle.json", JournalFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s not written: %v", f, err)
		}
	}
	var b onChainBundle
	if err := readJSON(filepath.Join(dir, "bundle.json"), &b); err != nil || b.ElectionID != "base-p01" {
		t.Fatalf("bundle election id = %q (%v), want base-p01", b.ElectionID, err)
	}
}

func TestPrecinctLifecycleStopsWhenTheHookFails(t *testing.T) {
	e, _, led := newPrecinctFolder(t, 2)
	_, err := e.PrecinctLifecycle(context.Background(), "precinct-01", PrecinctHooks{
		BeforeClose: func(context.Context) error { return os.ErrPermission },
	})
	if err == nil || !strings.Contains(err.Error(), "before close") {
		t.Fatalf("err = %v, want a before-close failure", err)
	}
	for _, c := range led.callNames() {
		if c == "CloseElection" {
			t.Fatal("CloseElection committed after the hook failed")
		}
	}
}

func TestPrecinctVerifyDumpsThePrecinctElection(t *testing.T) {
	e, dir, _ := newPrecinctFolder(t, 3)
	e.SetPrecinctDistribution("realistic")
	if _, err := e.PrecinctLifecycle(context.Background(), "precinct-01", PrecinctHooks{}); err != nil {
		t.Fatal(err)
	}
	sa, err := e.PrecinctVerify(context.Background(), "precinct-01")
	if err != nil || sa.Overall != "pass" {
		t.Fatalf("verify = %+v, %v", sa, err)
	}
	ballots, err := os.ReadFile(filepath.Join(dir, LedgerDir, BallotsFile))
	if err != nil {
		t.Fatalf("ledger dump missing: %v", err)
	}
	if n := bytes.Count(ballots, []byte("\n")); n != 3 {
		t.Fatalf("ledger dump holds %d ballots, want 3", n)
	}
	var lh map[string]any
	if err := readJSON(filepath.Join(dir, LedgerDir, headerFile), &lh); err != nil {
		t.Fatal(err)
	}
	if lh["election_id"] != "base-p01" {
		t.Fatalf("ledger header election id = %v, want the precinct election base-p01", lh["election_id"])
	}
	perf, err := os.ReadFile(filepath.Join(dir, PerfCSV))
	if err != nil || !strings.Contains(string(perf), "\nprecinct-01,onchain,3,1,2,realistic,") {
		t.Fatalf("perf.csv row missing (%v):\n%s", err, perf)
	}
	if got := readRunEnd(t, dir)["ledger_matches_local"]; got != true {
		t.Fatalf("run.end ledger_matches_local = %v, want true", got)
	}
}

func TestPrecinctChainInfoAndConsoleElectionID(t *testing.T) {
	e, _, led := newPrecinctFolder(t, 1)
	led.nextBlk = 41
	h, _, err := e.PrecinctChainInfo()
	if err != nil || h != 42 {
		t.Fatalf("height = %d, %v; want 42", h, err)
	}
	// A run the driver never registered keeps its run id as its election id.
	if got := e.electionID("run-xyz"); got != "run-xyz" {
		t.Fatalf("electionID(run-xyz) = %q", got)
	}
}

// T20 shape: the replayed tally took the slot, so the precinct's own
// PublishTally fails; tolerated only when asked for and only after the hook.
func TestPrecinctLifecycleToleratesTallyRefusalAfterTheHook(t *testing.T) {
	e, _, led := newPrecinctFolder(t, 2)
	led.failOn, led.failText = "PublishTally", "tally already published"
	hook := func(context.Context) error { return nil }
	tally, err := e.PrecinctLifecycle(context.Background(), "precinct-01",
		PrecinctHooks{BeforeTally: hook, TolerateTallyRefusal: true})
	if err != nil || !strings.Contains(tally, "refused: ") || !strings.Contains(tally, "already published") {
		t.Fatalf("tally %q, err %v", tally, err)
	}
	e2, _, led2 := newPrecinctFolder(t, 2)
	led2.failOn = "PublishTally"
	if _, err := e2.PrecinctLifecycle(context.Background(), "precinct-01",
		PrecinctHooks{TolerateTallyRefusal: true}); err == nil {
		t.Fatal("a refusal without a pre-tally hook must still fail")
	}
}
