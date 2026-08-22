package campaign

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

type fakeLedger struct {
	calls   []string // fn name, in call order
	failOn  string   // fn name to fail on ("" = never)
	nextBlk uint64
}

func (f *fakeLedger) SubmitWithReceipt(fn string, args ...string) ([]byte, clientsdk.Receipt, error) {
	f.calls = append(f.calls, fn)
	if fn == f.failOn {
		return nil, clientsdk.Receipt{}, errors.New("boom")
	}
	f.nextBlk++
	return nil, clientsdk.Receipt{TxID: fmt.Sprintf("tx-%d", f.nextBlk), BlockNumber: f.nextBlk}, nil
}
func (f *fakeLedger) LedgerReceipt(string) (clientsdk.Receipt, error) { return clientsdk.Receipt{}, nil }
func (f *fakeLedger) ChainInfo() (uint64, []byte, error)             { return f.nextBlk + 1, nil, nil }

// writeTestBundle writes a minimal bundle: 2 ballots, 2 partial decryptions.
// The hex payloads are opaque to the orchestrator — any string works against
// the fake ledger.
func writeTestBundle(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "bundle.json")
	data := `{"election_id":"run-1","params":"aa","dkg":"bb","ballots":["b0","b1"],"partial_decryptions":["p0","p1"],"tally":"tt"}`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// newTestExecutor builds an Executor rooted at dir (same NewExecutor
// constructor executor_test.go's newRun uses) and pre-creates the "run-1" run
// folder so submitOnChain's appendReceipt has somewhere to write.
func newTestExecutor(t *testing.T, dir string) *Executor {
	t.Helper()
	store := NewRunStore(dir)
	if err := os.MkdirAll(filepath.Join(dir, "run-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	return NewExecutor(store, NewHub(), "saksi-demo", "", FabricConfig{})
}

func TestSubmitOnChainOrder(t *testing.T) {
	dir := t.TempDir()
	led := &fakeLedger{}
	e := newTestExecutor(t, dir)
	err := e.submitOnChain(context.Background(), "run-1", ElectionConfig{}, led, writeTestBundle(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"CreateElection", "PublishDKGTranscript", "SubmitBallot", "SubmitBallot", "CloseElection", "SubmitPartialDecryption", "SubmitPartialDecryption", "PublishTally"}
	if len(led.calls) != len(want) {
		t.Fatalf("calls = %v", led.calls)
	}
	for i := range want {
		if led.calls[i] != want[i] {
			t.Fatalf("call %d = %s, want %s (all: %v)", i, led.calls[i], want[i], led.calls)
		}
	}
}

func TestSubmitOnChainFailsLoudMidLifecycle(t *testing.T) {
	dir := t.TempDir()
	led := &fakeLedger{failOn: "CloseElection"}
	e := newTestExecutor(t, dir)
	err := e.submitOnChain(context.Background(), "run-1", ElectionConfig{}, led, writeTestBundle(t, dir))
	if err == nil {
		t.Fatal("want error when CloseElection fails")
	}
	// Partial receipts must be preserved: header + 4 rows (create, dkg, 2 ballots).
	data, rerr := os.ReadFile(filepath.Join(dir, "run-1", "receipts.csv"))
	if rerr != nil {
		t.Fatalf("receipts.csv not written: %v", rerr)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 {
		t.Fatalf("want 5 receipts.csv lines (header + 4 rows), got %d: %q", len(lines), lines)
	}
}
