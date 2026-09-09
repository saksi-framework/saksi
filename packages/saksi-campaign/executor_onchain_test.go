package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

type fakeLedger struct {
	calls   []string // fn name, in call order
	failOn  string   // fn name to fail on ("" = never)
	nextBlk uint64
	// blocks is the minimal in-memory chain fakeLedger hands out: block n
	// holds the txIDs Submit/SubmitWithReceipt reported as landing there.
	// A trivially "linked" chain (previous_hash = the block number as bytes)
	// is enough here — nothing in campaign asserts on VerifyChain's output,
	// this just has to compile and stay deterministic.
	blocks map[uint64][]string
}

func (f *fakeLedger) SubmitWithReceipt(fn string, args ...string) ([]byte, clientsdk.Receipt, error) {
	f.calls = append(f.calls, fn)
	if fn == f.failOn {
		return nil, clientsdk.Receipt{}, errors.New("boom")
	}
	f.nextBlk++
	txID := fmt.Sprintf("tx-%d", f.nextBlk)
	f.recordBlock(f.nextBlk, txID)
	return nil, clientsdk.Receipt{TxID: txID, BlockNumber: f.nextBlk}, nil
}
func (f *fakeLedger) Submit(fn string, args ...string) (string, uint64, error) {
	f.calls = append(f.calls, fn)
	if fn == f.failOn {
		return "", 0, errors.New("boom")
	}
	f.nextBlk++
	txID := fmt.Sprintf("tx-%d", f.nextBlk)
	f.recordBlock(f.nextBlk, txID)
	return txID, f.nextBlk, nil
}
func (f *fakeLedger) recordBlock(n uint64, txID string) {
	if f.blocks == nil {
		f.blocks = map[uint64][]string{}
	}
	f.blocks[n] = append(f.blocks[n], txID)
}
func (f *fakeLedger) LedgerReceipt(string) (clientsdk.Receipt, error) {
	return clientsdk.Receipt{}, nil
}
func (f *fakeLedger) GetBlockByNumber(n uint64) (*common.Block, error) {
	return &common.Block{Header: &common.BlockHeader{Number: n}}, nil
}
func (f *fakeLedger) ReceiptsForBlock(n uint64, txIDs []string) ([]clientsdk.Receipt, error) {
	present := make(map[string]bool, len(f.blocks[n]))
	for _, id := range f.blocks[n] {
		present[id] = true
	}
	receipts := make([]clientsdk.Receipt, 0, len(txIDs))
	for _, id := range txIDs {
		if present[id] {
			receipts = append(receipts, clientsdk.Receipt{TxID: id, BlockNumber: n})
		}
	}
	return receipts, nil
}
func (f *fakeLedger) VerifyChain(from, to uint64, sample []clientsdk.Receipt) (clientsdk.ChainReport, error) {
	return clientsdk.ChainReport{Blocks: int(to - from + 1), Linked: true, Status: "PASS"}, nil
}
func (f *fakeLedger) ChainInfo() (uint64, []byte, error) { return f.nextBlk + 1, nil, nil }

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

// writeTestBundleWithBallots writes a bundle with n ballots and no partial
// decryptions, so submitOnChain's setup prefix (CreateElection,
// PublishDKGTranscript, N x SubmitBallot, CloseElection) is the only part of
// the lifecycle that records anything before a caller-chosen failure point.
func writeTestBundleWithBallots(t *testing.T, dir string, n int) string {
	t.Helper()
	ballots := make([]string, n)
	for i := range ballots {
		ballots[i] = fmt.Sprintf("b%d", i)
	}
	b := onChainBundle{ElectionID: "run-1", Params: "aa", DKG: "bb", Ballots: ballots, Tally: "tt"}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// newTestExecutor builds an Executor rooted at dir (same NewExecutor
// constructor executor_test.go's newRun uses) and pre-creates the "run-1" run
// folder so submitOnChain's receiptsWriter has somewhere to write.
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

// TestSubmitOnChainRoutesLifecycleEventsToNDJSONOnly is the executor-level
// proof that the step closure's SubmitBallot/Lifecycle split actually reaches
// disk: N ballots, no partial decryptions, and a failure forced at
// PublishTally so the lifecycle stops right after CloseElection — leaving
// exactly CreateElection, PublishDKGTranscript, N x SubmitBallot,
// CloseElection recorded. receipts.csv must have all of them; trail.ndjson
// must have only the 3 non-ballot events, in order, and never the string
// "SubmitBallot". Flipping the step closure's routing condition (Append vs
// Lifecycle) fails every assertion below.
func TestSubmitOnChainRoutesLifecycleEventsToNDJSONOnly(t *testing.T) {
	dir := t.TempDir()
	const nBallots = 3
	led := &fakeLedger{failOn: "PublishTally"}
	e := newTestExecutor(t, dir)
	path := writeTestBundleWithBallots(t, dir, nBallots)

	err := e.submitOnChain(context.Background(), "run-1", ElectionConfig{}, led, path)
	if err == nil {
		t.Fatal("want an error from the forced PublishTally failure")
	}

	csvData, rerr := os.ReadFile(filepath.Join(dir, "run-1", "receipts.csv"))
	if rerr != nil {
		t.Fatalf("receipts.csv not written: %v", rerr)
	}
	csvLines := strings.Split(strings.TrimSpace(string(csvData)), "\n")
	wantCSVLines := nBallots + 4 // header + CreateElection + PublishDKGTranscript + N ballots + CloseElection
	if len(csvLines) != wantCSVLines {
		t.Fatalf("want %d receipts.csv lines, got %d: %q", wantCSVLines, len(csvLines), csvLines)
	}
	ballotRows := 0
	for _, line := range csvLines[1:] {
		if strings.HasPrefix(line, "SubmitBallot,") {
			ballotRows++
		}
	}
	if ballotRows != nBallots {
		t.Fatalf("want %d SubmitBallot rows in receipts.csv, got %d: %q", nBallots, ballotRows, csvLines)
	}

	ndjsonData, nerr := os.ReadFile(filepath.Join(dir, "run-1", "trail.ndjson"))
	if nerr != nil {
		t.Fatalf("trail.ndjson not written: %v", nerr)
	}
	ndjsonLines := strings.Split(strings.TrimSpace(string(ndjsonData)), "\n")
	wantEvents := []string{"CreateElection", "PublishDKGTranscript", "CloseElection"}
	if len(ndjsonLines) != len(wantEvents) {
		t.Fatalf("want %d trail.ndjson lines, got %d: %q", len(wantEvents), len(ndjsonLines), ndjsonLines)
	}
	if strings.Contains(string(ndjsonData), "SubmitBallot") {
		t.Fatalf("trail.ndjson must never contain SubmitBallot, got: %q", ndjsonData)
	}
	for i, line := range ndjsonLines {
		var ev TrailEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("decode trail.ndjson line %d: %v", i, err)
		}
		if ev.Event != wantEvents[i] {
			t.Fatalf("trail.ndjson line %d event = %q, want %q", i, ev.Event, wantEvents[i])
		}
	}
}

// TestOpenReceiptsForRefCountPreventsUseAfterClose is the fix for the
// use-after-close race: two callers on the same run share one cached
// receiptsWriter, and one closing its reference must not close the
// underlying files while the other is still writing through it.
func TestOpenReceiptsForRefCountPreventsUseAfterClose(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	e := NewExecutor(NewRunStore(dir), NewHub(), "saksi-demo", "", FabricConfig{})

	w1, err := e.openReceiptsFor("run-1", runDir)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := e.openReceiptsFor("run-1", runDir)
	if err != nil {
		t.Fatal(err)
	}
	if w1 != w2 {
		t.Fatal("openReceiptsFor should return the same cached writer for a second caller on the same run")
	}

	const writes = 300
	firstWriteDone := make(chan struct{})
	var once sync.Once
	writerErr := make(chan error, 1)
	go func() {
		for i := 0; i < writes; i++ {
			if err := w2.Append(TrailEvent{Event: "SubmitBallot", Ref: fmt.Sprintf("%d", i)}); err != nil {
				writerErr <- err
				return
			}
			once.Do(func() { close(firstWriteDone) })
		}
		writerErr <- nil
	}()

	<-firstWriteDone
	// Release w1's reference while the goroutine above (holding w2, the same
	// underlying writer) is still writing. Without refcounting this closes
	// the files out from under the still-running writer.
	if err := e.closeReceipts("run-1"); err != nil {
		t.Fatalf("closeReceipts (first holder): %v", err)
	}
	if err := <-writerErr; err != nil {
		t.Fatalf("writer saw an error from the concurrent close: %v", err)
	}
	// Release the second (and last) reference.
	if err := e.closeReceipts("run-1"); err != nil {
		t.Fatalf("closeReceipts (second holder): %v", err)
	}

	events, rerr := readReceipts(runDir)
	if rerr != nil {
		t.Fatalf("readReceipts: %v", rerr)
	}
	if len(events) != writes {
		t.Fatalf("want %d rows, got %d", writes, len(events))
	}
	data, err := os.ReadFile(filepath.Join(runDir, "receipts.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), receiptsCSVHeader) != 1 {
		t.Fatalf("want exactly 1 header line, got: %q", data)
	}
}
