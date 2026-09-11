package campaign

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// fakeLedger is the in-memory stand-in for a Fabric ledger. The ballot window
// submits concurrently, so every field is guarded by mu.
type fakeLedger struct {
	mu      sync.Mutex
	calls   []string // fn name, in call order
	failOn  string   // fn name to fail on ("" = never)
	nextTx  uint64
	nextBlk uint64
	// blockSize batches transactions into blocks the way a real orderer does:
	// blockSize submissions share one block number. 0 = one block per
	// transaction (the original behaviour).
	blockSize int
	inBlock   int
	// qscc counts the system-chaincode round trips (block/receipt reads) the
	// console made — the cost the receipts-after-the-window design exists to
	// bound.
	qscc int
	// blocks is the minimal in-memory chain fakeLedger hands out: block n
	// holds the txIDs Submit/SubmitWithReceipt reported as landing there.
	// A trivially "linked" chain (previous_hash = the block number as bytes)
	// is enough here — nothing in campaign asserts on VerifyChain's output,
	// this just has to compile and stay deterministic.
	blocks map[uint64][]string

	// FailAt is the ballot ordinal (1-based) from which SubmitBallot fails and
	// cancels the run's context — the crash the resume path exists for. 0 =
	// never. Set it back to 0 to model the ledger coming back up.
	FailAt int
	cancel context.CancelFunc
	// RejectDuplicates makes a second SubmitBallot for an already-accepted
	// nullifier fail the way the chaincode's double-vote gate does.
	RejectDuplicates bool

	// Ballots is the chain's own copy of each accepted ballot, keyed by
	// nullifier hex — what GetBallot serves the ledger dump. A test mutates an
	// entry to model a chain holding something the console never wrote.
	Ballots map[string]string
	// The election's published artifacts, as GetElection / GetDKGTranscript /
	// GetTally / GetPartialDecryption (keyed "<contest>|<trustee>") serve them.
	Params, DKG, Tally string
	Partials           map[string]string
	// FailGetBallotAt is the 1-based GetBallot call that fails — the chain
	// going away mid-dump. 0 = never.
	FailGetBallotAt int
	getBallots      []string // nullifiers GetBallot was asked for, in call order

	// beforeCommit, when set, runs before every SubmitWithReceipt commit and
	// OUTSIDE f.mu — the hook the concurrency test uses to hold transactions in
	// flight while it counts them.
	beforeCommit func(fn string)
	// noBatch makes GetBallots report the error an older chaincode gives for an
	// unknown function, so the dump's fallback path can be exercised.
	noBatch bool
	// getBallotsBatches records the size of each GetBallots page asked for.
	getBallotsBatches []int

	ballots     int             // SubmitBallot attempts, accepted or not
	accepted    []string        // accepted nullifiers, in accept order
	acceptedSet map[string]bool // the same set, for the duplicate gate
	hidden      map[string]bool // accepted but withheld from the NEXT listing
	failAfter   map[string]bool // committed, then reported as failed
	reject      map[string]bool // never committed, always reported as failed
}

// hide withholds an accepted nullifier from the next completed ListNullifiers
// walk and no later one: the late commit that raced the resume's snapshot and
// is visible by the time the failures are re-checked.
func (f *fakeLedger) hide(nullifierHex string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hidden == nil {
		f.hidden = map[string]bool{}
	}
	f.hidden[nullifierHex] = true
}

// acceptButFail commits a ballot and still reports a generic validation
// failure to the caller — the peer losing the commit status of a transaction
// that was ordered anyway.
func (f *fakeLedger) acceptButFail(nullifierHex string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAfter == nil {
		f.failAfter = map[string]bool{}
	}
	f.failAfter[nullifierHex] = true
}

// rejectBallot fails a ballot without committing it: a genuine drop.
func (f *fakeLedger) rejectBallot(nullifierHex string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reject == nil {
		f.reject = map[string]bool{}
	}
	f.reject[nullifierHex] = true
}

// acceptedIndices maps the accepted nullifiers back to ballot indices, using
// the same deterministic nullifier the test stream writes for index i.
func (f *fakeLedger) acceptedIndices() map[int]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[int]bool, len(f.accepted))
	for _, n := range f.accepted {
		raw, err := hex.DecodeString(n)
		if err != nil || len(raw) != 32 {
			continue
		}
		out[int(binary.BigEndian.Uint32(raw[28:]))-1] = true
	}
	return out
}

// ballotGate is the chaincode-side half of SubmitBallot: the crash point, the
// double-vote check, and the accepted-nullifier set ListNullifiers serves.
//
// A payload that is not a decodable Ballot carries no nullifier, so it is
// committed without any of that bookkeeping — the older window tests submit
// opaque hex, which the real peer would reject but which is not what they are
// measuring.
func (f *fakeLedger) ballotGate(args []string) error {
	if len(args) == 0 {
		return errors.New("SubmitBallot without a ballot")
	}
	nul := ""
	if raw, err := hex.DecodeString(args[0]); err == nil {
		var b pb.Ballot
		if proto.Unmarshal(raw, &b) == nil {
			nul = hex.EncodeToString(b.GetCredentialPresentation().GetNullifier().GetValue())
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.ballots++
	if f.FailAt > 0 && f.ballots >= f.FailAt {
		if f.cancel != nil {
			f.cancel()
		}
		return errors.New("peer unavailable")
	}
	if nul == "" {
		return nil
	}
	if f.reject[nul] {
		return errors.New("tx did not validate (code 11)")
	}
	if f.RejectDuplicates && f.acceptedSet[nul] {
		return errors.New("tx did not validate (code 11)")
	}
	if f.acceptedSet == nil {
		f.acceptedSet = map[string]bool{}
	}
	f.acceptedSet[nul] = true
	f.accepted = append(f.accepted, nul)
	if f.failAfter[nul] {
		return errors.New("tx did not validate (code 11)")
	}
	return nil
}

// ListNullifiers serves the accepted set one page at a time, ordered, with an
// offset bookmark — the same contract *clientsdk.BulletinClient has.
func (f *fakeLedger) ListNullifiers(_ string, pageSize int, bookmark string) (clientsdk.NullifierPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := make([]string, 0, len(f.accepted))
	for _, n := range f.accepted {
		if !f.hidden[n] {
			list = append(list, n)
		}
	}
	sort.Strings(list)
	off, _ := strconv.Atoi(bookmark)
	if off < 0 || off > len(list) {
		off = len(list)
	}
	if pageSize <= 0 {
		pageSize = len(list)
	}
	end := off + pageSize
	if end > len(list) {
		end = len(list)
	}
	page := clientsdk.NullifierPage{Nullifiers: list[off:end]}
	if end < len(list) {
		page.NextBookmark = strconv.Itoa(end)
	} else {
		f.hidden = nil // the walk is complete; a hidden late commit is visible from here on
	}
	return page, nil
}

// accept records a nullifier as committed without going through SubmitBallot,
// so a test can start from a chain that already holds a run.
func (f *fakeLedger) accept(nullifierHex string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acceptedSet == nil {
		f.acceptedSet = map[string]bool{}
	}
	f.acceptedSet[nullifierHex] = true
	f.accepted = append(f.accepted, nullifierHex)
}

// GetBallot serves the chain's copy of one ballot, one call at a time — the
// only way the ledger dump can read the population.
func (f *fakeLedger) GetBallot(_, nullifier string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getBallots = append(f.getBallots, nullifier)
	if f.FailGetBallotAt > 0 && len(f.getBallots) >= f.FailGetBallotAt {
		return "", errors.New("peer unavailable")
	}
	hexBallot, ok := f.Ballots[nullifier]
	if !ok {
		return "", fmt.Errorf("no ballot for nullifier %s", nullifier)
	}
	return hexBallot, nil
}

func (f *fakeLedger) GetElection(string) (string, error)      { return f.Params, nil }
func (f *fakeLedger) GetDKGTranscript(string) (string, error) { return f.DKG, nil }
func (f *fakeLedger) GetTally(string) (string, error)         { return f.Tally, nil }
func (f *fakeLedger) GetPartialDecryption(_, contestID, trusteeID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pd, ok := f.Partials[contestID+"|"+trusteeID]
	if !ok {
		return "", fmt.Errorf("no partial decryption for %s/%s", contestID, trusteeID)
	}
	return pd, nil
}

func (f *fakeLedger) getBallotCalls() int { return len(f.getBallotOrder()) }

func (f *fakeLedger) getBallotOrder() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.getBallots))
	copy(out, f.getBallots)
	return out
}

// commit assigns the next txID and its block, honouring blockSize. Callers hold
// no lock; commit takes it.
func (f *fakeLedger) commit(fn string) (string, uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fn)
	if fn == f.failOn {
		return "", 0, false
	}
	f.nextTx++
	if f.blockSize <= 1 || f.inBlock >= f.blockSize || f.nextBlk == 0 {
		f.nextBlk++
		f.inBlock = 0
	}
	f.inBlock++
	txID := fmt.Sprintf("tx-%d", f.nextTx)
	f.recordBlock(f.nextBlk, txID)
	return txID, f.nextBlk, true
}

// distinctBlocks is how many blocks the run actually landed in.
func (f *fakeLedger) distinctBlocks() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.blocks)
}

// qsccCalls is how many block/receipt reads the console made.
func (f *fakeLedger) qsccCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.qscc
}

func (f *fakeLedger) callNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeLedger) SubmitWithReceipt(fn string, args ...string) ([]byte, clientsdk.Receipt, error) {
	if f.beforeCommit != nil {
		f.beforeCommit(fn)
	}
	txID, blk, ok := f.commit(fn)
	if !ok {
		return nil, clientsdk.Receipt{}, errors.New("boom")
	}
	// The real SubmitWithReceipt follows the commit with a qscc lookup.
	f.mu.Lock()
	f.qscc++
	f.mu.Unlock()
	return nil, clientsdk.Receipt{TxID: txID, BlockNumber: blk}, nil
}
func (f *fakeLedger) Submit(fn string, args ...string) (string, uint64, error) {
	if fn == "SubmitBallot" {
		if err := f.ballotGate(args); err != nil {
			return "", 0, err
		}
	}
	txID, blk, ok := f.commit(fn)
	if !ok {
		return "", 0, errors.New("boom")
	}
	return txID, blk, nil
}

// recordBlock appends txID to block n. Callers hold f.mu.
func (f *fakeLedger) recordBlock(n uint64, txID string) {
	if f.blocks == nil {
		f.blocks = map[uint64][]string{}
	}
	f.blocks[n] = append(f.blocks[n], txID)
}
func (f *fakeLedger) LedgerReceipt(string) (clientsdk.Receipt, error) {
	f.mu.Lock()
	f.qscc++
	f.mu.Unlock()
	return clientsdk.Receipt{}, nil
}
func (f *fakeLedger) GetBlockByNumber(n uint64) (*common.Block, error) {
	f.mu.Lock()
	f.qscc++
	f.mu.Unlock()
	return &common.Block{Header: &common.BlockHeader{Number: n}}, nil
}
func (f *fakeLedger) ReceiptsForBlock(n uint64, txIDs []string) ([]clientsdk.Receipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.qscc++ // one block fetch, however many txIDs it covers
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
func (f *fakeLedger) ChainInfo() (uint64, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nextBlk + 1, nil, nil
}

// writeTestBundle writes a minimal run: 2 ballots in ballots.ndjson and a
// bundle with 2 partial decryptions referencing them. The hex payloads are
// opaque to the orchestrator — any hex works against the fake ledger.
func writeTestBundle(t *testing.T, runDir string) string {
	t.Helper()
	writeBallotLinesFile(t, runDir, 2)
	path := filepath.Join(runDir, "bundle.json")
	data := `{"election_id":"run-1","params":"aa","dkg":"bb","ballots_file":"ballots.ndjson","ballot_count":2,"partial_decryptions":["p0","p1"],"tally":"tt"}`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeBallotLinesFile writes n hex ballot lines into runDir.
func writeBallotLinesFile(t *testing.T, runDir string, n int) {
	t.Helper()
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%08x\n", i)
	}
	if err := os.WriteFile(filepath.Join(runDir, BallotsFile), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeTestBundleWithBallots writes a run with n ballots and no partial
// decryptions, so submitOnChain's setup prefix (CreateElection,
// PublishDKGTranscript, N x SubmitBallot, CloseElection) is the only part of
// the lifecycle that records anything before a caller-chosen failure point.
func writeTestBundleWithBallots(t *testing.T, runDir string, n int) string {
	t.Helper()
	writeBallotLinesFile(t, runDir, n)
	b := onChainBundle{
		ElectionID: "run-1", Params: "aa", DKG: "bb", Tally: "tt",
		BallotsFile: BallotsFile, BallotCount: n,
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(runDir, "bundle.json")
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
	err := e.submitOnChain(context.Background(), "run-1", ElectionConfig{}, led, writeTestBundle(t, filepath.Join(dir, "run-1")))
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
	err := e.submitOnChain(context.Background(), "run-1", ElectionConfig{}, led, writeTestBundle(t, filepath.Join(dir, "run-1")))
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
	path := writeTestBundleWithBallots(t, filepath.Join(dir, "run-1"), nBallots)

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
