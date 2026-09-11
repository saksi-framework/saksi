package campaign

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

// readDumpFiles returns the two files the ledger dump writes.
func readDumpFiles(t *testing.T, runDir string) (ballots, header []byte) {
	t.Helper()
	dir := filepath.Join(runDir, LedgerDir)
	var err error
	if ballots, err = os.ReadFile(filepath.Join(dir, BallotsFile)); err != nil {
		t.Fatalf("read dumped ballots: %v", err)
	}
	if header, err = os.ReadFile(filepath.Join(dir, headerFile)); err != nil {
		t.Fatalf("read dumped header: %v", err)
	}
	return ballots, header
}

// TestLedgerDumpIsByteIdenticalOnBothReadPaths is the guarantee the batched
// read had to carry: the dump is an audited, published artifact, so making it
// cheaper must not change one byte of it. The same chain is dumped twice —
// once with GetBallots, once with the chaincode pretending not to have it —
// and both files, plus the nullifier-set digest the cross-check compares, must
// come out the same.
func TestLedgerDumpIsByteIdenticalOnBothReadPaths(t *testing.T) {
	_, runID, runDir, led := newLedgerRun(t, 7)

	n, path, err := dumpLedger(runDir, runID, led)
	if err != nil {
		t.Fatalf("batched dumpLedger: %v", err)
	}
	if path != ledgerReadBatched {
		t.Fatalf("read path = %q, want %q", path, ledgerReadBatched)
	}
	if n != 7 {
		t.Fatalf("dumped %d ballots, want 7", n)
	}
	batchedBallots, batchedHeader := readDumpFiles(t, runDir)
	batchedDigest, err := nullifierSetDigest(filepath.Join(runDir, LedgerDir))
	if err != nil {
		t.Fatalf("digest the batched dump: %v", err)
	}
	// The batched path must actually have been used: one page, not seven reads.
	if got := led.batchSizes(); len(got) != 1 || got[0] != 7 {
		t.Fatalf("GetBallots pages = %v, want one page of 7", got)
	}

	// Now the same chain, on chaincode that has never heard of GetBallots.
	led.noBatch = true
	before := led.getBallotCalls()
	n2, path2, err := dumpLedger(runDir, runID, led)
	if err != nil {
		t.Fatalf("fallback dumpLedger: %v", err)
	}
	if path2 != ledgerReadPerBallot {
		t.Fatalf("read path = %q, want %q", path2, ledgerReadPerBallot)
	}
	if n2 != n {
		t.Fatalf("fallback dumped %d ballots, batched dumped %d", n2, n)
	}
	if got := led.getBallotCalls() - before; got != 7 {
		t.Fatalf("the fallback made %d GetBallot calls, want 7 (one per ballot)", got)
	}
	fallbackBallots, fallbackHeader := readDumpFiles(t, runDir)
	fallbackDigest, err := nullifierSetDigest(filepath.Join(runDir, LedgerDir))
	if err != nil {
		t.Fatalf("digest the fallback dump: %v", err)
	}

	if !bytes.Equal(batchedBallots, fallbackBallots) {
		t.Fatalf("ballots.ndjson differs between the read paths\nbatched:  %q\nfallback: %q",
			batchedBallots, fallbackBallots)
	}
	if !bytes.Equal(batchedHeader, fallbackHeader) {
		t.Fatalf("header.json differs between the read paths\nbatched:  %s\nfallback: %s",
			batchedHeader, fallbackHeader)
	}
	if batchedDigest != fallbackDigest {
		t.Fatalf("nullifier-set digest differs: %s vs %s", batchedDigest, fallbackDigest)
	}
}

// TestLedgerDumpPagesAtTheBatchCap pins the paging: more ballots than one page
// holds are fetched in full pages, never one oversized call, and the lines come
// out in ListNullifiers order.
func TestLedgerDumpPagesAtTheBatchCap(t *testing.T) {
	const n = clientsdk.BallotBatchSize*2 + 37
	led := &fakeLedger{Ballots: map[string]string{}}
	for i := 0; i < n; i++ {
		nul := fmt.Sprintf("%064x", i+1)
		led.accept(nul)
		led.Ballots[nul] = hex.EncodeToString([]byte(nul))
	}

	dir := t.TempDir()
	got, path, err := dumpLedgerBallots(dir, "election-2026", led)
	if err != nil {
		t.Fatalf("dumpLedgerBallots: %v", err)
	}
	if got != n || path != ledgerReadBatched {
		t.Fatalf("dumped %d ballots via %q, want %d via %q", got, path, n, ledgerReadBatched)
	}
	want := []int{clientsdk.BallotBatchSize, clientsdk.BallotBatchSize, 37}
	sizes := led.batchSizes()
	if len(sizes) != len(want) {
		t.Fatalf("GetBallots pages = %v, want %v", sizes, want)
	}
	for i := range want {
		if sizes[i] != want[i] {
			t.Fatalf("GetBallots pages = %v, want %v", sizes, want)
		}
	}

	// Order: the dump must be exactly ListNullifiers' order, ballot for ballot.
	page, err := led.ListNullifiers("election-2026", nullifierPageSize, "")
	if err != nil {
		t.Fatal(err)
	}
	var expect bytes.Buffer
	for _, nul := range page.Nullifiers {
		expect.WriteString(led.Ballots[nul] + "\n")
	}
	data, err := os.ReadFile(filepath.Join(dir, BallotsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, expect.Bytes()) {
		t.Fatal("the dumped ballots are not in ListNullifiers order")
	}
}

// TestLedgerDumpFailsOnABallotTheChainLists is the absence contract at the
// client end: the chaincode reports a missing ballot as an empty entry, and the
// dump treats that as the fault it is — a chain disagreeing with its own
// nullifier index — rather than writing a blank line into an audited artifact.
func TestLedgerDumpFailsOnABallotTheChainLists(t *testing.T) {
	led := &fakeLedger{Ballots: map[string]string{}}
	for i := 0; i < 3; i++ {
		nul := fmt.Sprintf("%064x", i+1)
		led.accept(nul)
		led.Ballots[nul] = hex.EncodeToString([]byte(nul))
	}
	delete(led.Ballots, fmt.Sprintf("%064x", 2))

	if _, _, err := dumpLedgerBallots(t.TempDir(), "election-2026", led); err == nil {
		t.Fatal("a listed nullifier with no ballot must fail the dump")
	}
}

// bigFakeChain is a chain holding n ballots under deterministic 32-byte
// nullifiers, plus the expected ballots.ndjson for it in ListNullifiers order.
func bigFakeChain(t *testing.T, n int) (*fakeLedger, []byte) {
	t.Helper()
	led := &fakeLedger{Ballots: map[string]string{}}
	for i := 0; i < n; i++ {
		nul := fmt.Sprintf("%064x", i+1)
		led.accept(nul)
		led.Ballots[nul] = hex.EncodeToString([]byte(nul))
	}
	var want bytes.Buffer
	bookmark := ""
	for {
		page, err := led.ListNullifiers("election-2026", nullifierPageSize, bookmark)
		if err != nil {
			t.Fatal(err)
		}
		for _, nul := range page.Nullifiers {
			want.WriteString(led.Ballots[nul] + "\n")
		}
		if page.NextBookmark == "" || page.NextBookmark == bookmark {
			break
		}
		bookmark = page.NextBookmark
	}
	return led, want.Bytes()
}

// smallNullifierPages shrinks the ListNullifiers page size for one test, so a
// multi-page outer walk is reachable without seeding 10,000 ballots.
func smallNullifierPages(t *testing.T, size int) {
	t.Helper()
	was := nullifierPageSize
	nullifierPageSize = size
	t.Cleanup(func() { nullifierPageSize = was })
}

// TestLedgerDumpSpansMultipleNullifierPages walks more than one ListNullifiers
// page, each of which needs more than one GetBallots page. The nesting is the
// part that can go wrong — a chunk loop that reset per outer page, or a
// bookmark advanced before the last chunk was written, would lose or repeat
// ballots — so the dump is compared line for line against the chain's own
// listing order, and the batch sizes against the page arithmetic.
func TestLedgerDumpSpansMultipleNullifierPages(t *testing.T) {
	smallNullifierPages(t, 1200)
	const n = 2600 // outer pages of 1200, 1200, 200
	led, want := bigFakeChain(t, n)

	dir := t.TempDir()
	got, path, err := dumpLedgerBallots(dir, "election-2026", led)
	if err != nil {
		t.Fatalf("dumpLedgerBallots: %v", err)
	}
	if got != n || path != ledgerReadBatched {
		t.Fatalf("dumped %d ballots via %q, want %d via %q", got, path, n, ledgerReadBatched)
	}
	// 1200 = 500+500+200 twice, then 200.
	wantSizes := []int{500, 500, 200, 500, 500, 200, 200}
	if fmt.Sprint(led.batchSizes()) != fmt.Sprint(wantSizes) {
		t.Fatalf("GetBallots pages = %v, want %v", led.batchSizes(), wantSizes)
	}
	data, err := os.ReadFile(filepath.Join(dir, BallotsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Fatal("a multi-page dump is not the chain's ballots in listing order")
	}
}

// TestLedgerDumpFallsBackPartwayThroughAPopulation is the upgrade-in-flight
// case the fallback exists for, at its most awkward: the batched read works for
// a while and then stops being available. The chunk in progress must be redone
// per ballot (not skipped, not duplicated), the rest of the population must
// follow the same path, and the file must still come out byte-identical to a
// dump that never batched at all.
func TestLedgerDumpFallsBackPartwayThroughAPopulation(t *testing.T) {
	smallNullifierPages(t, 1200)
	const n = 2600
	led, want := bigFakeChain(t, n)
	led.noBatchAfter = 4 // batched through the first outer page and one chunk of the second

	dir := t.TempDir()
	got, path, err := dumpLedgerBallots(dir, "election-2026", led)
	if err != nil {
		t.Fatalf("dumpLedgerBallots: %v", err)
	}
	if got != n {
		t.Fatalf("dumped %d ballots, want %d", got, n)
	}
	if path != ledgerReadPerBallot {
		t.Fatalf("read path = %q, want %q once the fallback has fired", path, ledgerReadPerBallot)
	}
	data, err := os.ReadFile(filepath.Join(dir, BallotsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Fatal("the dump that fell back partway is not byte-identical to the chain's listing order")
	}

	// And identical to a dump that never batched: same bytes, different path.
	plain, _ := bigFakeChain(t, n)
	plain.noBatch = true
	plainDir := t.TempDir()
	if _, plainPath, err := dumpLedgerBallots(plainDir, "election-2026", plain); err != nil {
		t.Fatalf("per-ballot dumpLedgerBallots: %v", err)
	} else if plainPath != ledgerReadPerBallot {
		t.Fatalf("read path = %q, want %q", plainPath, ledgerReadPerBallot)
	}
	plainData, err := os.ReadFile(filepath.Join(plainDir, BallotsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, plainData) {
		t.Fatal("the partway-fallback dump and the never-batched dump differ")
	}
}
