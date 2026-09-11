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
