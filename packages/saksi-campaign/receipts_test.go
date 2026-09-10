package campaign

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

func TestReceiptsWriterAppendWritesCSVRow(t *testing.T) {
	dir := t.TempDir()
	w, err := openReceipts(dir)
	if err != nil {
		t.Fatal(err)
	}

	ts := time.Date(2026, 8, 22, 12, 30, 0, 0, time.UTC)
	ev := TrailEvent{Event: "SubmitBallot", Ref: "0", Receipt: clientsdk.Receipt{
		TxID: "tx1", BlockNumber: 7,
		BlockHash: []byte{0xaa}, DataHash: []byte{0xbb}, PreviousHash: []byte{0xcc},
		Timestamp: ts,
	}}
	if err := w.Append(ev); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(TrailEvent{Event: "CloseElection", Receipt: clientsdk.Receipt{TxID: "tx2", BlockNumber: 8}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	csvBytes, err := os.ReadFile(filepath.Join(dir, "receipts.csv"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(csvBytes)), "\n")
	if len(lines) != 3 { // header + 2 rows
		t.Fatalf("want 3 csv lines, got %d: %q", len(lines), lines)
	}
	if lines[0] != receiptsCSVHeader {
		t.Fatalf("bad header: %s", lines[0])
	}
	if lines[1] != "SubmitBallot,0,tx1,7,aa,bb,cc,"+ts.Format(time.RFC3339) {
		t.Fatalf("bad row: %s", lines[1])
	}
	if !strings.HasSuffix(lines[2], ",") { // CloseElection has zero Timestamp: empty trailing column
		t.Fatalf("expected empty timestamp column, got: %s", lines[2])
	}
}

// TestOpenReceiptsHeaderWrittenOnceOnNonEmptyPreexistingFile: openReceipts
// checks the file's SIZE at open, not merely whether it already existed — a
// non-empty pre-existing receipts.csv (e.g. from a prior process on the same
// run) never gets a second header.
func TestOpenReceiptsHeaderWrittenOnceOnNonEmptyPreexistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipts.csv")
	seed := receiptsCSVHeader + "\nCreateElection,,tx0,1,,,,\n"
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	w, err := openReceipts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(TrailEvent{Event: "CloseElection", Receipt: clientsdk.Receipt{TxID: "tx1", BlockNumber: 2}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), receiptsCSVHeader) != 1 {
		t.Fatalf("header must be written exactly once, got: %q", data)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 { // 1 header + 2 rows
		t.Fatalf("want 3 lines (1 header + 2 rows), got %d: %q", len(lines), lines)
	}
}

// TestLifecycleWritesBothAppendWritesCSVOnly: Lifecycle events go to both
// receipts.csv and trail.ndjson; SubmitBallot (via Append) goes only to
// receipts.csv.
func TestLifecycleWritesBothAppendWritesCSVOnly(t *testing.T) {
	dir := t.TempDir()
	w, err := openReceipts(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := w.Append(TrailEvent{Event: "SubmitBallot", Ref: "0", Receipt: clientsdk.Receipt{TxID: "tx1", BlockNumber: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Lifecycle(TrailEvent{Event: "CloseElection", Receipt: clientsdk.Receipt{TxID: "tx2", BlockNumber: 2}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	csvData, err := os.ReadFile(filepath.Join(dir, "receipts.csv"))
	if err != nil {
		t.Fatal(err)
	}
	csvLines := strings.Split(strings.TrimSpace(string(csvData)), "\n")
	if len(csvLines) != 3 { // header + SubmitBallot + CloseElection
		t.Fatalf("want 3 csv lines, got %d: %q", len(csvLines), csvLines)
	}

	ndjsonData, err := os.ReadFile(filepath.Join(dir, "trail.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	ndjsonLines := strings.Split(strings.TrimSpace(string(ndjsonData)), "\n")
	if len(ndjsonLines) != 1 { // only the Lifecycle call, not the Append (SubmitBallot) call
		t.Fatalf("want 1 trail.ndjson line, got %d: %q", len(ndjsonLines), ndjsonLines)
	}
	if !strings.Contains(ndjsonLines[0], "CloseElection") {
		t.Fatalf("trail.ndjson line should be the CloseElection event, got: %s", ndjsonLines[0])
	}
}

// TestReceiptsWriterConcurrentAppend is the concurrency-safety proof: 8
// goroutines x 1,000 Append calls must land as exactly one header + 8,000
// data rows, every one of them parseable — never a torn/interleaved line.
func TestReceiptsWriterConcurrentAppend(t *testing.T) {
	dir := t.TempDir()
	w, err := openReceipts(dir)
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 8
	const perGoroutine = 1000
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				ev := TrailEvent{
					Event: "SubmitBallot",
					Ref:   fmt.Sprintf("%d-%d", g, i),
					Receipt: clientsdk.Receipt{
						TxID:        fmt.Sprintf("tx-%d-%d", g, i),
						BlockNumber: uint64(i),
					},
				}
				if err := w.Append(ev); err != nil {
					t.Errorf("Append: %v", err)
				}
			}
		}(g)
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(filepath.Join(dir, "receipts.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	headerCount, dataRows := 0, 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == receiptsCSVHeader {
			headerCount++
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) != receiptsCSVFields {
			t.Fatalf("row has %d fields, want %d: %q", len(fields), receiptsCSVFields, line)
		}
		dataRows++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if headerCount != 1 {
		t.Fatalf("want exactly 1 header line, got %d", headerCount)
	}
	if dataRows != goroutines*perGoroutine {
		t.Fatalf("want %d data rows, got %d", goroutines*perGoroutine, dataRows)
	}

	events, err := readReceipts(dir)
	if err != nil {
		t.Fatalf("readReceipts: %v", err)
	}
	if len(events) != goroutines*perGoroutine {
		t.Fatalf("readReceipts returned %d events, want %d", len(events), goroutines*perGoroutine)
	}
}

// TestReadReceiptsTruncatedLastLine: a crash mid-Append leaves a short last
// line (fewer fields than the header, no trailing newline). readReceipts must
// return the rows written before it plus ErrTruncatedReceipts.
func TestReadReceiptsTruncatedLastLine(t *testing.T) {
	dir := t.TempDir()
	w, err := openReceipts(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		ev := TrailEvent{Event: "SubmitBallot", Ref: fmt.Sprintf("%d", i),
			Receipt: clientsdk.Receipt{TxID: fmt.Sprintf("tx%d", i), BlockNumber: uint64(i)}}
		if err := w.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "receipts.csv")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("SubmitBallot,3,tx3"); err != nil { // no trailing newline, only 3 of 8 fields
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	events, err := readReceipts(dir)
	if !errors.Is(err, ErrTruncatedReceipts) {
		t.Fatalf("want ErrTruncatedReceipts, got %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("want 3 rows parsed before the truncated line, got %d: %+v", len(events), events)
	}
}

// TestReadReceiptsWellFormedLastLineWithoutTrailingNewlineIsNotTruncated: a
// complete last row missing only its trailing newline (e.g. the process was
// killed right after the write, before the next Append) is well-formed and
// must not be reported as truncated.
func TestReadReceiptsWellFormedLastLineWithoutTrailingNewlineIsNotTruncated(t *testing.T) {
	dir := t.TempDir()
	w, err := openReceipts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(TrailEvent{Event: "SubmitBallot", Ref: "0", Receipt: clientsdk.Receipt{TxID: "tx0", BlockNumber: 0}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "receipts.csv"))
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimRight(string(data), "\n")
	if err := os.WriteFile(filepath.Join(dir, "receipts.csv"), []byte(trimmed), 0o644); err != nil {
		t.Fatal(err)
	}

	events, err := readReceipts(dir)
	if err != nil {
		t.Fatalf("well-formed last line without a trailing newline must not be truncated, got err: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
}
