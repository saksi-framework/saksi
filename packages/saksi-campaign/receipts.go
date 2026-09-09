package campaign

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

// TrailEvent is one lifecycle event's ledger receipt, as recorded in the run
// folder (receipts.csv for the evidence-CSV export set, trail.ndjson for the
// UI's lifecycle trail).
type TrailEvent struct {
	Event   string            `json:"event"`
	Ref     string            `json:"ref"`
	Receipt clientsdk.Receipt `json:"receipt"`
}

const receiptsCSVHeader = "event,ref,tx_id,block_number,block_hash,data_hash,previous_hash,timestamp"

// receiptsCSVFields is len(strings.Split(receiptsCSVHeader, ",")) — the
// column count every well-formed data row must have.
const receiptsCSVFields = 8

// ErrTruncatedReceipts is returned by readReceipts alongside the rows parsed
// so far when receipts.csv's last line is a partial write (a crash mid
// Append) rather than a complete row.
var ErrTruncatedReceipts = errors.New("receipts.csv: truncated last row")

// receiptsWriter is the concurrency-safe, per-run sink for lifecycle
// receipts: every Append/Lifecycle call takes mu and issues one write —
// receipts.csv is only ever appended to, never rewritten, so N ballots costs
// N writes instead of the old rewrite-the-whole-trail O(n^2) behavior.
type receiptsWriter struct {
	mu     sync.Mutex
	f      *os.File // receipts.csv
	trail  *os.File // trail.ndjson
	runDir string
}

// openReceipts opens <runDir>/receipts.csv (O_APPEND|O_CREATE|O_WRONLY) and
// <runDir>/trail.ndjson the same way, writing the CSV header iff the file was
// empty at open (a size check, not an existence check — an empty pre-existing
// file still gets a header, a non-empty one never gets a second one).
func openReceipts(runDir string) (*receiptsWriter, error) {
	f, err := os.OpenFile(filepath.Join(runDir, "receipts.csv"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open receipts.csv: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat receipts.csv: %w", err)
	}
	if info.Size() == 0 {
		if _, err := fmt.Fprintln(f, receiptsCSVHeader); err != nil {
			f.Close()
			return nil, err
		}
	}

	trail, err := os.OpenFile(filepath.Join(runDir, trailNDJSONFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("open trail.ndjson: %w", err)
	}
	return &receiptsWriter{f: f, trail: trail, runDir: runDir}, nil
}

// Append writes ev as one locked CSV row to receipts.csv. Same columns/order
// as receiptsCSVHeader.
func (w *receiptsWriter) Append(ev TrailEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeCSVRow(ev)
}

// Lifecycle writes ev to receipts.csv (as Append does) and, under the same
// lock, appends one JSON line to trail.ndjson — never a rewrite.
func (w *receiptsWriter) Lifecycle(ev TrailEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.writeCSVRow(ev); err != nil {
		return err
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.trail.Write(data)
	return err
}

// writeCSVRow issues the row's Fprintf. Callers hold w.mu.
func (w *receiptsWriter) writeCSVRow(ev TrailEvent) error {
	r := ev.Receipt
	ts := ""
	if !r.Timestamp.IsZero() {
		ts = r.Timestamp.Format(time.RFC3339)
	}
	_, err := fmt.Fprintf(w.f, "%s,%s,%s,%d,%s,%s,%s,%s\n",
		ev.Event, ev.Ref, r.TxID, r.BlockNumber,
		hex.EncodeToString(r.BlockHash), hex.EncodeToString(r.DataHash), hex.EncodeToString(r.PreviousHash), ts)
	return err
}

// Close closes both underlying files.
func (w *receiptsWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	err := w.f.Close()
	if terr := w.trail.Close(); err == nil {
		err = terr
	}
	return err
}

// readReceipts parses receipts.csv with encoding/csv. A crash mid-Append
// leaves a truncated last line (fewer fields than the header, or a field that
// fails to decode) with no trailing newline; readReceipts tolerates that by
// returning every row parsed before it plus ErrTruncatedReceipts. A
// well-formed last row with no trailing newline is not truncated — encoding/csv
// accepts EOF as a valid record terminator.
func readReceipts(runDir string) ([]TrailEvent, error) {
	f, err := os.Open(filepath.Join(runDir, "receipts.csv"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open receipts.csv: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // validated manually below, so a short row is reported as truncation, not a hard error

	if _, err := r.Read(); err == io.EOF {
		return nil, nil // empty file: no header, no rows
	} else if err != nil {
		return nil, fmt.Errorf("read receipts.csv header: %w", err)
	}

	var events []TrailEvent
	for {
		row, err := r.Read()
		if err == io.EOF {
			return events, nil
		}
		if err != nil || len(row) < receiptsCSVFields {
			return events, ErrTruncatedReceipts
		}
		ev, perr := parseReceiptRow(row)
		if perr != nil {
			return events, ErrTruncatedReceipts
		}
		events = append(events, ev)
	}
}

func parseReceiptRow(row []string) (TrailEvent, error) {
	blockNum, err := strconv.ParseUint(row[3], 10, 64)
	if err != nil {
		return TrailEvent{}, err
	}
	blockHash, err := hex.DecodeString(row[4])
	if err != nil {
		return TrailEvent{}, err
	}
	dataHash, err := hex.DecodeString(row[5])
	if err != nil {
		return TrailEvent{}, err
	}
	prevHash, err := hex.DecodeString(row[6])
	if err != nil {
		return TrailEvent{}, err
	}
	var ts time.Time
	if row[7] != "" {
		ts, err = time.Parse(time.RFC3339, row[7])
		if err != nil {
			return TrailEvent{}, err
		}
	}
	return TrailEvent{
		Event: row[0],
		Ref:   row[1],
		Receipt: clientsdk.Receipt{
			TxID:         row[2],
			BlockNumber:  blockNum,
			BlockHash:    blockHash,
			DataHash:     dataHash,
			PreviousHash: prevHash,
			Timestamp:    ts,
		},
	}, nil
}
