package campaign

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

// TrailEvent is one lifecycle event's ledger receipt, as recorded in the run
// folder (receipts.csv for the evidence-CSV export set, trail.json for the UI).
type TrailEvent struct {
	Event   string            `json:"event"`
	Ref     string            `json:"ref"`
	Receipt clientsdk.Receipt `json:"receipt"`
}

const receiptsCSVHeader = "event,ref,tx_id,block_number,block_hash,data_hash,previous_hash,timestamp"

// appendReceipt appends the event to receipts.csv (creating it with a header)
// and rewrites trail.json with the full ordered event list.
func appendReceipt(runDir string, ev TrailEvent) error {
	csvPath := filepath.Join(runDir, "receipts.csv")
	newFile := false
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		newFile = true
	}
	f, err := os.OpenFile(csvPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open receipts.csv: %w", err)
	}
	defer f.Close()
	if newFile {
		if _, err := fmt.Fprintln(f, receiptsCSVHeader); err != nil {
			return err
		}
	}
	r := ev.Receipt
	ts := ""
	if !r.Timestamp.IsZero() {
		ts = r.Timestamp.Format(time.RFC3339)
	}
	if _, err := fmt.Fprintf(f, "%s,%s,%s,%d,%s,%s,%s,%s\n",
		ev.Event, ev.Ref, r.TxID, r.BlockNumber,
		hex.EncodeToString(r.BlockHash), hex.EncodeToString(r.DataHash), hex.EncodeToString(r.PreviousHash), ts); err != nil {
		return err
	}

	trailPath := filepath.Join(runDir, "trail.json")
	var trail []TrailEvent
	if data, err := os.ReadFile(trailPath); err == nil {
		_ = json.Unmarshal(data, &trail) // corrupt trail.json: start over rather than fail the run
	}
	trail = append(trail, ev)
	data, err := json.MarshalIndent(trail, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(trailPath, data, 0o644)
}
