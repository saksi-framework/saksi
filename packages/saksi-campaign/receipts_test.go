package campaign

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

func TestAppendReceipt(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 8, 22, 12, 30, 0, 0, time.UTC)
	ev := TrailEvent{Event: "SubmitBallot", Ref: "0", Receipt: clientsdk.Receipt{
		TxID: "tx1", BlockNumber: 7,
		BlockHash: []byte{0xaa}, DataHash: []byte{0xbb}, PreviousHash: []byte{0xcc},
		Timestamp: ts,
	}}
	if err := appendReceipt(dir, ev); err != nil {
		t.Fatal(err)
	}
	if err := appendReceipt(dir, TrailEvent{Event: "CloseElection", Receipt: clientsdk.Receipt{TxID: "tx2", BlockNumber: 8}}); err != nil {
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
	if lines[0] != "event,ref,tx_id,block_number,block_hash,data_hash,previous_hash,timestamp" {
		t.Fatalf("bad header: %s", lines[0])
	}
	if lines[1] != "SubmitBallot,0,tx1,7,aa,bb,cc,"+ts.Format(time.RFC3339) {
		t.Fatalf("bad row: %s", lines[1])
	}
	if !strings.HasSuffix(lines[2], ",") { // CloseElection has zero Timestamp: empty trailing column
		t.Fatalf("expected empty timestamp column, got: %s", lines[2])
	}

	var trail []TrailEvent
	data, err := os.ReadFile(filepath.Join(dir, "trail.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &trail); err != nil {
		t.Fatal(err)
	}
	if len(trail) != 2 || trail[1].Event != "CloseElection" {
		t.Fatalf("bad trail: %+v", trail)
	}
}
