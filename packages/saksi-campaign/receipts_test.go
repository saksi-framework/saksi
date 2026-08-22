package campaign

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

func TestAppendReceipt(t *testing.T) {
	dir := t.TempDir()
	ev := TrailEvent{Event: "SubmitBallot", Ref: "0", Receipt: clientsdk.Receipt{
		TxID: "tx1", BlockNumber: 7,
		BlockHash: []byte{0xaa}, DataHash: []byte{0xbb}, PreviousHash: []byte{0xcc},
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
	if lines[0] != "event,ref,tx_id,block_number,block_hash,data_hash,previous_hash" {
		t.Fatalf("bad header: %s", lines[0])
	}
	if !strings.HasPrefix(lines[1], "SubmitBallot,0,tx1,7,aa,bb,cc") {
		t.Fatalf("bad row: %s", lines[1])
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
