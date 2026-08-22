package clientsdk

import (
	"encoding/hex"
	"testing"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// Golden values captured from the QSCC spike (CI run 32551023972, Fabric
// 2.5.15): GetChainInfo.CurrentBlockHash at height 29 is the hash of block 28.
func TestBlockHeaderHashGolden(t *testing.T) {
	prev := mustHex(t, "003ef1053b17f9cf286bd087f03dbd72cddb7c1fb8f2e680128c32e5c6db6b8d")
	data := mustHex(t, "9cd1500e262501b40b0c9c7dba2dc17fd7282d3b9f91c04f26f6564d774d3655")
	want := "5f896f60ee4a5a755dacd92ba162a707299621442683754c2469de8a123c43da"
	got := hex.EncodeToString(blockHeaderHash(28, prev, data))
	if got != want {
		t.Fatalf("blockHeaderHash = %s, want %s", got, want)
	}
}

func TestReceiptFromBlock(t *testing.T) {
	prev := mustHex(t, "003ef1053b17f9cf286bd087f03dbd72cddb7c1fb8f2e680128c32e5c6db6b8d")
	data := mustHex(t, "9cd1500e262501b40b0c9c7dba2dc17fd7282d3b9f91c04f26f6564d774d3655")
	block := &common.Block{Header: &common.BlockHeader{Number: 28, PreviousHash: prev, DataHash: data}}
	r := receiptFromBlock("tx-abc", block)
	if r.TxID != "tx-abc" || r.BlockNumber != 28 {
		t.Fatalf("bad receipt identity: %+v", r)
	}
	if hex.EncodeToString(r.BlockHash) != "5f896f60ee4a5a755dacd92ba162a707299621442683754c2469de8a123c43da" {
		t.Fatalf("bad block hash: %x", r.BlockHash)
	}
}
