package clientsdk

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
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

// buildEnvelope builds a marshaled common.Envelope carrying the given txID
// and timestamp in its ChannelHeader, mirroring what a real proposal produces.
func buildEnvelope(t *testing.T, txID string, ts *timestamppb.Timestamp) []byte {
	t.Helper()
	chdr, err := proto.Marshal(&common.ChannelHeader{TxId: txID, Timestamp: ts})
	if err != nil {
		t.Fatalf("marshal channel header: %v", err)
	}
	payload, err := proto.Marshal(&common.Payload{Header: &common.Header{ChannelHeader: chdr}})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	env, err := proto.Marshal(&common.Envelope{Payload: payload})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return env
}

func TestTxTimestampFound(t *testing.T) {
	want := time.Date(2026, 8, 22, 12, 30, 0, 0, time.UTC)
	block := &common.Block{
		Data: &common.BlockData{
			Data: [][]byte{
				buildEnvelope(t, "other-tx", timestamppb.New(want.Add(-time.Hour))),
				buildEnvelope(t, "tx-abc", timestamppb.New(want)),
			},
		},
	}
	got, ok := txTimestamp(block, "tx-abc")
	if !ok {
		t.Fatal("txTimestamp: not found, want found")
	}
	if !got.Equal(want) {
		t.Fatalf("txTimestamp = %v, want %v", got, want)
	}
}

func TestTxTimestampNotFound(t *testing.T) {
	block := &common.Block{
		Data: &common.BlockData{
			Data: [][]byte{buildEnvelope(t, "other-tx", timestamppb.New(time.Now()))},
		},
	}
	if _, ok := txTimestamp(block, "tx-abc"); ok {
		t.Fatal("txTimestamp: found, want not found")
	}
}

func TestTxTimestampMalformedEnvelopeSkipped(t *testing.T) {
	block := &common.Block{
		Data: &common.BlockData{
			Data: [][]byte{[]byte("not a valid envelope"), buildEnvelope(t, "tx-abc", timestamppb.New(time.Now()))},
		},
	}
	if _, ok := txTimestamp(block, "tx-abc"); !ok {
		t.Fatal("txTimestamp: expected to find tx after skipping malformed envelope")
	}
}
