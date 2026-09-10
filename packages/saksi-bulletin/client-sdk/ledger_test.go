package clientsdk

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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

// testDataHash stands in for fabric protoutil.BlockDataHash, which is not
// vendored here (only fabric-protos-go-apiv2 and fabric-gateway are, neither
// of which carries protoutil) — sha256 over the concatenated envelope bytes.
// This only needs to be a deterministic hash consistent with itself: neither
// VerifyChain nor blockHeaderHash recomputes DataHash from block data, they
// only ever chain blockHeaderHash off the header's stored PreviousHash/
// DataHash fields.
func testDataHash(data [][]byte) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// buildTestChain builds n linked synthetic blocks numbered 0..n-1, each
// carrying one envelope for "tx-<i>", with real blockHeaderHash chaining
// (block i's PreviousHash is blockHeaderHash of block i-1).
func buildTestChain(t *testing.T, n int) []*common.Block {
	t.Helper()
	blocks := make([]*common.Block, n)
	var prevHash []byte
	for i := 0; i < n; i++ {
		data := [][]byte{buildEnvelope(t, fmt.Sprintf("tx-%d", i), timestamppb.New(time.Now()))}
		dataHash := testDataHash(data)
		blocks[i] = &common.Block{
			Header: &common.BlockHeader{Number: uint64(i), PreviousHash: prevHash, DataHash: dataHash},
			Data:   &common.BlockData{Data: data},
		}
		prevHash = blockHeaderHash(uint64(i), prevHash, dataHash)
	}
	return blocks
}

func getBlockFromSlice(blocks []*common.Block) func(uint64) (*common.Block, error) {
	return func(n uint64) (*common.Block, error) {
		if n >= uint64(len(blocks)) {
			return nil, fmt.Errorf("no block %d", n)
		}
		return blocks[n], nil
	}
}

func TestVerifyChainLinkedPasses(t *testing.T) {
	blocks := buildTestChain(t, 3)
	report, err := verifyChain(0, 2, nil, getBlockFromSlice(blocks))
	if err != nil {
		t.Fatalf("verifyChain: %v", err)
	}
	if report.Status != "PASS" {
		t.Fatalf("Status = %q, want PASS (report: %+v)", report.Status, report)
	}
	if !report.Linked || report.FirstBreak != nil || report.Blocks != 3 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestVerifyChainTamperedPreviousHashFails(t *testing.T) {
	blocks := buildTestChain(t, 3)
	blocks[2].Header.PreviousHash = []byte("tampered")
	report, err := verifyChain(0, 2, nil, getBlockFromSlice(blocks))
	if err != nil {
		t.Fatalf("verifyChain: %v", err)
	}
	if report.Status != "FAIL" {
		t.Fatalf("Status = %q, want FAIL", report.Status)
	}
	if report.Linked {
		t.Fatal("Linked = true, want false")
	}
	if report.FirstBreak == nil || *report.FirstBreak != 2 {
		t.Fatalf("FirstBreak = %v, want 2", report.FirstBreak)
	}
}

func TestVerifyChainTamperedReceiptFails(t *testing.T) {
	blocks := buildTestChain(t, 3)
	good := receiptFromBlock("tx-1", blocks[1])
	bad := good
	bad.BlockHash = []byte("wrong-hash")
	report, err := verifyChain(0, 2, []Receipt{good, bad}, getBlockFromSlice(blocks))
	if err != nil {
		t.Fatalf("verifyChain: %v", err)
	}
	if report.ReceiptsChecked != 2 {
		t.Fatalf("ReceiptsChecked = %d, want 2", report.ReceiptsChecked)
	}
	if report.ReceiptMismatches != 1 {
		t.Fatalf("ReceiptMismatches = %d, want 1", report.ReceiptMismatches)
	}
	if !report.Linked {
		t.Fatal("Linked = false, want true (only the receipt was tampered)")
	}
	if report.Status != "FAIL" {
		t.Fatalf("Status = %q, want FAIL", report.Status)
	}
}

func TestVerifyChainFetchErrorNotRun(t *testing.T) {
	blocks := buildTestChain(t, 3)
	getBlock := func(n uint64) (*common.Block, error) {
		if n == 1 {
			return nil, errors.New("boom")
		}
		return getBlockFromSlice(blocks)(n)
	}
	report, err := verifyChain(0, 2, nil, getBlock)
	if err == nil {
		t.Fatal("verifyChain: want error on fetch failure")
	}
	if report.Status != "not run" {
		t.Fatalf("Status = %q, want %q", report.Status, "not run")
	}
	if report.Linked || report.Blocks != 0 {
		t.Fatalf("want a zero-value report on fetch error, got %+v", report)
	}
}

func TestVerifyChainSampleOutOfRangeSkipped(t *testing.T) {
	blocks := buildTestChain(t, 3)
	outOfRange := receiptFromBlock("tx-999", &common.Block{
		Header: &common.BlockHeader{Number: 999, PreviousHash: []byte("x"), DataHash: []byte("y")},
	})
	report, err := verifyChain(0, 2, []Receipt{outOfRange}, getBlockFromSlice(blocks))
	if err != nil {
		t.Fatalf("verifyChain: %v", err)
	}
	if report.ReceiptsChecked != 0 || report.ReceiptMismatches != 0 {
		t.Fatalf("out-of-range receipt should be skipped, got %+v", report)
	}
	if report.Status != "PASS" {
		t.Fatalf("Status = %q, want PASS", report.Status)
	}
}

func TestVerifyChainToBeforeFromErrors(t *testing.T) {
	report, err := verifyChain(5, 3, nil, getBlockFromSlice(buildTestChain(t, 6)))
	if err == nil {
		t.Fatal("verifyChain: want error when to < from")
	}
	if report.Status != "not run" {
		t.Fatalf("Status = %q, want %q", report.Status, "not run")
	}
}

func TestReceiptsForBlockTwoOfThreePresent(t *testing.T) {
	block := &common.Block{
		Header: &common.BlockHeader{Number: 5},
		Data: &common.BlockData{
			Data: [][]byte{
				buildEnvelope(t, "tx-a", timestamppb.New(time.Now())),
				buildEnvelope(t, "tx-b", timestamppb.New(time.Now())),
				buildEnvelope(t, "tx-c", timestamppb.New(time.Now())),
			},
		},
	}
	got := receiptsFromBlock(block, []string{"tx-a", "tx-c", "tx-missing"})
	if len(got) != 2 {
		t.Fatalf("want 2 receipts, got %d: %+v", len(got), got)
	}
	if got[0].TxID != "tx-a" || got[1].TxID != "tx-c" {
		t.Fatalf("want [tx-a, tx-c] in order, got %+v", got)
	}
}

func TestReceiptsForBlockNonePresent(t *testing.T) {
	block := &common.Block{
		Header: &common.BlockHeader{Number: 5},
		Data:   &common.BlockData{Data: [][]byte{buildEnvelope(t, "tx-a", timestamppb.New(time.Now()))}},
	}
	got := receiptsFromBlock(block, []string{"tx-missing"})
	if len(got) != 0 {
		t.Fatalf("want 0 receipts, got %d: %+v", len(got), got)
	}
}
