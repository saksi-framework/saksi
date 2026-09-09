// Ledger receipts: proof that a transaction committed on the Fabric ledger.
//
// A Fabric block's hash is stored in no block field — it is SHA256 over the
// ASN.1-DER encoding of the header (number, previous_hash, data_hash), exactly
// as fabric's protoutil computes it. blockHeaderHash reproduces that, so
// receipts carry a real block hash for ANY block, tip or not.
package clientsdk

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"google.golang.org/protobuf/proto"
)

// Receipt is a transaction's ledger receipt.
type Receipt struct {
	TxID         string
	BlockNumber  uint64
	BlockHash    []byte
	DataHash     []byte
	PreviousHash []byte
	// Timestamp is the client's proposal time from the transaction's
	// ChannelHeader (not consensus/commit time). Zero if not found.
	Timestamp time.Time
}

// asn1Header mirrors fabric protoutil's ASN.1 block-header encoding.
type asn1Header struct {
	Number       *big.Int
	PreviousHash []byte
	DataHash     []byte
}

func blockHeaderHash(number uint64, previousHash, dataHash []byte) []byte {
	der, err := asn1.Marshal(asn1Header{
		Number:       new(big.Int).SetUint64(number),
		PreviousHash: previousHash,
		DataHash:     dataHash,
	})
	if err != nil {
		// Marshalling a struct of int + byte slices cannot fail at runtime.
		panic(err)
	}
	sum := sha256.Sum256(der)
	return sum[:]
}

// ChainReport is the result of walking a block range and checking it links up,
// plus spot-checking a sample of receipts against the blocks as served now.
// Status is never "PASS" unless the walk actually ran and both checks held —
// a fetch error or an unrun check must never read as success.
type ChainReport struct {
	Blocks            int
	Linked            bool
	FirstBreak        *uint64
	ReceiptsChecked   int
	ReceiptMismatches int
	Status            string // PASS|FAIL|not run
}

// Ledger is the receipt-bearing view of the chain. The console mocks this
// interface in unit tests; Connection provides the real one.
type Ledger interface {
	// SubmitWithReceipt submits a bulletin-chaincode transaction and returns
	// its result plus the ledger receipt (waits for commit; errors if the
	// transaction does not validate).
	SubmitWithReceipt(fn string, args ...string) ([]byte, Receipt, error)
	// Submit submits a bulletin-chaincode transaction and returns its
	// transaction ID and commit block number, without fetching a receipt
	// (no qscc call) — the untimed-submit half of SubmitWithReceipt, for
	// callers that time submission separately from receipt retrieval.
	Submit(fn string, args ...string) (txID string, blockNumber uint64, err error)
	// LedgerReceipt fetches the receipt for an already-committed transaction
	// via the qscc system chaincode.
	LedgerReceipt(txID string) (Receipt, error)
	// GetBlockByNumber fetches a decoded block by number via the qscc system
	// chaincode.
	GetBlockByNumber(n uint64) (*common.Block, error)
	// ReceiptsForBlock fetches block n once and returns the receipts for
	// whichever of txIDs are present in it, in the order given. txIDs absent
	// from the block are simply omitted (not an error).
	ReceiptsForBlock(n uint64, txIDs []string) ([]Receipt, error)
	// ChainInfo returns the channel height and the current (tip) block hash.
	ChainInfo() (height uint64, currentBlockHash []byte, err error)
	// VerifyChain walks blocks from..to (inclusive) and checks each block's
	// previous_hash links to the recomputed hash of its predecessor, then
	// spot-checks each Receipt in sample whose BlockNumber falls in range
	// against the hash the corresponding block serves now.
	VerifyChain(from, to uint64, sample []Receipt) (ChainReport, error)
}

// ledger implements Ledger over an open gateway connection.
type ledger struct {
	network  *client.Network
	contract *client.Contract // the bulletin chaincode
	qscc     *client.Contract
	channel  string
}

// Ledger returns the receipt-bearing view of this connection's channel.
func (c *Connection) Ledger() Ledger {
	network := c.gateway.GetNetwork(c.channel)
	return &ledger{
		network:  network,
		contract: network.GetContract(c.chaincode),
		qscc:     network.GetContract("qscc"),
		channel:  c.channel,
	}
}

func (l *ledger) SubmitWithReceipt(fn string, args ...string) ([]byte, Receipt, error) {
	result, commit, err := l.contract.SubmitAsync(fn, client.WithArguments(args...))
	if err != nil {
		return nil, Receipt{}, fmt.Errorf("submit %s: %w", fn, err)
	}
	status, err := commit.Status()
	if err != nil {
		return nil, Receipt{}, fmt.Errorf("commit status for %s: %w", fn, err)
	}
	if !status.Successful {
		return nil, Receipt{}, fmt.Errorf("%s tx %s did not validate (code %d)", fn, commit.TransactionID(), int32(status.Code))
	}
	receipt, err := l.LedgerReceipt(commit.TransactionID())
	if err != nil {
		return nil, Receipt{}, err
	}
	return result, receipt, nil
}

// Submit submits fn and waits for its commit status, returning the block
// number it landed in. It makes no qscc call, so it is the piece of
// SubmitWithReceipt safe to put inside a timed window.
func (l *ledger) Submit(fn string, args ...string) (string, uint64, error) {
	_, commit, err := l.contract.SubmitAsync(fn, client.WithArguments(args...))
	if err != nil {
		return "", 0, fmt.Errorf("submit %s: %w", fn, err)
	}
	status, err := commit.Status()
	if err != nil {
		return "", 0, fmt.Errorf("commit status for %s: %w", fn, err)
	}
	if !status.Successful {
		return "", 0, fmt.Errorf("%s tx %s did not validate (code %d)", fn, commit.TransactionID(), int32(status.Code))
	}
	return commit.TransactionID(), status.BlockNumber, nil
}

func (l *ledger) LedgerReceipt(txID string) (Receipt, error) {
	blockBytes, err := l.qscc.EvaluateTransaction("GetBlockByTxID", l.channel, txID)
	if err != nil {
		return Receipt{}, fmt.Errorf("qscc GetBlockByTxID: %w", err)
	}
	var block common.Block
	if err := proto.Unmarshal(blockBytes, &block); err != nil {
		return Receipt{}, fmt.Errorf("decode block: %w", err)
	}
	receipt := receiptFromBlock(txID, &block)
	if ts, ok := txTimestamp(&block, txID); ok {
		receipt.Timestamp = ts
	}
	return receipt, nil
}

// txTimestamp walks a block's envelopes looking for txID and returns the
// client proposal time recorded in its ChannelHeader. A malformed or
// non-matching envelope is skipped rather than treated as fatal: a missing
// timestamp should never fail receipt retrieval.
func txTimestamp(block *common.Block, txID string) (time.Time, bool) {
	for _, envBytes := range block.GetData().GetData() {
		var env common.Envelope
		if err := proto.Unmarshal(envBytes, &env); err != nil {
			continue
		}
		var payload common.Payload
		if err := proto.Unmarshal(env.GetPayload(), &payload); err != nil {
			continue
		}
		var chdr common.ChannelHeader
		if err := proto.Unmarshal(payload.GetHeader().GetChannelHeader(), &chdr); err != nil {
			continue
		}
		if chdr.GetTxId() != txID {
			continue
		}
		ts := chdr.GetTimestamp()
		if ts == nil {
			return time.Time{}, false
		}
		return ts.AsTime(), true
	}
	return time.Time{}, false
}

func (l *ledger) ChainInfo() (uint64, []byte, error) {
	infoBytes, err := l.qscc.EvaluateTransaction("GetChainInfo", l.channel)
	if err != nil {
		return 0, nil, fmt.Errorf("qscc GetChainInfo: %w", err)
	}
	var info common.BlockchainInfo
	if err := proto.Unmarshal(infoBytes, &info); err != nil {
		return 0, nil, fmt.Errorf("decode chain info: %w", err)
	}
	return info.GetHeight(), info.GetCurrentBlockHash(), nil
}

// GetBlockByNumber fetches and decodes block n via the qscc system chaincode.
func (l *ledger) GetBlockByNumber(n uint64) (*common.Block, error) {
	blockBytes, err := l.qscc.EvaluateTransaction("GetBlockByNumber", l.channel, strconv.FormatUint(n, 10))
	if err != nil {
		return nil, fmt.Errorf("qscc GetBlockByNumber: %w", err)
	}
	var block common.Block
	if err := proto.Unmarshal(blockBytes, &block); err != nil {
		return nil, fmt.Errorf("decode block: %w", err)
	}
	return &block, nil
}

// ReceiptsForBlock fetches block n once and returns receipts for whichever of
// txIDs it actually contains, in the order given. A txID not found in the
// block is omitted, not an error — the caller reconciles against what it
// submitted.
func (l *ledger) ReceiptsForBlock(n uint64, txIDs []string) ([]Receipt, error) {
	block, err := l.GetBlockByNumber(n)
	if err != nil {
		return nil, err
	}
	return receiptsFromBlock(block, txIDs), nil
}

// receiptsFromBlock returns receipts for whichever of txIDs are present in
// block, in the order given; a txID absent from the block is omitted, not an
// error. Pulled out of ReceiptsForBlock so it's testable without qscc.
func receiptsFromBlock(block *common.Block, txIDs []string) []Receipt {
	present := make(map[string]bool, len(block.GetData().GetData()))
	for _, envBytes := range block.GetData().GetData() {
		var env common.Envelope
		if err := proto.Unmarshal(envBytes, &env); err != nil {
			continue
		}
		var payload common.Payload
		if err := proto.Unmarshal(env.GetPayload(), &payload); err != nil {
			continue
		}
		var chdr common.ChannelHeader
		if err := proto.Unmarshal(payload.GetHeader().GetChannelHeader(), &chdr); err != nil {
			continue
		}
		present[chdr.GetTxId()] = true
	}
	receipts := make([]Receipt, 0, len(txIDs))
	for _, txID := range txIDs {
		if !present[txID] {
			continue
		}
		receipt := receiptFromBlock(txID, block)
		if ts, ok := txTimestamp(block, txID); ok {
			receipt.Timestamp = ts
		}
		receipts = append(receipts, receipt)
	}
	return receipts
}

// VerifyChain walks blocks from..to (inclusive), checking that each block's
// stated previous_hash matches the recomputed header hash of its predecessor,
// and spot-checks sample against the hashes the range serves now. Any block
// fetch error aborts with Status "not run" — VerifyChain never reports PASS
// without having actually walked the range.
func (l *ledger) VerifyChain(from, to uint64, sample []Receipt) (ChainReport, error) {
	return verifyChain(from, to, sample, l.GetBlockByNumber)
}

// verifyChain is VerifyChain's logic, parameterized over block fetching so
// it's testable without a live qscc. Any fetch error aborts immediately with
// Status "not run" — it must never report PASS without having walked the
// whole range.
func verifyChain(from, to uint64, sample []Receipt, getBlock func(uint64) (*common.Block, error)) (ChainReport, error) {
	report := ChainReport{Status: "not run"}
	if to < from {
		return report, fmt.Errorf("verify chain: to (%d) < from (%d)", to, from)
	}

	blocks := make(map[uint64]*common.Block, to-from+1)
	for n := from; n <= to; n++ {
		block, err := getBlock(n)
		if err != nil {
			return report, fmt.Errorf("verify chain: fetch block %d: %w", n, err)
		}
		blocks[n] = block
	}

	report.Blocks = len(blocks)
	report.Linked = true
	for n := from + 1; n <= to; n++ {
		prevHeader := blocks[n-1].GetHeader()
		wantPrevHash := blockHeaderHash(prevHeader.GetNumber(), prevHeader.GetPreviousHash(), prevHeader.GetDataHash())
		gotPrevHash := blocks[n].GetHeader().GetPreviousHash()
		if !bytes.Equal(gotPrevHash, wantPrevHash) {
			report.Linked = false
			broken := n
			report.FirstBreak = &broken
			break
		}
	}

	for _, r := range sample {
		if r.BlockNumber < from || r.BlockNumber > to {
			continue
		}
		report.ReceiptsChecked++
		h := blocks[r.BlockNumber].GetHeader()
		want := blockHeaderHash(h.GetNumber(), h.GetPreviousHash(), h.GetDataHash())
		if !bytes.Equal(r.BlockHash, want) {
			report.ReceiptMismatches++
		}
	}

	if report.Linked && report.ReceiptMismatches == 0 {
		report.Status = "PASS"
	} else {
		report.Status = "FAIL"
	}
	return report, nil
}

func receiptFromBlock(txID string, block *common.Block) Receipt {
	h := block.GetHeader()
	return Receipt{
		TxID:         txID,
		BlockNumber:  h.GetNumber(),
		BlockHash:    blockHeaderHash(h.GetNumber(), h.GetPreviousHash(), h.GetDataHash()),
		DataHash:     h.GetDataHash(),
		PreviousHash: h.GetPreviousHash(),
	}
}
