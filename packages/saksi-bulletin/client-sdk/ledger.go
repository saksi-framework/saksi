// Ledger receipts: proof that a transaction committed on the Fabric ledger.
//
// A Fabric block's hash is stored in no block field — it is SHA256 over the
// ASN.1-DER encoding of the header (number, previous_hash, data_hash), exactly
// as fabric's protoutil computes it. blockHeaderHash reproduces that, so
// receipts carry a real block hash for ANY block, tip or not.
package clientsdk

import (
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"

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

// Ledger is the receipt-bearing view of the chain. The console mocks this
// interface in unit tests; Connection provides the real one.
type Ledger interface {
	// SubmitWithReceipt submits a bulletin-chaincode transaction and returns
	// its result plus the ledger receipt (waits for commit; errors if the
	// transaction does not validate).
	SubmitWithReceipt(fn string, args ...string) ([]byte, Receipt, error)
	// LedgerReceipt fetches the receipt for an already-committed transaction
	// via the qscc system chaincode.
	LedgerReceipt(txID string) (Receipt, error)
	// ChainInfo returns the channel height and the current (tip) block hash.
	ChainInfo() (height uint64, currentBlockHash []byte, err error)
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

func (l *ledger) LedgerReceipt(txID string) (Receipt, error) {
	blockBytes, err := l.qscc.EvaluateTransaction("GetBlockByTxID", l.channel, txID)
	if err != nil {
		return Receipt{}, fmt.Errorf("qscc GetBlockByTxID: %w", err)
	}
	var block common.Block
	if err := proto.Unmarshal(blockBytes, &block); err != nil {
		return Receipt{}, fmt.Errorf("decode block: %w", err)
	}
	return receiptFromBlock(txID, &block), nil
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
