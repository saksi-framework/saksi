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
	"math/big"
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
