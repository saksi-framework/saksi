// Command qscc-probe — THROWAWAY (QSCC spike).
//
// Proves that a ballot committed to the saksi chaincode has a retrievable
// ledger receipt (block number, tx id, block hash) via Fabric's qscc system
// chaincode. It submits ONE ballot from a `saksi-demo gen` bundle (the
// election must already be set up on-chain, e.g. via `saksi-console
// --setup-only --bundle <same bundle>`), captures the transaction id from the
// gateway commit, then queries qscc:
//
//	GetBlockByTxID(channel, txid)   — the required call: the block holding the tx
//	GetChainInfo(channel)           — height + CurrentBlockHash (the block hash, at tip)
//	GetBlockByNumber(channel, N)    — corroboration only
//
// NOTE on "block hash": a Fabric block's hash is SHA256 over the ASN.1-DER
// header and is stored in no block field. Right after commit the ballot's
// block is the chain tip, so GetChainInfo.CurrentBlockHash IS its hash. The
// real audit-trail feature must compute the ASN.1 header hash (or read block
// N+1's previous_hash) for non-tip blocks.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	"google.golang.org/protobuf/proto"
)

// bundle mirrors the JSON emitted by `saksi-demo gen` (subset the probe needs).
type bundle struct {
	ElectionID string   `json:"election_id"`
	Ballots    []string `json:"ballots"`
}

func main() {
	var cfg clientsdk.ConnectionConfig
	flag.StringVar(&cfg.PeerEndpoint, "peer-endpoint", "localhost:7051", "gateway peer host:port")
	flag.StringVar(&cfg.GatewayPeer, "gateway-peer", "peer0.org1.example.com", "peer TLS server name override")
	flag.StringVar(&cfg.TLSCertPath, "tls-cert", "", "PEM file with the peer's TLS CA certificate")
	flag.StringVar(&cfg.MSPID, "msp-id", "Org1MSP", "acting organization MSP id")
	flag.StringVar(&cfg.CertPath, "cert", "", "PEM file with the client identity certificate")
	flag.StringVar(&cfg.KeyPath, "key", "", "PEM file with the client identity private key")
	flag.StringVar(&cfg.Channel, "channel", "saksi", "Fabric channel name")
	flag.StringVar(&cfg.Chaincode, "chaincode", "saksi-bulletin", "deployed chaincode name")
	bundlePath := flag.String("bundle", "", "path to a demo bundle JSON (from `saksi-demo gen`) (required)")
	ballotIndex := flag.Int("ballot-index", 0, "which bundle ballot to submit (retry escape: a crashed run's nullifier is spent)")
	flag.Parse()

	if *bundlePath == "" {
		log.Fatal("--bundle is required")
	}
	raw, err := os.ReadFile(*bundlePath)
	if err != nil {
		log.Fatalf("read bundle: %v", err)
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		log.Fatalf("parse bundle: %v", err)
	}
	if *ballotIndex < 0 || *ballotIndex >= len(b.Ballots) {
		log.Fatalf("--ballot-index %d out of range (bundle has %d ballots)", *ballotIndex, len(b.Ballots))
	}
	ballotHex := b.Ballots[*ballotIndex]

	conn, err := clientsdk.Connect(cfg)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	network := conn.Gateway().GetNetwork(cfg.Channel)
	contract := network.GetContract(cfg.Chaincode)

	fmt.Printf("Submitting ballot %d of election %q...\n", *ballotIndex, b.ElectionID)
	_, commit, err := contract.SubmitAsync("SubmitBallot", client.WithArguments(ballotHex))
	if err != nil {
		log.Fatalf("submit ballot: %v", err)
	}
	txid := commit.TransactionID()
	status, err := commit.Status()
	if err != nil {
		log.Fatalf("commit status: %v", err)
	}
	if !status.Successful {
		log.Fatalf("transaction %s did NOT commit: validation code %d", txid, int32(status.Code))
	}
	fmt.Printf("Committed: txid=%s block_number=%d (from Commit.Status — free at submit time)\n",
		txid, status.BlockNumber)

	qscc := network.GetContract("qscc")

	// The required call: block by tx id.
	blockBytes, err := qscc.EvaluateTransaction("GetBlockByTxID", cfg.Channel, txid)
	if err != nil {
		log.Fatalf("qscc GetBlockByTxID: %v", err)
	}
	var block common.Block
	if err := proto.Unmarshal(blockBytes, &block); err != nil {
		log.Fatalf("decode block: %v", err)
	}
	fmt.Printf("GetBlockByTxID: block_number=%d data_hash=%x previous_hash=%x txs=%d\n",
		block.GetHeader().GetNumber(), block.GetHeader().GetDataHash(),
		block.GetHeader().GetPreviousHash(), len(block.GetData().GetData()))
	if !blockContainsTx(&block, txid) {
		log.Fatalf("FAIL: txid %s not found inside the returned block", txid)
	}
	fmt.Println("txid found inside the block ✔")
	if block.GetHeader().GetNumber() != status.BlockNumber {
		log.Fatalf("FAIL: GetBlockByTxID block %d != Commit.Status block %d",
			block.GetHeader().GetNumber(), status.BlockNumber)
	}

	// Corroboration: chain info (height + the tip's block hash).
	infoBytes, err := qscc.EvaluateTransaction("GetChainInfo", cfg.Channel)
	if err != nil {
		log.Fatalf("qscc GetChainInfo: %v", err)
	}
	var info common.BlockchainInfo
	if err := proto.Unmarshal(infoBytes, &info); err != nil {
		log.Fatalf("decode chain info: %v", err)
	}
	fmt.Printf("GetChainInfo: height=%d current_block_hash=%x previous_block_hash=%x\n",
		info.GetHeight(), info.GetCurrentBlockHash(), info.GetPreviousBlockHash())
	if info.GetHeight() == block.GetHeader().GetNumber()+1 {
		fmt.Printf("ballot block is the chain tip → BLOCK HASH = %x (CurrentBlockHash)\n",
			info.GetCurrentBlockHash())
	} else {
		fmt.Println("NOTE: chain advanced past the ballot block; block hash needs the ASN.1 header computation (feature-phase).")
	}

	// Corroboration: same block by number.
	byNumBytes, err := qscc.EvaluateTransaction("GetBlockByNumber", cfg.Channel,
		strconv.FormatUint(block.GetHeader().GetNumber(), 10))
	if err != nil {
		log.Fatalf("qscc GetBlockByNumber: %v", err)
	}
	var byNum common.Block
	if err := proto.Unmarshal(byNumBytes, &byNum); err != nil {
		log.Fatalf("decode block-by-number: %v", err)
	}
	if !proto.Equal(byNum.GetHeader(), block.GetHeader()) {
		log.Fatal("FAIL: GetBlockByNumber header differs from GetBlockByTxID header")
	}
	fmt.Println("GetBlockByNumber header matches ✔")

	fmt.Println("\nRECEIPT (spike answer: YES)")
	fmt.Printf("  tx_id         = %s\n", txid)
	fmt.Printf("  block_number  = %d\n", block.GetHeader().GetNumber())
	fmt.Printf("  block_hash    = %x (CurrentBlockHash while at tip)\n", info.GetCurrentBlockHash())
	fmt.Printf("  data_hash     = %x\n", block.GetHeader().GetDataHash())
	fmt.Printf("  previous_hash = %x\n", block.GetHeader().GetPreviousHash())
	fmt.Printf("  chain_height  = %d\n", info.GetHeight())
}

// blockContainsTx scans the block's envelopes for the channel-header tx id.
func blockContainsTx(block *common.Block, txid string) bool {
	for _, envBytes := range block.GetData().GetData() {
		var env common.Envelope
		if err := proto.Unmarshal(envBytes, &env); err != nil {
			continue
		}
		var payload common.Payload
		if err := proto.Unmarshal(env.GetPayload(), &payload); err != nil {
			continue
		}
		var ch common.ChannelHeader
		if err := proto.Unmarshal(payload.GetHeader().GetChannelHeader(), &ch); err != nil {
			continue
		}
		if ch.GetTxId() == txid {
			return true
		}
	}
	return false
}
