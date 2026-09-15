// Command samplechain captures and decodes a real Fabric ledger in full text,
// for the ledger-sample documentation (not part of the console or the study).
//
//	samplechain fetch --out DIR [--fabric-*]
//	samplechain decode --in DIR [--chaincode saksi-bulletin]
//	samplechain submit-ballot --hex-file F [--fabric-*]
//	samplechain submit-tampered-partial --bundle RUN/bundle.json --trustee ID --contest ID [--fabric-*]
//
// fetch pulls every block of the configured channel via qscc, byte for byte,
// into DIR/blocks/NNNN.block. decode then turns those blocks into an
// annotated full-text record: DIR/fulltext/NNNN.json (one file per block),
// DIR/index.json (one row per transaction) and DIR/ledger.txt (a readable
// walk of the chain) — see decode.go for what each field means.
//
// submit-ballot and submit-tampered-partial mount the two ledger-sample
// attacks: a ballot signed by an attacker's own credential (paired with
// `saksi-demo forge-ballot`, which builds the hex file), and a trustee's
// partial decryption with its Chaum-Pedersen proof deliberately broken (the
// same mutation a staged attack applies, via campaign.TamperPartialProof).
// Both submit for real — this is not a simulation — so run them only against
// a sample channel, never the study's.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	campaign "github.com/saksi-framework/saksi/packages/saksi-campaign"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "fetch":
		cmdFetch(os.Args[2:])
	case "decode":
		cmdDecode(os.Args[2:])
	case "submit-ballot":
		cmdSubmitBallot(os.Args[2:])
	case "submit-tampered-partial":
		cmdSubmitTamperedPartial(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: samplechain {fetch|decode|submit-ballot|submit-tampered-partial} [flags]")
}

// fabricFlags registers the same --fabric-* flags cmd/saksi-campaign's serve
// does (same names and defaults), so one bring-up script's flags work for
// both. Returns a getter rather than a value: flag.Parse must run first.
func fabricFlags(fs *flag.FlagSet) func() campaign.FabricConfig {
	peerEndpoint := fs.String("fabric-peer", "localhost:7051", "Fabric gateway peer endpoint (host:port)")
	gatewayPeer := fs.String("fabric-gateway-peer", "peer0.org1.example.com", "Fabric gateway peer TLS server name")
	tlsCert := fs.String("fabric-tls-cert", "", "path to the peer TLS CA certificate")
	mspID := fs.String("fabric-msp-id", "Org1MSP", "Fabric MSP id of the acting organization")
	cert := fs.String("fabric-cert", "", "path to the client identity certificate")
	key := fs.String("fabric-key", "", "path to the client identity private key")
	channel := fs.String("fabric-channel", "saksi", "Fabric channel to read or write")
	chaincode := fs.String("fabric-chaincode", "saksi-bulletin", "deployed chaincode name")
	return func() campaign.FabricConfig {
		return campaign.FabricConfig{
			PeerEndpoint: *peerEndpoint, GatewayPeer: *gatewayPeer, TLSCert: *tlsCert,
			MSPID: *mspID, Cert: *cert, Key: *key, Channel: *channel, Chaincode: *chaincode,
		}
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "samplechain: "+msg)
	os.Exit(1)
}

func must(err error) {
	if err != nil {
		fatal(err.Error())
	}
}

func cmdFetch(args []string) {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	out := fs.String("out", "", "directory to write blocks/NNNN.block into (required)")
	getCfg := fabricFlags(fs)
	must(fs.Parse(args))
	if *out == "" {
		fatal("fetch: --out is required")
	}
	cfg := getCfg()
	if !cfg.Enabled() {
		fatal("fetch: incomplete --fabric-* flags")
	}
	conn, err := cfg.Connect()
	must(err)
	defer conn.Close()
	led := conn.Ledger()

	height, _, err := led.ChainInfo()
	must(err)
	blocksDir := filepath.Join(*out, "blocks")
	must(os.MkdirAll(blocksDir, 0o755))
	for n := uint64(0); n < height; n++ {
		block, err := led.GetBlockByNumber(n)
		must(err)
		raw, err := proto.Marshal(block)
		must(err)
		must(os.WriteFile(filepath.Join(blocksDir, fmt.Sprintf("%04d.block", n)), raw, 0o644))
	}
	fmt.Printf("fetched %d blocks (channel %q) into %s\n", height, cfg.Channel, blocksDir)
}

func cmdDecode(args []string) {
	fs := flag.NewFlagSet("decode", flag.ExitOnError)
	in := fs.String("in", "", "directory holding blocks/NNNN.block, as fetch writes it (required)")
	ccName := fs.String("chaincode", "saksi-bulletin", "chaincode namespace to decode saksi values from")
	must(fs.Parse(args))
	if *in == "" {
		fatal("decode: --in is required")
	}
	blockFiles, err := filepath.Glob(filepath.Join(*in, "blocks", "*.block"))
	must(err)
	sort.Strings(blockFiles)
	if len(blockFiles) == 0 {
		fatal("decode: no blocks/*.block under " + *in + " — run fetch first")
	}

	fullTextDir := filepath.Join(*in, "fulltext")
	must(os.MkdirAll(fullTextDir, 0o755))

	var index []indexRow
	var ledgerTxt strings.Builder
	for _, bf := range blockFiles {
		raw, err := os.ReadFile(bf)
		must(err)
		var block common.Block
		must(proto.Unmarshal(raw, &block))

		var filter []byte
		if meta := block.GetMetadata().GetMetadata(); len(meta) > int(common.BlockMetadataIndex_TRANSACTIONS_FILTER) {
			filter = meta[common.BlockMetadataIndex_TRANSACTIONS_FILTER]
		}
		bd := decodeBlock(&block, filter, *ccName)

		j, err := json.MarshalIndent(bd, "", " ")
		must(err)
		must(os.WriteFile(filepath.Join(fullTextDir, fmt.Sprintf("%04d.json", bd.Number)), j, 0o644))

		writeLedgerText(&ledgerTxt, bd)
		for _, tx := range bd.Transactions {
			index = append(index, indexRow{
				Block: bd.Number, TxIndex: tx.Index, TxID: tx.TxID, Type: tx.Type,
				Function: tx.Function, Valid: tx.Valid, ValidationCode: tx.ValidationCode,
			})
		}
	}

	ij, err := json.MarshalIndent(index, "", " ")
	must(err)
	must(os.WriteFile(filepath.Join(*in, "index.json"), ij, 0o644))
	must(os.WriteFile(filepath.Join(*in, "ledger.txt"), []byte(ledgerTxt.String()), 0o644))
	fmt.Printf("decoded %d blocks, %d transactions, into %s\n", len(blockFiles), len(index), *in)
}

// indexRow is one row of index.json: one line per transaction across every
// block, so a reader can find "the SubmitBallot that committed block 9" (or
// count invalid transactions) without opening every fulltext/NNNN.json.
type indexRow struct {
	Block          uint64 `json:"block"`
	TxIndex        int    `json:"tx_index"`
	TxID           string `json:"tx_id"`
	Type           string `json:"type"`
	Function       string `json:"function,omitempty"`
	Valid          bool   `json:"valid"`
	ValidationCode string `json:"validation_code"`
}

// writeLedgerText appends bd as a readable walk of the chain: no JSON, just
// what a person reads to see what the block did.
func writeLedgerText(w *strings.Builder, bd BlockDecode) {
	fmt.Fprintf(w, "block %d  previous_hash=%s  header_hash=%s\n", bd.Number, short(bd.PreviousHash), short(bd.HeaderHash))
	for _, tx := range bd.Transactions {
		status := "valid"
		if !tx.Valid {
			status = "INVALID (" + tx.ValidationCode + ")"
		}
		fmt.Fprintf(w, "  tx %d  %s  %s  %s\n", tx.Index, tx.TxID, tx.Type, status)
		if tx.DecodeNote != "" {
			fmt.Fprintf(w, "    (%s)\n", tx.DecodeNote)
		}
		if tx.Function != "" {
			fmt.Fprintf(w, "    creator: %s\n", tx.CreatorMSP)
			fmt.Fprintf(w, "    function: %s\n", tx.Function)
			for _, a := range tx.Args {
				if a.Meaning != "" {
					fmt.Fprintf(w, "      arg[%d]: %s\n", a.Index, a.Meaning)
				} else {
					fmt.Fprintf(w, "      arg[%d]: %q\n", a.Index, a.Raw)
				}
			}
			for _, wr := range tx.Writes {
				if wr.Meaning != "" {
					fmt.Fprintf(w, "    wrote: %s\n", wr.Meaning)
				}
			}
			for _, e := range tx.Endorsers {
				fmt.Fprintf(w, "    endorsed by: %s\n", e.MSP)
			}
		}
	}
	w.WriteByte('\n')
}

func short(hexStr string) string {
	if len(hexStr) <= 16 {
		return hexStr
	}
	return hexStr[:8] + "…" + hexStr[len(hexStr)-8:]
}

func cmdSubmitBallot(args []string) {
	fs := flag.NewFlagSet("submit-ballot", flag.ExitOnError)
	hexFile := fs.String("hex-file", "", "file holding one hex-encoded Ballot, e.g. saksi-demo forge-ballot's output (required)")
	getCfg := fabricFlags(fs)
	must(fs.Parse(args))
	if *hexFile == "" {
		fatal("submit-ballot: --hex-file is required")
	}
	raw, err := os.ReadFile(*hexFile)
	must(err)
	cfg := getCfg()
	if !cfg.Enabled() {
		fatal("submit-ballot: incomplete --fabric-* flags")
	}
	conn, err := cfg.Connect()
	must(err)
	defer conn.Close()

	txID, block, err := conn.Ledger().Submit("SubmitBallot", strings.TrimSpace(string(raw)))
	if err != nil {
		fatal("submit-ballot: " + err.Error())
	}
	fmt.Printf("committed tx %s in block %d\n", txID, block)
}

// bundleDoc is the fields of a run's bundle.json or header.json this command
// needs — both carry election_id and partial_decryptions with the same JSON
// shape (executor.go's onChainBundle and stream.go's StreamHeader).
type bundleDoc struct {
	ElectionID         string   `json:"election_id"`
	PartialDecryptions []string `json:"partial_decryptions"`
}

func cmdSubmitTamperedPartial(args []string) {
	fs := flag.NewFlagSet("submit-tampered-partial", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "the run's bundle.json or header.json (required)")
	trustee := fs.String("trustee", "", "trustee id whose share to tamper (required)")
	contest := fs.String("contest", "", "contest id whose share to tamper, e.g. president/cand0 (required)")
	getCfg := fabricFlags(fs)
	must(fs.Parse(args))
	if *bundlePath == "" || *trustee == "" || *contest == "" {
		fatal("submit-tampered-partial: --bundle, --trustee and --contest are required")
	}

	raw, err := os.ReadFile(*bundlePath)
	must(err)
	var doc bundleDoc
	must(json.Unmarshal(raw, &doc))
	if doc.ElectionID == "" {
		fatal(*bundlePath + " has no election_id")
	}

	var found string
	for _, hexStr := range doc.PartialDecryptions {
		pdRaw, err := hex.DecodeString(hexStr)
		if err != nil {
			continue
		}
		var pd pb.PartialDecryption
		if proto.Unmarshal(pdRaw, &pd) != nil {
			continue
		}
		if pd.GetTrusteeId() == *trustee && pd.GetContestId() == *contest {
			found = hexStr
			break
		}
	}
	if found == "" {
		fatal(fmt.Sprintf("no partial decryption for trustee %q, contest %q in %s", *trustee, *contest, *bundlePath))
	}
	tampered, err := campaign.TamperPartialProof(found)
	must(err)

	cfg := getCfg()
	if !cfg.Enabled() {
		fatal("submit-tampered-partial: incomplete --fabric-* flags")
	}
	conn, err := cfg.Connect()
	must(err)
	defer conn.Close()

	txID, block, err := conn.Ledger().Submit("SubmitPartialDecryption", doc.ElectionID, tampered)
	if err != nil {
		fatal("submit-tampered-partial: " + err.Error())
	}
	fmt.Printf("committed tampered partial (trustee %s, contest %s) as tx %s in block %d\n", *trustee, *contest, txID, block)
}
