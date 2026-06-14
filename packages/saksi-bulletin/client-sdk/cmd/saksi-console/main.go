// Command saksi-console is an interactive driver for the Saksi bulletin board.
// It connects to a running Fabric network and runs the full election lifecycle
// from a demo bundle (produced by `saksi-demo gen`): create election, publish
// the DKG transcript, submit ballots, close, submit partial decryptions, and
// publish the tally — either step by step from a menu, or all at once with
// --auto.
//
// Example:
//
//	go run ./cmd/saksi-console \
//	  --tls-cert .../tlsca-cert.pem --cert .../cert.pem --key .../priv.pem \
//	  --msp-id Org1MSP --channel saksi --chaincode saksi-bulletin \
//	  --bundle /tmp/saksi-bundle.json          # add --auto for non-interactive
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// bundle mirrors the JSON emitted by `saksi-demo gen`.
type bundle struct {
	ElectionID         string   `json:"election_id"`
	Params             string   `json:"params"`
	DKG                string   `json:"dkg"`
	IssuerPK           string   `json:"issuer_pk"`
	BindingContext     string   `json:"binding_context"`
	Ballots            []string `json:"ballots"`
	PartialDecryptions []string `json:"partial_decryptions"`
	Tally              string   `json:"tally"`
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
	auto := flag.Bool("auto", false, "run the full election cycle non-interactively, then exit")
	flag.Parse()

	if *bundlePath == "" {
		log.Fatal("--bundle is required")
	}
	b := loadBundle(*bundlePath)

	conn, err := clientsdk.Connect(cfg)
	if err != nil {
		log.Fatalf("connect to bulletin board: %v", err)
	}
	defer func() { _ = conn.Close() }()
	client := conn.Bulletin

	fmt.Printf("Connected to %s (channel=%s chaincode=%s)\n", cfg.PeerEndpoint, cfg.Channel, cfg.Chaincode)
	fmt.Printf("Election %q: %d ballots, %d partial decryptions.\n",
		b.ElectionID, len(b.Ballots), len(b.PartialDecryptions))

	if *auto {
		if err := runFullCycle(client, b); err != nil {
			log.Fatalf("election cycle failed: %v", err)
		}
		return
	}
	menu(client, b)
}

func loadBundle(path string) bundle {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read bundle: %v", err)
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		log.Fatalf("parse bundle JSON: %v", err)
	}
	if b.ElectionID == "" || b.Params == "" {
		log.Fatal("bundle is missing election_id/params")
	}
	return b
}

func menu(client *clientsdk.BulletinClient, b bundle) {
	in := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(`
saksi-console
─────────────
 1) Create election
 2) Publish DKG transcript
 3) Submit ballots
 4) Election status
 5) Close election
 6) Submit partial decryptions
 7) Publish tally
 8) Get tally
 9) Run FULL cycle (1→7)
 0) Exit
select> `)
		if !in.Scan() {
			return
		}
		switch strings.TrimSpace(in.Text()) {
		case "1":
			report("CreateElection", client.CreateElection(b.Params))
		case "2":
			report("PublishDKGTranscript", client.PublishDKGTranscript(b.DKG))
		case "3":
			submitBallots(client, b)
		case "4":
			status, err := client.GetElectionStatus(b.ElectionID)
			if err != nil {
				report("GetElectionStatus", err)
			} else {
				fmt.Printf("  status = %s\n", status)
			}
		case "5":
			report("CloseElection", client.CloseElection(b.ElectionID))
		case "6":
			submitPartials(client, b)
		case "7":
			report("PublishTally", client.PublishTally(b.Tally))
		case "8":
			getTally(client, b)
		case "9":
			if err := runFullCycle(client, b); err != nil {
				fmt.Printf("  cycle stopped: %v\n", err)
			}
		case "0", "":
			return
		default:
			fmt.Println("  unknown option")
		}
	}
}

func runFullCycle(client *clientsdk.BulletinClient, b bundle) error {
	steps := []struct {
		name string
		fn   func() error
	}{
		{"CreateElection", func() error { return client.CreateElection(b.Params) }},
		{"PublishDKGTranscript", func() error { return client.PublishDKGTranscript(b.DKG) }},
		{"SubmitBallots", func() error { return submitBallots(client, b) }},
		{"CloseElection", func() error { return client.CloseElection(b.ElectionID) }},
		{"SubmitPartialDecryptions", func() error { return submitPartials(client, b) }},
		{"PublishTally", func() error { return client.PublishTally(b.Tally) }},
	}
	for _, s := range steps {
		fmt.Printf("→ %s ...\n", s.name)
		if err := s.fn(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}
	getTally(client, b)
	fmt.Println("✓ Full election cycle committed on the bulletin board.")
	return nil
}

// submitBallots submits every ballot and reads the first one back.
func submitBallots(client *clientsdk.BulletinClient, b bundle) error {
	for i, ballotHex := range b.Ballots {
		if err := client.SubmitBallot(ballotHex); err != nil {
			return fmt.Errorf("ballot %d: %w", i, err)
		}
		fmt.Printf("  ballot %d committed\n", i)
	}
	// Read the first ballot back as a liveness check.
	if len(b.Ballots) > 0 {
		nullifier, err := nullifierOf(b.Ballots[0])
		if err == nil {
			if _, err := client.GetBallot(b.ElectionID, nullifier); err != nil {
				return fmt.Errorf("read-back ballot 0: %w", err)
			}
			fmt.Printf("  read-back OK (nullifier %s…)\n", nullifier[:16])
		}
	}
	return nil
}

func submitPartials(client *clientsdk.BulletinClient, b bundle) error {
	for i, partialHex := range b.PartialDecryptions {
		if err := client.SubmitPartialDecryption(b.ElectionID, partialHex); err != nil {
			return fmt.Errorf("partial %d: %w", i, err)
		}
		fmt.Printf("  partial decryption %d committed\n", i)
	}
	return nil
}

func getTally(client *clientsdk.BulletinClient, b bundle) {
	got, err := client.GetTally(b.ElectionID)
	if err != nil {
		report("GetTally", err)
		return
	}
	if got == b.Tally {
		fmt.Println("  tally on-chain matches the published bundle.")
	} else {
		fmt.Println("  WARNING: on-chain tally differs from the bundle.")
	}
}

// nullifierOf decodes a hex ballot and returns its credential nullifier as hex.
func nullifierOf(ballotHex string) (string, error) {
	raw, err := hex.DecodeString(ballotHex)
	if err != nil {
		return "", err
	}
	var ballot saksiprotocolv1.Ballot
	if err := proto.Unmarshal(raw, &ballot); err != nil {
		return "", err
	}
	pres := ballot.GetCredentialPresentation()
	if pres == nil || pres.GetNullifier() == nil {
		return "", fmt.Errorf("ballot has no nullifier")
	}
	return hex.EncodeToString(pres.GetNullifier().GetValue()), nil
}

func report(op string, err error) {
	if err != nil {
		fmt.Printf("  %s: %v\n", op, err)
	} else {
		fmt.Printf("  %s: OK\n", op)
	}
}
