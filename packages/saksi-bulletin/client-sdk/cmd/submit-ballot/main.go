// Command submit-ballot runs a single end-to-end bulletin-board transaction
// against a running Saksi Fabric network: it submits one ballot and reads it
// back. It is the smallest demonstration that the chaincode, network, and SDK
// work together.
//
// Example (paths point at MSP material produced by the dev network):
//
//	go run ./cmd/submit-ballot \
//	  --peer-endpoint localhost:7051 \
//	  --gateway-peer peer0.org1.example.com \
//	  --tls-cert   organizations/.../tlsca/tlsca-cert.pem \
//	  --cert       organizations/.../User1@org1/msp/signcerts/cert.pem \
//	  --key        organizations/.../User1@org1/msp/keystore/priv.pem \
//	  --msp-id Org1MSP --channel saksi --chaincode saksi-bulletin \
//	  --ballot ../../../saksi-protocol/test-vectors/ballot-v1.hex
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	saksiprotocol "github.com/saksi-framework/saksi/packages/saksi-protocol/go"
)

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
	ballotPath := flag.String("ballot", "", "path to a file holding a hex-encoded ballot (required)")
	flag.Parse()

	if *ballotPath == "" {
		log.Fatal("--ballot is required")
	}
	raw, err := os.ReadFile(*ballotPath)
	if err != nil {
		log.Fatalf("read ballot file: %v", err)
	}
	ballotHex := strings.TrimSpace(string(raw))

	decoded, err := hex.DecodeString(ballotHex)
	if err != nil {
		log.Fatalf("ballot is not valid hex: %v", err)
	}
	ballot, err := saksiprotocol.UnmarshalBallot(decoded)
	if err != nil {
		log.Fatalf("decode ballot: %v", err)
	}
	if ballot.CredentialPresentation == nil || ballot.CredentialPresentation.Nullifier == nil {
		log.Fatal("ballot has no credential-presentation nullifier")
	}
	nullifier := hex.EncodeToString(ballot.CredentialPresentation.Nullifier.Value)

	conn, err := clientsdk.Connect(cfg)
	if err != nil {
		log.Fatalf("connect to bulletin board: %v", err)
	}
	defer func() { _ = conn.Close() }()

	fmt.Println("Submitting ballot...")
	if err := conn.Bulletin.SubmitBallot(ballotHex); err != nil {
		log.Fatalf("submit ballot: %v", err)
	}
	fmt.Println("Ballot endorsed, ordered, and committed.")

	fmt.Printf("Reading it back (election=%q nullifier=%s)...\n", ballot.ElectionID, nullifier)
	got, err := conn.Bulletin.GetBallot(ballot.ElectionID, nullifier)
	if err != nil {
		log.Fatalf("get ballot: %v", err)
	}
	if got == ballotHex {
		fmt.Println("Round-trip OK: the bulletin board returned the same ballot.")
		return
	}
	fmt.Println("WARNING: the returned ballot differs from the submitted ballot.")
	os.Exit(1)
}
