package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// TestCallerFingerprintMatchesSharedVector pins callerOf's fingerprint to
// saksi-protocol/test-vectors/machine-fingerprint-v1.json, the vector the
// client SDK's CertFingerprint is checked against too: what a console
// registers is what the chaincode compares.
func TestCallerFingerprintMatchesSharedVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "saksi-protocol", "test-vectors", "machine-fingerprint-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		CertPEM     string `json:"cert_pem"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(v.CertPEM))
	if block == nil {
		t.Fatal("vector cert_pem holds no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ctx := newContext().as(&fakeIdentity{mspID: "Org1MSP", cert: cert})
	got, err := callerOf(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != v.Fingerprint {
		t.Fatalf("callerOf fingerprint %s, vector %s", got.Fingerprint, v.Fingerprint)
	}
}
