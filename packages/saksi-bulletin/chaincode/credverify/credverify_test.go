package credverify

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// loadVector reads the cross-language credential-signature golden vector
// (compress(Pk_i) || compress(C) || compress(R') || s) produced by the Rust
// saksi-credentials test `credential_signature_golden_vector`.
func loadVector(t *testing.T) (pk, c, r, s []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(
		"..", "..", "..", "saksi-protocol", "test-vectors", "credential-sig-v1.hex",
	))
	if err != nil {
		t.Fatalf("read golden vector: %v", err)
	}
	decoded, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		t.Fatalf("decode golden vector hex: %v", err)
	}
	if len(decoded) != 128 {
		t.Fatalf("golden vector is %d bytes, want 128", len(decoded))
	}
	return decoded[0:32], decoded[32:64], decoded[64:96], decoded[96:128]
}

func TestVerifyIssuerSignatureAcceptsGoldenVector(t *testing.T) {
	pk, c, r, s := loadVector(t)
	if err := VerifyIssuerSignature(pk, c, r, s); err != nil {
		t.Fatalf("golden vector must verify (Go must agree byte-for-byte with Rust): %v", err)
	}
}

func TestVerifyIssuerSignatureRejectsTamper(t *testing.T) {
	pk, c, r, s := loadVector(t)

	cases := []struct {
		name             string
		pk, c, r, s      []byte
		flipIndexInField string
	}{
		{name: "tampered scalar s", pk: pk, c: c, r: r, s: flip(s)},
		{name: "tampered commitment", pk: pk, c: flip(c), r: r, s: s},
		{name: "tampered R'", pk: pk, c: c, r: flip(r), s: s},
		{name: "tampered issuer pk", pk: flip(pk), c: c, r: r, s: s},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyIssuerSignature(tc.pk, tc.c, tc.r, tc.s); err == nil {
				t.Fatalf("%s must be rejected", tc.name)
			}
		})
	}
}

func TestVerifyIssuerSignatureRejectsBadLength(t *testing.T) {
	pk, c, r, s := loadVector(t)
	if err := VerifyIssuerSignature(pk[:31], c, r, s); err == nil {
		t.Fatal("short issuer pk must be rejected")
	}
}

// flip returns a copy of b with its first byte flipped.
func flip(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[0] ^= 0x01
	return out
}
