package saksiprotocol_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	saksiprotocol "github.com/saksi-framework/saksi/packages/saksi-protocol/go"
)

func goldenBallotBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "test-vectors", "ballot-v1.hex"))
	if err != nil {
		t.Fatalf("read test vector: %v", err)
	}
	wire, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		t.Fatalf("decode hex vector: %v", err)
	}
	return wire
}

// The Go codec must decode the golden vector to the same logical message the
// Rust prost types produced, and re-encode it to byte-identical canonical bytes.
func TestBallotGoldenDecodeMatchesFields(t *testing.T) {
	ballot, err := saksiprotocol.UnmarshalBallot(goldenBallotBytes(t))
	if err != nil {
		t.Fatalf("decode ballot: %v", err)
	}

	if ballot.Version != saksiprotocol.WireVersion {
		t.Fatalf("version = %d, want %d", ballot.Version, saksiprotocol.WireVersion)
	}
	if ballot.ElectionID != "election-2026" {
		t.Fatalf("election id = %q, want election-2026", ballot.ElectionID)
	}
	if got := ballot.VoterCredentialCommitment; !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("voter credential commitment = %x, want 010203", got)
	}
	if len(ballot.Ciphertexts) != 1 {
		t.Fatalf("ciphertext count = %d, want 1", len(ballot.Ciphertexts))
	}
	if got := len(ballot.Ciphertexts[0].Pad); got != 32 {
		t.Fatalf("ciphertext pad length = %d, want 32", got)
	}
	if got := len(ballot.Ciphertexts[0].Data); got != 32 {
		t.Fatalf("ciphertext data length = %d, want 32", got)
	}
	if len(ballot.WellFormednessProofs) != 1 {
		t.Fatalf("proof count = %d, want 1", len(ballot.WellFormednessProofs))
	}
	if len(ballot.WellFormednessProofs[0].Branches) != 1 {
		t.Fatalf("proof branch count = %d, want 1", len(ballot.WellFormednessProofs[0].Branches))
	}
	cp := ballot.CredentialPresentation
	if cp == nil {
		t.Fatal("credential presentation is nil")
	}
	if cp.Nullifier == nil {
		t.Fatal("nullifier is nil")
	}
	if got := len(cp.Nullifier.Value); got != 32 {
		t.Fatalf("nullifier value length = %d, want 32", got)
	}
}

func TestBallotGoldenRoundTripIsByteIdentical(t *testing.T) {
	want := goldenBallotBytes(t)
	ballot, err := saksiprotocol.UnmarshalBallot(want)
	if err != nil {
		t.Fatalf("decode ballot: %v", err)
	}
	got := ballot.Marshal()
	if !bytes.Equal(got, want) {
		t.Fatalf("re-encoded ballot does not match golden vector\n got: %x\nwant: %x", got, want)
	}
}
