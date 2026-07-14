package saksiprotocolv1_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func goldenBallotBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", "ballot-v1.hex"))
	if err != nil {
		t.Fatalf("read test vector: %v", err)
	}
	wire, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		t.Fatalf("decode hex vector: %v", err)
	}
	return wire
}

// The generated Go types must decode the golden vector (produced by the Rust
// prost types) to the same logical message and re-encode to byte-identical
// canonical bytes — pinning Go↔Rust wire equivalence.
func TestBallotGoldenDecodeMatchesFields(t *testing.T) {
	var ballot saksiprotocolv1.Ballot
	if err := proto.Unmarshal(goldenBallotBytes(t), &ballot); err != nil {
		t.Fatalf("decode ballot: %v", err)
	}

	if ballot.GetVersion() != saksiprotocolv1.WireVersion {
		t.Fatalf("version = %d, want %d", ballot.GetVersion(), saksiprotocolv1.WireVersion)
	}
	if ballot.GetElectionId() != "election-2026" {
		t.Fatalf("election id = %q, want election-2026", ballot.GetElectionId())
	}
	if got := ballot.GetVoterCredentialCommitment(); !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("voter credential commitment = %x, want 010203", got)
	}
	if len(ballot.GetCiphertexts()) != 1 {
		t.Fatalf("ciphertext count = %d, want 1", len(ballot.GetCiphertexts()))
	}
	if got := len(ballot.GetCiphertexts()[0].GetPad()); got != 32 {
		t.Fatalf("ciphertext pad length = %d, want 32", got)
	}
	if got := len(ballot.GetCiphertexts()[0].GetData()); got != 32 {
		t.Fatalf("ciphertext data length = %d, want 32", got)
	}
	if len(ballot.GetWellFormednessProofs()) != 1 {
		t.Fatalf("proof count = %d, want 1", len(ballot.GetWellFormednessProofs()))
	}
	cp := ballot.GetCredentialPresentation()
	if cp == nil || cp.GetNullifier() == nil {
		t.Fatal("credential presentation / nullifier is nil")
	}
	if got := len(cp.GetNullifier().GetValue()); got != 32 {
		t.Fatalf("nullifier value length = %d, want 32", got)
	}
	if ballot.GetPositionId() != "president" {
		t.Fatalf("position id = %q, want president", ballot.GetPositionId())
	}
}

func TestBallotGoldenRoundTripIsByteIdentical(t *testing.T) {
	want := goldenBallotBytes(t)
	var ballot saksiprotocolv1.Ballot
	if err := proto.Unmarshal(want, &ballot); err != nil {
		t.Fatalf("decode ballot: %v", err)
	}
	got, err := proto.MarshalOptions{Deterministic: true}.Marshal(&ballot)
	if err != nil {
		t.Fatalf("re-encode ballot: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("re-encoded ballot does not match golden vector\n got: %x\nwant: %x", got, want)
	}
}

// Field-layout pin: the golden vector's top-level fields keep their numbers and
// wire types, independent of the generated accessors.
func TestBallotVectorUsesStableFieldLayout(t *testing.T) {
	wire := goldenBallotBytes(t)
	fields := map[protowire.Number]protowire.Type{}
	for len(wire) > 0 {
		number, typ, n := protowire.ConsumeTag(wire)
		if n < 0 {
			t.Fatalf("consume tag: %v", protowire.ParseError(n))
		}
		wire = wire[n:]
		valueLen := protowire.ConsumeFieldValue(number, typ, wire)
		if valueLen < 0 {
			t.Fatalf("consume field %d: %v", number, protowire.ParseError(valueLen))
		}
		fields[number] = typ
		wire = wire[valueLen:]
	}
	want := map[protowire.Number]protowire.Type{
		1: protowire.VarintType,
		2: protowire.BytesType,
		3: protowire.BytesType,
		4: protowire.BytesType,
		5: protowire.BytesType,
		6: protowire.BytesType,
	}
	for number, typ := range want {
		if fields[number] != typ {
			t.Fatalf("field %d type = %v, want %v", number, fields[number], typ)
		}
	}
}
