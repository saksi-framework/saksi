package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// fakeStub is an in-memory ChaincodeStubInterface covering only the methods the
// contract uses. Embedding the interface satisfies the full method set; calling
// an unimplemented method panics, which keeps the fake honest.
type fakeStub struct {
	shim.ChaincodeStubInterface
	state map[string][]byte
}

func newFakeStub() *fakeStub { return &fakeStub{state: map[string][]byte{}} }

func (f *fakeStub) CreateCompositeKey(objectType string, attributes []string) (string, error) {
	return objectType + "\x00" + strings.Join(attributes, "\x00"), nil
}

func (f *fakeStub) GetState(key string) ([]byte, error) { return f.state[key], nil }

func (f *fakeStub) PutState(key string, value []byte) error {
	f.state[key] = value
	return nil
}

type fakeContext struct {
	contractapi.TransactionContextInterface
	stub *fakeStub
}

func (c *fakeContext) GetStub() shim.ChaincodeStubInterface { return c.stub }

func newContext() *fakeContext { return &fakeContext{stub: newFakeStub()} }

func mustMarshal(t *testing.T, ballot *saksiprotocolv1.Ballot) string {
	t.Helper()
	raw, err := proto.Marshal(ballot)
	if err != nil {
		t.Fatalf("marshal ballot: %v", err)
	}
	return hex.EncodeToString(raw)
}

func goldenBallotHex(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "saksi-protocol", "test-vectors", "ballot-v1.hex"))
	if err != nil {
		t.Fatalf("read golden ballot: %v", err)
	}
	return string(bytes.TrimSpace(raw))
}

func nullifierHexOf(t *testing.T, ballotHex string) (electionID, nullifier string) {
	t.Helper()
	raw, err := hex.DecodeString(ballotHex)
	if err != nil {
		t.Fatalf("decode ballot hex: %v", err)
	}
	var ballot saksiprotocolv1.Ballot
	if err := proto.Unmarshal(raw, &ballot); err != nil {
		t.Fatalf("decode ballot: %v", err)
	}
	return ballot.GetElectionId(), hex.EncodeToString(ballot.GetCredentialPresentation().GetNullifier().GetValue())
}

func TestSubmitBallotThenGetBallotRoundTrips(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	ballotHex := goldenBallotHex(t)

	if err := sc.SubmitBallot(ctx, ballotHex); err != nil {
		t.Fatalf("SubmitBallot: %v", err)
	}

	electionID, nullifier := nullifierHexOf(t, ballotHex)
	got, err := sc.GetBallot(ctx, electionID, nullifier)
	if err != nil {
		t.Fatalf("GetBallot: %v", err)
	}
	if got != ballotHex {
		t.Fatalf("GetBallot returned a different ballot\n got: %s\nwant: %s", got, ballotHex)
	}
}

func TestSubmitBallotRejectsDoubleVote(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	ballotHex := goldenBallotHex(t)

	if err := sc.SubmitBallot(ctx, ballotHex); err != nil {
		t.Fatalf("first SubmitBallot should succeed: %v", err)
	}
	err := sc.SubmitBallot(ctx, ballotHex)
	if err == nil {
		t.Fatal("second SubmitBallot with the same nullifier should fail")
	}
	if !strings.Contains(err.Error(), "double vote") {
		t.Fatalf("expected a double-vote error, got: %v", err)
	}
}

func TestGetBallotMissingIsError(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	if _, err := sc.GetBallot(ctx, "election-2026", "deadbeef"); err == nil {
		t.Fatal("GetBallot for an unknown ballot should fail")
	}
}

func TestSubmitBallotRejectsBadHex(t *testing.T) {
	sc := &SmartContract{}
	if err := sc.SubmitBallot(newContext(), "nothex!!"); err == nil {
		t.Fatal("SubmitBallot should reject non-hex input")
	}
}

func TestSubmitBallotRejectsMissingNullifier(t *testing.T) {
	ballot := &saksiprotocolv1.Ballot{
		Version:    saksiprotocolv1.WireVersion,
		ElectionId: "election-2026",
		Ciphertexts: []*saksiprotocolv1.Ciphertext{
			{Version: saksiprotocolv1.WireVersion, Pad: bytes.Repeat([]byte{1}, 32), Data: bytes.Repeat([]byte{2}, 32)},
		},
	}
	sc := &SmartContract{}
	err := sc.SubmitBallot(newContext(), mustMarshal(t, ballot))
	if err == nil || !strings.Contains(err.Error(), "nullifier") {
		t.Fatalf("expected a missing-nullifier error, got: %v", err)
	}
}

func TestSubmitBallotRejectsMalformedCiphertext(t *testing.T) {
	ballot := &saksiprotocolv1.Ballot{
		Version:    saksiprotocolv1.WireVersion,
		ElectionId: "election-2026",
		Ciphertexts: []*saksiprotocolv1.Ciphertext{
			{Version: saksiprotocolv1.WireVersion, Pad: bytes.Repeat([]byte{1}, 16), Data: bytes.Repeat([]byte{2}, 32)},
		},
		CredentialPresentation: &saksiprotocolv1.CredentialPresentation{
			Version:   saksiprotocolv1.WireVersion,
			Nullifier: &saksiprotocolv1.Nullifier{Version: saksiprotocolv1.WireVersion, Value: bytes.Repeat([]byte{9}, 32)},
		},
	}
	sc := &SmartContract{}
	err := sc.SubmitBallot(newContext(), mustMarshal(t, ballot))
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("expected a malformed-ciphertext error, got: %v", err)
	}
}

func TestSubmitBallotRejectsWrongVersion(t *testing.T) {
	ballot := &saksiprotocolv1.Ballot{
		Version:    99,
		ElectionId: "election-2026",
		Ciphertexts: []*saksiprotocolv1.Ciphertext{
			{Version: saksiprotocolv1.WireVersion, Pad: bytes.Repeat([]byte{1}, 32), Data: bytes.Repeat([]byte{2}, 32)},
		},
		CredentialPresentation: &saksiprotocolv1.CredentialPresentation{
			Version:   saksiprotocolv1.WireVersion,
			Nullifier: &saksiprotocolv1.Nullifier{Version: saksiprotocolv1.WireVersion, Value: bytes.Repeat([]byte{9}, 32)},
		},
	}
	sc := &SmartContract{}
	err := sc.SubmitBallot(newContext(), mustMarshal(t, ballot))
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected an unsupported-version error, got: %v", err)
	}
}
