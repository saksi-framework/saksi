package main

import (
	"bytes"
	"encoding/binary"
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

// loadSigVector reads the cross-language credential-signature golden vector
// (compress(Pk_i) || compress(C) || compress(R') || s).
func loadSigVector(t *testing.T) (pk, commitment, rPrime, s []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "saksi-protocol", "test-vectors", "credential-sig-v1.hex"))
	if err != nil {
		t.Fatalf("read credential-sig vector: %v", err)
	}
	d, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		t.Fatalf("decode credential-sig vector: %v", err)
	}
	if len(d) != 128 {
		t.Fatalf("credential-sig vector is %d bytes, want 128", len(d))
	}
	return d[0:32], d[32:64], d[64:96], d[96:128]
}

// validBallot builds a ballot whose credential presentation carries a real
// issuer signature (from the golden vector) so it passes the on-chain
// credential-signature check. The nullifier is caller-supplied so double-vote
// tests can repeat or vary it. Ciphertext bytes are shape-valid placeholders;
// the chaincode checks only their shape (the NIZKs are off-chain).
func validBallot(t *testing.T, nullifier []byte) *saksiprotocolv1.Ballot {
	t.Helper()
	pk, commitment, rPrime, s := loadSigVector(t)
	proof := append(append([]byte{}, rPrime...), s...) // R' || s (64 bytes)
	return &saksiprotocolv1.Ballot{
		Version:    saksiprotocolv1.WireVersion,
		ElectionId: "election-2026",
		Ciphertexts: []*saksiprotocolv1.Ciphertext{
			{Version: saksiprotocolv1.WireVersion, Pad: bytes.Repeat([]byte{1}, 32), Data: bytes.Repeat([]byte{2}, 32)},
		},
		CredentialPresentation: &saksiprotocolv1.CredentialPresentation{
			Version:              saksiprotocolv1.WireVersion,
			CredentialCommitment: commitment,
			IssuerPublicKey:      pk,
			PresentationProof:    proof,
			Nullifier:            &saksiprotocolv1.Nullifier{Version: saksiprotocolv1.WireVersion, Value: nullifier},
		},
	}
}

func validBallotHex(t *testing.T, nullifier []byte) string {
	t.Helper()
	return mustMarshal(t, validBallot(t, nullifier))
}

// loadCDSVector parses the cross-language CDS golden vector (produced by the
// Rust saksi-crypto test `cds_golden_vector`) into its components.
func loadCDSVector(t *testing.T) (electionID, contestID string, nullifier, pk, pad, data []byte, branches []*saksiprotocolv1.CDSProofBranch) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "saksi-protocol", "test-vectors", "cds-proof-v1.hex"))
	if err != nil {
		t.Fatalf("read cds vector: %v", err)
	}
	buf, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		t.Fatalf("decode cds vector: %v", err)
	}
	off := 0
	readLP := func() []byte {
		n := int(binary.BigEndian.Uint64(buf[off : off+8]))
		off += 8
		s := buf[off : off+n]
		off += n
		return s
	}
	next := func(n int) []byte {
		s := buf[off : off+n]
		off += n
		return s
	}
	electionID = string(readLP())
	contestID = string(readLP())
	nullifier = next(32)
	pk = next(32)
	pad = next(32)
	data = next(32)
	nb := int(buf[off])
	off++
	for i := 0; i < nb; i++ {
		branches = append(branches, &saksiprotocolv1.CDSProofBranch{
			CommitmentA: next(32),
			CommitmentB: next(32),
			Challenge:   next(32),
			Response:    next(32),
		})
	}
	return
}

// validCDSBallot builds a ballot that passes the full on-chain gate: a real
// issuer signature (credential-sig vector), a real CDS well-formedness proof
// and matching ciphertext (CDS vector), and a nullifier equal to the one the
// CDS proof is bound to. Pair with withCDSElection so the derived election key
// matches the vector.
func validCDSBallot(t *testing.T) *saksiprotocolv1.Ballot {
	t.Helper()
	electionID, _, nullifier, _, pad, data, branches := loadCDSVector(t)
	sigPK, commitment, rPrime, s := loadSigVector(t)
	proof := append(append([]byte{}, rPrime...), s...)
	return &saksiprotocolv1.Ballot{
		Version:    saksiprotocolv1.WireVersion,
		ElectionId: electionID,
		Ciphertexts: []*saksiprotocolv1.Ciphertext{
			{Version: saksiprotocolv1.WireVersion, Pad: pad, Data: data},
		},
		WellFormednessProofs: []*saksiprotocolv1.CDSProof{
			{Version: saksiprotocolv1.WireVersion, Branches: branches},
		},
		CredentialPresentation: &saksiprotocolv1.CredentialPresentation{
			Version:              saksiprotocolv1.WireVersion,
			CredentialCommitment: commitment,
			IssuerPublicKey:      sigPK,
			PresentationProof:    proof,
			Nullifier:            &saksiprotocolv1.Nullifier{Version: saksiprotocolv1.WireVersion, Value: nullifier},
		},
	}
}

// withCDSElection creates a single-contest, single-trustee election whose
// derived joint key equals the CDS golden vector's public key, and publishes
// the matching DKG transcript, so validCDSBallot's CDS proof verifies on-chain.
func withCDSElection(t *testing.T, sc *SmartContract, ctx *fakeContext) {
	t.Helper()
	_, contestID, _, pk, _, _, _ := loadCDSVector(t)
	params := &saksiprotocolv1.ElectionParameters{
		Version:    saksiprotocolv1.WireVersion,
		ElectionId: "election-2026",
		ContestIds: []string{contestID},
		TrusteeIds: []string{"t1"},
		Threshold:  1,
	}
	if err := sc.CreateElection(ctx, mustMarshalParams(t, params)); err != nil {
		t.Fatalf("CreateElection: %v", err)
	}
	dkg := &saksiprotocolv1.DKGTranscript{
		Version:    saksiprotocolv1.WireVersion,
		ElectionId: "election-2026",
		Threshold:  1,
		TrusteeCommitments: []*saksiprotocolv1.TrusteeCommitment{
			{TrusteeId: "t1", CoefficientCommitments: [][]byte{pk}},
		},
	}
	if err := sc.PublishDKGTranscript(ctx, mustMarshalDKG(t, dkg)); err != nil {
		t.Fatalf("PublishDKGTranscript: %v", err)
	}
}

// defaultNullifier is the canonical nullifier used by the happy-path ballot.
func defaultNullifier() []byte { return bytes.Repeat([]byte{9}, 32) }

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
	withCDSElection(t, sc, ctx)
	ballotHex := mustMarshal(t, validCDSBallot(t))

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
	withCDSElection(t, sc, ctx)
	ballotHex := mustMarshal(t, validCDSBallot(t))

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

// TestSubmitBallotRejectsTamperedCDSProof is the positive/negative pair for the
// on-chain CDS gate: the same setup that accepts validCDSBallot must reject a
// ballot whose CDS proof is tampered.
func TestSubmitBallotRejectsTamperedCDSProof(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withCDSElection(t, sc, ctx)
	ballot := validCDSBallot(t)
	// Flip a byte in the first branch's response scalar.
	ballot.WellFormednessProofs[0].Branches[0].Response[0] ^= 0x01
	err := sc.SubmitBallot(ctx, mustMarshal(t, ballot))
	if err == nil || !strings.Contains(err.Error(), "well-formedness proof failed") {
		t.Fatalf("expected a CDS-proof failure, got: %v", err)
	}
}

// TestSubmitBallotRejectsMissingDKG: on-chain CDS needs the joint key, so a
// ballot for an election with no published DKG transcript is rejected.
func TestSubmitBallotRejectsMissingDKG(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	_, contestID, _, _, _, _, _ := loadCDSVector(t)
	params := &saksiprotocolv1.ElectionParameters{
		Version:    saksiprotocolv1.WireVersion,
		ElectionId: "election-2026",
		ContestIds: []string{contestID},
		TrusteeIds: []string{"t1"},
		Threshold:  1,
	}
	if err := sc.CreateElection(ctx, mustMarshalParams(t, params)); err != nil {
		t.Fatalf("CreateElection: %v", err)
	}
	err := sc.SubmitBallot(ctx, mustMarshal(t, validCDSBallot(t)))
	if err == nil || !strings.Contains(err.Error(), "no published DKG transcript") {
		t.Fatalf("expected a missing-DKG error, got: %v", err)
	}
}

// TestSubmitBallotRejectsContestCountMismatch: the ballot's ciphertext/proof
// counts must match the election's contest count.
func TestSubmitBallotRejectsContestCountMismatch(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withCDSElection(t, sc, ctx) // one contest
	ballot := validCDSBallot(t)
	// Drop the well-formedness proof so counts disagree (1 ciphertext, 0 proofs).
	ballot.WellFormednessProofs = nil
	err := sc.SubmitBallot(ctx, mustMarshal(t, ballot))
	if err == nil || !strings.Contains(err.Error(), "ciphertexts") {
		t.Fatalf("expected a ciphertext/proof-count error, got: %v", err)
	}
}

// TestContestIndicesForPosition pins the position→contest mapping and its parity
// with the Rust auditor's contest_indices_for_position (byte-for-byte semantics).
func TestContestIndicesForPosition(t *testing.T) {
	contests := []string{"pos0/cand0", "pos0/cand1", "pos1/cand0", "pos10/cand0"}
	cases := []struct {
		position string
		want     []int
	}{
		{"", []int{0, 1, 2, 3}}, // legacy: all contests
		{"pos0", []int{0, 1}},   // one position's candidates
		{"pos1", []int{2}},      // slash disambiguates pos1 from pos10
		{"pos10", []int{3}},     // ...and vice versa
		{"ghost", []int{}},      // unknown position → none
	}
	for _, c := range cases {
		got := contestIndicesForPosition(contests, c.position)
		if len(got) != len(c.want) {
			t.Fatalf("position %q: got %v, want %v", c.position, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("position %q: got %v, want %v", c.position, got, c.want)
			}
		}
	}
}

// TestSubmitBallotRejectsUnknownPosition: a ballot whose position_id matches no
// contest in the election is rejected at endorsement (ADR-0007 per-position gate).
func TestSubmitBallotRejectsUnknownPosition(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withCDSElection(t, sc, ctx)
	ballot := validCDSBallot(t)
	ballot.PositionId = "ghost" // no contest is prefixed "ghost/"
	err := sc.SubmitBallot(ctx, mustMarshal(t, ballot))
	if err == nil || !strings.Contains(err.Error(), "matches no contest") {
		t.Fatalf("expected an unknown-position rejection, got: %v", err)
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

func validElectionParams() *saksiprotocolv1.ElectionParameters {
	return &saksiprotocolv1.ElectionParameters{
		Version:    saksiprotocolv1.WireVersion,
		ElectionId: "election-2026",
		ContestIds: []string{"contest-1", "contest-2"},
		TrusteeIds: []string{"t1", "t2", "t3", "t4", "t5"},
		Threshold:  3,
	}
}

func mustMarshalParams(t *testing.T, p *saksiprotocolv1.ElectionParameters) string {
	t.Helper()
	raw, err := proto.Marshal(p)
	if err != nil {
		t.Fatalf("marshal election parameters: %v", err)
	}
	return hex.EncodeToString(raw)
}

func TestCreateElectionThenGetElectionRoundTrips(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	paramsHex := mustMarshalParams(t, validElectionParams())

	if err := sc.CreateElection(ctx, paramsHex); err != nil {
		t.Fatalf("CreateElection: %v", err)
	}
	got, err := sc.GetElection(ctx, "election-2026")
	if err != nil {
		t.Fatalf("GetElection: %v", err)
	}
	if got != paramsHex {
		t.Fatalf("GetElection returned different parameters\n got: %s\nwant: %s", got, paramsHex)
	}
}

func TestCreateElectionRejectsDuplicate(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	paramsHex := mustMarshalParams(t, validElectionParams())

	if err := sc.CreateElection(ctx, paramsHex); err != nil {
		t.Fatalf("first CreateElection: %v", err)
	}
	err := sc.CreateElection(ctx, paramsHex)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected a duplicate-election error, got: %v", err)
	}
}

func TestCreateElectionRejectsBadThreshold(t *testing.T) {
	for _, th := range []uint32{0, 6} {
		p := validElectionParams()
		p.Threshold = th
		err := (&SmartContract{}).CreateElection(newContext(), mustMarshalParams(t, p))
		if err == nil || !strings.Contains(err.Error(), "threshold") {
			t.Fatalf("threshold %d: expected a threshold error, got: %v", th, err)
		}
	}
}

func TestCreateElectionRejectsEmptyContestsOrTrustees(t *testing.T) {
	noContests := validElectionParams()
	noContests.ContestIds = nil
	if err := (&SmartContract{}).CreateElection(newContext(), mustMarshalParams(t, noContests)); err == nil || !strings.Contains(err.Error(), "contest") {
		t.Fatalf("expected a no-contests error, got: %v", err)
	}
	noTrustees := validElectionParams()
	noTrustees.TrusteeIds = nil
	if err := (&SmartContract{}).CreateElection(newContext(), mustMarshalParams(t, noTrustees)); err == nil || !strings.Contains(err.Error(), "trustee") {
		t.Fatalf("expected a no-trustees error, got: %v", err)
	}
}

func TestCreateElectionRejectsMissingIDOrWrongVersion(t *testing.T) {
	noID := validElectionParams()
	noID.ElectionId = ""
	if err := (&SmartContract{}).CreateElection(newContext(), mustMarshalParams(t, noID)); err == nil || !strings.Contains(err.Error(), "election id") {
		t.Fatalf("expected a missing-id error, got: %v", err)
	}
	wrongVersion := validElectionParams()
	wrongVersion.Version = 99
	if err := (&SmartContract{}).CreateElection(newContext(), mustMarshalParams(t, wrongVersion)); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected a version error, got: %v", err)
	}
}

func TestCreateElectionRejectsBadHex(t *testing.T) {
	if err := (&SmartContract{}).CreateElection(newContext(), "nothex!!"); err == nil {
		t.Fatal("CreateElection should reject non-hex input")
	}
}

func TestGetElectionMissingIsError(t *testing.T) {
	if _, err := (&SmartContract{}).GetElection(newContext(), "no-such-election"); err == nil {
		t.Fatal("GetElection for an unknown election should fail")
	}
}

func validDKGTranscript() *saksiprotocolv1.DKGTranscript {
	ids := []string{"t1", "t2", "t3", "t4", "t5"}
	commits := make([]*saksiprotocolv1.TrusteeCommitment, len(ids))
	for i, id := range ids {
		commits[i] = &saksiprotocolv1.TrusteeCommitment{
			TrusteeId: id,
			CoefficientCommitments: [][]byte{
				bytes.Repeat([]byte{byte(i + 1)}, 32),
				bytes.Repeat([]byte{byte(i + 1)}, 32),
				bytes.Repeat([]byte{byte(i + 1)}, 32),
			},
		}
	}
	return &saksiprotocolv1.DKGTranscript{
		Version:            saksiprotocolv1.WireVersion,
		ElectionId:         "election-2026",
		Threshold:          3,
		TrusteeCommitments: commits,
	}
}

func mustMarshalDKG(t *testing.T, d *saksiprotocolv1.DKGTranscript) string {
	t.Helper()
	raw, err := proto.Marshal(d)
	if err != nil {
		t.Fatalf("marshal DKG transcript: %v", err)
	}
	return hex.EncodeToString(raw)
}

// withElection creates the canonical election in ctx so DKG/lifecycle tests can
// build on it.
func withElection(t *testing.T, sc *SmartContract, ctx *fakeContext) {
	t.Helper()
	if err := sc.CreateElection(ctx, mustMarshalParams(t, validElectionParams())); err != nil {
		t.Fatalf("CreateElection: %v", err)
	}
}

func TestPublishDKGTranscriptThenGetRoundTrips(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withElection(t, sc, ctx)
	transcriptHex := mustMarshalDKG(t, validDKGTranscript())

	if err := sc.PublishDKGTranscript(ctx, transcriptHex); err != nil {
		t.Fatalf("PublishDKGTranscript: %v", err)
	}
	got, err := sc.GetDKGTranscript(ctx, "election-2026")
	if err != nil {
		t.Fatalf("GetDKGTranscript: %v", err)
	}
	if got != transcriptHex {
		t.Fatalf("GetDKGTranscript returned a different transcript")
	}
}

func TestPublishDKGTranscriptRejectsMissingElection(t *testing.T) {
	sc := &SmartContract{}
	err := sc.PublishDKGTranscript(newContext(), mustMarshalDKG(t, validDKGTranscript()))
	if err == nil || !strings.Contains(err.Error(), "no election found") {
		t.Fatalf("expected a missing-election error, got: %v", err)
	}
}

func TestPublishDKGTranscriptRejectsDuplicate(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withElection(t, sc, ctx)
	transcriptHex := mustMarshalDKG(t, validDKGTranscript())
	if err := sc.PublishDKGTranscript(ctx, transcriptHex); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	err := sc.PublishDKGTranscript(ctx, transcriptHex)
	if err == nil || !strings.Contains(err.Error(), "already published") {
		t.Fatalf("expected a duplicate-transcript error, got: %v", err)
	}
}

func TestPublishDKGTranscriptRejectsThresholdMismatch(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withElection(t, sc, ctx)
	bad := validDKGTranscript()
	bad.Threshold = 4
	err := sc.PublishDKGTranscript(ctx, mustMarshalDKG(t, bad))
	if err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("expected a threshold-mismatch error, got: %v", err)
	}
}

func TestPublishDKGTranscriptRejectsTrusteeCountMismatch(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withElection(t, sc, ctx)
	bad := validDKGTranscript()
	bad.TrusteeCommitments = bad.TrusteeCommitments[:4]
	err := sc.PublishDKGTranscript(ctx, mustMarshalDKG(t, bad))
	if err == nil || !strings.Contains(err.Error(), "trustee") {
		t.Fatalf("expected a trustee-count error, got: %v", err)
	}
}

func TestPublishDKGTranscriptRejectsWrongVersion(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withElection(t, sc, ctx)
	bad := validDKGTranscript()
	bad.Version = 99
	err := sc.PublishDKGTranscript(ctx, mustMarshalDKG(t, bad))
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected a version error, got: %v", err)
	}
}

func TestGetDKGTranscriptMissingIsError(t *testing.T) {
	if _, err := (&SmartContract{}).GetDKGTranscript(newContext(), "election-2026"); err == nil {
		t.Fatal("GetDKGTranscript for an election with no transcript should fail")
	}
}

func TestSubmitBallotRejectsUnknownElection(t *testing.T) {
	sc := &SmartContract{}
	err := sc.SubmitBallot(newContext(), validBallotHex(t, defaultNullifier()))
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected an unknown-election error, got: %v", err)
	}
}

func TestSubmitBallotRejectsBadCredentialSignature(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withElection(t, sc, ctx)
	ballot := validBallot(t, defaultNullifier())
	// Flip a byte in the signature scalar s (bytes 32..64 of the proof prefix).
	ballot.CredentialPresentation.PresentationProof[40] ^= 0x01
	err := sc.SubmitBallot(ctx, mustMarshal(t, ballot))
	if err == nil || !strings.Contains(err.Error(), "credential signature") {
		t.Fatalf("expected a credential-signature error, got: %v", err)
	}
}

func TestSubmitBallotRejectsClosedElection(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withElection(t, sc, ctx)
	if err := sc.CloseElection(ctx, "election-2026"); err != nil {
		t.Fatalf("CloseElection: %v", err)
	}
	err := sc.SubmitBallot(ctx, validBallotHex(t, defaultNullifier()))
	if err == nil || !strings.Contains(err.Error(), "not open") {
		t.Fatalf("expected a not-open error, got: %v", err)
	}
}

func TestCloseElectionTransitionsStatus(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withElection(t, sc, ctx)
	if got, err := sc.GetElectionStatus(ctx, "election-2026"); err != nil || got != "open" {
		t.Fatalf("status after create = %q (err %v), want open", got, err)
	}
	if err := sc.CloseElection(ctx, "election-2026"); err != nil {
		t.Fatalf("CloseElection: %v", err)
	}
	if got, err := sc.GetElectionStatus(ctx, "election-2026"); err != nil || got != "closed" {
		t.Fatalf("status after close = %q (err %v), want closed", got, err)
	}
}

func TestCloseElectionRejectsMissing(t *testing.T) {
	if err := (&SmartContract{}).CloseElection(newContext(), "no-such-election"); err == nil || !strings.Contains(err.Error(), "no election") {
		t.Fatalf("expected a missing-election error, got: %v", err)
	}
}

func TestCloseElectionRejectsAlreadyClosed(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withElection(t, sc, ctx)
	if err := sc.CloseElection(ctx, "election-2026"); err != nil {
		t.Fatalf("first close: %v", err)
	}
	err := sc.CloseElection(ctx, "election-2026")
	if err == nil || !strings.Contains(err.Error(), "already closed") {
		t.Fatalf("expected an already-closed error, got: %v", err)
	}
}

func TestGetElectionStatusMissingIsError(t *testing.T) {
	if _, err := (&SmartContract{}).GetElectionStatus(newContext(), "no-such-election"); err == nil {
		t.Fatal("GetElectionStatus for an unknown election should fail")
	}
}

func validPartialDecryption() *saksiprotocolv1.PartialDecryption {
	return &saksiprotocolv1.PartialDecryption{
		Version:   saksiprotocolv1.WireVersion,
		TrusteeId: "t1",
		ContestId: "contest-1",
		Share:     bytes.Repeat([]byte{7}, 32),
		Proof:     &saksiprotocolv1.ChaumPedersenProof{Version: saksiprotocolv1.WireVersion},
	}
}

func mustMarshalPartial(t *testing.T, p *saksiprotocolv1.PartialDecryption) string {
	t.Helper()
	raw, err := proto.Marshal(p)
	if err != nil {
		t.Fatalf("marshal partial decryption: %v", err)
	}
	return hex.EncodeToString(raw)
}

// withClosedElection creates the canonical election and closes it, the state
// from which threshold decryption and tallying proceed.
func withClosedElection(t *testing.T, sc *SmartContract, ctx *fakeContext) {
	t.Helper()
	withElection(t, sc, ctx)
	if err := sc.CloseElection(ctx, "election-2026"); err != nil {
		t.Fatalf("CloseElection: %v", err)
	}
}

func TestSubmitPartialDecryptionThenGetRoundTrips(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withClosedElection(t, sc, ctx)
	partialHex := mustMarshalPartial(t, validPartialDecryption())

	if err := sc.SubmitPartialDecryption(ctx, "election-2026", partialHex); err != nil {
		t.Fatalf("SubmitPartialDecryption: %v", err)
	}
	got, err := sc.GetPartialDecryption(ctx, "election-2026", "contest-1", "t1")
	if err != nil {
		t.Fatalf("GetPartialDecryption: %v", err)
	}
	if got != partialHex {
		t.Fatalf("GetPartialDecryption returned a different partial decryption")
	}
}

func TestSubmitPartialDecryptionRejectsOpenElection(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withElection(t, sc, ctx) // still open
	err := sc.SubmitPartialDecryption(ctx, "election-2026", mustMarshalPartial(t, validPartialDecryption()))
	if err == nil || !strings.Contains(err.Error(), "not closed") {
		t.Fatalf("expected a not-closed error, got: %v", err)
	}
}

func TestSubmitPartialDecryptionRejectsUnknownElection(t *testing.T) {
	err := (&SmartContract{}).SubmitPartialDecryption(newContext(), "election-2026", mustMarshalPartial(t, validPartialDecryption()))
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected an unknown-election error, got: %v", err)
	}
}

func TestSubmitPartialDecryptionRejectsUnknownContestOrTrustee(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withClosedElection(t, sc, ctx)

	badContest := validPartialDecryption()
	badContest.ContestId = "contest-9"
	if err := sc.SubmitPartialDecryption(ctx, "election-2026", mustMarshalPartial(t, badContest)); err == nil || !strings.Contains(err.Error(), "contest") {
		t.Fatalf("expected an unknown-contest error, got: %v", err)
	}

	badTrustee := validPartialDecryption()
	badTrustee.TrusteeId = "t9"
	if err := sc.SubmitPartialDecryption(ctx, "election-2026", mustMarshalPartial(t, badTrustee)); err == nil || !strings.Contains(err.Error(), "trustee") {
		t.Fatalf("expected an unknown-trustee error, got: %v", err)
	}
}

func TestSubmitPartialDecryptionRejectsDuplicate(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withClosedElection(t, sc, ctx)
	partialHex := mustMarshalPartial(t, validPartialDecryption())
	if err := sc.SubmitPartialDecryption(ctx, "election-2026", partialHex); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	err := sc.SubmitPartialDecryption(ctx, "election-2026", partialHex)
	if err == nil || !strings.Contains(err.Error(), "already submitted") {
		t.Fatalf("expected a duplicate-share error, got: %v", err)
	}
}

func TestSubmitPartialDecryptionRejectsMalformedShareOrMissingProof(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withClosedElection(t, sc, ctx)

	badShare := validPartialDecryption()
	badShare.Share = bytes.Repeat([]byte{7}, 16)
	if err := sc.SubmitPartialDecryption(ctx, "election-2026", mustMarshalPartial(t, badShare)); err == nil || !strings.Contains(err.Error(), "share") {
		t.Fatalf("expected a share-shape error, got: %v", err)
	}

	noProof := validPartialDecryption()
	noProof.Proof = nil
	if err := sc.SubmitPartialDecryption(ctx, "election-2026", mustMarshalPartial(t, noProof)); err == nil || !strings.Contains(err.Error(), "proof") {
		t.Fatalf("expected a missing-proof error, got: %v", err)
	}
}

func TestSubmitPartialDecryptionRejectsWrongVersion(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withClosedElection(t, sc, ctx)
	bad := validPartialDecryption()
	bad.Version = 99
	err := sc.SubmitPartialDecryption(ctx, "election-2026", mustMarshalPartial(t, bad))
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected a version error, got: %v", err)
	}
}

func TestGetPartialDecryptionMissingIsError(t *testing.T) {
	if _, err := (&SmartContract{}).GetPartialDecryption(newContext(), "election-2026", "contest-1", "t1"); err == nil {
		t.Fatal("GetPartialDecryption for an absent share should fail")
	}
}

func validTally() *saksiprotocolv1.TallyResult {
	return &saksiprotocolv1.TallyResult{
		Version:    saksiprotocolv1.WireVersion,
		ElectionId: "election-2026",
		Totals:     []uint64{12, 7}, // two contests
	}
}

func mustMarshalTally(t *testing.T, tr *saksiprotocolv1.TallyResult) string {
	t.Helper()
	raw, err := proto.Marshal(tr)
	if err != nil {
		t.Fatalf("marshal tally: %v", err)
	}
	return hex.EncodeToString(raw)
}

func TestPublishTallyThenGetRoundTrips(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withClosedElection(t, sc, ctx)
	tallyHex := mustMarshalTally(t, validTally())

	if err := sc.PublishTally(ctx, tallyHex); err != nil {
		t.Fatalf("PublishTally: %v", err)
	}
	got, err := sc.GetTally(ctx, "election-2026")
	if err != nil {
		t.Fatalf("GetTally: %v", err)
	}
	if got != tallyHex {
		t.Fatalf("GetTally returned a different tally")
	}
}

func TestPublishTallyRejectsOpenElection(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withElection(t, sc, ctx) // still open
	err := sc.PublishTally(ctx, mustMarshalTally(t, validTally()))
	if err == nil || !strings.Contains(err.Error(), "not closed") {
		t.Fatalf("expected a not-closed error, got: %v", err)
	}
}

func TestPublishTallyRejectsWrongTotalsCount(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withClosedElection(t, sc, ctx)
	bad := validTally()
	bad.Totals = []uint64{1} // election has two contests
	err := sc.PublishTally(ctx, mustMarshalTally(t, bad))
	if err == nil || !strings.Contains(err.Error(), "totals") {
		t.Fatalf("expected a totals-count error, got: %v", err)
	}
}

func TestPublishTallyRejectsDuplicate(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	withClosedElection(t, sc, ctx)
	tallyHex := mustMarshalTally(t, validTally())
	if err := sc.PublishTally(ctx, tallyHex); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	err := sc.PublishTally(ctx, tallyHex)
	if err == nil || !strings.Contains(err.Error(), "already published") {
		t.Fatalf("expected a duplicate-tally error, got: %v", err)
	}
}

func TestGetTallyMissingIsError(t *testing.T) {
	if _, err := (&SmartContract{}).GetTally(newContext(), "election-2026"); err == nil {
		t.Fatal("GetTally for an election with no tally should fail")
	}
}
