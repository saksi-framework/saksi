package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
)

// selectionVector is the Rust-produced selection golden vector (saksi-crypto
// `selection_golden_vector`): one position with n candidates, an honest
// one-hot record with CDS proofs and its selection proof, and an overvote
// record (every candidate at 1) with valid CDS proofs.
type selectionVector struct {
	electionID, positionID string
	nullifier, pk          []byte
	honest, overvote       []*saksiprotocolv1.Ciphertext
	honestCDS, overCDS     []*saksiprotocolv1.CDSProof
	proof                  *saksiprotocolv1.ChaumPedersenProof
}

func loadSelectionVector(t *testing.T) selectionVector {
	t.Helper()
	return loadVector(t, "selection-proof-v1.hex", true)
}

// loadVector reads a vector in the selection-vector layout from
// saksi-protocol's test-vectors; withOvervote says it ends in an overvote
// record.
func loadVector(t *testing.T, file string, withOvervote bool) selectionVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "saksi-protocol", "test-vectors", file))
	if err != nil {
		t.Fatalf("read selection vector: %v", err)
	}
	buf, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		t.Fatalf("decode selection vector: %v", err)
	}
	off := 0
	next := func(n int) []byte { s := buf[off : off+n]; off += n; return s }
	readLP := func() []byte { return next(int(binary.BigEndian.Uint64(next(8)))) }
	var v selectionVector
	v.electionID = string(readLP())
	v.positionID = string(readLP())
	v.nullifier = next(32)
	v.pk = next(32)
	n := int(next(1)[0])
	record := func() (cts []*saksiprotocolv1.Ciphertext, proofs []*saksiprotocolv1.CDSProof) {
		for k := 0; k < n; k++ {
			cts = append(cts, &saksiprotocolv1.Ciphertext{Version: saksiprotocolv1.WireVersion, Pad: next(32), Data: next(32)})
			p := &saksiprotocolv1.CDSProof{Version: saksiprotocolv1.WireVersion}
			for b := 0; b < 2; b++ {
				p.Branches = append(p.Branches, &saksiprotocolv1.CDSProofBranch{
					CommitmentA: next(32), CommitmentB: next(32), Challenge: next(32), Response: next(32),
				})
			}
			proofs = append(proofs, p)
		}
		return
	}
	v.honest, v.honestCDS = record()
	v.proof = &saksiprotocolv1.ChaumPedersenProof{
		Version:     saksiprotocolv1.WireVersion,
		CommitmentA: next(32), CommitmentB: next(32), Challenge: next(32), Response: next(32),
	}
	if withOvervote {
		v.overvote, v.overCDS = record()
	}
	if off != len(buf) {
		t.Fatalf("selection vector has %d trailing bytes", len(buf)-off)
	}
	return v
}

// withSelectionElection creates the vector's election (one position, one
// contest per candidate, joint key = the vector's pk) bound to issuerPK.
func withSelectionElection(t *testing.T, sc *SmartContract, ctx *fakeContext, v selectionVector, issuerPK []byte) {
	t.Helper()
	contests := make([]string, len(v.honest))
	for k := range contests {
		contests[k] = fmt.Sprintf("%s/%d", v.positionID, k)
	}
	params := &saksiprotocolv1.ElectionParameters{
		Version:         saksiprotocolv1.WireVersion,
		ElectionId:      v.electionID,
		ContestIds:      contests,
		TrusteeIds:      []string{"t1"},
		Threshold:       1,
		IssuerPublicKey: issuerPK,
	}
	if err := sc.CreateElection(ctx, mustMarshalParams(t, params)); err != nil {
		t.Fatalf("CreateElection: %v", err)
	}
	dkg := &saksiprotocolv1.DKGTranscript{
		Version:    saksiprotocolv1.WireVersion,
		ElectionId: v.electionID,
		Threshold:  1,
		TrusteeCommitments: []*saksiprotocolv1.TrusteeCommitment{
			{TrusteeId: "t1", CoefficientCommitments: [][]byte{v.pk}},
		},
	}
	if err := sc.PublishDKGTranscript(ctx, mustMarshalDKG(t, dkg)); err != nil {
		t.Fatalf("PublishDKGTranscript: %v", err)
	}
}

// selectionBallot is a position record from the vector with a real issuer
// signature (credential-sig vector). overvote picks the all-ones record.
func selectionBallot(t *testing.T, v selectionVector, overvote bool, proof *saksiprotocolv1.ChaumPedersenProof) *saksiprotocolv1.Ballot {
	t.Helper()
	sigPK, commitment, rPrime, s := loadSigVector(t)
	cts, cds := v.honest, v.honestCDS
	if overvote {
		cts, cds = v.overvote, v.overCDS
	}
	return &saksiprotocolv1.Ballot{
		Version:              saksiprotocolv1.WireVersion,
		ElectionId:           v.electionID,
		PositionId:           v.positionID,
		Ciphertexts:          cts,
		WellFormednessProofs: cds,
		SelectionProof:       proof,
		CredentialPresentation: &saksiprotocolv1.CredentialPresentation{
			Version:              saksiprotocolv1.WireVersion,
			CredentialCommitment: commitment,
			IssuerPublicKey:      sigPK,
			PresentationProof:    append(append([]byte{}, rPrime...), s...),
			Nullifier:            &saksiprotocolv1.Nullifier{Version: saksiprotocolv1.WireVersion, Value: v.nullifier},
		},
	}
}

// The selection gate: on an election bound to an issuer, a record must carry
// a verifying sum-to-one proof. An overvote whose every CDS proof is valid is
// refused `selection`, with the honest proof or with none; a legacy election
// without an issuer key keeps accepting as before.
func TestSubmitBallotSelectionProof(t *testing.T) {
	v := loadSelectionVector(t)
	sigPK, _, _, _ := loadSigVector(t)

	submit := func(issuerPK []byte, b *saksiprotocolv1.Ballot) string {
		sc, ctx := &SmartContract{}, newContext()
		withSelectionElection(t, sc, ctx, v, issuerPK)
		return gateIDOf(sc.SubmitBallot(ctx, mustMarshal(t, b)))
	}

	tampered := selectionBallot(t, v, false, v.proof)
	tampered.SelectionProof = &saksiprotocolv1.ChaumPedersenProof{
		Version:     v.proof.Version,
		CommitmentA: v.proof.CommitmentA,
		CommitmentB: v.proof.CommitmentB,
		Challenge:   v.proof.Challenge,
		Response:    append([]byte{v.proof.Response[0] ^ 0x01}, v.proof.Response[1:]...),
	}
	wrongVersion := selectionBallot(t, v, false, &saksiprotocolv1.ChaumPedersenProof{
		Version:     saksiprotocolv1.WireVersion + 1,
		CommitmentA: v.proof.CommitmentA, CommitmentB: v.proof.CommitmentB,
		Challenge: v.proof.Challenge, Response: v.proof.Response,
	})

	for _, c := range []struct {
		name     string
		issuerPK []byte
		ballot   *saksiprotocolv1.Ballot
		want     string
	}{
		{"honest one-hot", sigPK, selectionBallot(t, v, false, v.proof), "<accepted>"},
		{"honest without a proof", sigPK, selectionBallot(t, v, false, nil), "selection"},
		{"tampered proof", sigPK, tampered, "selection"},
		{"unknown proof version", sigPK, wrongVersion, "selection"},
		{"overvote reusing the honest proof", sigPK, selectionBallot(t, v, true, v.proof), "selection"},
		{"overvote without a proof", sigPK, selectionBallot(t, v, true, nil), "selection"},
		{"legacy election, overvote without a proof", nil, selectionBallot(t, v, true, nil), "<accepted>"},
	} {
		if got := submit(c.issuerPK, c.ballot); got != c.want {
			t.Errorf("%s: refused at %q, want %q", c.name, got, c.want)
		}
	}
}

// An empty position_id is the legacy whole-ballot record: its nullifier is no
// position's and its selection proof only bounds the sum over every contest.
// After a voter's per-position record is in, such a record would be a second
// vote in that position, so an issuer-bound election with per-position
// contests refuses it at `shape`. Legacy elections keep accepting it.
func TestSubmitBallotRefusesAnEmptyPositionOnAPositionedElection(t *testing.T) {
	v := loadSelectionVector(t)
	sigPK, _, _, _ := loadSigVector(t)

	sc, ctx := &SmartContract{}, newContext()
	withSelectionElection(t, sc, ctx, v, sigPK)
	if err := sc.SubmitBallot(ctx, mustMarshal(t, selectionBallot(t, v, false, v.proof))); err != nil {
		t.Fatalf("the per-position record must be accepted: %v", err)
	}
	// The exploit: the same voter's fully valid whole-ballot record. Its
	// nullifier is the one a presentation for position "" derives (distinct
	// from the per-position one, so the nullifier gate passes), its CDS proofs
	// are bound to it, and its selection proof over both contests verifies.
	if got := gateIDOf(sc.SubmitBallot(ctx, mustMarshal(t, wholeBallot(t)))); got != "shape" {
		t.Errorf("whole-ballot record after a per-position one: refused at %q, want shape", got)
	}

	// A position that matches no contest was already refused at shape.
	nowhere := selectionBallot(t, v, false, v.proof)
	nowhere.PositionId = "no-such-position"
	nowhere.CredentialPresentation.Nullifier.Value = bytes.Repeat([]byte{0x43}, 32)
	if got := gateIDOf(sc.SubmitBallot(ctx, mustMarshal(t, nowhere))); got != "shape" {
		t.Errorf("unknown position: refused at %q, want shape", got)
	}

	// Legacy control: without an issuer key the same record is accepted
	// after the per-position one, as before.
	sc2, ctx2 := &SmartContract{}, newContext()
	withSelectionElection(t, sc2, ctx2, v, nil)
	if err := sc2.SubmitBallot(ctx2, mustMarshal(t, selectionBallot(t, v, false, v.proof))); err != nil {
		t.Fatalf("legacy election: the per-position record must be accepted: %v", err)
	}
	if err := sc2.SubmitBallot(ctx2, mustMarshal(t, wholeBallot(t))); err != nil {
		t.Errorf("legacy election: the whole-ballot record must still be accepted: %v", err)
	}
}

// wholeBallot is the whole-ballot-record vector (Rust
// whole_ballot_record_vector) as a ballot with an empty position_id, carrying
// the credential-sig vector's issuer signature like selectionBallot.
func wholeBallot(t *testing.T) *saksiprotocolv1.Ballot {
	t.Helper()
	w := loadVector(t, "whole-ballot-record-v1.hex", false)
	if w.positionID != "" {
		t.Fatalf("whole-ballot vector names position %q", w.positionID)
	}
	w.positionID = "p0" // selectionBallot takes the record's fields from w
	b := selectionBallot(t, w, false, w.proof)
	b.PositionId = ""
	return b
}
