// Package cdsverify performs on-chain verification of the Cramer-Damgård-
// Schoenmakers (CDS) OR-proof that a ballot's per-contest ciphertext encrypts a
// value in the binary set {0, 1} — i.e. ballot well-formedness.
//
// This mirrors, byte for byte, the Rust reference implementation in
// saksi-crypto (`nizk::cds::CDSProof::verify` + `binding_context`): the
// Fiat-Shamir challenge is derived from a Merlin transcript labelled
// "saksi.nizk.cds.v1", the context binding is length-prefixed
// `election_id || contest_id || nullifier`, and the choice set is {0, 1}.
//
// Per ADR-0007 (superseding ADR-0005's off-chain-only split), this is verified
// on-chain at endorsement. The binding uses the ballot's nullifier rather than
// a positional serial precisely because endorsement runs before ordering and
// cannot know a ballot's commit position; the nullifier is a per-ballot unique
// tag reconstructible at endorsement, so verification is order-independent
// (safe under concurrent submission). A cross-language golden vector
// (saksi-protocol/test-vectors/cds-proof-v1.hex) pins the byte agreement.
//
// Determinism (endorsement-safe): every point/scalar is decoded with
// SetCanonicalBytes, which rejects non-canonical encodings identically to the
// Rust verifier; all error paths return an error (never panic, never a
// sometimes-true branch); there is no map iteration. Two endorsing peers on the
// same input therefore reach the same verdict.
package cdsverify

import (
	"fmt"

	"github.com/gtank/merlin"
	"github.com/gtank/ristretto255"
)

// transcriptLabel is the Merlin domain-separation label for the CDS OR-proof.
// It must equal saksi-crypto's TRANSCRIPT_LABEL_CDS.
const transcriptLabel = "saksi.nizk.cds.v1"

// Branch is one branch of the CDS OR-proof in canonical wire form: two 32-byte
// compressed ristretto255 points and two 32-byte canonical scalars.
type Branch struct {
	CommitmentA []byte
	CommitmentB []byte
	Challenge   []byte
	Response    []byte
}

// decodedBranch holds a branch after canonical decoding.
type decodedBranch struct {
	commitmentG, commitmentH *ristretto255.Element
	challenge, response      *ristretto255.Scalar
}

// BindingContext reconstructs the CDS Fiat-Shamir context binding —
// length-prefixed election_id || contest_id || nullifier — byte-identical to
// saksi-crypto's `binding_context`. The 8-byte big-endian length prefixes keep
// the three fields unambiguous.
func BindingContext(electionID, contestID string, nullifier []byte) []byte {
	parts := [][]byte{[]byte(electionID), []byte(contestID), nullifier}
	out := make([]byte, 0, 3*8+len(electionID)+len(contestID)+len(nullifier))
	for _, p := range parts {
		var lenPrefix [8]byte
		putU64BE(lenPrefix[:], uint64(len(p)))
		out = append(out, lenPrefix[:]...)
		out = append(out, p...)
	}
	return out
}

// VerifyBinaryCDS verifies a binary-{0,1} CDS OR-proof for a single contest
// ciphertext (pad, data) under electionPK, bound to
// BindingContext(electionID, contestID, nullifier). Every point/scalar argument
// is a 32-byte canonical ristretto255 encoding. Returns nil iff the proof
// verifies.
func VerifyBinaryCDS(electionID, contestID string, nullifier, electionPK, pad, data []byte, branches []Branch) error {
	if len(branches) != 2 {
		return fmt.Errorf("binary CDS proof must have exactly 2 branches, got %d", len(branches))
	}

	pk, err := decodePoint(electionPK, "election public key")
	if err != nil {
		return err
	}
	bigR, err := decodePoint(pad, "ciphertext pad")
	if err != nil {
		return err
	}
	bigS, err := decodePoint(data, "ciphertext data")
	if err != nil {
		return err
	}

	// Decode branch points/scalars up front (rejects non-canonical encodings).
	decoded := make([]decodedBranch, len(branches))
	for i, b := range branches {
		cg, err := decodePoint(b.CommitmentA, "branch commitment_g")
		if err != nil {
			return err
		}
		ch, err := decodePoint(b.CommitmentB, "branch commitment_h")
		if err != nil {
			return err
		}
		c, err := decodeScalar(b.Challenge, "branch challenge")
		if err != nil {
			return err
		}
		s, err := decodeScalar(b.Response, "branch response")
		if err != nil {
			return err
		}
		decoded[i] = decodedBranch{cg, ch, c, s}
	}

	// The binary choice set {0, 1} as canonical scalar encodings.
	zeroScalar := ristretto255.NewScalar() // 0
	oneScalar := ristretto255.NewScalar()
	if _, err := oneScalar.SetCanonicalBytes(scalarOneBytes()); err != nil {
		return fmt.Errorf("internal: scalar one is not canonical: %w", err)
	}
	choiceScalars := []*ristretto255.Scalar{zeroScalar, oneScalar}

	ctx := BindingContext(electionID, contestID, nullifier)

	// 1. Rebuild the Fiat-Shamir total challenge and compare to Sum(c_i).
	recomputed := fiatShamirTotalChallenge(pk, bigR, bigS, choiceScalars, ctx, decoded)
	cSum := ristretto255.NewScalar()
	for i := range decoded {
		cSum = cSum.Add(cSum, decoded[i].challenge)
	}
	if cSum.Equal(recomputed) != 1 {
		return fmt.Errorf("CDS challenge sum does not match Fiat-Shamir total")
	}

	// 2. Per-branch verification equations:
	//    s*G  == T_g + c*R
	//    s*pk == T_h + c*Y_i,  where Y_i = S - m_i*G
	g := ristretto255.NewIdentityElement().ScalarBaseMult(oneScalar) // G = 1*G
	for i := range decoded {
		br := decoded[i]

		miG := ristretto255.NewIdentityElement().ScalarBaseMult(choiceScalars[i]) // m_i*G
		yi := ristretto255.NewIdentityElement().Subtract(bigS, miG)

		lhsG := ristretto255.NewIdentityElement().ScalarMult(br.response, g)
		rhsG := ristretto255.NewIdentityElement().ScalarMult(br.challenge, bigR)
		rhsG = rhsG.Add(rhsG, br.commitmentG)

		lhsH := ristretto255.NewIdentityElement().ScalarMult(br.response, pk)
		rhsH := ristretto255.NewIdentityElement().ScalarMult(br.challenge, yi)
		rhsH = rhsH.Add(rhsH, br.commitmentH)

		if lhsG.Equal(rhsG) != 1 || lhsH.Equal(rhsH) != 1 {
			return fmt.Errorf("CDS branch %d verification equation failed", i)
		}
	}

	return nil
}

// fiatShamirTotalChallenge rebuilds the CDS Merlin transcript exactly as the
// Rust prover/verifier does and extracts the total challenge scalar.
func fiatShamirTotalChallenge(
	pk, bigR, bigS *ristretto255.Element,
	choiceSet []*ristretto255.Scalar,
	ctx []byte,
	branches []decodedBranch,
) *ristretto255.Scalar {
	t := merlin.NewTranscript(transcriptLabel)
	t.AppendMessage([]byte("public_key"), pk.Bytes())
	t.AppendMessage([]byte("ciphertext_pad"), bigR.Bytes())
	t.AppendMessage([]byte("ciphertext_data"), bigS.Bytes())

	var lenBuf [8]byte
	putU64BE(lenBuf[:], uint64(len(choiceSet)))
	t.AppendMessage([]byte("choice_set_len"), lenBuf[:])
	for _, choice := range choiceSet {
		t.AppendMessage([]byte("choice"), choice.Bytes())
	}
	t.AppendMessage([]byte("context"), ctx)
	for i := range branches {
		t.AppendMessage([]byte("branch_commitment_g"), branches[i].commitmentG.Bytes())
		t.AppendMessage([]byte("branch_commitment_h"), branches[i].commitmentH.Bytes())
	}

	buf := t.ExtractBytes([]byte("total_challenge"), 64)
	out, err := ristretto255.NewScalar().SetUniformBytes(buf)
	if err != nil {
		// ExtractBytes always returns exactly 64 bytes, so this never fires.
		panic(fmt.Sprintf("challenge reduction: %v", err))
	}
	return out
}

func decodePoint(b []byte, what string) (*ristretto255.Element, error) {
	e := ristretto255.NewIdentityElement()
	if _, err := e.SetCanonicalBytes(b); err != nil {
		return nil, fmt.Errorf("%s is not a valid canonical ristretto255 point: %w", what, err)
	}
	return e, nil
}

func decodeScalar(b []byte, what string) (*ristretto255.Scalar, error) {
	s := ristretto255.NewScalar()
	if _, err := s.SetCanonicalBytes(b); err != nil {
		return nil, fmt.Errorf("%s is not a canonical scalar: %w", what, err)
	}
	return s, nil
}

// scalarOneBytes is the canonical 32-byte little-endian encoding of the scalar 1.
func scalarOneBytes() []byte {
	b := make([]byte, 32)
	b[0] = 1
	return b
}

func putU64BE(dst []byte, v uint64) {
	dst[0] = byte(v >> 56)
	dst[1] = byte(v >> 48)
	dst[2] = byte(v >> 40)
	dst[3] = byte(v >> 32)
	dst[4] = byte(v >> 24)
	dst[5] = byte(v >> 16)
	dst[6] = byte(v >> 8)
	dst[7] = byte(v)
}
