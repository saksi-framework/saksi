// Package selectionverify performs on-chain verification of a ballot record's
// sum-to-one selection proof: the record's ciphertexts encrypt exactly one
// selection in total.
//
// This mirrors, byte for byte, saksi-crypto's `nizk::selection`: with
// A = Σ pad_k and B = Σ data_k − G, the proof is a Chaum-Pedersen proof that
// log_G(A) = log_Y(B) (Y the joint election key), whose Merlin transcript is
// labelled "saksi.nizk.chaum-pedersen.v1" and whose context is
// "saksi.ballot.selection.v1" || BindingContext(election_id, position_id,
// nullifier). A cross-language golden vector
// (saksi-protocol/test-vectors/selection-proof-v1.hex) pins the agreement.
//
// Determinism (endorsement-safe) follows cdsverify: canonical decoding only,
// every failure is an error, no map iteration.
package selectionverify

import (
	"fmt"

	"github.com/gtank/merlin"
	"github.com/gtank/ristretto255"
	"github.com/saksi-framework/saksi/packages/saksi-bulletin/chaincode/cdsverify"
)

// transcriptLabel must equal saksi-crypto's TRANSCRIPT_LABEL_CHAUM_PEDERSEN.
const transcriptLabel = "saksi.nizk.chaum-pedersen.v1"

// contextLabel must equal saksi-crypto's SELECTION_CONTEXT_LABEL.
const contextLabel = "saksi.ballot.selection.v1"

// Proof is a Chaum-Pedersen proof in wire form: two 32-byte compressed points
// and two 32-byte canonical scalars.
type Proof struct {
	CommitmentA []byte
	CommitmentB []byte
	Challenge   []byte
	Response    []byte
}

// Context is contextLabel || cdsverify.BindingContext(electionID, positionID, nullifier).
func Context(electionID, positionID string, nullifier []byte) []byte {
	return append([]byte(contextLabel), cdsverify.BindingContext(electionID, positionID, nullifier)...)
}

// Verify checks that the ciphertexts (pads[k], datas[k]) under electionPK
// encrypt exactly one selection, bound to Context(electionID, positionID,
// nullifier). Returns nil iff the proof verifies.
func Verify(electionID, positionID string, nullifier, electionPK []byte, pads, datas [][]byte, proof Proof) error {
	if len(pads) == 0 || len(pads) != len(datas) {
		return fmt.Errorf("selection proof needs matching non-empty ciphertexts, got %d pads / %d datas", len(pads), len(datas))
	}
	y, err := decodePoint(electionPK, "election public key")
	if err != nil {
		return err
	}
	a := ristretto255.NewIdentityElement()
	b := ristretto255.NewIdentityElement()
	for k := range pads {
		pad, err := decodePoint(pads[k], "ciphertext pad")
		if err != nil {
			return err
		}
		data, err := decodePoint(datas[k], "ciphertext data")
		if err != nil {
			return err
		}
		a = a.Add(a, pad)
		b = b.Add(b, data)
	}
	g := ristretto255.NewGeneratorElement()
	b = b.Subtract(b, g)

	tg, err := decodePoint(proof.CommitmentA, "commitment_a")
	if err != nil {
		return err
	}
	th, err := decodePoint(proof.CommitmentB, "commitment_b")
	if err != nil {
		return err
	}
	c, err := decodeScalar(proof.Challenge, "challenge")
	if err != nil {
		return err
	}
	s, err := decodeScalar(proof.Response, "response")
	if err != nil {
		return err
	}

	t := merlin.NewTranscript(transcriptLabel)
	t.AppendMessage([]byte("g"), g.Bytes())
	t.AppendMessage([]byte("h"), y.Bytes())
	t.AppendMessage([]byte("a"), a.Bytes())
	t.AppendMessage([]byte("b"), b.Bytes())
	t.AppendMessage([]byte("context"), Context(electionID, positionID, nullifier))
	t.AppendMessage([]byte("commitment_g"), tg.Bytes())
	t.AppendMessage([]byte("commitment_h"), th.Bytes())
	recomputed, err := ristretto255.NewScalar().SetUniformBytes(t.ExtractBytes([]byte("challenge"), 64))
	if err != nil {
		return fmt.Errorf("internal: challenge reduction: %w", err)
	}
	if recomputed.Equal(c) != 1 {
		return fmt.Errorf("selection proof challenge does not match Fiat-Shamir transcript")
	}

	// s*G == T_g + c*A  and  s*Y == T_h + c*B
	lhsG := ristretto255.NewIdentityElement().ScalarBaseMult(s)
	rhsG := ristretto255.NewIdentityElement().ScalarMult(c, a)
	rhsG = rhsG.Add(rhsG, tg)
	lhsH := ristretto255.NewIdentityElement().ScalarMult(s, y)
	rhsH := ristretto255.NewIdentityElement().ScalarMult(c, b)
	rhsH = rhsH.Add(rhsH, th)
	if lhsG.Equal(rhsG) != 1 || lhsH.Equal(rhsH) != 1 {
		return fmt.Errorf("selection proof verification equation failed")
	}
	return nil
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
