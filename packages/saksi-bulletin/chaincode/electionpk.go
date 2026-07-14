package main

import (
	"fmt"

	"github.com/gtank/ristretto255"
	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
)

// deriveElectionPublicKey computes the joint ElGamal public key from a published
// DKG transcript: the sum of every trustee's constant-term coefficient
// commitment. This mirrors saksi-crypto's DKG combine
// (`public_point += coefficient_commitments[0]` over the active commitments).
//
// The published transcript stores only qualified commitments — dealers
// disqualified by complaints are already excluded before publication — so the
// on-chain sum needs no complaint filtering. Returns the 32-byte canonical
// ristretto255 encoding of the joint key.
func deriveElectionPublicKey(transcript *saksiprotocolv1.DKGTranscript) ([]byte, error) {
	commitments := transcript.GetTrusteeCommitments()
	if len(commitments) == 0 {
		return nil, fmt.Errorf("DKG transcript has no trustee commitments")
	}
	sum := ristretto255.NewIdentityElement()
	for i, c := range commitments {
		coeffs := c.GetCoefficientCommitments()
		if len(coeffs) == 0 {
			return nil, fmt.Errorf("trustee commitment %d has no coefficient commitments", i)
		}
		point := ristretto255.NewIdentityElement()
		if _, err := point.SetCanonicalBytes(coeffs[0]); err != nil {
			return nil, fmt.Errorf("trustee commitment %d constant term is not a canonical ristretto255 point: %w", i, err)
		}
		sum = sum.Add(sum, point)
	}
	return sum.Bytes(), nil
}
