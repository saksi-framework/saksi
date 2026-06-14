// Package credverify performs on-chain verification of the issuer Schnorr
// signature carried in a Saksi credential presentation.
//
// This mirrors, byte for byte, the Rust reference implementation in
// saksi-credentials (`verify_issuer_signature` / `compute_issuance_challenge`):
// the Fiat-Shamir challenge is derived from a Merlin transcript labelled
// "saksi.credentials.issuance.v1", and the signature equation checked is
// `s·G == R' + e·Pk_i` over ristretto255.
//
// Per the locked hybrid-verification split, this is the one NIZK-adjacent check
// the chaincode performs on submission; the heavier well-formedness proofs
// (CDS, Chaum-Pedersen) remain off-chain in the auditor. A cross-language golden
// vector (saksi-protocol/test-vectors/credential-sig-v1.hex) pins the byte
// agreement between this verifier and the Rust signer.
package credverify

import (
	"fmt"

	"github.com/gtank/merlin"
	"github.com/gtank/ristretto255"
)

// transcriptLabel is the Merlin domain-separation label for the issuance
// challenge. It must equal saksi-credentials' TRANSCRIPT_LABEL_ISSUANCE.
const transcriptLabel = "saksi.credentials.issuance.v1"

// VerifyIssuerSignature checks the issuer Schnorr signature (rPrime, s) on the
// credential commitment under issuerPK. Every argument is a 32-byte canonical
// ristretto255 encoding: issuerPK, commitment and rPrime are points, s is a
// scalar. Returns nil iff the signature verifies.
func VerifyIssuerSignature(issuerPK, commitment, rPrime, s []byte) error {
	pk := ristretto255.NewIdentityElement()
	if _, err := pk.SetCanonicalBytes(issuerPK); err != nil {
		return fmt.Errorf("issuer public key is not a valid ristretto255 point: %w", err)
	}
	c := ristretto255.NewIdentityElement()
	if _, err := c.SetCanonicalBytes(commitment); err != nil {
		return fmt.Errorf("credential commitment is not a valid ristretto255 point: %w", err)
	}
	r := ristretto255.NewIdentityElement()
	if _, err := r.SetCanonicalBytes(rPrime); err != nil {
		return fmt.Errorf("signature R' is not a valid ristretto255 point: %w", err)
	}
	sc := ristretto255.NewScalar()
	if _, err := sc.SetCanonicalBytes(s); err != nil {
		return fmt.Errorf("signature scalar is not canonical: %w", err)
	}

	e := issuanceChallenge(pk, c, r)

	// lhs = s·G ; rhs = R' + e·Pk_i
	lhs := ristretto255.NewIdentityElement().ScalarBaseMult(sc)
	rhs := ristretto255.NewIdentityElement().ScalarMult(e, pk)
	rhs = rhs.Add(rhs, r)

	if lhs.Equal(rhs) != 1 {
		return fmt.Errorf("credential signature does not verify")
	}
	return nil
}

// issuanceChallenge recomputes e = H(transcript, Pk_i, C, R') exactly as the
// Rust compute_issuance_challenge does: append the three compressed points
// under their labels, extract 64 bytes, reduce mod the group order.
func issuanceChallenge(pk, c, r *ristretto255.Element) *ristretto255.Scalar {
	t := merlin.NewTranscript(transcriptLabel)
	t.AppendMessage([]byte("issuer-pk"), pk.Bytes())
	t.AppendMessage([]byte("commitment"), c.Bytes())
	t.AppendMessage([]byte("r-prime"), r.Bytes())
	buf := t.ExtractBytes([]byte("challenge"), 64)
	e, err := ristretto255.NewScalar().SetUniformBytes(buf)
	if err != nil {
		// buf is always exactly 64 bytes from ExtractBytes, so this never fires.
		panic(fmt.Sprintf("challenge reduction: %v", err))
	}
	return e
}
