// Package sigverify performs on-chain verification of the Schnorr signatures a
// tally carries: each trustee's proof of knowledge of its DKG share, taken over
// the published totals.
//
// This mirrors, byte for byte, the Rust reference implementation —
// saksi-crypto's `nizk::schnorr::SchnorrProof::verify` for the proof itself,
// saksi-auditor's `tally::tally_sig_context` for the signed bytes, and
// saksi-auditor's `dkg::trustee_verification_key` for the key each signature is
// checked under. A cross-language golden vector
// (saksi-protocol/test-vectors/tally-sig-v1.hex) pins the byte agreement.
//
// Together with cdsverify and credverify this is the third NIZK-adjacent check
// the chaincode performs; it is what lets PublishTally refuse a tally that
// fewer than `threshold` trustees endorsed, rather than leaving the count to
// the console (see contract.go's PublishTally).
//
// Determinism (endorsement-safe): every point and scalar is decoded with
// SetCanonicalBytes, which rejects non-canonical encodings identically to the
// Rust verifier; every failure path returns an error (never panics); there is
// no map iteration. Two endorsing peers on the same input reach the same
// verdict.
package sigverify

import (
	"encoding/binary"
	"fmt"

	"github.com/gtank/merlin"
	"github.com/gtank/ristretto255"
	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
)

// transcriptLabel is the Merlin domain-separation label for a Schnorr proof.
// It must equal saksi-crypto's TRANSCRIPT_LABEL_SCHNORR.
const transcriptLabel = "saksi.nizk.schnorr.v1"

// tallySigDomain is the domain separator a trustee signs a tally under. It must
// equal saksi-auditor's TALLY_SIG_DOMAIN.
const tallySigDomain = "saksi.tally.sig.v1"

// signatureLength is the wire size of SchnorrProof::to_bytes: a 32-byte
// compressed commitment followed by a 32-byte canonical scalar response.
const signatureLength = 64

// TallySigContext reconstructs the exact bytes a trustee signs when endorsing a
// published tally: `b"saksi.tally.sig.v1" || election_id || totals[0..n]`, each
// total as 8 little-endian bytes in contest order.
//
// **There are no length prefixes**, matching the Rust definition byte for byte.
// The layout is unambiguous only because the election id is fixed at election
// creation (this package is called with the id from the stored
// ElectionParameters, never one the tally chose), so no party who would benefit
// can pick an id whose tail absorbs a total. A v2 domain should length-prefix
// the id rather than rely on that.
func TallySigContext(electionID string, totals []uint64) []byte {
	out := make([]byte, 0, len(tallySigDomain)+len(electionID)+8*len(totals))
	out = append(out, tallySigDomain...)
	out = append(out, electionID...)
	var le [8]byte
	for _, total := range totals {
		binary.LittleEndian.PutUint64(le[:], total)
		out = append(out, le[:]...)
	}
	return out
}

// DeriveVerificationKey computes the public verification key of one trustee
// from the DKG transcript alone:
//
//	vk_i = Σ_j Σ_k C_{j,k} · i^k
//
// summed over EVERY dealer j in `transcript.trustee_commitments`. Because the
// DKG hands trustee i the share s_i = Σ_j f_j(i), the result is exactly s_i·G.
//
// **Index convention: `i` is the trustee's 1-based position in `trusteeIDs` —
// the election's `ElectionParameters.trustee_ids` — and never a number parsed
// out of the id string.** Trustee ids are opaque labels; the golden vector
// deliberately uses non-numeric, non-sorted ones so a port that parsed or
// sorted them cannot pass. This is saksi-crypto's own indexing
// (`dkg::run_in_memory` evaluates every dealer polynomial at recipient_id =
// position + 1) and matches saksi-auditor's `dkg::trustee_verification_key`.
//
// Returns the 32-byte canonical ristretto255 encoding of the key.
func DeriveVerificationKey(transcript *saksiprotocolv1.DKGTranscript, trusteeIDs []string, trusteeID string) ([]byte, error) {
	index := -1
	for i, id := range trusteeIDs {
		if id == trusteeID {
			index = i + 1 // 1-based: the DKG never evaluates a share at x = 0
			break
		}
	}
	if index < 0 {
		return nil, fmt.Errorf("trustee %q is not in the election's trustee set", trusteeID)
	}

	dealers := transcript.GetTrusteeCommitments()
	if len(dealers) == 0 {
		return nil, fmt.Errorf("DKG transcript has no trustee commitments")
	}

	x, err := scalarFromUint64(uint64(index))
	if err != nil {
		return nil, err
	}

	sum := ristretto255.NewIdentityElement()
	for j, dealer := range dealers {
		coeffs := dealer.GetCoefficientCommitments()
		if len(coeffs) == 0 {
			return nil, fmt.Errorf("trustee commitment %d has no coefficient commitments", j)
		}
		// Horner over the dealer's polynomial: C_0 + x·(C_1 + x·(C_2 + …)).
		acc := ristretto255.NewIdentityElement()
		for k := len(coeffs) - 1; k >= 0; k-- {
			point := ristretto255.NewIdentityElement()
			if _, err := point.SetCanonicalBytes(coeffs[k]); err != nil {
				return nil, fmt.Errorf(
					"trustee commitment %d coefficient_commitments[%d] is not a canonical ristretto255 point: %w", j, k, err)
			}
			acc = acc.ScalarMult(x, acc)
			acc = acc.Add(acc, point)
		}
		sum = sum.Add(sum, acc)
	}
	return sum.Bytes(), nil
}

// VerifySchnorr checks a 64-byte Schnorr proof (compressed commitment R ‖
// scalar response s) of knowledge of the discrete log of `verificationKey` to
// the ristretto255 basepoint, bound to `context`. Returns nil iff it verifies.
//
// The transcript is Rust's `SchnorrProof::verify` verbatim: base, statement and
// context appended under their labels, then the commitment, then 64 challenge
// bytes reduced mod the group order; the equation checked is s·G == R + c·P.
func VerifySchnorr(verificationKey, context, signature []byte) error {
	if len(signature) != signatureLength {
		return fmt.Errorf("tally signature is %d bytes, want %d", len(signature), signatureLength)
	}
	statement := ristretto255.NewIdentityElement()
	if _, err := statement.SetCanonicalBytes(verificationKey); err != nil {
		return fmt.Errorf("verification key is not a canonical ristretto255 point: %w", err)
	}
	commitment := ristretto255.NewIdentityElement()
	if _, err := commitment.SetCanonicalBytes(signature[:32]); err != nil {
		return fmt.Errorf("signature commitment is not a canonical ristretto255 point: %w", err)
	}
	response := ristretto255.NewScalar()
	if _, err := response.SetCanonicalBytes(signature[32:]); err != nil {
		return fmt.Errorf("signature response is not a canonical scalar: %w", err)
	}

	one, err := scalarFromUint64(1)
	if err != nil {
		return err
	}
	base := ristretto255.NewIdentityElement().ScalarBaseMult(one) // G = 1·G

	challenge, err := schnorrChallenge(base, statement, context, commitment)
	if err != nil {
		return err
	}

	// s·G == R + c·P
	lhs := ristretto255.NewIdentityElement().ScalarMult(response, base)
	rhs := ristretto255.NewIdentityElement().ScalarMult(challenge, statement)
	rhs = rhs.Add(rhs, commitment)
	if lhs.Equal(rhs) != 1 {
		return fmt.Errorf("tally signature does not verify")
	}
	return nil
}

// schnorrChallenge rebuilds the Merlin transcript exactly as the Rust
// prover/verifier does (append_statement then derive_challenge) and extracts
// the challenge scalar.
func schnorrChallenge(base, statement *ristretto255.Element, context []byte, commitment *ristretto255.Element) (*ristretto255.Scalar, error) {
	t := merlin.NewTranscript(transcriptLabel)
	t.AppendMessage([]byte("base"), base.Bytes())
	t.AppendMessage([]byte("statement"), statement.Bytes())
	t.AppendMessage([]byte("context"), context)
	t.AppendMessage([]byte("commitment"), commitment.Bytes())

	buf := t.ExtractBytes([]byte("challenge"), 64)
	challenge, err := ristretto255.NewScalar().SetUniformBytes(buf)
	if err != nil {
		// ExtractBytes always returns exactly 64 bytes, so this never fires.
		return nil, fmt.Errorf("challenge reduction: %w", err)
	}
	return challenge, nil
}

// scalarFromUint64 encodes v as a canonical little-endian ristretto255 scalar.
func scalarFromUint64(v uint64) (*ristretto255.Scalar, error) {
	var buf [32]byte
	binary.LittleEndian.PutUint64(buf[:8], v)
	s := ristretto255.NewScalar()
	if _, err := s.SetCanonicalBytes(buf[:]); err != nil {
		return nil, fmt.Errorf("internal: scalar %d is not canonical: %w", v, err)
	}
	return s, nil
}
