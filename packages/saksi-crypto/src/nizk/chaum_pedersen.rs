//! Chaum-Pedersen equality-of-discrete-log proofs.
//!
//! Sigma protocol proving the statement `A = x*G ∧ B = x*H` for two
//! independent bases `G` and `H`, made non-interactive via the Merlin
//! Fiat-Shamir transform bound to [`TRANSCRIPT_LABEL_CHAUM_PEDERSEN`].
//!
//! Used by trustees to prove that a partial decryption `D_i = s_i * R` (where
//! `R` is the ElGamal pad) was computed with the same share `s_i` that
//! corresponds to the trustee's published public-key share `pub_i = s_i * G`.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use saksi_protocol::{ChaumPedersenProof as ProtocolChaumPedersenProof, WIRE_VERSION};

use crate::{
    group::{compress_point, point_from_compressed, scalar_from_canonical_bytes},
    transcript::{new_transcript, TRANSCRIPT_LABEL_CHAUM_PEDERSEN},
    CryptoError, CryptoResult,
};

pub const MODULE_NAME: &str = "chaum-pedersen";

/// Non-interactive Chaum-Pedersen proof of equality of two discrete logarithms.
///
/// The proof carries the prover's two commitments (`commitment_g = k*G` and
/// `commitment_h = k*H`), the Fiat-Shamir [`challenge`] (cached so a verifier
/// can detect tampering before evaluating the algebra), and the [`response`]
/// `s = k + c*x`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChaumPedersenProof {
    /// `T_g = k * G` — prover's commitment under the first base.
    pub commitment_g: RistrettoPoint,
    /// `T_h = k * H` — prover's commitment under the second base.
    pub commitment_h: RistrettoPoint,
    /// Fiat-Shamir challenge scalar `c`.
    pub challenge: Scalar,
    /// Response `s = k + c * x` (mod ℓ).
    pub response: Scalar,
}

impl ChaumPedersenProof {
    /// Produce a proof of `a = witness * g ∧ b = witness * h` bound to
    /// `context`. The caller must ensure `a` and `b` actually equal those
    /// products; this routine does not re-check the witness.
    pub fn prove(
        g: &RistrettoPoint,
        h: &RistrettoPoint,
        a: &RistrettoPoint,
        b: &RistrettoPoint,
        witness: &Scalar,
        context: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Self {
        let mut k = Scalar::random(rng);
        let t_g = k * g;
        let t_h = k * h;

        let challenge = fiat_shamir_challenge(g, h, a, b, context, &t_g, &t_h);
        let response = k + challenge * witness;

        // `k` is the only secret value (besides the witness, owned by caller);
        // zeroize it so it does not linger on the stack.
        k.zeroize();

        Self {
            commitment_g: t_g,
            commitment_h: t_h,
            challenge,
            response,
        }
    }

    /// Verify that the proof attests to `a = x*g ∧ b = x*h` for some `x`,
    /// bound to `context`. Returns [`CryptoError::VerificationFailed`] on any
    /// mismatch.
    pub fn verify(
        &self,
        g: &RistrettoPoint,
        h: &RistrettoPoint,
        a: &RistrettoPoint,
        b: &RistrettoPoint,
        context: &[u8],
    ) -> CryptoResult<()> {
        // Belt-and-suspenders: recompute the Fiat-Shamir challenge and detect
        // mutation of the stored `challenge` field before doing any algebra.
        let recomputed =
            fiat_shamir_challenge(g, h, a, b, context, &self.commitment_g, &self.commitment_h);
        if !bool::from(recomputed.to_bytes().ct_eq(&self.challenge.to_bytes())) {
            return Err(CryptoError::VerificationFailed);
        }

        // s*G == T_g + c*A  and  s*H == T_h + c*B
        let lhs_g = self.response * g;
        let rhs_g = self.commitment_g + self.challenge * a;
        let lhs_h = self.response * h;
        let rhs_h = self.commitment_h + self.challenge * b;

        if lhs_g == rhs_g && lhs_h == rhs_h {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }

    /// Encode the proof as its canonical [`ProtocolChaumPedersenProof`] wire
    /// representation (four 32-byte fields plus [`WIRE_VERSION`]).
    pub fn to_wire(&self) -> ProtocolChaumPedersenProof {
        ProtocolChaumPedersenProof {
            version: WIRE_VERSION,
            commitment_a: compress_point(&self.commitment_g).to_vec(),
            commitment_b: compress_point(&self.commitment_h).to_vec(),
            challenge: self.challenge.to_bytes().to_vec(),
            response: self.response.to_bytes().to_vec(),
        }
    }

    /// Decode a [`ProtocolChaumPedersenProof`]. Rejects unknown wire versions,
    /// non-32-byte fields, malformed ristretto encodings
    /// ([`CryptoError::InvalidPoint`]), and non-canonical scalars
    /// ([`CryptoError::InvalidScalar`]).
    pub fn from_wire(wire: &ProtocolChaumPedersenProof) -> CryptoResult<Self> {
        if wire.version != WIRE_VERSION {
            return Err(CryptoError::InvalidParameters(
                "unsupported ChaumPedersenProof wire version",
            ));
        }

        let commitment_g = decode_point(&wire.commitment_a)?;
        let commitment_h = decode_point(&wire.commitment_b)?;
        let challenge = decode_scalar(&wire.challenge)?;
        let response = decode_scalar(&wire.response)?;

        Ok(Self {
            commitment_g,
            commitment_h,
            challenge,
            response,
        })
    }
}

fn fiat_shamir_challenge(
    g: &RistrettoPoint,
    h: &RistrettoPoint,
    a: &RistrettoPoint,
    b: &RistrettoPoint,
    context: &[u8],
    t_g: &RistrettoPoint,
    t_h: &RistrettoPoint,
) -> Scalar {
    let mut transcript = new_transcript(TRANSCRIPT_LABEL_CHAUM_PEDERSEN);
    transcript.append_message(b"g", &compress_point(g));
    transcript.append_message(b"h", &compress_point(h));
    transcript.append_message(b"a", &compress_point(a));
    transcript.append_message(b"b", &compress_point(b));
    transcript.append_message(b"context", context);
    transcript.append_message(b"commitment_g", &compress_point(t_g));
    transcript.append_message(b"commitment_h", &compress_point(t_h));

    let mut buf = [0u8; 64];
    transcript.challenge_bytes(b"challenge", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

fn decode_point(bytes: &[u8]) -> CryptoResult<RistrettoPoint> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidPoint)?;
    point_from_compressed(array)
}

fn decode_scalar(bytes: &[u8]) -> CryptoResult<Scalar> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidScalar)?;
    scalar_from_canonical_bytes(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
    use rand_core::OsRng;

    use crate::group::basepoint;

    /// Build a canonical (G, H, A, B, x) statement for a random witness.
    fn statement(
        rng: &mut OsRng,
    ) -> (
        RistrettoPoint,
        RistrettoPoint,
        RistrettoPoint,
        RistrettoPoint,
        Scalar,
    ) {
        let g = basepoint();
        // H must be an independent base; pick H = h_secret * G for a fixed
        // non-trivial scalar so the test is deterministic-ish but H != G.
        let h = Scalar::from(9_973u64) * g;
        let x = Scalar::random(rng);
        let a = x * g;
        let b = x * h;
        (g, h, a, b, x)
    }

    #[test]
    fn completeness_random_witness() {
        let mut rng = OsRng;
        for _ in 0..16 {
            let (g, h, a, b, x) = statement(&mut rng);
            let proof = ChaumPedersenProof::prove(&g, &h, &a, &b, &x, b"completeness", &mut rng);
            proof
                .verify(&g, &h, &a, &b, b"completeness")
                .expect("honest proof verifies");
        }
    }

    #[test]
    fn tampered_commitment_g_fails() {
        let mut rng = OsRng;
        let (g, h, a, b, x) = statement(&mut rng);
        let proof = ChaumPedersenProof::prove(&g, &h, &a, &b, &x, b"ctx", &mut rng);
        let tampered = ChaumPedersenProof {
            commitment_g: proof.commitment_g + basepoint(),
            ..proof
        };
        assert_eq!(
            tampered.verify(&g, &h, &a, &b, b"ctx"),
            Err(CryptoError::VerificationFailed),
        );
    }

    #[test]
    fn tampered_commitment_h_fails() {
        let mut rng = OsRng;
        let (g, h, a, b, x) = statement(&mut rng);
        let proof = ChaumPedersenProof::prove(&g, &h, &a, &b, &x, b"ctx", &mut rng);
        let tampered = ChaumPedersenProof {
            commitment_h: proof.commitment_h + basepoint(),
            ..proof
        };
        assert_eq!(
            tampered.verify(&g, &h, &a, &b, b"ctx"),
            Err(CryptoError::VerificationFailed),
        );
    }

    #[test]
    fn tampered_response_fails() {
        let mut rng = OsRng;
        let (g, h, a, b, x) = statement(&mut rng);
        let proof = ChaumPedersenProof::prove(&g, &h, &a, &b, &x, b"ctx", &mut rng);
        let tampered = ChaumPedersenProof {
            response: proof.response + Scalar::from(1u64),
            ..proof
        };
        assert_eq!(
            tampered.verify(&g, &h, &a, &b, b"ctx"),
            Err(CryptoError::VerificationFailed),
        );
    }

    #[test]
    fn tampered_challenge_fails() {
        let mut rng = OsRng;
        let (g, h, a, b, x) = statement(&mut rng);
        let proof = ChaumPedersenProof::prove(&g, &h, &a, &b, &x, b"ctx", &mut rng);
        // Bump the cached challenge by one. Verifier recomputes the canonical
        // challenge from the transcript and the stored value no longer matches.
        let tampered = ChaumPedersenProof {
            challenge: proof.challenge + Scalar::from(1u64),
            ..proof
        };
        assert_eq!(
            tampered.verify(&g, &h, &a, &b, b"ctx"),
            Err(CryptoError::VerificationFailed),
        );
    }

    #[test]
    fn wrong_statement_a_fails() {
        let mut rng = OsRng;
        let (g, h, a, b, x) = statement(&mut rng);
        let proof = ChaumPedersenProof::prove(&g, &h, &a, &b, &x, b"ctx", &mut rng);
        let bad_a = a + g; // (x + 1) * G
        assert_eq!(
            proof.verify(&g, &h, &bad_a, &b, b"ctx"),
            Err(CryptoError::VerificationFailed),
        );
    }

    #[test]
    fn wrong_statement_b_fails() {
        let mut rng = OsRng;
        let (g, h, a, b, x) = statement(&mut rng);
        let proof = ChaumPedersenProof::prove(&g, &h, &a, &b, &x, b"ctx", &mut rng);
        let bad_b = b + h; // (x + 1) * H
        assert_eq!(
            proof.verify(&g, &h, &a, &bad_b, b"ctx"),
            Err(CryptoError::VerificationFailed),
        );
    }

    #[test]
    fn swapped_bases_fail() {
        let mut rng = OsRng;
        let (g, h, a, b, x) = statement(&mut rng);
        let proof = ChaumPedersenProof::prove(&g, &h, &a, &b, &x, b"ctx", &mut rng);
        // Verify with bases swapped while the statement (A, B) is not.
        assert_eq!(
            proof.verify(&h, &g, &a, &b, b"ctx"),
            Err(CryptoError::VerificationFailed),
        );
    }

    #[test]
    fn context_binding_rejects_wrong_context() {
        let mut rng = OsRng;
        let (g, h, a, b, x) = statement(&mut rng);
        let proof = ChaumPedersenProof::prove(&g, &h, &a, &b, &x, b"trustee=1", &mut rng);
        assert_eq!(
            proof.verify(&g, &h, &a, &b, b"trustee=2"),
            Err(CryptoError::VerificationFailed),
        );
        // And honest context still works.
        proof
            .verify(&g, &h, &a, &b, b"trustee=1")
            .expect("matching context verifies");
    }

    #[test]
    fn wire_roundtrip_preserves_proof() {
        let mut rng = OsRng;
        let (g, h, a, b, x) = statement(&mut rng);
        let proof = ChaumPedersenProof::prove(&g, &h, &a, &b, &x, b"ctx", &mut rng);
        let wire = proof.to_wire();

        assert_eq!(wire.version, WIRE_VERSION);
        assert_eq!(wire.commitment_a.len(), 32);
        assert_eq!(wire.commitment_b.len(), 32);
        assert_eq!(wire.challenge.len(), 32);
        assert_eq!(wire.response.len(), 32);

        let decoded = ChaumPedersenProof::from_wire(&wire).expect("roundtrip succeeds");
        assert_eq!(decoded, proof);
        decoded
            .verify(&g, &h, &a, &b, b"ctx")
            .expect("decoded proof still verifies");
    }

    #[test]
    fn from_wire_rejects_unknown_version() {
        let mut rng = OsRng;
        let (g, h, a, b, x) = statement(&mut rng);
        let proof = ChaumPedersenProof::prove(&g, &h, &a, &b, &x, b"ctx", &mut rng);
        let mut wire = proof.to_wire();
        wire.version = WIRE_VERSION + 1;
        assert!(matches!(
            ChaumPedersenProof::from_wire(&wire),
            Err(CryptoError::InvalidParameters(_)),
        ));
    }

    #[test]
    fn from_wire_rejects_malformed_point() {
        let mut rng = OsRng;
        let (g, h, a, b, x) = statement(&mut rng);
        let proof = ChaumPedersenProof::prove(&g, &h, &a, &b, &x, b"ctx", &mut rng);

        // Truncated point bytes -> InvalidPoint via the length check.
        let mut wire = proof.to_wire();
        wire.commitment_a = vec![0u8; 31];
        assert_eq!(
            ChaumPedersenProof::from_wire(&wire),
            Err(CryptoError::InvalidPoint),
        );

        // 32 bytes that do not decompress to a valid ristretto point.
        // 0xff repeated is non-canonical and rejected by CompressedRistretto.
        let mut wire = proof.to_wire();
        wire.commitment_b = vec![0xff; 32];
        // Sanity: confirm the chosen bytes really are not a valid point.
        assert!(CompressedRistretto([0xff; 32]).decompress().is_none());
        assert_eq!(
            ChaumPedersenProof::from_wire(&wire),
            Err(CryptoError::InvalidPoint),
        );
    }

    #[test]
    fn from_wire_rejects_malformed_scalar() {
        let mut rng = OsRng;
        let (g, h, a, b, x) = statement(&mut rng);
        let proof = ChaumPedersenProof::prove(&g, &h, &a, &b, &x, b"ctx", &mut rng);

        // Wrong length on the challenge field.
        let mut wire = proof.to_wire();
        wire.challenge = vec![0u8; 16];
        assert_eq!(
            ChaumPedersenProof::from_wire(&wire),
            Err(CryptoError::InvalidScalar),
        );

        // Non-canonical 32-byte scalar on the response field.
        let mut wire = proof.to_wire();
        wire.response = vec![0xff; 32];
        assert_eq!(
            ChaumPedersenProof::from_wire(&wire),
            Err(CryptoError::InvalidScalar),
        );
    }

    /// End-to-end vector: a trustee proves that its published partial
    /// decryption `D_i = s_i * R` corresponds to its public share
    /// `pub_i = s_i * G`. The pad `R` is built independently of the elgamal
    /// module to avoid coupling.
    #[test]
    fn partial_decryption_vector() {
        let mut rng = OsRng;
        let g = basepoint();
        let pad = Scalar::from(7u64) * g; // R — the ElGamal pad.
        let share = Scalar::from(123_456u64); // s_i
        let public_share = share * g; // pub_i = s_i * G
        let partial = share * pad; // D_i = s_i * R

        let context = b"election=2026|trustee=3|share-index=1";
        let proof =
            ChaumPedersenProof::prove(&g, &pad, &public_share, &partial, &share, context, &mut rng);
        proof
            .verify(&g, &pad, &public_share, &partial, context)
            .expect("partial-decryption proof verifies");

        // A trustee that publishes the same proof against a forged partial
        // decryption (e.g. partial' = partial + G) must fail verification.
        let forged_partial = partial + g;
        assert_eq!(
            proof.verify(&g, &pad, &public_share, &forged_partial, context),
            Err(CryptoError::VerificationFailed),
        );
    }
}
