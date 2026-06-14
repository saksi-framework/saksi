//! Schnorr proof of knowledge of a discrete logarithm.
//!
//! Sigma protocol made non-interactive via Merlin Fiat-Shamir, bound to the
//! [`TRANSCRIPT_LABEL_SCHNORR`](crate::transcript::TRANSCRIPT_LABEL_SCHNORR)
//! label. Given a public point `P = x·B` for some caller-chosen generator `B`,
//! the prover demonstrates knowledge of the witness `x` without revealing it.
//!
//! The prover is constant-time in the witness; the verifier only ever touches
//! public data, so its timing carries no secret signal. (We could dispatch
//! `RistrettoPoint::vartime_multiscalar_mul` for a small speedup, but that
//! impl requires the `alloc` feature on `curve25519-dalek`, which the
//! workspace deliberately does not enable. Plain scalar multiplication is
//! correct and fast enough here.)

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::IsIdentity};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::{
    group::{compress_point, point_from_compressed, scalar_from_canonical_bytes},
    transcript::{new_transcript, TRANSCRIPT_LABEL_SCHNORR},
    CryptoError, CryptoResult,
};

/// Length of a serialized Schnorr proof: a compressed point followed by a scalar.
pub const SCHNORR_PROOF_LENGTH: usize = 64;

/// Non-interactive Schnorr proof of knowledge of `x` such that `P = x·B`.
///
/// The proof carries no secret data, so deriving `Debug`/`Clone`/`Copy`/`Eq` is
/// safe. The companion `to_bytes`/`from_bytes` methods give a canonical
/// 64-byte wire encoding (32-byte compressed commitment + 32-byte canonical
/// scalar response).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchnorrProof {
    commitment: RistrettoPoint,
    response: Scalar,
}

impl SchnorrProof {
    /// Generates a Schnorr proof of knowledge of `witness` such that
    /// `statement = witness · base`.
    ///
    /// `context` is appended verbatim to the transcript so higher-level
    /// protocols (CDS, credentials, ...) can bind their own framing into the
    /// challenge. The blinding nonce is sampled with `rng`, used in
    /// constant-time arithmetic, and zeroized before the function returns.
    pub fn prove(
        base: &RistrettoPoint,
        statement: &RistrettoPoint,
        witness: &Scalar,
        context: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Self {
        let mut nonce = Scalar::random(rng);
        let commitment = nonce * base;

        let mut transcript = new_transcript(TRANSCRIPT_LABEL_SCHNORR);
        append_statement(&mut transcript, base, statement, context);
        let challenge = derive_challenge(&mut transcript, &commitment);

        // s = k + c·x (constant-time scalar arithmetic).
        let response = nonce + challenge * witness;

        // Wipe the blinding nonce; it must not linger on the stack.
        nonce.zeroize();

        Self {
            commitment,
            response,
        }
    }

    /// Verifies the proof against `base`, `statement`, and `context`. Returns
    /// [`CryptoError::VerificationFailed`] on any mismatch. Variable-time over
    /// public inputs is acceptable here.
    pub fn verify(
        &self,
        base: &RistrettoPoint,
        statement: &RistrettoPoint,
        context: &[u8],
    ) -> CryptoResult<()> {
        let mut transcript = new_transcript(TRANSCRIPT_LABEL_SCHNORR);
        append_statement(&mut transcript, base, statement, context);
        let challenge = derive_challenge(&mut transcript, &self.commitment);

        // Check s·B == R + c·P; equivalently, s·B − c·P − R must be the
        // identity point.
        let residual = self.response * base - challenge * statement - self.commitment;

        if residual.is_identity() {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }

    /// Returns the proof commitment `R = k·B`.
    pub fn commitment(&self) -> &RistrettoPoint {
        &self.commitment
    }

    /// Returns the proof response `s = k + c·x`.
    pub fn response(&self) -> &Scalar {
        &self.response
    }

    /// Canonical 64-byte wire encoding: compressed commitment ‖ scalar.
    pub fn to_bytes(&self) -> [u8; SCHNORR_PROOF_LENGTH] {
        let mut out = [0u8; SCHNORR_PROOF_LENGTH];
        out[..32].copy_from_slice(&compress_point(&self.commitment));
        out[32..].copy_from_slice(&self.response.to_bytes());
        out
    }

    /// Decodes a proof from its canonical 64-byte wire encoding. Non-canonical
    /// commitments yield [`CryptoError::InvalidPoint`]; non-canonical scalars
    /// yield [`CryptoError::InvalidScalar`].
    pub fn from_bytes(bytes: &[u8; SCHNORR_PROOF_LENGTH]) -> CryptoResult<Self> {
        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(&bytes[..32]);
        let commitment = point_from_compressed(commitment_bytes)?;

        let mut response_bytes = [0u8; 32];
        response_bytes.copy_from_slice(&bytes[32..]);
        let response = scalar_from_canonical_bytes(response_bytes)?;

        Ok(Self {
            commitment,
            response,
        })
    }
}

fn append_statement(
    transcript: &mut Transcript,
    base: &RistrettoPoint,
    statement: &RistrettoPoint,
    context: &[u8],
) {
    transcript.append_message(b"base", &compress_point(base));
    transcript.append_message(b"statement", &compress_point(statement));
    transcript.append_message(b"context", context);
}

fn derive_challenge(transcript: &mut Transcript, commitment: &RistrettoPoint) -> Scalar {
    transcript.append_message(b"commitment", &compress_point(commitment));

    let mut challenge_bytes = [0u8; 64];
    transcript.challenge_bytes(b"challenge", &mut challenge_bytes);
    let challenge = Scalar::from_bytes_mod_order_wide(&challenge_bytes);
    challenge_bytes.zeroize();
    challenge
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::basepoint;
    use rand_core::OsRng;

    fn make_statement(witness: &Scalar, base: &RistrettoPoint) -> RistrettoPoint {
        witness * base
    }

    #[test]
    fn completeness_random_witness_verifies() {
        let base = basepoint();
        let witness = Scalar::random(&mut OsRng);
        let statement = make_statement(&witness, &base);

        let proof = SchnorrProof::prove(&base, &statement, &witness, b"ctx", &mut OsRng);
        assert!(proof.verify(&base, &statement, b"ctx").is_ok());
    }

    #[test]
    fn tampered_commitment_is_rejected() {
        let base = basepoint();
        let witness = Scalar::random(&mut OsRng);
        let statement = make_statement(&witness, &base);

        let proof = SchnorrProof::prove(&base, &statement, &witness, b"ctx", &mut OsRng);
        let mut bytes = proof.to_bytes();
        // Flip a low byte of the compressed commitment; ristretto255 decoders
        // sometimes reject outright, in which case we accept that too — both
        // are "verification failed" for the caller.
        bytes[0] ^= 0x01;
        match SchnorrProof::from_bytes(&bytes) {
            Ok(tampered) => {
                assert_eq!(
                    tampered.verify(&base, &statement, b"ctx"),
                    Err(CryptoError::VerificationFailed)
                );
            }
            Err(err) => {
                assert!(matches!(err, CryptoError::InvalidPoint));
            }
        }
    }

    #[test]
    fn tampered_response_is_rejected() {
        let base = basepoint();
        let witness = Scalar::random(&mut OsRng);
        let statement = make_statement(&witness, &base);

        let proof = SchnorrProof::prove(&base, &statement, &witness, b"ctx", &mut OsRng);
        let tampered = SchnorrProof {
            commitment: proof.commitment,
            response: proof.response + Scalar::ONE,
        };
        assert_eq!(
            tampered.verify(&base, &statement, b"ctx"),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn wrong_statement_is_rejected() {
        let base = basepoint();
        let witness = Scalar::random(&mut OsRng);
        let statement = make_statement(&witness, &base);

        let proof = SchnorrProof::prove(&base, &statement, &witness, b"ctx", &mut OsRng);

        let other_witness = Scalar::random(&mut OsRng);
        let other_statement = make_statement(&other_witness, &base);
        assert_eq!(
            proof.verify(&base, &other_statement, b"ctx"),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn wrong_base_is_rejected() {
        let base = basepoint();
        let witness = Scalar::random(&mut OsRng);
        let statement = make_statement(&witness, &base);

        let proof = SchnorrProof::prove(&base, &statement, &witness, b"ctx", &mut OsRng);

        // A different base reuses none of the original transcript binding.
        let other_base = Scalar::from(7u64) * base;
        assert_eq!(
            proof.verify(&other_base, &statement, b"ctx"),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn wrong_context_is_rejected() {
        let base = basepoint();
        let witness = Scalar::random(&mut OsRng);
        let statement = make_statement(&witness, &base);

        let proof = SchnorrProof::prove(&base, &statement, &witness, b"ctx-A", &mut OsRng);
        assert_eq!(
            proof.verify(&base, &statement, b"ctx-B"),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn serde_round_trip_preserves_proof() {
        let base = basepoint();
        let witness = Scalar::random(&mut OsRng);
        let statement = make_statement(&witness, &base);

        let proof = SchnorrProof::prove(&base, &statement, &witness, b"ctx", &mut OsRng);
        let decoded = SchnorrProof::from_bytes(&proof.to_bytes()).expect("canonical bytes decode");

        assert_eq!(decoded, proof);
        assert!(decoded.verify(&base, &statement, b"ctx").is_ok());
    }

    #[test]
    fn from_bytes_rejects_non_canonical_scalar() {
        let base = basepoint();
        let witness = Scalar::random(&mut OsRng);
        let statement = make_statement(&witness, &base);

        let proof = SchnorrProof::prove(&base, &statement, &witness, b"ctx", &mut OsRng);
        let mut bytes = proof.to_bytes();
        // 0xff…ff is far above the ristretto scalar group order, so
        // `Scalar::from_canonical_bytes` must reject it.
        for slot in bytes[32..].iter_mut() {
            *slot = 0xff;
        }
        assert_eq!(
            SchnorrProof::from_bytes(&bytes),
            Err(CryptoError::InvalidScalar)
        );
    }

    #[test]
    fn from_bytes_rejects_non_canonical_point() {
        // 0xff…ff is not a valid compressed ristretto255 encoding.
        let mut bytes = [0u8; SCHNORR_PROOF_LENGTH];
        for slot in bytes[..32].iter_mut() {
            *slot = 0xff;
        }
        // Leave the scalar portion at zero (canonical).
        assert_eq!(
            SchnorrProof::from_bytes(&bytes),
            Err(CryptoError::InvalidPoint)
        );
    }

    #[test]
    fn non_basepoint_base_proves_and_verifies() {
        // A random non-basepoint generator: scale the basepoint by a fresh
        // secret scalar.
        let base = Scalar::random(&mut OsRng) * basepoint();
        let witness = Scalar::random(&mut OsRng);
        let statement = make_statement(&witness, &base);

        let proof = SchnorrProof::prove(&base, &statement, &witness, b"ctx", &mut OsRng);
        assert!(proof.verify(&base, &statement, b"ctx").is_ok());

        // And a tampered response still fails over a non-basepoint generator.
        let tampered = SchnorrProof {
            commitment: proof.commitment,
            response: proof.response + Scalar::ONE,
        };
        assert_eq!(
            tampered.verify(&base, &statement, b"ctx"),
            Err(CryptoError::VerificationFailed)
        );
    }
}
