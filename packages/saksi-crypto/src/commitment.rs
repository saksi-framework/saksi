//! Pedersen commitment over ristretto255.
//!
//! A Pedersen commitment is `C = m·G + r·H` where:
//!
//! - `G` is the standard ristretto255 basepoint (see [`crate::group::basepoint`]).
//! - `H` is a second generator with unknown discrete logarithm relative to `G`,
//!   derived deterministically via hash-to-point. We compute it as
//!   `RistrettoPoint::hash_from_bytes::<Sha512>(b"saksi.commitment.pedersen.H.v1")`.
//!   Because the input is a fixed public string and the hash-to-point map is
//!   one-way, nobody (not even the framework authors) knows `log_G H`. Knowledge
//!   of that discrete log would break the *binding* property: an adversary could
//!   open a commitment to two different messages.
//!
//! The commitment is *perfectly hiding* (the randomness `r` is uniform over the
//! scalar field) and *computationally binding* (assuming discrete log is hard
//! in ristretto255). It is also additively homomorphic:
//!
//! ```text
//! commit(m1, r1) + commit(m2, r2) = commit(m1 + m2, r1 + r2)
//! ```
//!
//! Callers that need to fold a commitment into a Fiat-Shamir transcript should
//! use [`crate::transcript::TRANSCRIPT_LABEL_PEDERSEN_COMMITMENT`] when binding
//! the compressed bytes. This module itself does not invoke Merlin — the
//! commitment is just a single group element.

use core::ops::{Add, AddAssign};

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use saksi_protocol::{PedersenCommitment as ProtocolPedersenCommitment, WIRE_VERSION};
use sha2::Sha512;
use subtle::ConstantTimeEq;

use crate::{
    group::{basepoint, compress_point, point_from_compressed, scalar_from_canonical_bytes},
    CryptoError, CryptoResult,
};

/// Domain-separation tag for the Pedersen `H` generator.
///
/// This string is hashed with SHA-512 and mapped to a ristretto255 point via
/// `RistrettoPoint::hash_from_bytes`. The derivation is deterministic, public,
/// and audit-reviewable: nobody knows the discrete log of the resulting point
/// relative to the basepoint.
pub const PEDERSEN_H_DOMAIN: &[u8] = b"saksi.commitment.pedersen.H.v1";

/// Returns the Pedersen `H` generator.
///
/// `H = RistrettoPoint::hash_from_bytes::<Sha512>(PEDERSEN_H_DOMAIN)`.
///
/// The result is deterministic. We do not cache it because (a) the crate has
/// no `once_cell` dependency, and (b) hashing 30 bytes plus one ristretto
/// `from_uniform_bytes` is cheap enough that callers in the hot path can cache
/// the value themselves if they need to.
pub fn pedersen_h() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(PEDERSEN_H_DOMAIN)
}

/// A Pedersen commitment `C = m·G + r·H`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment {
    point: RistrettoPoint,
}

impl Commitment {
    /// Commits to `message` with blinding factor `randomness`.
    ///
    /// Returns `C = message·G + randomness·H`.
    pub fn commit(message: &Scalar, randomness: &Scalar) -> Self {
        Self {
            point: message * basepoint() + randomness * pedersen_h(),
        }
    }

    /// Verifies that this commitment opens to `(message, randomness)`.
    ///
    /// Uses constant-time comparison on the compressed bytes to avoid leaking
    /// information about the opened message through timing side channels.
    pub fn verify_opening(&self, message: &Scalar, randomness: &Scalar) -> bool {
        let expected = Self::commit(message, randomness);
        let lhs = self.point.compress().to_bytes();
        let rhs = expected.point.compress().to_bytes();
        bool::from(lhs.ct_eq(&rhs))
    }

    /// Returns the underlying ristretto255 point.
    pub fn as_point(&self) -> &RistrettoPoint {
        &self.point
    }

    /// Constructs a commitment directly from a ristretto255 point.
    ///
    /// Use this when combining commitments produced elsewhere (for example, a
    /// commitment recovered from a Merlin transcript).
    pub fn from_point(point: RistrettoPoint) -> Self {
        Self { point }
    }

    /// Returns the canonical 32-byte compressed encoding of the commitment.
    pub fn to_compressed_bytes(&self) -> [u8; 32] {
        compress_point(&self.point)
    }

    /// Decodes a commitment from its canonical 32-byte compressed encoding.
    ///
    /// Returns [`CryptoError::InvalidPoint`] if the bytes are not a valid
    /// ristretto255 compression.
    pub fn from_compressed_bytes(bytes: &[u8; 32]) -> CryptoResult<Self> {
        Ok(Self {
            point: point_from_compressed(*bytes)?,
        })
    }

    /// Adds `delta` to the committed message without changing the randomness.
    ///
    /// Returns `self + delta·G`, which by the homomorphism corresponds to the
    /// commitment `commit(m + delta, r)`. Useful when the caller learns a
    /// plaintext adjustment and wants to fold it in without re-blinding.
    pub fn add_scalar_message(&self, delta: &Scalar) -> Self {
        Self {
            point: self.point + delta * basepoint(),
        }
    }

    /// Serializes to the protobuf wire shape.
    ///
    /// If `opening` is `Some(r)`, the wire `opening` field carries the 32-byte
    /// canonical scalar encoding of `r` (an "opened" commitment). If `opening`
    /// is `None`, the wire `opening` field is empty (a "closed" commitment).
    pub fn to_wire(&self, opening: Option<&Scalar>) -> ProtocolPedersenCommitment {
        ProtocolPedersenCommitment {
            version: WIRE_VERSION,
            commitment: self.to_compressed_bytes().to_vec(),
            opening: opening
                .map(|scalar| scalar.to_bytes().to_vec())
                .unwrap_or_default(),
        }
    }

    /// Parses a commitment (and optional opening) from the protobuf wire shape.
    ///
    /// Returns [`CryptoError::InvalidPoint`] if the `commitment` field is not a
    /// canonical 32-byte ristretto compression and [`CryptoError::InvalidScalar`]
    /// if the `opening` field is present but is not a canonical 32-byte scalar.
    /// An empty `opening` is treated as a closed commitment and yields `None`.
    pub fn from_wire(wire: &ProtocolPedersenCommitment) -> CryptoResult<(Self, Option<Scalar>)> {
        let commitment_bytes: [u8; 32] = wire
            .commitment
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidPoint)?;
        let commitment = Self::from_compressed_bytes(&commitment_bytes)?;

        let opening = if wire.opening.is_empty() {
            None
        } else {
            let opening_bytes: [u8; 32] = wire
                .opening
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidScalar)?;
            Some(scalar_from_canonical_bytes(opening_bytes)?)
        };

        Ok((commitment, opening))
    }
}

impl Default for Commitment {
    fn default() -> Self {
        Self {
            point: RistrettoPoint::identity(),
        }
    }
}

impl Add for Commitment {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            point: self.point + rhs.point,
        }
    }
}

impl AddAssign for Commitment {
    fn add_assign(&mut self, rhs: Self) {
        self.point += rhs.point;
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{scalar::Scalar, traits::Identity};

    use super::{pedersen_h, Commitment};
    use crate::{
        group::{basepoint, compress_point},
        CryptoError,
    };
    use curve25519_dalek::ristretto::RistrettoPoint;
    use saksi_protocol::{PedersenCommitment as ProtocolPedersenCommitment, WIRE_VERSION};

    fn hex_lower(bytes: &[u8]) -> String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(TABLE[(byte >> 4) as usize] as char);
            out.push(TABLE[(byte & 0x0f) as usize] as char);
        }
        out
    }

    #[test]
    fn pedersen_h_is_deterministic_and_independent() {
        let h1 = pedersen_h();
        let h2 = pedersen_h();
        assert_eq!(h1, h2, "pedersen_h must be deterministic");
        assert_ne!(h1, basepoint(), "H must not equal the basepoint");
        assert_ne!(
            h1,
            RistrettoPoint::identity(),
            "H must not be the identity point"
        );
    }

    #[test]
    fn open_then_verify_round_trips() {
        let message = Scalar::from(12345u64);
        let randomness = Scalar::from(67890u64);
        let commitment = Commitment::commit(&message, &randomness);
        assert!(commitment.verify_opening(&message, &randomness));
    }

    #[test]
    fn binding_rejects_wrong_message_or_randomness() {
        let message = Scalar::from(7u64);
        let randomness = Scalar::from(11u64);
        let commitment = Commitment::commit(&message, &randomness);

        let wrong_message = Scalar::from(8u64);
        let wrong_randomness = Scalar::from(12u64);
        assert!(!commitment.verify_opening(&wrong_message, &randomness));
        assert!(!commitment.verify_opening(&message, &wrong_randomness));
        assert!(!commitment.verify_opening(&wrong_message, &wrong_randomness));
    }

    #[test]
    fn different_randomness_changes_commitment() {
        let message = Scalar::from(42u64);
        let r1 = Scalar::from(1u64);
        let r2 = Scalar::from(2u64);
        assert_ne!(
            Commitment::commit(&message, &r1),
            Commitment::commit(&message, &r2),
            "different randomness must yield different commitments"
        );
    }

    #[test]
    fn addition_is_homomorphic() {
        let m1 = Scalar::from(3u64);
        let r1 = Scalar::from(5u64);
        let m2 = Scalar::from(7u64);
        let r2 = Scalar::from(11u64);

        let c1 = Commitment::commit(&m1, &r1);
        let c2 = Commitment::commit(&m2, &r2);
        let sum = c1 + c2;
        let expected = Commitment::commit(&(m1 + m2), &(r1 + r2));

        assert_eq!(sum.to_compressed_bytes(), expected.to_compressed_bytes());

        let mut acc = c1;
        acc += c2;
        assert_eq!(acc.to_compressed_bytes(), expected.to_compressed_bytes());
    }

    #[test]
    fn add_scalar_message_matches_recommit() {
        let m = Scalar::from(9u64);
        let r = Scalar::from(13u64);
        let delta = Scalar::from(4u64);
        let c = Commitment::commit(&m, &r);
        let bumped = c.add_scalar_message(&delta);
        let expected = Commitment::commit(&(m + delta), &r);
        assert_eq!(bumped, expected);
    }

    #[test]
    fn zero_commitment_is_identity() {
        let zero = Scalar::from(0u64);
        let c = Commitment::commit(&zero, &zero);
        let identity = Commitment::from_point(RistrettoPoint::identity());
        assert_eq!(c, identity);
        assert_eq!(
            c.to_compressed_bytes(),
            compress_point(&RistrettoPoint::identity())
        );
    }

    #[test]
    fn compressed_bytes_round_trip() {
        let m = Scalar::from(123u64);
        let r = Scalar::from(456u64);
        let c = Commitment::commit(&m, &r);
        let bytes = c.to_compressed_bytes();
        let recovered = Commitment::from_compressed_bytes(&bytes).expect("decodes");
        assert_eq!(recovered, c);
    }

    #[test]
    fn compressed_bytes_reject_garbage() {
        let err = Commitment::from_compressed_bytes(&[0xFF; 32]).expect_err("must fail");
        assert_eq!(err, CryptoError::InvalidPoint);
    }

    #[test]
    fn wire_closed_commitment_round_trips() {
        let m = Scalar::from(2024u64);
        let r = Scalar::from(11u64);
        let c = Commitment::commit(&m, &r);

        let wire = c.to_wire(None);
        assert_eq!(wire.version, WIRE_VERSION);
        assert_eq!(wire.commitment.len(), 32);
        assert!(
            wire.opening.is_empty(),
            "closed commitments must publish an empty opening field"
        );

        let (recovered, opening) = Commitment::from_wire(&wire).expect("decodes");
        assert_eq!(recovered, c);
        assert!(opening.is_none());
    }

    #[test]
    fn wire_opened_commitment_round_trips_and_verifies() {
        let m = Scalar::from(99u64);
        let r = Scalar::from(31415u64);
        let c = Commitment::commit(&m, &r);

        let wire = c.to_wire(Some(&r));
        assert_eq!(wire.version, WIRE_VERSION);
        assert_eq!(wire.commitment.len(), 32);
        assert_eq!(wire.opening.len(), 32);

        let (recovered, opening) = Commitment::from_wire(&wire).expect("decodes");
        assert_eq!(recovered, c);
        let opening = opening.expect("opening present");
        assert!(recovered.verify_opening(&m, &opening));
    }

    #[test]
    fn wire_rejects_short_commitment() {
        let wire = ProtocolPedersenCommitment {
            version: WIRE_VERSION,
            commitment: vec![0; 16],
            opening: vec![],
        };
        let err = Commitment::from_wire(&wire).expect_err("must reject");
        assert_eq!(err, CryptoError::InvalidPoint);
    }

    #[test]
    fn wire_rejects_non_canonical_commitment_point() {
        let wire = ProtocolPedersenCommitment {
            version: WIRE_VERSION,
            commitment: vec![0xFF; 32],
            opening: vec![],
        };
        let err = Commitment::from_wire(&wire).expect_err("must reject");
        assert_eq!(err, CryptoError::InvalidPoint);
    }

    #[test]
    fn wire_rejects_short_opening() {
        let c = Commitment::commit(&Scalar::from(1u64), &Scalar::from(2u64));
        let wire = ProtocolPedersenCommitment {
            version: WIRE_VERSION,
            commitment: c.to_compressed_bytes().to_vec(),
            opening: vec![0],
        };
        let err = Commitment::from_wire(&wire).expect_err("must reject");
        assert_eq!(err, CryptoError::InvalidScalar);
    }

    #[test]
    fn wire_rejects_non_canonical_opening() {
        let c = Commitment::commit(&Scalar::from(1u64), &Scalar::from(2u64));
        let wire = ProtocolPedersenCommitment {
            version: WIRE_VERSION,
            commitment: c.to_compressed_bytes().to_vec(),
            opening: vec![0xFF; 32],
        };
        let err = Commitment::from_wire(&wire).expect_err("must reject");
        assert_eq!(err, CryptoError::InvalidScalar);
    }

    /// Deterministic test vector pinning the derivation of `H`.
    ///
    /// If this hex ever changes, either the SHA-512 hash, the ristretto255
    /// hash-to-point map, or [`super::PEDERSEN_H_DOMAIN`] has drifted, and the
    /// commitment scheme is no longer compatible with previously published
    /// transcripts. Treat any such drift as a wire-breaking change.
    #[test]
    fn deterministic_test_vector_pins_h_derivation() {
        let m = Scalar::from(7u64);
        let r = Scalar::from(11u64);
        let c = Commitment::commit(&m, &r);
        assert_eq!(
            hex_lower(&c.to_compressed_bytes()),
            "2258d267653d6ab3e0d6657147b6bee67cda6c32b733af4d856cf506daa27529"
        );
    }
}
