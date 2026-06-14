//! Deterministic credential nullifier (PRF over the secret credential scalar).
//!
//! A nullifier is the per-election fingerprint of an anonymous credential. It
//! is computed as
//!
//! ```text
//! H_e = RistrettoPoint::hash_from_bytes::<Sha512>(NULLIFIER_DOMAIN || election_id)
//! nullifier = s_cred · H_e
//! ```
//!
//! and serialized as the 32-byte compressed ristretto encoding of the point.
//!
//! Properties relied upon by the rest of the framework:
//!
//! - **Determinism:** the same `(s_cred, election_id)` always yields the
//!   same 32-byte value. The bulletin board uses byte equality on this
//!   value to detect double-voting.
//! - **Election-independence:** different `election_id` inputs are routed
//!   through the hash-to-point map, so they produce two independent bases
//!   `H_{e1}` and `H_{e2}`. An adversary that sees both nullifiers learns
//!   nothing more than two random group elements (under DDH).
//! - **PRF security:** assuming DDH in ristretto255, the map
//!   `election_id ↦ s_cred · H_e` is a pseudo-random function of
//!   `election_id` keyed on `s_cred`. Hence "the same voter casting in two
//!   different elections" is unlinkable.
//!
//! The companion serialization helpers ([`compress_nullifier`],
//! [`decompress_nullifier`]) round-trip the 32-byte wire encoding used by
//! [`saksi_protocol::Nullifier`].

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use sha2::Sha512;

use saksi_crypto::{
    group::{compress_point, point_from_compressed},
    CryptoResult,
};

/// Domain-separation tag for the nullifier hash-to-point.
///
/// Concatenated with the caller-supplied `election_id` before being hashed
/// with SHA-512 and mapped to a ristretto point. The domain tag ensures
/// `nullifier_h(election_id)` is independent of any other hash-to-point the
/// framework uses (e.g. the Pedersen `H` generator).
pub const NULLIFIER_DOMAIN: &[u8] = b"saksi.credentials.nullifier.v1";

/// Returns the per-election nullifier base point `H_e`.
///
/// `H_e = RistrettoPoint::hash_from_bytes::<Sha512>(NULLIFIER_DOMAIN || election_id)`.
///
/// The output is deterministic — same `election_id` bytes, same point — and
/// callers must be careful to pass the canonical bytes of the election
/// identifier (this crate does not normalize them).
pub fn nullifier_h(election_id: &[u8]) -> RistrettoPoint {
    // We avoid allocating a single contiguous buffer by feeding both parts
    // into the SHA-512 state directly. `RistrettoPoint::hash_from_bytes`
    // doesn't expose an incremental API, so we settle for the small alloc
    // — `election_id` is bounded by the calling protocol (`election_id` is
    // typically <= 64 bytes).
    let mut input = Vec::with_capacity(NULLIFIER_DOMAIN.len() + election_id.len());
    input.extend_from_slice(NULLIFIER_DOMAIN);
    input.extend_from_slice(election_id);
    RistrettoPoint::hash_from_bytes::<Sha512>(&input)
}

/// Derives the nullifier `n = s_cred · H_e` from the voter's secret
/// credential scalar and the election identifier.
///
/// The scalar multiplication is constant-time, so this function does not
/// leak `s_cred` through timing. The return value is a raw ristretto point;
/// use [`compress_nullifier`] to obtain the 32-byte wire encoding the
/// bulletin board stores.
pub fn derive_nullifier(s_cred: &Scalar, election_id: &[u8]) -> RistrettoPoint {
    s_cred * nullifier_h(election_id)
}

/// Compresses a nullifier point to its canonical 32-byte ristretto encoding.
pub fn compress_nullifier(nullifier: &RistrettoPoint) -> [u8; 32] {
    compress_point(nullifier)
}

/// Decompresses a 32-byte wire encoding back into the nullifier point.
///
/// Returns [`CryptoError::InvalidPoint`] if `bytes` is not a canonical
/// ristretto compression.
pub fn decompress_nullifier(bytes: [u8; 32]) -> CryptoResult<RistrettoPoint> {
    point_from_compressed(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use saksi_crypto::CryptoError;

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
    fn derive_nullifier_is_deterministic() {
        let s = Scalar::from(42u64);
        let n1 = derive_nullifier(&s, b"election-2026");
        let n2 = derive_nullifier(&s, b"election-2026");
        assert_eq!(
            compress_nullifier(&n1),
            compress_nullifier(&n2),
            "same (s_cred, election_id) must give byte-identical nullifiers"
        );
    }

    #[test]
    fn different_election_id_changes_nullifier() {
        let s = Scalar::from(42u64);
        let a = derive_nullifier(&s, b"election-2026-A");
        let b = derive_nullifier(&s, b"election-2026-B");
        assert_ne!(
            compress_nullifier(&a),
            compress_nullifier(&b),
            "distinct election_id must produce distinct nullifiers"
        );
    }

    #[test]
    fn different_s_cred_changes_nullifier() {
        let s1 = Scalar::from(42u64);
        let s2 = Scalar::from(43u64);
        let a = derive_nullifier(&s1, b"election-2026");
        let b = derive_nullifier(&s2, b"election-2026");
        assert_ne!(
            compress_nullifier(&a),
            compress_nullifier(&b),
            "distinct s_cred must produce distinct nullifiers"
        );
    }

    #[test]
    fn nullifier_h_is_election_dependent() {
        let h1 = nullifier_h(b"e1");
        let h2 = nullifier_h(b"e2");
        let h1_again = nullifier_h(b"e1");
        assert_eq!(h1, h1_again);
        assert_ne!(h1, h2);
    }

    #[test]
    fn compress_decompress_round_trips() {
        let s = Scalar::from(7u64);
        let n = derive_nullifier(&s, b"e");
        let bytes = compress_nullifier(&n);
        let recovered = decompress_nullifier(bytes).expect("canonical bytes decode");
        assert_eq!(recovered, n);
    }

    #[test]
    fn decompress_rejects_garbage() {
        assert!(matches!(
            decompress_nullifier([0xff; 32]),
            Err(CryptoError::InvalidPoint)
        ));
    }

    /// Pinned vector: `s_cred = 123`, `election_id = b"election-2026"`.
    ///
    /// If this hex ever changes, either [`NULLIFIER_DOMAIN`], SHA-512, the
    /// ristretto255 hash-to-point map, or the scalar multiplication has
    /// drifted; any of those is a wire-breaking change.
    #[test]
    fn pinned_nullifier_vector() {
        let s = Scalar::from(123u64);
        let n = derive_nullifier(&s, b"election-2026");
        assert_eq!(
            hex_lower(&compress_nullifier(&n)),
            "1414ed00f2788047a0b6068f9ffd49059e7dc81b297b1542a96cc5c840463006",
            "pinned nullifier vector must remain stable across releases"
        );
    }
}
