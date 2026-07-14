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

/// Returns the per-election, per-position nullifier base point `H_e`.
///
/// `H_e = hash_to_point(NULLIFIER_DOMAIN || len(election_id) || election_id ||
/// len(position_id) || position_id)`, with 8-byte big-endian length prefixes so
/// the `election_id`/`position_id` boundary is unambiguous.
///
/// Binding the position means a voter's nullifier differs per position, so
/// double voting is prevented **per voter per position** (the paper's
/// multi-position model). An **empty `position_id`** reproduces the legacy
/// per-election nullifier — the single-position / transitional path until the
/// generator emits one record per position (Phase 1).
///
/// The output is deterministic — same bytes, same point — and callers must pass
/// the canonical bytes of the identifiers (this crate does not normalize them).
pub fn nullifier_h(election_id: &[u8], position_id: &[u8]) -> RistrettoPoint {
    let mut input =
        Vec::with_capacity(NULLIFIER_DOMAIN.len() + 16 + election_id.len() + position_id.len());
    input.extend_from_slice(NULLIFIER_DOMAIN);
    input.extend_from_slice(&(election_id.len() as u64).to_be_bytes());
    input.extend_from_slice(election_id);
    input.extend_from_slice(&(position_id.len() as u64).to_be_bytes());
    input.extend_from_slice(position_id);
    RistrettoPoint::hash_from_bytes::<Sha512>(&input)
}

/// Derives the nullifier `n = s_cred · H_e` from the voter's secret credential
/// scalar, the election identifier, and the position identifier.
///
/// The scalar multiplication is constant-time, so this function does not leak
/// `s_cred` through timing. The return value is a raw ristretto point; use
/// [`compress_nullifier`] to obtain the 32-byte wire encoding the bulletin board
/// stores. Pass an empty `position_id` for the legacy per-election nullifier.
pub fn derive_nullifier(s_cred: &Scalar, election_id: &[u8], position_id: &[u8]) -> RistrettoPoint {
    s_cred * nullifier_h(election_id, position_id)
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
        let n1 = derive_nullifier(&s, b"election-2026", b"president");
        let n2 = derive_nullifier(&s, b"election-2026", b"president");
        assert_eq!(
            compress_nullifier(&n1),
            compress_nullifier(&n2),
            "same (s_cred, election_id, position_id) must give byte-identical nullifiers"
        );
    }

    #[test]
    fn different_election_id_changes_nullifier() {
        let s = Scalar::from(42u64);
        let a = derive_nullifier(&s, b"election-2026-A", b"president");
        let b = derive_nullifier(&s, b"election-2026-B", b"president");
        assert_ne!(
            compress_nullifier(&a),
            compress_nullifier(&b),
            "distinct election_id must produce distinct nullifiers"
        );
    }

    #[test]
    fn different_position_id_changes_nullifier() {
        // The R2 property: one voter, one election, two positions -> two
        // distinct nullifiers, so double voting is prevented per position while
        // the same voter can still vote in every position.
        let s = Scalar::from(42u64);
        let president = derive_nullifier(&s, b"election-2026", b"president");
        let senator = derive_nullifier(&s, b"election-2026", b"senator");
        assert_ne!(
            compress_nullifier(&president),
            compress_nullifier(&senator),
            "distinct position_id must produce distinct nullifiers (per-position double-vote prevention)"
        );
    }

    #[test]
    fn empty_position_is_the_legacy_per_election_nullifier() {
        // The single-position / transitional path: an empty position_id must be
        // deterministic and independent of any non-empty position.
        let s = Scalar::from(42u64);
        let legacy1 = derive_nullifier(&s, b"election-2026", b"");
        let legacy2 = derive_nullifier(&s, b"election-2026", b"");
        assert_eq!(compress_nullifier(&legacy1), compress_nullifier(&legacy2));
        let positioned = derive_nullifier(&s, b"election-2026", b"president");
        assert_ne!(
            compress_nullifier(&legacy1),
            compress_nullifier(&positioned)
        );
    }

    #[test]
    fn length_prefix_disambiguates_election_and_position() {
        // Without length prefixes, ("ab","c") and ("a","bc") would collide.
        let s = Scalar::from(9u64);
        let ab_c = derive_nullifier(&s, b"ab", b"c");
        let a_bc = derive_nullifier(&s, b"a", b"bc");
        assert_ne!(compress_nullifier(&ab_c), compress_nullifier(&a_bc));
    }

    #[test]
    fn different_s_cred_changes_nullifier() {
        let s1 = Scalar::from(42u64);
        let s2 = Scalar::from(43u64);
        let a = derive_nullifier(&s1, b"election-2026", b"president");
        let b = derive_nullifier(&s2, b"election-2026", b"president");
        assert_ne!(
            compress_nullifier(&a),
            compress_nullifier(&b),
            "distinct s_cred must produce distinct nullifiers"
        );
    }

    #[test]
    fn nullifier_h_is_election_and_position_dependent() {
        let h1 = nullifier_h(b"e1", b"p1");
        let h2 = nullifier_h(b"e2", b"p1");
        let h3 = nullifier_h(b"e1", b"p2");
        let h1_again = nullifier_h(b"e1", b"p1");
        assert_eq!(h1, h1_again);
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn compress_decompress_round_trips() {
        let s = Scalar::from(7u64);
        let n = derive_nullifier(&s, b"e", b"p");
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

    /// Pinned vector: `s_cred = 123`, `election_id = b"election-2026"`,
    /// `position_id = b"president"`.
    ///
    /// If this hex ever changes, either [`NULLIFIER_DOMAIN`], the length-prefix
    /// framing, SHA-512, the ristretto255 hash-to-point map, or the scalar
    /// multiplication has drifted; any of those is a wire-breaking change.
    #[test]
    fn pinned_nullifier_vector() {
        let s = Scalar::from(123u64);
        let n = derive_nullifier(&s, b"election-2026", b"president");
        assert_eq!(
            hex_lower(&compress_nullifier(&n)),
            "682bab1fac2ec1fbbcbde1774aad52067ce115c703a7d70c9edd8324435fd354",
            "pinned nullifier vector must remain stable across releases"
        );
    }
}
