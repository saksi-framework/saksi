//! Hex codecs for the live wire format.
//!
//! Every point is the 32-byte compressed ristretto255 encoding, every scalar
//! the 32-byte canonical little-endian encoding, and every protobuf message its
//! canonical `prost` encoding; all of them travel as lowercase hex. Decoding is
//! strict: a non-canonical scalar, an invalid point or a short value is an
//! error that names the field, never a silent default.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use prost::Message;
use saksi_crypto::group::{compress_point, point_from_compressed, scalar_from_canonical_bytes};
use zeroize::Zeroize;

/// Errors from this crate are plain strings: they cross a process or a
/// WebAssembly boundary as `{"error": "..."}` and never carry secret material.
pub type LiveResult<T> = Result<T, String>;

/// Lowercase hex of a compressed point.
pub fn point_hex(point: &RistrettoPoint) -> String {
    hex::encode(compress_point(point))
}

/// Lowercase hex of a canonical scalar. The byte copy is wiped, since the
/// scalar may be a secret.
pub fn scalar_hex(scalar: &Scalar) -> String {
    let mut b = scalar.to_bytes();
    let h = hex::encode(b);
    b.zeroize();
    h
}

/// Decodes `value` as hex bytes. `what` names the field in the error.
pub fn bytes(value: &str, what: &str) -> LiveResult<Vec<u8>> {
    // The decoder's own error names the offending character; in a secret
    // field that would be one character of the secret, so it is not quoted.
    hex::decode(value.trim()).map_err(|_| format!("{what} is not valid hex"))
}

/// Decodes exactly 32 hex bytes. The intermediate buffer is wiped, since the
/// value may be a secret scalar.
pub fn bytes32(value: &str, what: &str) -> LiveResult<[u8; 32]> {
    let mut raw = bytes(value, what)?;
    let out = <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| format!("{what} is {} bytes, want 32", raw.len()));
    raw.zeroize();
    out
}

/// Decodes a compressed ristretto255 point.
pub fn point(value: &str, what: &str) -> LiveResult<RistrettoPoint> {
    point_from_compressed(bytes32(value, what)?)
        .map_err(|_| format!("{what} is not a valid ristretto255 point"))
}

/// Decodes a compressed point and refuses the identity: a public key or a
/// DH input of zero would make every derived secret public.
pub fn nonzero_point(value: &str, what: &str) -> LiveResult<RistrettoPoint> {
    use curve25519_dalek::traits::Identity;
    let p = point(value, what)?;
    if p == RistrettoPoint::identity() {
        return Err(format!("{what} is the identity point"));
    }
    Ok(p)
}

/// Decodes a canonical scalar.
pub fn scalar(value: &str, what: &str) -> LiveResult<Scalar> {
    let mut raw = bytes32(value, what)?;
    let s =
        scalar_from_canonical_bytes(raw).map_err(|_| format!("{what} is not a canonical scalar"));
    raw.zeroize();
    s
}

/// Lowercase hex of a protobuf message's canonical encoding.
pub fn message_hex<M: Message>(message: &M) -> String {
    hex::encode(message.encode_to_vec())
}

/// Decodes a hex protobuf message.
pub fn message<M: Message + Default>(value: &str, what: &str) -> LiveResult<M> {
    let raw = bytes(value, what)?;
    M::decode(raw.as_slice()).map_err(|e| format!("{what} does not decode: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use saksi_crypto::group::basepoint;

    #[test]
    fn point_and_scalar_round_trip_and_reject_bad_input() {
        let s = Scalar::from(7u64);
        let p = s * basepoint();
        assert_eq!(scalar(&scalar_hex(&s), "s").unwrap(), s);
        assert_eq!(point(&point_hex(&p), "p").unwrap(), p);
        assert!(scalar(&"ff".repeat(32), "s")
            .unwrap_err()
            .contains("canonical"));
        assert!(point("00", "p").unwrap_err().contains("1 bytes"));
        assert!(nonzero_point(&"00".repeat(32), "p")
            .unwrap_err()
            .contains("identity"));
    }
}
