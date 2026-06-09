use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};

use crate::{CryptoError, CryptoResult};

pub use curve25519_dalek::traits::Identity;

pub const COMPRESSED_RISTRETTO_LENGTH: usize = 32;

pub fn basepoint() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

pub fn scalar_from_canonical_bytes(bytes: [u8; 32]) -> CryptoResult<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).ok_or(CryptoError::InvalidScalar)
}

pub fn point_from_compressed(bytes: [u8; 32]) -> CryptoResult<RistrettoPoint> {
    CompressedRistretto(bytes)
        .decompress()
        .ok_or(CryptoError::InvalidPoint)
}

pub fn compress_point(point: &RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use proptest::prelude::*;

    use super::{basepoint, compress_point, point_from_compressed, scalar_from_canonical_bytes};

    proptest! {
        #[test]
        fn basepoint_multiples_round_trip(value in 0u64..1_000_000) {
            let scalar = Scalar::from(value);
            let point = scalar * basepoint();
            let decoded = point_from_compressed(compress_point(&point)).expect("point decodes");
            prop_assert_eq!(decoded, point);
        }
    }

    #[test]
    fn scalar_rejects_non_canonical_bytes() {
        assert!(scalar_from_canonical_bytes([255; 32]).is_err());
    }
}
