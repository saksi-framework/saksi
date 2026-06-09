//! ElGamal public-key encryption over ristretto255.

use core::ops::{Add, AddAssign, Mul};

use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::{Identity, IsIdentity},
};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::group::{basepoint, compress_point};

#[derive(Clone)]
pub struct SecretKey {
    scalar: Scalar,
}

impl SecretKey {
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self {
            scalar: Scalar::random(rng),
        }
    }

    pub fn from_scalar(scalar: Scalar) -> Self {
        Self { scalar }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            point: self.scalar * basepoint(),
        }
    }

    pub fn as_scalar(&self) -> &Scalar {
        &self.scalar
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    point: RistrettoPoint,
}

impl PublicKey {
    pub fn from_point(point: RistrettoPoint) -> Self {
        Self { point }
    }

    pub fn as_point(&self) -> &RistrettoPoint {
        &self.point
    }

    pub fn to_compressed_bytes(&self) -> [u8; 32] {
        compress_point(&self.point)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plaintext {
    point: RistrettoPoint,
}

impl Plaintext {
    pub fn from_point(point: RistrettoPoint) -> Self {
        Self { point }
    }

    pub fn from_scalar(scalar: Scalar) -> Self {
        Self {
            point: scalar * basepoint(),
        }
    }

    pub fn from_small_integer(value: u64) -> Self {
        Self::from_scalar(Scalar::from(value))
    }

    pub fn identity() -> Self {
        Self {
            point: RistrettoPoint::identity(),
        }
    }

    pub fn as_point(&self) -> &RistrettoPoint {
        &self.point
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub pad: RistrettoPoint,
    pub data: RistrettoPoint,
}

impl Ciphertext {
    pub fn new(pad: RistrettoPoint, data: RistrettoPoint) -> Self {
        Self { pad, data }
    }

    pub fn to_compressed_bytes(&self) -> ([u8; 32], [u8; 32]) {
        (compress_point(&self.pad), compress_point(&self.data))
    }
}

impl Add for Ciphertext {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            pad: self.pad + rhs.pad,
            data: self.data + rhs.data,
        }
    }
}

impl AddAssign for Ciphertext {
    fn add_assign(&mut self, rhs: Self) {
        self.pad += rhs.pad;
        self.data += rhs.data;
    }
}

impl Mul<Scalar> for Ciphertext {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Self {
            pad: rhs * self.pad,
            data: rhs * self.data,
        }
    }
}

pub fn encrypt(public_key: &PublicKey, message: Plaintext, randomness: Scalar) -> Ciphertext {
    Ciphertext {
        pad: randomness * basepoint(),
        data: message.point + randomness * public_key.point,
    }
}

pub fn decrypt(secret_key: &SecretKey, ciphertext: &Ciphertext) -> Plaintext {
    Plaintext {
        point: ciphertext.data - secret_key.scalar * ciphertext.pad,
    }
}

pub fn re_encrypt(
    public_key: &PublicKey,
    ciphertext: &Ciphertext,
    randomness: Scalar,
) -> Ciphertext {
    *ciphertext + encrypt(public_key, Plaintext::identity(), randomness)
}

pub fn ciphertexts_equal(lhs: &Ciphertext, rhs: &Ciphertext) -> bool {
    let pad_eq = lhs
        .pad
        .compress()
        .as_bytes()
        .ct_eq(rhs.pad.compress().as_bytes());
    let data_eq = lhs
        .data
        .compress()
        .as_bytes()
        .ct_eq(rhs.data.compress().as_bytes());
    bool::from(pad_eq & data_eq)
}

pub fn plaintext_is_identity(plaintext: &Plaintext) -> bool {
    plaintext.point.is_identity()
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;

    use super::{
        ciphertexts_equal, decrypt, encrypt, plaintext_is_identity, re_encrypt, Plaintext,
        SecretKey,
    };
    use crate::group::compress_point;

    #[test]
    fn round_trip_encrypt_decrypt_for_small_scalars() {
        let secret_key = SecretKey::from_scalar(Scalar::from(7u64));
        let public_key = secret_key.public_key();

        for value in 0..32 {
            let plaintext = Plaintext::from_small_integer(value);
            let ciphertext = encrypt(&public_key, plaintext, Scalar::from(value + 100));
            assert_eq!(decrypt(&secret_key, &ciphertext), plaintext);
        }
    }

    #[test]
    fn ciphertext_addition_is_homomorphic() {
        let secret_key = SecretKey::from_scalar(Scalar::from(11u64));
        let public_key = secret_key.public_key();
        let first = Plaintext::from_small_integer(2);
        let second = Plaintext::from_small_integer(3);

        let encrypted_first = encrypt(&public_key, first, Scalar::from(17u64));
        let encrypted_second = encrypt(&public_key, second, Scalar::from(19u64));
        let decrypted_sum = decrypt(&secret_key, &(encrypted_first + encrypted_second));

        assert_eq!(decrypted_sum, Plaintext::from_small_integer(5));
    }

    #[test]
    fn ciphertext_scalar_multiplication_is_homomorphic() {
        let secret_key = SecretKey::from_scalar(Scalar::from(13u64));
        let public_key = secret_key.public_key();
        let ciphertext = encrypt(
            &public_key,
            Plaintext::from_small_integer(4),
            Scalar::from(23u64),
        );

        let decrypted = decrypt(&secret_key, &(ciphertext * Scalar::from(3u64)));

        assert_eq!(decrypted, Plaintext::from_small_integer(12));
    }

    #[test]
    fn re_encryption_preserves_plaintext_and_refreshes_ciphertext() {
        let secret_key = SecretKey::from_scalar(Scalar::from(29u64));
        let public_key = secret_key.public_key();
        let plaintext = Plaintext::from_small_integer(1);
        let ciphertext = encrypt(&public_key, plaintext, Scalar::from(31u64));
        let refreshed = re_encrypt(&public_key, &ciphertext, Scalar::from(37u64));

        assert_eq!(decrypt(&secret_key, &refreshed), plaintext);
        assert!(!ciphertexts_equal(&ciphertext, &refreshed));
    }

    #[test]
    fn identity_plaintext_detects_identity_point() {
        assert!(plaintext_is_identity(&Plaintext::identity()));
        assert!(!plaintext_is_identity(&Plaintext::from_small_integer(1)));
    }

    #[test]
    fn deterministic_vector_is_stable() {
        let secret_key = SecretKey::from_scalar(Scalar::from(42u64));
        let public_key = secret_key.public_key();
        let plaintext = Plaintext::from_small_integer(1);
        let ciphertext = encrypt(&public_key, plaintext, Scalar::from(99u64));

        assert_eq!(
            hex_lower(&public_key.to_compressed_bytes()),
            "e00af9c74d9edb8ebcc160ceec97d531cbd6e2956f9e9162b8e9eda260e82e43"
        );
        let (pad, data) = ciphertext.to_compressed_bytes();
        assert_eq!(
            hex_lower(&pad),
            "0e1d5b2771666dd340a8285c3d315e94f21c3b48be9c5d65352eb952541db019"
        );
        assert_eq!(
            hex_lower(&data),
            "8af8a8933f35789af543aa4aeace1b033a03e87bb603bc77f8bb85e2b2bff92a"
        );
        assert_eq!(
            hex_lower(&compress_point(
                decrypt(&secret_key, &ciphertext).as_point()
            )),
            hex_lower(&compress_point(plaintext.as_point()))
        );
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(TABLE[(byte >> 4) as usize] as char);
            out.push(TABLE[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
