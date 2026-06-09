#![doc = "Canonical Rust cryptography for Saksi and BalotaChain."]
#![doc = ""]
#![doc = "The crate standardizes on ristretto255 group operations and Merlin"]
#![doc = "transcripts for Fiat-Shamir transforms. Constant-time discipline is"]
#![doc = "required for code handling secrets: avoid secret-dependent branches,"]
#![doc = "secret-dependent memory access, early exits on secret data, and debug"]
#![doc = "output that exposes secret material."]

pub mod benaloh;
pub mod commitment;
pub mod dkg;
pub mod elgamal;
pub mod error;
pub mod group;
pub mod nizk;
pub mod transcript;

pub use error::{CryptoError, CryptoResult};

/// Returns the package name for smoke tests and FFI metadata.
pub fn package_name() -> &'static str {
    "saksi-crypto"
}

#[cfg(test)]
mod tests {
    use super::package_name;

    #[test]
    fn exposes_package_name() {
        assert_eq!(package_name(), "saksi-crypto");
    }
}
