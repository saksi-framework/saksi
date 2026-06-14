//! Benaloh cast-or-challenge helpers for cast-as-intended verification.
//!
//! A voter-side device encrypts the chosen plaintext as a regular ElGamal
//! ciphertext and binds `(public_key, plaintext_label, context, ciphertext)`
//! into a Merlin transcript digest. The voter then either:
//!
//! * **casts** the commitment, which discards the randomness forever (so
//!   ballot secrecy is preserved); or
//! * **challenges** it, which exposes the randomness so the voter (or a
//!   helper app) can re-encrypt the same plaintext and verify the device's
//!   ciphertext matches. A challenged ballot must be discarded and a fresh
//!   one cast.
//!
//! The transcript digest is a binding tag (not a Fiat-Shamir challenge): it
//! fixes the `(ciphertext, plaintext, context)` tuple at commit time so the
//! device cannot switch what it claimed after seeing the voter's choice.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::elgamal::{self, Ciphertext, Plaintext, PublicKey};
use crate::group::compress_point;
use crate::transcript::{new_transcript, TRANSCRIPT_LABEL_BENALOH_CHALLENGE};
use crate::{CryptoError, CryptoResult};

pub const MODULE_NAME: &str = "benaloh";

/// Length in bytes of a Benaloh transcript digest.
pub const BENALOH_DIGEST_LENGTH: usize = 32;

/// Device-side commitment produced when a voter selects a choice.
///
/// Holds the ElGamal randomness in cleartext; the randomness is zeroized on
/// drop so neither casting nor dropping the commitment can leak it.
pub struct BenalohCommitment {
    ciphertext: Ciphertext,
    randomness: Scalar,
    plaintext: Plaintext,
    transcript_digest: [u8; BENALOH_DIGEST_LENGTH],
}

impl BenalohCommitment {
    /// Encrypt `plaintext` under `public_key` with the supplied randomness
    /// and bind `(public_key, plaintext_label, context, ciphertext)` into a
    /// Merlin transcript digest.
    ///
    /// `plaintext_label` is a stable identifier of the choice being committed
    /// to (e.g. `b"contest=president,choice=alice"`). `context` binds the
    /// surrounding session (election id, device id, ballot serial).
    pub fn commit(
        public_key: &PublicKey,
        plaintext: Plaintext,
        plaintext_label: &[u8],
        context: &[u8],
        randomness: Scalar,
    ) -> Self {
        let ciphertext = elgamal::encrypt(public_key, plaintext, randomness);
        let transcript_digest = compute_digest(public_key, plaintext_label, context, &ciphertext);
        Self {
            ciphertext,
            randomness,
            plaintext,
            transcript_digest,
        }
    }

    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }

    pub fn transcript_digest(&self) -> [u8; BENALOH_DIGEST_LENGTH] {
        self.transcript_digest
    }

    /// Consume the commitment and produce a cast receipt. The randomness is
    /// zeroized as part of dropping `self`, so it cannot be recovered after
    /// casting.
    pub fn cast(self) -> CastReceipt {
        CastReceipt {
            ciphertext: self.ciphertext,
            transcript_digest: self.transcript_digest,
        }
    }

    /// Consume the commitment and reveal the randomness so the voter (or a
    /// helper app) can re-encrypt and verify. A challenged ballot must not
    /// be cast — the randomness is now public.
    pub fn challenge(mut self) -> ChallengeReveal {
        let ciphertext = self.ciphertext;
        let plaintext = self.plaintext;
        let transcript_digest = self.transcript_digest;
        // Move the randomness out without going through Drop, so we don't
        // zeroize the value we are about to hand to the caller.
        let randomness = core::mem::replace(&mut self.randomness, Scalar::ZERO);
        ChallengeReveal {
            ciphertext,
            plaintext,
            randomness,
            transcript_digest,
        }
    }
}

impl Drop for BenalohCommitment {
    fn drop(&mut self) {
        self.randomness.zeroize();
    }
}

/// Public receipt of a cast ballot. Carries no secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CastReceipt {
    pub ciphertext: Ciphertext,
    pub transcript_digest: [u8; BENALOH_DIGEST_LENGTH],
}

/// Reveal of a challenged commitment. Exposes the ElGamal randomness so the
/// device's behaviour can be audited on this ballot.
pub struct ChallengeReveal {
    pub ciphertext: Ciphertext,
    pub plaintext: Plaintext,
    pub randomness: Scalar,
    pub transcript_digest: [u8; BENALOH_DIGEST_LENGTH],
}

impl ChallengeReveal {
    /// Re-run the binding transcript with the supplied `(public_key,
    /// plaintext_label, context)` plus the revealed ciphertext, then check:
    ///
    /// 1. the rebuilt transcript digest matches the stored one in constant
    ///    time;
    /// 2. re-encrypting `plaintext` under `public_key` with the revealed
    ///    `randomness` reproduces the stored ciphertext.
    ///
    /// Any mismatch returns [`CryptoError::VerificationFailed`].
    pub fn verify(
        &self,
        public_key: &PublicKey,
        plaintext_label: &[u8],
        context: &[u8],
    ) -> CryptoResult<()> {
        let expected_digest =
            compute_digest(public_key, plaintext_label, context, &self.ciphertext);
        let digest_ok: bool = expected_digest.ct_eq(&self.transcript_digest).into();

        let recomputed = elgamal::encrypt(public_key, self.plaintext, self.randomness);
        let ciphertext_ok = elgamal::ciphertexts_equal(&recomputed, &self.ciphertext);

        if digest_ok && ciphertext_ok {
            Ok(())
        } else {
            Err(CryptoError::VerificationFailed)
        }
    }
}

impl Drop for ChallengeReveal {
    fn drop(&mut self) {
        self.randomness.zeroize();
    }
}

fn compute_digest(
    public_key: &PublicKey,
    plaintext_label: &[u8],
    context: &[u8],
    ciphertext: &Ciphertext,
) -> [u8; BENALOH_DIGEST_LENGTH] {
    let mut transcript: Transcript = new_transcript(TRANSCRIPT_LABEL_BENALOH_CHALLENGE);
    transcript.append_message(b"public_key", &public_key.to_compressed_bytes());
    transcript.append_message(b"plaintext_label", plaintext_label);
    transcript.append_message(b"context", context);
    transcript.append_message(b"ciphertext_pad", &compress_point(&ciphertext.pad));
    transcript.append_message(b"ciphertext_data", &compress_point(&ciphertext.data));

    let mut digest = [0u8; BENALOH_DIGEST_LENGTH];
    transcript.challenge_bytes(b"benaloh_digest", &mut digest);
    digest
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;

    use super::{BenalohCommitment, ChallengeReveal};
    use crate::elgamal::{self, ciphertexts_equal, Plaintext, SecretKey};
    use crate::error::CryptoError;
    use crate::group::basepoint;

    fn fixture() -> (
        SecretKey,
        elgamal::PublicKey,
        Plaintext,
        &'static [u8],
        &'static [u8],
        Scalar,
    ) {
        let secret_key = SecretKey::from_scalar(Scalar::from(7u64));
        let public_key = secret_key.public_key();
        let plaintext = Plaintext::from_small_integer(3);
        let label: &[u8] = b"contest=president,choice=alice";
        let context: &[u8] = b"election=demo-2026,device=kiosk-01,ballot=42";
        let randomness = Scalar::from(123_456_789u64);
        (
            secret_key, public_key, plaintext, label, context, randomness,
        )
    }

    #[test]
    fn cast_receipt_matches_independent_encryption() {
        let (_sk, pk, plaintext, label, context, r) = fixture();
        let commitment = BenalohCommitment::commit(&pk, plaintext, label, context, r);
        let stored_ciphertext = *commitment.ciphertext();
        let stored_digest = commitment.transcript_digest();

        let receipt = commitment.cast();

        let recomputed = elgamal::encrypt(&pk, plaintext, r);
        assert!(ciphertexts_equal(&receipt.ciphertext, &recomputed));
        assert!(ciphertexts_equal(&receipt.ciphertext, &stored_ciphertext));
        assert_eq!(receipt.transcript_digest, stored_digest);
    }

    #[test]
    fn challenge_happy_path_verifies() {
        let (_sk, pk, plaintext, label, context, r) = fixture();
        let commitment = BenalohCommitment::commit(&pk, plaintext, label, context, r);
        let reveal = commitment.challenge();

        assert_eq!(reveal.randomness, r);
        assert_eq!(reveal.plaintext, plaintext);
        reveal
            .verify(&pk, label, context)
            .expect("challenge verifies");
    }

    #[test]
    fn challenge_rejects_wrong_plaintext_label() {
        let (_sk, pk, plaintext, label, context, r) = fixture();
        let reveal = BenalohCommitment::commit(&pk, plaintext, label, context, r).challenge();

        assert_eq!(
            reveal.verify(&pk, b"contest=president,choice=bob", context),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn challenge_rejects_wrong_context() {
        let (_sk, pk, plaintext, label, context, r) = fixture();
        let reveal = BenalohCommitment::commit(&pk, plaintext, label, context, r).challenge();

        assert_eq!(
            reveal.verify(&pk, label, b"election=demo-2026,device=kiosk-01,ballot=43"),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn challenge_rejects_wrong_public_key() {
        let (_sk, pk, plaintext, label, context, r) = fixture();
        let reveal = BenalohCommitment::commit(&pk, plaintext, label, context, r).challenge();

        let other_pk = SecretKey::from_scalar(Scalar::from(11u64)).public_key();
        assert_eq!(
            reveal.verify(&other_pk, label, context),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn challenge_rejects_tampered_ciphertext() {
        let (_sk, pk, plaintext, label, context, r) = fixture();
        let mut reveal = BenalohCommitment::commit(&pk, plaintext, label, context, r).challenge();

        reveal.ciphertext.pad += basepoint();

        assert_eq!(
            reveal.verify(&pk, label, context),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn challenge_rejects_tampered_randomness() {
        let (_sk, pk, plaintext, label, context, r) = fixture();
        let mut reveal = BenalohCommitment::commit(&pk, plaintext, label, context, r).challenge();

        // Bumping the randomness leaves the digest valid (digest binds the
        // ciphertext, not the randomness) but breaks the re-encryption check.
        reveal.randomness += Scalar::ONE;

        assert_eq!(
            reveal.verify(&pk, label, context),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn challenge_rejects_tampered_plaintext() {
        let (_sk, pk, plaintext, label, context, r) = fixture();
        let reveal = BenalohCommitment::commit(&pk, plaintext, label, context, r).challenge();

        let swapped = ChallengeReveal {
            ciphertext: reveal.ciphertext,
            plaintext: Plaintext::from_small_integer(4),
            randomness: reveal.randomness,
            transcript_digest: reveal.transcript_digest,
        };

        assert_eq!(
            swapped.verify(&pk, label, context),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn digest_is_stable_across_runs() {
        let (_sk, pk, plaintext, label, context, r) = fixture();
        let a = BenalohCommitment::commit(&pk, plaintext, label, context, r).transcript_digest();
        let b = BenalohCommitment::commit(&pk, plaintext, label, context, r).transcript_digest();
        assert_eq!(a, b);
    }

    #[test]
    fn digest_separates_label_and_context() {
        let (_sk, pk, plaintext, label, context, r) = fixture();
        let baseline =
            BenalohCommitment::commit(&pk, plaintext, label, context, r).transcript_digest();

        let other_label =
            BenalohCommitment::commit(&pk, plaintext, b"contest=president,choice=bob", context, r)
                .transcript_digest();
        assert_ne!(baseline, other_label);

        let other_context = BenalohCommitment::commit(
            &pk,
            plaintext,
            label,
            b"election=demo-2026,device=kiosk-01,ballot=99",
            r,
        )
        .transcript_digest();
        assert_ne!(baseline, other_context);
    }
}
