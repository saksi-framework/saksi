//! Pedersen/Feldman distributed key generation primitives.

use std::collections::BTreeSet;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use saksi_protocol::{
    DKGComplaint as ProtocolDKGComplaint, DKGTranscript as ProtocolDKGTranscript,
    TrusteeCommitment as ProtocolTrusteeCommitment, WIRE_VERSION,
};

use crate::{
    elgamal::{Ciphertext, Plaintext, PublicKey},
    group::{basepoint, compress_point},
    CryptoError, CryptoResult,
};

pub const DEFAULT_THRESHOLD: usize = 3;
pub const DEFAULT_TRUSTEES: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DkgConfig {
    pub threshold: usize,
    pub trustees: usize,
}

impl DkgConfig {
    pub fn new(threshold: usize, trustees: usize) -> CryptoResult<Self> {
        if threshold == 0 {
            return Err(CryptoError::InvalidParameters("threshold must be non-zero"));
        }
        if trustees == 0 {
            return Err(CryptoError::InvalidParameters(
                "trustee count must be non-zero",
            ));
        }
        if threshold > trustees {
            return Err(CryptoError::InvalidParameters(
                "threshold cannot exceed trustee count",
            ));
        }
        Ok(Self {
            threshold,
            trustees,
        })
    }

    pub fn default_3_of_5() -> Self {
        Self {
            threshold: DEFAULT_THRESHOLD,
            trustees: DEFAULT_TRUSTEES,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Dealer {
    pub trustee_id: usize,
    pub coefficients: Vec<Scalar>,
}

impl Dealer {
    pub fn new(trustee_id: usize, coefficients: Vec<Scalar>) -> Self {
        Self {
            trustee_id,
            coefficients,
        }
    }

    pub fn commitments(&self) -> DealerCommitments {
        DealerCommitments {
            trustee_id: self.trustee_id,
            coefficient_commitments: self
                .coefficients
                .iter()
                .map(|coefficient| coefficient * basepoint())
                .collect(),
        }
    }

    pub fn share_for(&self, recipient_id: usize) -> DealerShare {
        DealerShare {
            dealer_id: self.trustee_id,
            recipient_id,
            value: evaluate_polynomial(&self.coefficients, Scalar::from(recipient_id as u64)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DealerCommitments {
    pub trustee_id: usize,
    pub coefficient_commitments: Vec<RistrettoPoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DealerShare {
    pub dealer_id: usize,
    pub recipient_id: usize,
    pub value: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Complaint {
    pub complainant_id: usize,
    pub accused_id: usize,
    pub reason: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrusteeShare {
    pub trustee_id: usize,
    pub value: Scalar,
}

#[derive(Clone, Debug)]
pub struct ShareCorruption {
    pub dealer_id: usize,
    pub recipient_id: usize,
    pub delta: Scalar,
}

#[derive(Clone, Debug)]
pub struct DkgOutput {
    pub public_key: PublicKey,
    pub trustee_shares: Vec<TrusteeShare>,
    pub commitments: Vec<DealerCommitments>,
    pub complaints: Vec<Complaint>,
    pub threshold: usize,
}

impl DkgOutput {
    pub fn to_protocol_transcript(&self, election_id: impl Into<String>) -> ProtocolDKGTranscript {
        ProtocolDKGTranscript {
            version: WIRE_VERSION,
            election_id: election_id.into(),
            threshold: self.threshold as u32,
            trustee_commitments: self
                .commitments
                .iter()
                .map(|commitment| ProtocolTrusteeCommitment {
                    trustee_id: commitment.trustee_id.to_string(),
                    coefficient_commitments: commitment
                        .coefficient_commitments
                        .iter()
                        .map(compress_point)
                        .map(Vec::from)
                        .collect(),
                })
                .collect(),
            complaints: self
                .complaints
                .iter()
                .map(|complaint| ProtocolDKGComplaint {
                    complainant_id: complaint.complainant_id.to_string(),
                    accused_id: complaint.accused_id.to_string(),
                    reason: complaint.reason.to_owned(),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialDecryptionShare {
    pub trustee_id: usize,
    pub value: RistrettoPoint,
}

pub fn run_in_memory(config: DkgConfig, dealers: &[Dealer]) -> CryptoResult<DkgOutput> {
    run_in_memory_with_corruptions(config, dealers, &[])
}

pub fn run_in_memory_with_corruptions(
    config: DkgConfig,
    dealers: &[Dealer],
    corruptions: &[ShareCorruption],
) -> CryptoResult<DkgOutput> {
    validate_dealers(config, dealers)?;

    let commitments: Vec<_> = dealers.iter().map(Dealer::commitments).collect();
    let mut complaints = Vec::new();
    let mut accused = BTreeSet::new();

    let mut shares_by_recipient: Vec<Vec<DealerShare>> = (0..config.trustees)
        .map(|recipient_index| {
            let recipient_id = recipient_index + 1;
            dealers
                .iter()
                .map(|dealer| dealer.share_for(recipient_id))
                .collect()
        })
        .collect();

    for corruption in corruptions {
        if let Some(share) = shares_by_recipient.iter_mut().flatten().find(|share| {
            share.dealer_id == corruption.dealer_id && share.recipient_id == corruption.recipient_id
        }) {
            share.value += corruption.delta;
        }
    }

    for recipient_shares in &shares_by_recipient {
        for share in recipient_shares {
            let commitment = commitments
                .iter()
                .find(|commitment| commitment.trustee_id == share.dealer_id)
                .ok_or(CryptoError::InvalidParameters("missing dealer commitment"))?;
            if !verify_share(share, commitment) {
                complaints.push(Complaint {
                    complainant_id: share.recipient_id,
                    accused_id: share.dealer_id,
                    reason: "share did not verify against coefficient commitments",
                });
                accused.insert(share.dealer_id);
            }
        }
    }

    let active_commitments: Vec<_> = commitments
        .iter()
        .filter(|commitment| !accused.contains(&commitment.trustee_id))
        .cloned()
        .collect();

    if active_commitments.len() < config.threshold {
        return Err(CryptoError::InvalidParameters(
            "not enough honest dealers remain after complaints",
        ));
    }

    let mut public_point = RistrettoPoint::identity();
    for commitment in &active_commitments {
        public_point += commitment.coefficient_commitments[0];
    }

    let trustee_shares = shares_by_recipient
        .into_iter()
        .enumerate()
        .map(|(index, shares)| {
            let mut value = Scalar::from(0u64);
            for share in shares {
                if !accused.contains(&share.dealer_id) {
                    value += share.value;
                }
            }
            TrusteeShare {
                trustee_id: index + 1,
                value,
            }
        })
        .collect();

    Ok(DkgOutput {
        public_key: PublicKey::from_point(public_point),
        trustee_shares,
        commitments: active_commitments,
        complaints,
        threshold: config.threshold,
    })
}

pub fn verify_share(share: &DealerShare, commitments: &DealerCommitments) -> bool {
    let x = Scalar::from(share.recipient_id as u64);
    let mut power = Scalar::from(1u64);
    let mut expected = RistrettoPoint::identity();
    for commitment in &commitments.coefficient_commitments {
        expected += commitment * power;
        power *= x;
    }
    share.value * basepoint() == expected
}

pub fn partial_decrypt(
    trustee_share: &TrusteeShare,
    ciphertext: &Ciphertext,
) -> PartialDecryptionShare {
    PartialDecryptionShare {
        trustee_id: trustee_share.trustee_id,
        value: trustee_share.value * ciphertext.pad,
    }
}

pub fn combine_partial_decryptions(
    ciphertext: &Ciphertext,
    shares: &[PartialDecryptionShare],
) -> CryptoResult<Plaintext> {
    if shares.is_empty() {
        return Err(CryptoError::InvalidParameters(
            "at least one partial decryption is required",
        ));
    }

    let mut shared_secret = RistrettoPoint::identity();
    for share in shares {
        let lambda = lagrange_coefficient_at_zero(share.trustee_id, shares)?;
        shared_secret += lambda * share.value;
    }

    Ok(Plaintext::from_point(ciphertext.data - shared_secret))
}

pub fn lagrange_coefficient_at_zero(
    trustee_id: usize,
    shares: &[PartialDecryptionShare],
) -> CryptoResult<Scalar> {
    let x_i = Scalar::from(trustee_id as u64);
    let mut numerator = Scalar::from(1u64);
    let mut denominator = Scalar::from(1u64);

    for share in shares {
        if share.trustee_id == trustee_id {
            continue;
        }
        let x_j = Scalar::from(share.trustee_id as u64);
        numerator *= -x_j;
        denominator *= x_i - x_j;
    }

    if denominator == Scalar::from(0u64) {
        return Err(CryptoError::InvalidParameters(
            "duplicate trustee id in partial decryptions",
        ));
    }

    Ok(numerator * denominator.invert())
}

fn validate_dealers(config: DkgConfig, dealers: &[Dealer]) -> CryptoResult<()> {
    if dealers.len() != config.trustees {
        return Err(CryptoError::InvalidParameters(
            "dealer count must match trustee count",
        ));
    }
    for dealer in dealers {
        if dealer.coefficients.len() != config.threshold {
            return Err(CryptoError::InvalidParameters(
                "dealer polynomial degree must match threshold - 1",
            ));
        }
    }
    Ok(())
}

fn evaluate_polynomial(coefficients: &[Scalar], x: Scalar) -> Scalar {
    coefficients
        .iter()
        .rev()
        .fold(Scalar::from(0u64), |acc, coefficient| acc * x + coefficient)
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;

    use super::{
        combine_partial_decryptions, partial_decrypt, run_in_memory,
        run_in_memory_with_corruptions, Dealer, DkgConfig, ShareCorruption,
    };
    use crate::elgamal::{decrypt, encrypt, Plaintext, SecretKey};

    fn deterministic_dealers(config: DkgConfig) -> Vec<Dealer> {
        (1..=config.trustees)
            .map(|dealer_id| {
                Dealer::new(
                    dealer_id,
                    (0..config.threshold)
                        .map(|coefficient| Scalar::from((dealer_id * 10 + coefficient + 1) as u64))
                        .collect(),
                )
            })
            .collect()
    }

    #[test]
    fn three_of_five_dkg_decrypts_elgamal_ciphertext() {
        let config = DkgConfig::default_3_of_5();
        let output = run_in_memory(config, &deterministic_dealers(config)).expect("dkg completes");
        let plaintext = Plaintext::from_small_integer(1);
        let ciphertext = encrypt(&output.public_key, plaintext, Scalar::from(77u64));
        let partials: Vec<_> = output
            .trustee_shares
            .iter()
            .take(config.threshold)
            .map(|share| partial_decrypt(share, &ciphertext))
            .collect();

        let decrypted =
            combine_partial_decryptions(&ciphertext, &partials).expect("partials combine");

        assert_eq!(decrypted, plaintext);
        assert!(output.complaints.is_empty());
    }

    #[test]
    fn malformed_share_triggers_complaint_and_honest_threshold_completes() {
        let config = DkgConfig::default_3_of_5();
        let output = run_in_memory_with_corruptions(
            config,
            &deterministic_dealers(config),
            &[ShareCorruption {
                dealer_id: 5,
                recipient_id: 1,
                delta: Scalar::from(1u64),
            }],
        )
        .expect("dkg completes with remaining honest dealers");

        assert_eq!(output.complaints.len(), 1);
        assert_eq!(output.complaints[0].complainant_id, 1);
        assert_eq!(output.complaints[0].accused_id, 5);
        assert_eq!(output.commitments.len(), 4);

        let plaintext = Plaintext::from_small_integer(2);
        let ciphertext = encrypt(&output.public_key, plaintext, Scalar::from(91u64));
        let partials: Vec<_> = output
            .trustee_shares
            .iter()
            .take(config.threshold)
            .map(|share| partial_decrypt(share, &ciphertext))
            .collect();

        let decrypted =
            combine_partial_decryptions(&ciphertext, &partials).expect("partials combine");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn transcript_uses_protocol_dkg_shape() {
        let config = DkgConfig::default_3_of_5();
        let output = run_in_memory(config, &deterministic_dealers(config)).expect("dkg completes");
        let transcript = output.to_protocol_transcript("election-2026");

        assert_eq!(transcript.election_id, "election-2026");
        assert_eq!(transcript.trustee_commitments.len(), 5);
        assert!(transcript.complaints.is_empty());
    }

    #[test]
    fn combined_threshold_secret_matches_full_secret_for_test_only() {
        let config = DkgConfig::default_3_of_5();
        let dealers = deterministic_dealers(config);
        let output = run_in_memory(config, &dealers).expect("dkg completes");
        let total_secret = dealers.iter().fold(Scalar::from(0u64), |acc, dealer| {
            acc + dealer.coefficients[0]
        });
        let full_secret_key = SecretKey::from_scalar(total_secret);
        let plaintext = Plaintext::from_small_integer(3);
        let ciphertext = encrypt(&output.public_key, plaintext, Scalar::from(101u64));

        assert_eq!(decrypt(&full_secret_key, &ciphertext), plaintext);
    }
}
