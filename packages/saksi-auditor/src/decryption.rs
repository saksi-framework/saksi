//! Per-trustee partial-decryption verification.
//!
//! For each [`saksi_protocol::PartialDecryption`] in the report, decode the
//! share point and the Chaum-Pedersen proof, and verify the proof against:
//!
//! - `G = basepoint`,
//! - `H = aggregate ElGamal pad for this contest = Σ_b ballots[b].ciphertexts[contest].pad`,
//! - `A = pub_share_k = Σ_d Σ_j (k+1)^j · A_{d,j}` (aggregated DKG public share
//!   evaluated at the trustee's index), supplied by [`crate::dkg`],
//! - `B = decoded share point`,
//! - `context = binding_context || trustee_id || contest_id`.
//!
//! Also enforces:
//!
//! - per-decryption version / trustee_id-in-parameters checks (shape),
//! - the **threshold count**: the number of distinct trustee ids that submitted
//!   a partial decryption for any given contest must be at least
//!   `parameters.threshold`.
//!
//! ## Layout assumption (v1)
//!
//! The wire schema has no contest field on [`saksi_protocol::PartialDecryption`].
//! The auditor therefore assumes a canonical layout:
//!
//! ```text
//! partial_decryptions.len() == contest_count * trustee_count
//! partial_decryptions[c * trustee_count + t]
//!     = trustee parameters.trustee_ids[t] decrypting contest c
//! ```
//!
//! The bulletin-board client SDK (Phase D) is expected to produce this
//! layout. A mismatch is a shape failure.

use std::collections::HashSet;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};

use saksi_crypto::{
    group::{basepoint, point_from_compressed, scalar_from_canonical_bytes},
    nizk::chaum_pedersen::ChaumPedersenProof,
};
use saksi_protocol::{Ballot, ElectionParameters, PartialDecryption, WIRE_VERSION};

use crate::report::ReportBuilder;

/// One verified partial decryption — its share point plus the trustee index
/// (position in `parameters.trustee_ids`) used as Lagrange `x = index + 1`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VerifiedShare {
    pub(crate) trustee_index: usize,
    pub(crate) share_point: RistrettoPoint,
}

/// Verification result for partial decryptions across every contest.
#[derive(Clone, Debug)]
pub(crate) struct DecryptionVerification {
    /// `aggregate_pads[c]` = Σ_b eligible_ballots[b].ciphertexts[c].pad.
    /// Reserved for downstream consumers that may want to spot-check the
    /// aggregate without recomputing it.
    #[allow(dead_code)]
    pub(crate) aggregate_pads: Vec<RistrettoPoint>,
    /// `aggregate_data[c]` = Σ_b eligible_ballots[b].ciphertexts[c].data.
    pub(crate) aggregate_data: Vec<RistrettoPoint>,
    /// `verified_shares[c]` = the partial decryptions for contest c whose
    /// Chaum-Pedersen proof verified, in input order.
    pub(crate) verified_shares: Vec<Vec<VerifiedShare>>,
    /// True iff every contest had `>= threshold` distinct verified trustees.
    pub(crate) threshold_satisfied: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_partial_decryptions(
    parameters: &ElectionParameters,
    eligible_ballots: &[&Ballot],
    partial_decryptions: &[PartialDecryption],
    trustee_share_publics: &[RistrettoPoint],
    binding_context: &[u8],
    builder: &mut ReportBuilder,
) -> Option<DecryptionVerification> {
    let contest_count = parameters.contest_ids.len();
    let trustee_count = parameters.trustee_ids.len();
    let threshold = parameters.threshold as usize;

    // -- 1. Per-contest aggregate ElGamal ciphertexts -----------------------

    let mut aggregate_pads = vec![RistrettoPoint::identity(); contest_count];
    let mut aggregate_data = vec![RistrettoPoint::identity(); contest_count];
    for ballot in eligible_ballots {
        for (c, ct) in ballot.ciphertexts.iter().enumerate().take(contest_count) {
            // Ballots that passed `verify_ballots` already had their
            // ciphertexts decoded once; we redo it here so this module is
            // standalone and we don't ferry decoded points around. Failures
            // here are very unlikely (would mean a ballot that survived the
            // shape check has a malformed point).
            let pad_array: [u8; 32] = match ct.pad.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    builder.fail(
                        "tally.aggregate",
                        format!("eligible ballot contest {c}: ciphertext pad has wrong length"),
                    );
                    return None;
                }
            };
            let data_array: [u8; 32] = match ct.data.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    builder.fail(
                        "tally.aggregate",
                        format!("eligible ballot contest {c}: ciphertext data has wrong length"),
                    );
                    return None;
                }
            };
            let pad = match point_from_compressed(pad_array) {
                Ok(p) => p,
                Err(_) => {
                    builder.fail(
                        "tally.aggregate",
                        format!("eligible ballot contest {c}: ciphertext pad is invalid"),
                    );
                    return None;
                }
            };
            let data = match point_from_compressed(data_array) {
                Ok(p) => p,
                Err(_) => {
                    builder.fail(
                        "tally.aggregate",
                        format!("eligible ballot contest {c}: ciphertext data is invalid"),
                    );
                    return None;
                }
            };
            aggregate_pads[c] += pad;
            aggregate_data[c] += data;
        }
    }
    builder.pass(
        "tally.aggregate",
        "aggregate ElGamal ciphertexts assembled per contest",
    );

    // -- 2. Shape: layout (contest_count * trustee_count) -------------------

    let expected_len = contest_count * trustee_count;
    if partial_decryptions.len() != expected_len {
        builder.fail(
            "decryption.shape",
            format!(
                "partial_decryptions length {} != contest_count * trustee_count = {} * {} = {}",
                partial_decryptions.len(),
                contest_count,
                trustee_count,
                expected_len
            ),
        );
        return None;
    }
    builder.pass(
        "decryption.shape",
        "partial_decryptions length matches contest_count * trustee_count",
    );

    // -- 3. Per-contest verification of each PartialDecryption --------------

    let mut verified_shares: Vec<Vec<VerifiedShare>> =
        (0..contest_count).map(|_| Vec::new()).collect();

    for c in 0..contest_count {
        let contest_id = &parameters.contest_ids[c];
        let aggregate_pad = aggregate_pads[c];
        for t in 0..trustee_count {
            let idx = c * trustee_count + t;
            let pd = &partial_decryptions[idx];

            if pd.version != WIRE_VERSION {
                builder.fail(
                    "decryption.shape",
                    format!(
                        "partial_decryptions[{idx}] (contest {contest_id}, slot {t}) version {} != supported {}",
                        pd.version, WIRE_VERSION
                    ),
                );
                continue;
            }

            // `trustee_id` is a string; map back to the index it must occupy
            // in the canonical layout.
            let expected_trustee_id = &parameters.trustee_ids[t];
            if &pd.trustee_id != expected_trustee_id {
                builder.fail(
                    "decryption.shape",
                    format!(
                        "partial_decryptions[{idx}] trustee_id {:?} does not match expected slot {:?} (contest {contest_id})",
                        pd.trustee_id, expected_trustee_id
                    ),
                );
                continue;
            }

            let trustee_index = match parameters
                .trustee_ids
                .iter()
                .position(|id| id == &pd.trustee_id)
            {
                Some(i) => i,
                None => {
                    builder.fail(
                        "decryption.shape",
                        format!(
                            "partial_decryptions[{idx}] trustee_id {:?} not in parameters.trustee_ids",
                            pd.trustee_id
                        ),
                    );
                    continue;
                }
            };

            // decode share point
            let share_array: [u8; 32] = match pd.share.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    builder.fail(
                        "decryption.share_decode",
                        format!("partial_decryptions[{idx}] share has wrong length"),
                    );
                    continue;
                }
            };
            let share_point = match point_from_compressed(share_array) {
                Ok(p) => p,
                Err(_) => {
                    builder.fail(
                        "decryption.share_decode",
                        format!("partial_decryptions[{idx}] share is not a valid ristretto point"),
                    );
                    continue;
                }
            };

            // decode Chaum-Pedersen proof
            let cp_wire = match pd.proof.as_ref() {
                Some(w) => w,
                None => {
                    builder.fail(
                        "decryption.cp_decode",
                        format!("partial_decryptions[{idx}] missing Chaum-Pedersen proof"),
                    );
                    continue;
                }
            };
            let cp_proof = match ChaumPedersenProof::from_wire(cp_wire) {
                Ok(p) => p,
                Err(err) => {
                    builder.fail(
                        "decryption.cp_decode",
                        format!(
                            "partial_decryptions[{idx}] Chaum-Pedersen proof failed to decode: {err}"
                        ),
                    );
                    continue;
                }
            };

            // Sanity-decode the cached scalar fields too — a tampered
            // `response` field that survives `from_wire` (because it stayed
            // canonical) will fail the verifier below; non-canonical bytes
            // would have failed from_wire. Either way we reject.
            let _ = {
                let bytes: [u8; 32] = cp_wire.response.as_slice().try_into().unwrap_or([0u8; 32]);
                scalar_from_canonical_bytes(bytes).ok()
            };

            // Verify against the aggregate pad and the trustee's public share.
            let g = basepoint();
            let pub_share = trustee_share_publics[trustee_index];
            let context = cp_context(binding_context, &pd.trustee_id, contest_id);
            match cp_proof.verify(&g, &aggregate_pad, &pub_share, &share_point, &context) {
                Ok(()) => {
                    builder.pass(
                        "decryption.cp_proof",
                        format!(
                            "partial_decryptions[{idx}] (trustee {}, contest {contest_id}) Chaum-Pedersen verifies",
                            pd.trustee_id
                        ),
                    );
                    verified_shares[c].push(VerifiedShare {
                        trustee_index,
                        share_point,
                    });
                }
                Err(err) => {
                    builder.fail(
                        "decryption.cp_proof",
                        format!(
                            "partial_decryptions[{idx}] (trustee {}, contest {contest_id}) Chaum-Pedersen failed: {err}",
                            pd.trustee_id
                        ),
                    );
                }
            }
        }
    }

    // -- 4. Threshold satisfied per contest --------------------------------

    let mut threshold_satisfied = true;
    for (c, contest_id) in parameters.contest_ids.iter().enumerate() {
        let distinct: HashSet<usize> = verified_shares[c].iter().map(|s| s.trustee_index).collect();
        if distinct.len() < threshold {
            builder.fail(
                "decryption.threshold",
                format!(
                    "contest {contest_id}: only {} distinct verified trustees submitted, threshold is {}",
                    distinct.len(),
                    threshold
                ),
            );
            threshold_satisfied = false;
        } else {
            builder.pass(
                "decryption.threshold",
                format!(
                    "contest {contest_id}: {} distinct verified trustees >= threshold {}",
                    distinct.len(),
                    threshold
                ),
            );
        }
    }

    Some(DecryptionVerification {
        aggregate_pads,
        aggregate_data,
        verified_shares,
        threshold_satisfied,
    })
}

/// Per-decryption Chaum-Pedersen transcript context:
/// `binding_context || trustee_id || contest_id` with explicit length prefixes.
fn cp_context(binding_context: &[u8], trustee_id: &str, contest_id: &str) -> Vec<u8> {
    let mut ctx =
        Vec::with_capacity(binding_context.len() + trustee_id.len() + contest_id.len() + 3 * 8);
    ctx.extend_from_slice(&(binding_context.len() as u64).to_be_bytes());
    ctx.extend_from_slice(binding_context);
    ctx.extend_from_slice(&(trustee_id.len() as u64).to_be_bytes());
    ctx.extend_from_slice(trustee_id.as_bytes());
    ctx.extend_from_slice(&(contest_id.len() as u64).to_be_bytes());
    ctx.extend_from_slice(contest_id.as_bytes());
    ctx
}

/// Test-only mirror so the fixture builder can produce proofs against the
/// same transcript bytes the auditor reconstructs.
#[cfg(test)]
pub(crate) fn cp_context_for_test(
    binding_context: &[u8],
    trustee_id: &str,
    contest_id: &str,
) -> Vec<u8> {
    cp_context(binding_context, trustee_id, contest_id)
}

/// Compute the Lagrange coefficient at `x = 0` for the trustee with index
/// `target_index` (so Lagrange `x_i = target_index + 1`) given the active
/// subset `subset_indices` (1-based `x` values are `i + 1` for each `i`).
/// Returns `None` if `subset_indices` contains duplicates.
pub(crate) fn lagrange_coefficient_at_zero(
    target_index: usize,
    subset_indices: &[usize],
) -> Option<Scalar> {
    let x_i = Scalar::from((target_index as u64) + 1);
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;
    for &j in subset_indices {
        if j == target_index {
            continue;
        }
        let x_j = Scalar::from((j as u64) + 1);
        numerator *= -x_j;
        let diff = x_i - x_j;
        if diff == Scalar::ZERO {
            return None;
        }
        denominator *= diff;
    }
    Some(numerator * denominator.invert())
}
