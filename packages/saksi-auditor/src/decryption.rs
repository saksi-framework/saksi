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
//! - per-decryption version / contest_id / trustee_id-in-parameters checks (shape),
//! - **at most one** partial decryption per `(contest_id, trustee_id)` (a trustee
//!   may not submit two shares for the same contest),
//! - the **threshold count**: the number of distinct trustee ids that submitted
//!   a partial decryption for any given contest must be at least
//!   `parameters.threshold`.
//!
//! ## Self-describing routing
//!
//! Each [`saksi_protocol::PartialDecryption`] now carries its own `contest_id`
//! (matching the on-chain `SubmitPartialDecryption`), so the auditor routes each
//! share to the contest it names rather than relying on a positional layout.
//! Partial decryptions may appear in any order, and a contest need not have a
//! share from every trustee — only `>= threshold` distinct verified trustees.

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

    // -- 2/3. Route each partial decryption to its named contest and verify -

    let mut verified_shares: Vec<Vec<VerifiedShare>> =
        (0..contest_count).map(|_| Vec::new()).collect();
    // Reject a trustee submitting more than one share for the same contest.
    let mut seen: HashSet<(usize, usize)> = HashSet::new();

    for (idx, pd) in partial_decryptions.iter().enumerate() {
        if pd.version != WIRE_VERSION {
            builder.fail(
                "decryption.shape",
                format!(
                    "partial_decryptions[{idx}] version {} != supported {}",
                    pd.version, WIRE_VERSION
                ),
            );
            continue;
        }

        // Route by the share's own contest_id (self-describing — no positional
        // layout assumption).
        let c = match parameters
            .contest_ids
            .iter()
            .position(|id| id == &pd.contest_id)
        {
            Some(c) => c,
            None => {
                builder.fail(
                    "decryption.shape",
                    format!(
                        "partial_decryptions[{idx}] contest_id {:?} not in parameters.contest_ids",
                        pd.contest_id
                    ),
                );
                continue;
            }
        };
        let contest_id = &parameters.contest_ids[c];

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

        // At most one share per (contest, trustee).
        if !seen.insert((c, trustee_index)) {
            builder.fail(
                "decryption.duplicate",
                format!(
                    "partial_decryptions[{idx}]: trustee {:?} submitted more than one share for contest {contest_id}",
                    pd.trustee_id
                ),
            );
            continue;
        }
        builder.pass(
            "decryption.shape",
            format!(
                "partial_decryptions[{idx}] routes to contest {contest_id}, trustee {:?}",
                pd.trustee_id
            ),
        );

        let aggregate_pad = aggregate_pads[c];

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

        // Sanity-decode the cached scalar fields too — a tampered `response`
        // field that survives `from_wire` (because it stayed canonical) will
        // fail the verifier below; non-canonical bytes would have failed
        // from_wire. Either way we reject.
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
#[cfg(any(test, feature = "demo"))]
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
