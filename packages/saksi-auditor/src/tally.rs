//! Homomorphic-sum tally verification.
//!
//! Combines the threshold-many verified partial decryptions for each contest
//! via Lagrange interpolation at `x = 0`, recovers the plaintext point
//! `M = D - Σ λ_k · share_k`, brute-force decodes it as a small non-negative
//! integer in `[0, total_ballots]`, and compares against
//! `tally.totals[contest]`.

use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};

use saksi_crypto::group::basepoint;
use saksi_protocol::{ElectionParameters, TallyResult, WIRE_VERSION};

use crate::{
    decryption::{lagrange_coefficient_at_zero, DecryptionVerification},
    report::ReportBuilder,
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_tally(
    parameters: &ElectionParameters,
    tally: &TallyResult,
    decryption: &DecryptionVerification,
    eligible_ballot_count: usize,
    ground_truth: Option<&[u64]>,
    builder: &mut ReportBuilder,
) {
    // -- shape --------------------------------------------------------------

    if tally.version != WIRE_VERSION {
        builder.fail(
            "tally.shape",
            format!(
                "tally version {} != supported {}",
                tally.version, WIRE_VERSION
            ),
        );
        return;
    }
    if tally.election_id != parameters.election_id {
        builder.fail(
            "tally.shape",
            format!(
                "tally.election_id {:?} != parameters.election_id {:?}",
                tally.election_id, parameters.election_id
            ),
        );
        return;
    }
    if tally.totals.len() != parameters.contest_ids.len() {
        builder.fail(
            "tally.shape",
            format!(
                "tally has {} totals, expected {} (one per contest)",
                tally.totals.len(),
                parameters.contest_ids.len()
            ),
        );
        return;
    }
    builder.pass("tally.shape", "tally shape matches parameters");

    // If a prior phase already failed to satisfy threshold or aggregate the
    // ciphertexts, decoding via Lagrange combine would mix verified-and-
    // failing trustees; skip and let the existing failures speak for
    // themselves.
    if !decryption.threshold_satisfied {
        builder.fail(
            "tally.homomorphic_sum",
            "skipped homomorphic sum: threshold not satisfied across all contests",
        );
        return;
    }

    // Validate the ground-truth width once; a mismatch disables the accuracy
    // check (and is reported) rather than risking an out-of-bounds index.
    let ground_truth = match ground_truth {
        Some(truth) if truth.len() != parameters.contest_ids.len() => {
            builder.fail(
                "tally.accuracy",
                format!(
                    "ground truth has {} entries, expected {} (one per contest); accuracy check skipped",
                    truth.len(),
                    parameters.contest_ids.len()
                ),
            );
            None
        }
        other => other,
    };

    let threshold = parameters.threshold as usize;
    let g = basepoint();

    for (c, contest_id) in parameters.contest_ids.iter().enumerate() {
        let verified = &decryption.verified_shares[c];
        if verified.len() < threshold {
            // Threshold check already failed above for this contest; record
            // the cascading skip and continue.
            builder.fail(
                "tally.homomorphic_sum",
                format!(
                    "contest {contest_id}: not enough verified shares ({} < threshold {threshold})",
                    verified.len()
                ),
            );
            continue;
        }

        // Pick the first `threshold` verified shares for determinism.
        let subset = &verified[..threshold];
        let subset_indices: Vec<usize> = subset.iter().map(|s| s.trustee_index).collect();

        let mut shared_secret = RistrettoPoint::identity();
        let mut bad_lagrange = false;
        for share in subset {
            let lambda = match lagrange_coefficient_at_zero(share.trustee_index, &subset_indices) {
                Some(l) => l,
                None => {
                    builder.fail(
                        "tally.homomorphic_sum",
                        format!("contest {contest_id}: duplicate trustee in Lagrange subset"),
                    );
                    bad_lagrange = true;
                    break;
                }
            };
            shared_secret += lambda * share.share_point;
        }
        if bad_lagrange {
            continue;
        }

        let plaintext_point = decryption.aggregate_data[c] - shared_secret;

        // Brute-force discrete log in [0, eligible_ballot_count].
        let mut decoded: Option<u64> = None;
        let mut candidate = RistrettoPoint::identity();
        for k in 0..=(eligible_ballot_count as u64) {
            if candidate == plaintext_point {
                decoded = Some(k);
                break;
            }
            candidate += g;
        }

        match decoded {
            None => {
                builder.fail(
                    "tally.homomorphic_sum",
                    format!(
                        "contest {contest_id}: plaintext point did not decode to any value in [0, {eligible_ballot_count}]"
                    ),
                );
            }
            Some(k) => {
                let published = tally.totals[c];
                if k == published {
                    builder.pass(
                        "tally.homomorphic_sum",
                        format!(
                            "contest {contest_id}: homomorphic decode = {k} matches published tally"
                        ),
                    );
                } else {
                    builder.fail(
                        "tally.homomorphic_sum",
                        format!(
                            "contest {contest_id}: homomorphic decode = {k}, published tally = {published}"
                        ),
                    );
                }

                // Accuracy (E = 0): the value recovered by real threshold
                // decryption must equal the independently-seeded ground truth.
                // This is stronger than the homomorphic_sum check above (decode
                // vs *published* tally) — it catches a published tally that was
                // set to a wrong value that happens to differ from the real
                // decrypt, and a decrypt that drifts from the seeded intent.
                if let Some(truth) = ground_truth {
                    let expected = truth[c];
                    if k == expected {
                        builder.pass(
                            "tally.accuracy",
                            format!(
                                "contest {contest_id}: decoded tally = {k} == ground truth (E=0)"
                            ),
                        );
                    } else {
                        builder.fail(
                            "tally.accuracy",
                            format!(
                                "contest {contest_id}: decoded tally = {k} != ground truth {expected} (E={})",
                                k as i64 - expected as i64
                            ),
                        );
                    }
                }
            }
        }
    }

    // Also verify mirror-totals look numerically sane (each total <=
    // eligible_ballot_count). This is implied by a successful homomorphic
    // decode, but report it as its own check so a stress test against
    // garbage tallies surfaces clearly.
    for (c, &published) in tally.totals.iter().enumerate() {
        let contest_id = &parameters.contest_ids[c];
        if published as usize > eligible_ballot_count {
            builder.fail(
                "tally.range",
                format!(
                    "contest {contest_id}: published total {published} exceeds eligible ballot count {eligible_ballot_count}"
                ),
            );
        }
    }
}

/// Internal helper kept here (instead of inline) so it can be unit tested
/// against the in-memory DKG path: take a contest's plaintext point and
/// brute-force decode it as a small non-negative integer.
#[allow(dead_code)]
pub(crate) fn brute_force_decode(plaintext: RistrettoPoint, max: u64) -> Option<u64> {
    let g = basepoint();
    let mut candidate = RistrettoPoint::identity();
    for k in 0..=max {
        if candidate == plaintext {
            return Some(k);
        }
        candidate += g;
    }
    None
}
