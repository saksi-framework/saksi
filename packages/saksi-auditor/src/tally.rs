//! Homomorphic-sum tally verification.
//!
//! Combines the threshold-many verified partial decryptions for each contest
//! via Lagrange interpolation at `x = 0`, recovers the plaintext point
//! `M = D - Σ λ_k · share_k`, brute-force decodes it as a small non-negative
//! integer in `[0, total_ballots]`, and compares against
//! `tally.totals[contest]`.

use std::collections::HashMap;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};

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

        // Recover the integer tally in [0, eligible_ballot_count]: linear scan at
        // small tiers, baby-step giant-step at >= 50k (see decode_tally).
        let decoded = decode_tally(plaintext_point, eligible_ballot_count as u64);

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

/// Tier at or above which tally recovery switches from a linear scan to
/// baby-step giant-step. The manuscript (p.40) commits to "a linear scan at the
/// smaller tiers and Shanks's baby-step giant-step method at fifty thousand
/// voters and above", so the boundary is exactly 50_000.
pub(crate) const BSGS_THRESHOLD: u64 = 50_000;

/// Recover the integer `T` from the tally point `T·G`, with `0 <= T <= max`.
/// `max` is the accepted-ballot count, so the search is bounded and always
/// terminates (an out-of-range point returns `None`). Uses a linear scan below
/// [`BSGS_THRESHOLD`] and baby-step giant-step at or above it — the two paths
/// return identical results (see the differential test); the split is purely a
/// performance choice (`O(max)` vs `O(√max)`) that matches the manuscript.
pub(crate) fn decode_tally(plaintext: RistrettoPoint, max: u64) -> Option<u64> {
    if max < BSGS_THRESHOLD {
        linear_decode(plaintext, max)
    } else {
        bsgs_decode(plaintext, max)
    }
}

/// Linear discrete-log: walk `k·G` for `k` in `[0, max]`.
fn linear_decode(plaintext: RistrettoPoint, max: u64) -> Option<u64> {
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

/// Baby-step giant-step discrete-log in `[0, max]`. Write `T = i·m + j` with
/// `m = ⌈√(max+1)⌉` and `0 <= j < m`: build the baby table `{ j·G → j }`, then
/// for each giant step `i` test whether `P − i·m·G` (a `j·G`) is in the table.
/// Memory + time are `O(√max)`.
fn bsgs_decode(plaintext: RistrettoPoint, max: u64) -> Option<u64> {
    let g = basepoint();
    let m = ((max as f64 + 1.0).sqrt().ceil() as u64).max(1);

    // Baby steps: j·G → j for j in [0, m).
    let mut table: HashMap<[u8; 32], u64> = HashMap::with_capacity(m as usize);
    let mut baby = RistrettoPoint::identity();
    for j in 0..m {
        table.insert(baby.compress().to_bytes(), j);
        baby += g;
    }

    // Giant steps: gamma_i = P − i·m·G; when gamma_i == j·G we have T = i·m + j.
    let m_g = g * Scalar::from(m);
    let mut gamma = plaintext;
    for i in 0..=m {
        if let Some(&j) = table.get(&gamma.compress().to_bytes()) {
            let t = i * m + j;
            if t <= max {
                return Some(t);
            }
        }
        gamma -= m_g;
    }
    None
}

#[cfg(test)]
mod decode_tests {
    use super::*;

    /// The tally point for integer `t`: `t·G`.
    fn point(t: u64) -> RistrettoPoint {
        basepoint() * Scalar::from(t)
    }

    #[test]
    fn linear_and_bsgs_agree_across_range_and_boundaries() {
        // Same bound for both paths so they are directly comparable, including
        // the ends (0, 1) and the boundary values around the 50k threshold.
        let max = BSGS_THRESHOLD; // 50_000
        for t in [0u64, 1, 2, 224, 1000, 49_999, 50_000] {
            let p = point(t);
            assert_eq!(linear_decode(p, max), Some(t), "linear t={t}");
            assert_eq!(bsgs_decode(p, max), Some(t), "bsgs t={t}");
        }
    }

    #[test]
    fn decode_tally_routes_by_threshold_but_recovers_t() {
        assert_eq!(decode_tally(point(7), 10), Some(7)); // linear path (max<50k)
        assert_eq!(decode_tally(point(7), BSGS_THRESHOLD), Some(7)); // bsgs path
        // Boundary value at the boundary max, via the bsgs path.
        assert_eq!(
            decode_tally(point(BSGS_THRESHOLD), BSGS_THRESHOLD),
            Some(BSGS_THRESHOLD)
        );
    }

    #[test]
    fn out_of_range_returns_none() {
        // A value beyond `max` must not decode — the search is bounded.
        assert_eq!(linear_decode(point(11), 10), None);
        assert_eq!(bsgs_decode(point(BSGS_THRESHOLD + 5), BSGS_THRESHOLD), None);
    }

    #[test]
    fn zero_decodes_to_zero() {
        assert_eq!(decode_tally(RistrettoPoint::identity(), 10), Some(0));
        assert_eq!(bsgs_decode(RistrettoPoint::identity(), BSGS_THRESHOLD), Some(0));
    }
}
