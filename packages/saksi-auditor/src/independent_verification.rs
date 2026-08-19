//! Formal end-to-end independent-verification test (panel #29 / matrix M21).
//!
//! Demonstrates "software independence" (Rivest): a verifier given ONLY the
//! public election record reproduces the tally and accepts every proof; and when
//! any single public record is modified, the verifier detects the inconsistency.
//!
//! The verifier here is `saksi-auditor::audit` run on
//! [`ElectionFixture::public_artifacts`] — the public bulletin-board data with
//! the seeded `ground_truth` answer key STRIPPED (`ground_truth: None`). Verifying
//! from the public record alone, never against a private answer key, is the whole
//! point of the claim; the `E = 0`-vs-ground-truth check is a separate
//! generator-side test (`demo::audit_scores_e0_accuracy_against_ground_truth`).
//!
//! The tamper matrix covers every class of public-record mutation (matrix F5):
//! ballot ciphertext/proof, tally total, dropped ballot, reordered ballots,
//! partial-decryption share, and DKG transcript.

use crate::fixtures::{multi_position_fixture, SelectionProfile};
use crate::{audit, AuditStatus};

fn fixture() -> crate::fixtures::ElectionFixture {
    multi_position_fixture(4, 2, 2, SelectionProfile::Uniform)
}

/// Positive: from the public record alone (no ground truth) the verifier
/// reproduces the tally and accepts every proof.
#[test]
fn public_record_verification_reproduces_and_accepts() {
    let f = fixture();
    let report = audit(f.public_artifacts());

    assert!(
        report.passed(),
        "verifier must accept the untampered public record: {report:#?}"
    );
    // It reproduced the tally by real decryption (decode == published)…
    assert!(
        matches!(
            report.finding("tally.homomorphic_sum").map(|f| &f.status),
            Some(AuditStatus::Pass)
        ),
        "tally must be reproduced + verified from public data: {report:#?}"
    );
    // …and it did so WITHOUT any ground-truth answer key present.
    assert!(
        report.finding("tally.accuracy").is_none(),
        "public-record verification must not consult a seeded answer key"
    );
}

/// A flipped ballot proof/ciphertext byte is detected.
#[test]
fn tamper_ballot_proof_detected() {
    let mut f = fixture();
    f.ballots[0].well_formedness_proofs[0].branches[0].response[0] ^= 0x01;
    let report = audit(f.public_artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert!(
        report
            .findings
            .iter()
            .any(|x| x.check == "ballot.cds_proof" && matches!(x.status, AuditStatus::Fail)),
        "expected ballot.cds_proof Fail: {report:#?}"
    );
}

/// An altered published tally total is detected.
#[test]
fn tamper_tally_total_detected() {
    let mut f = fixture();
    f.tally.totals[0] += 1;
    let report = audit(f.public_artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert!(
        report
            .findings
            .iter()
            .any(|x| x.check == "tally.homomorphic_sum" && matches!(x.status, AuditStatus::Fail)),
        "expected tally.homomorphic_sum Fail: {report:#?}"
    );
}

/// A dropped ballot is detected (recorded set no longer sums to the tally).
#[test]
fn dropped_ballot_detected() {
    let mut f = fixture();
    f.ballots.remove(0);
    let report = audit(f.public_artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert!(
        report
            .findings
            .iter()
            .any(|x| x.check == "tally.homomorphic_sum" && matches!(x.status, AuditStatus::Fail)),
        "expected tally.homomorphic_sum Fail: {report:#?}"
    );
}

/// A pure reorder leaves the order-independent tally clean, so it is detected by
/// the append-only ledger digest (the sole detector of a reorder).
#[test]
fn reordered_ballots_detected_by_ledger_digest() {
    let f = fixture();
    let recorded = crate::ledger::ledger_digest(&f.ballots);
    let mut served = f.ballots.clone();
    served.reverse();
    assert_ne!(
        crate::ledger::ledger_digest(&served),
        recorded,
        "reordering must change the ledger digest"
    );
    // And confirm the tally itself is order-blind (so the digest is the detector).
    let mut reordered = fixture();
    reordered.ballots.reverse();
    assert!(audit(reordered.public_artifacts()).passed());
}

/// A tampered trustee partial-decryption share is detected.
#[test]
fn tamper_partial_decryption_detected() {
    let mut f = fixture();
    f.partial_decryptions[0].share[0] ^= 0x01;
    let report = audit(f.public_artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert!(
        report.findings.iter().any(|x| {
            matches!(x.status, AuditStatus::Fail)
                && (x.check == "decryption.cp_proof" || x.check == "decryption.share_decode")
        }),
        "expected a decryption.* Fail: {report:#?}"
    );
}

/// A tampered DKG transcript is detected.
#[test]
fn tamper_dkg_transcript_detected() {
    let mut f = fixture();
    f.dkg_transcript.trustee_commitments[0].coefficient_commitments[0][0] ^= 0x01;
    let report = audit(f.public_artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert!(
        report
            .findings
            .iter()
            .any(|x| x.check.starts_with("dkg.") && matches!(x.status, AuditStatus::Fail)),
        "expected a dkg.* Fail: {report:#?}"
    );
}
