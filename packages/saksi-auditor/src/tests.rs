//! End-to-end auditor tests. Builds the synthetic happy-path election from
//! [`crate::fixtures`], applies one targeted mutation, and asserts the audit
//! verdict and the specific finding that catches it.

use rand_core::OsRng;

use saksi_credentials::IssuerSecretKey;

use crate::fixtures::happy_path_fixture;
use crate::{audit, AuditStatus};

// ---------------------------------------------------------------------------
// 1. Happy path
// ---------------------------------------------------------------------------

#[test]
fn happy_path_audit_passes() {
    let fixture = happy_path_fixture();
    let report = audit(fixture.artifacts());
    assert!(
        report.passed(),
        "happy-path audit should pass; failing findings: {:#?}",
        report
            .findings
            .iter()
            .filter(|f| matches!(f.status, AuditStatus::Fail))
            .collect::<Vec<_>>()
    );

    // Sanity: the auditor really did run the expected checks (not silently
    // skipping anything). One Pass finding from each "milestone" check
    // should appear.
    for check in [
        "parameters.shape",
        "dkg.shape",
        "dkg.decode",
        "dkg.joint_public_key",
        "dkg.trustee_share_publics",
        "ballot.shape",
        "ballot.cds_proof",
        "ballot.credential",
        "ballot.issuer_binding",
        "nullifier.unique",
        "tally.aggregate",
        "decryption.shape",
        "decryption.cp_proof",
        "decryption.threshold",
        "tally.shape",
        "tally.homomorphic_sum",
    ] {
        assert!(
            report.finding(check).is_some(),
            "happy-path report missing expected milestone check {check}; got: {:#?}",
            report.findings.iter().map(|f| f.check).collect::<Vec<_>>()
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Tampered ballot CDS proof
// ---------------------------------------------------------------------------

#[test]
fn tampered_ballot_cds_proof_is_caught() {
    let mut fixture = happy_path_fixture();
    // Bump a byte deep inside the first branch's response.
    fixture.ballots[0].well_formedness_proofs[0].branches[0].response[0] ^= 0x01;

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    let cds_fail = report
        .findings
        .iter()
        .any(|f| f.check == "ballot.cds_proof" && matches!(f.status, AuditStatus::Fail));
    assert!(cds_fail, "expected ballot.cds_proof Fail in {:#?}", report);
}

// ---------------------------------------------------------------------------
// 3. Tampered credential presentation proof
// ---------------------------------------------------------------------------

#[test]
fn tampered_credential_presentation_proof_is_caught() {
    let mut fixture = happy_path_fixture();
    // Flip a byte well past the signature prefix so the CP-proof bytes
    // get mutated (mirrors saksi-credentials' own tamper test).
    let presentation = fixture.ballots[0]
        .credential_presentation
        .as_mut()
        .expect("credential presentation present");
    // 64 bytes signature prefix + a few -> hit the CP proof bytes.
    let idx = 64 + 4;
    presentation.presentation_proof[idx] ^= 0x01;

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.check == "ballot.credential" && matches!(f.status, AuditStatus::Fail)),
        "expected ballot.credential Fail in {:#?}",
        report
    );
}

// ---------------------------------------------------------------------------
// 4. Reused nullifier
// ---------------------------------------------------------------------------

#[test]
fn reused_nullifier_is_caught() {
    let mut fixture = happy_path_fixture();
    let stolen = fixture.ballots[0]
        .credential_presentation
        .as_ref()
        .unwrap()
        .nullifier
        .as_ref()
        .unwrap()
        .value
        .clone();
    fixture.ballots[1]
        .credential_presentation
        .as_mut()
        .unwrap()
        .nullifier
        .as_mut()
        .unwrap()
        .value = stolen;

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    let null_fail = report
        .findings
        .iter()
        .find(|f| f.check == "nullifier.unique" && matches!(f.status, AuditStatus::Fail));
    assert!(
        null_fail.is_some(),
        "expected nullifier.unique Fail in {:#?}",
        report
    );
    let detail = &null_fail.unwrap().detail;
    assert!(
        detail.contains("ballots 0 and 1"),
        "nullifier finding should list the colliding ballot indices; got {detail:?}"
    );
}

// ---------------------------------------------------------------------------
// 5. Tampered partial decryption share
// ---------------------------------------------------------------------------

#[test]
fn tampered_partial_decryption_share_is_caught() {
    let mut fixture = happy_path_fixture();
    fixture.partial_decryptions[0].share[0] ^= 0x01;

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    // Either the CP-proof verify fails (most common — the share is the
    // statement B in the proof) or the share doesn't decode. Either is a
    // soundness failure.
    let dec_fail = report.findings.iter().any(|f| {
        matches!(f.status, AuditStatus::Fail)
            && (f.check == "decryption.cp_proof" || f.check == "decryption.share_decode")
    });
    assert!(
        dec_fail,
        "expected decryption.cp_proof or decryption.share_decode Fail in {:#?}",
        report
    );
}

// ---------------------------------------------------------------------------
// 6. Tampered Chaum-Pedersen proof field
// ---------------------------------------------------------------------------

#[test]
fn tampered_chaum_pedersen_response_is_caught() {
    let mut fixture = happy_path_fixture();
    // Flip a byte in the response of the first partial decryption's CP
    // proof. Canonical scalars have their top byte clamped, so flip a
    // low byte to stay canonical (and force the verifier — not the
    // wire decoder — to do the rejecting).
    fixture.partial_decryptions[0]
        .proof
        .as_mut()
        .unwrap()
        .response[0] ^= 0x01;

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    let cp_fail = report.findings.iter().any(|f| {
        matches!(f.status, AuditStatus::Fail)
            && (f.check == "decryption.cp_proof" || f.check == "decryption.cp_decode")
    });
    assert!(
        cp_fail,
        "expected decryption.cp_proof or decryption.cp_decode Fail in {:#?}",
        report
    );
}

// ---------------------------------------------------------------------------
// 7. Under-threshold decryptions
// ---------------------------------------------------------------------------

#[test]
fn under_threshold_decryptions_are_caught() {
    let mut fixture = happy_path_fixture();
    // The canonical layout is contest_count * trustee_count = 2 * 5 = 10.
    // Drop entries to leave fewer than `threshold` per contest. The
    // simplest way that respects the layout is to keep only
    // `threshold - 1` trustees per contest.
    let trustee_count = fixture.parameters.trustee_ids.len();
    let threshold = fixture.parameters.threshold as usize;
    let contest_count = fixture.parameters.contest_ids.len();

    let mut trimmed = Vec::with_capacity((threshold - 1) * contest_count);
    for c in 0..contest_count {
        for t in 0..(threshold - 1) {
            trimmed.push(fixture.partial_decryptions[c * trustee_count + t].clone());
        }
    }
    fixture.partial_decryptions = trimmed;

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    // The shape check is what fires first because we changed the total
    // length away from `contest_count * trustee_count`. The shape failure
    // already prevents tally combination. The spec asks for a
    // `decryption.threshold` failure specifically, so we also assert the
    // *cascade*: when length is short, downstream shape detection still
    // yields a decryption-stage Fail.
    assert!(
        report.findings.iter().any(|f| {
            (f.check == "decryption.threshold" || f.check == "decryption.shape")
                && matches!(f.status, AuditStatus::Fail)
        }),
        "expected decryption.threshold or decryption.shape Fail in {:#?}",
        report
    );
}

#[test]
fn under_threshold_with_canonical_layout_is_caught() {
    // Stronger variant of test 7: keep the canonical layout but mark
    // `threshold - 1` trustees worth of CP proofs as tampered (so they
    // fail verification), leaving the verified count below threshold.
    let mut fixture = happy_path_fixture();
    let trustee_count = fixture.parameters.trustee_ids.len();
    let threshold = fixture.parameters.threshold as usize;
    let contest_count = fixture.parameters.contest_ids.len();

    // Tamper threshold trustees in every contest -> only `trustee_count -
    // threshold` (= 2) succeed, which is < threshold (= 3).
    for c in 0..contest_count {
        for t in 0..threshold {
            fixture.partial_decryptions[c * trustee_count + t]
                .proof
                .as_mut()
                .unwrap()
                .response[0] ^= 0x01;
        }
    }

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.check == "decryption.threshold" && matches!(f.status, AuditStatus::Fail)),
        "expected decryption.threshold Fail in {:#?}",
        report
    );
}

// ---------------------------------------------------------------------------
// 8. Wrong tally
// ---------------------------------------------------------------------------

#[test]
fn wrong_tally_is_caught() {
    let mut fixture = happy_path_fixture();
    fixture.tally.totals[0] += 1;

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.check == "tally.homomorphic_sum" && matches!(f.status, AuditStatus::Fail)),
        "expected tally.homomorphic_sum Fail in {:#?}",
        report
    );
}

// ---------------------------------------------------------------------------
// 9. Bad parameters version
// ---------------------------------------------------------------------------

#[test]
fn bad_parameters_version_is_caught() {
    let mut fixture = happy_path_fixture();
    fixture.parameters.version = 99;

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.check == "parameters.shape" && matches!(f.status, AuditStatus::Fail)),
        "expected parameters.shape Fail in {:#?}",
        report
    );
}

// ---------------------------------------------------------------------------
// 10. Empty contests
// ---------------------------------------------------------------------------

#[test]
fn empty_contests_is_caught() {
    let mut fixture = happy_path_fixture();
    fixture.parameters.contest_ids = vec![];

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.check == "parameters.shape" && matches!(f.status, AuditStatus::Fail)),
        "expected parameters.shape Fail in {:#?}",
        report
    );
}

// ---------------------------------------------------------------------------
// 11. Wrong issuer pk
// ---------------------------------------------------------------------------

#[test]
fn wrong_issuer_pk_is_caught() {
    let fixture = happy_path_fixture();
    let other_issuer_sk = IssuerSecretKey::generate(&mut OsRng);
    let other_pk = other_issuer_sk.public_key();

    let mut artifacts = fixture.artifacts();
    artifacts.issuer_public_key = &other_pk;
    let report = audit(artifacts);
    assert_eq!(report.overall, AuditStatus::Fail);
    // Two Fail findings cascade here: ballot.issuer_binding (embedded vs
    // supplied mismatch) and ballot.credential (verify_presentation
    // rejects the wrong supplied pk). Assert at least one fires.
    assert!(
        report.findings.iter().any(|f| {
            (f.check == "ballot.issuer_binding" || f.check == "ballot.credential")
                && matches!(f.status, AuditStatus::Fail)
        }),
        "expected ballot.issuer_binding or ballot.credential Fail in {:#?}",
        report
    );
}

// ---------------------------------------------------------------------------
// 12. DKG transcript trustee-count mismatch
// ---------------------------------------------------------------------------

#[test]
fn dkg_transcript_trustee_count_mismatch_is_caught() {
    let mut fixture = happy_path_fixture();
    fixture.dkg_transcript.trustee_commitments.pop();

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.check == "dkg.shape" && matches!(f.status, AuditStatus::Fail)),
        "expected dkg.shape Fail in {:#?}",
        report
    );
}

// ---------------------------------------------------------------------------
// 13. Partial decryptions are routed by contest_id, not by position
// ---------------------------------------------------------------------------

#[test]
fn partial_decryptions_in_any_order_still_pass() {
    let mut fixture = happy_path_fixture();
    // Each PartialDecryption carries its own contest_id, so a non-canonical
    // order must not change the verdict.
    fixture.partial_decryptions.reverse();

    let report = audit(fixture.artifacts());
    assert_eq!(
        report.overall,
        AuditStatus::Pass,
        "reordered partial decryptions should still pass: {:#?}",
        report
    );
}

#[test]
fn partial_decryption_with_unknown_contest_id_is_caught() {
    let mut fixture = happy_path_fixture();
    fixture.partial_decryptions[0].contest_id = "contest-bogus".into();

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.check == "decryption.shape" && matches!(f.status, AuditStatus::Fail)),
        "expected decryption.shape Fail for an unknown contest_id in {:#?}",
        report
    );
}

#[test]
fn duplicate_partial_decryption_for_contest_is_caught() {
    let mut fixture = happy_path_fixture();
    // A trustee submitting a second share for the same contest must be rejected.
    let dup = fixture.partial_decryptions[0].clone();
    fixture.partial_decryptions.push(dup);

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.check == "decryption.duplicate" && matches!(f.status, AuditStatus::Fail)),
        "expected decryption.duplicate Fail in {:#?}",
        report
    );
}
