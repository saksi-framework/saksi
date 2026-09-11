//! End-to-end auditor tests. Builds the synthetic happy-path election from
//! [`crate::fixtures`], applies one targeted mutation, and asserts the audit
//! verdict and the specific finding that catches it.

use rand_core::OsRng;

use saksi_credentials::IssuerSecretKey;

use saksi_protocol::Ballot;

use crate::fixtures::{
    happy_path_fixture, multi_position_fixture, ElectionFixture, GenParams, SelectionProfile,
};
use crate::{audit, AuditReport, AuditStatus};

// ---------------------------------------------------------------------------
// 0. Multi-position model (ADR-0007 one-record-per-position)
// ---------------------------------------------------------------------------

#[test]
fn multi_position_audit_passes() {
    // 4 voters, 3 positions, 3 candidates → 12 ballot records, 9 P×C contests.
    let fixture = multi_position_fixture(&GenParams::simple(4, 3, 3, SelectionProfile::Uniform));
    assert_eq!(
        fixture.ballots.len(),
        4 * 3,
        "one record per (voter, position)"
    );
    assert_eq!(fixture.parameters.contest_ids.len(), 3 * 3, "P×C contests");
    // Each position elects exactly one candidate per voter, so the per-position
    // ground-truth totals sum to the voter count.
    for p in 0..3 {
        let sum: u64 = (0..3).map(|k| fixture.ground_truth[p * 3 + k]).sum();
        assert_eq!(sum, 4, "position {p}: one selection per voter");
    }
    let report = audit(fixture.artifacts());
    assert!(
        report.passed(),
        "multi-position audit should pass; failing: {:#?}",
        report
            .findings
            .iter()
            .filter(|f| matches!(f.status, AuditStatus::Fail))
            .collect::<Vec<_>>()
    );
}

#[test]
fn single_position_axis_audit_passes() {
    // positions == 1 is the single-position ballot axis.
    let fixture = multi_position_fixture(&GenParams::simple(5, 1, 4, SelectionProfile::Uniform));
    assert_eq!(fixture.ballots.len(), 5);
    let report = audit(fixture.artifacts());
    assert!(report.passed(), "single-position axis should audit clean");
}

#[test]
fn per_position_double_vote_is_caught() {
    // A voter voting the SAME position twice replays that position's nullifier —
    // caught by cross-ballot nullifier uniqueness.
    let mut fixture =
        multi_position_fixture(&GenParams::simple(3, 3, 3, SelectionProfile::Uniform));
    // Ballot 0 and 1 are voter 0's position 0 and 1; duplicate ballot 0 as a
    // second submission for the same (voter, position) → identical nullifier.
    let replay = fixture.ballots[0].clone();
    fixture.ballots.push(replay);
    let report = audit(fixture.artifacts());
    assert_eq!(
        report.overall,
        AuditStatus::Fail,
        "replaying a (voter, position) nullifier must fail the audit"
    );
    assert!(
        matches!(
            report.finding("nullifier.unique").map(|f| &f.status),
            Some(AuditStatus::Fail)
        ),
        "the duplicate must be caught by nullifier.unique"
    );
}

#[test]
fn same_voter_different_positions_is_allowed() {
    // The complement of the double-vote test: one voter voting across DIFFERENT
    // positions yields DISTINCT nullifiers, so the honest election audits clean.
    let fixture = multi_position_fixture(&GenParams::simple(1, 3, 2, SelectionProfile::Uniform));
    assert_eq!(fixture.ballots.len(), 3, "one voter, three positions");
    let nullifiers: std::collections::HashSet<Vec<u8>> = fixture
        .ballots
        .iter()
        .map(|b| {
            b.credential_presentation
                .as_ref()
                .unwrap()
                .nullifier
                .as_ref()
                .unwrap()
                .value
                .clone()
        })
        .collect();
    assert_eq!(nullifiers.len(), 3, "distinct per-position nullifiers");
    assert!(audit(fixture.artifacts()).passed());
}

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
        "tally.signatures",
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

// ---------------------------------------------------------------------------
// Stage timings
// ---------------------------------------------------------------------------

/// The four stage timers must actually measure something, and they must be
/// disjoint spans of the one audit — so their sum cannot exceed the wall time
/// the whole audit took.
#[test]
fn audit_stage_timings_are_measured_and_within_the_wall() {
    let fixture = multi_position_fixture(&GenParams::simple(100, 1, 2, SelectionProfile::Uniform));
    let started = std::time::Instant::now();
    let (report, _evidence, timings) = crate::audit_with_evidence(fixture.artifacts(), None);
    let wall = started.elapsed();

    assert!(
        report.passed(),
        "100-voter fixture audits clean: {report:#?}"
    );
    for (name, spent) in [
        ("verify_ballots", timings.verify_ballots),
        ("aggregate", timings.aggregate),
        ("combine", timings.combine),
        ("decode", timings.decode),
    ] {
        assert!(
            spent > std::time::Duration::ZERO,
            "stage {name} recorded no time at all"
        );
    }
    let sum = timings.verify_ballots + timings.aggregate + timings.combine + timings.decode;
    assert!(
        sum <= wall,
        "stage timings {sum:?} exceed the audit's wall time {wall:?}"
    );
}

/// A clean audit of a thousand ballots must not keep a thousand findings: the
/// per-ballot passes are counted and rolled up (failures are still listed one
/// by one). This is the report-side half of the streaming memory bound — the
/// findings Vec was the largest thing left in the process.
#[test]
fn per_ballot_passes_are_rolled_up_not_stored() {
    // 500 voters x 2 positions = 1,000 ballot records.
    let fixture = multi_position_fixture(&GenParams::simple(500, 2, 2, SelectionProfile::Uniform));
    assert_eq!(fixture.ballots.len(), 1_000);

    let report = audit(fixture.artifacts());
    assert!(report.passed(), "{report:#?}");
    assert!(
        report.findings.len() < 100,
        "a clean 1,000-ballot audit kept {} findings — per-ballot passes are being stored",
        report.findings.len()
    );
    // The rollup still names every per-ballot check, exactly once.
    for check in [
        "ballot.shape",
        "ballot.cds_proof",
        "ballot.issuer_binding",
        "ballot.credential",
    ] {
        assert_eq!(
            report.findings.iter().filter(|f| f.check == check).count(),
            1,
            "{check} should appear once as a rollup: {report:#?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Trustee tally signatures (`tally.signatures`)
// ---------------------------------------------------------------------------

/// Finding lookup that names the failing report when the check is absent.
fn signature_finding(report: &crate::AuditReport) -> &crate::AuditFinding {
    report.finding("tally.signatures").unwrap_or_else(|| {
        panic!("tally.signatures must be reported whenever the DKG verified: {report:#?}")
    })
}

#[test]
fn trustee_tally_signatures_verify() {
    let fixture = happy_path_fixture();
    assert_eq!(
        fixture.tally.signatures.len(),
        fixture.parameters.trustee_ids.len(),
        "every trustee signs the published tally"
    );
    let report = audit(fixture.artifacts());
    assert!(report.passed(), "{report:#?}");
    assert_eq!(signature_finding(&report).status, AuditStatus::Pass);
}

#[test]
fn missing_tally_signatures_are_caught() {
    let mut fixture = happy_path_fixture();
    fixture.tally.signatures.clear();

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    let finding = signature_finding(&report);
    assert_eq!(finding.status, AuditStatus::Fail);
    assert_eq!(finding.detail, "missing");
}

#[test]
fn tampered_tally_signature_is_caught() {
    let mut fixture = happy_path_fixture();
    // Flip a bit in the response scalar: still a canonical 64-byte proof, but
    // it no longer satisfies s·G == R + c·vk.
    fixture.tally.signatures[0].signature[32] ^= 0x01;

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert_eq!(signature_finding(&report).status, AuditStatus::Fail);
}

#[test]
fn tally_signature_over_different_totals_is_caught() {
    let mut fixture = happy_path_fixture();
    // Re-sign nothing, just move the totals the signatures commit to. The
    // homomorphic sum catches this too; the point here is that the signature
    // check catches it independently.
    fixture.tally.totals[0] += 1;

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert_eq!(signature_finding(&report).status, AuditStatus::Fail);
}

#[test]
fn duplicate_trustee_signature_is_caught() {
    let mut fixture = happy_path_fixture();
    fixture.tally.signatures[1] = fixture.tally.signatures[0].clone();

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    let finding = signature_finding(&report);
    assert_eq!(finding.status, AuditStatus::Fail);
    assert!(finding.detail.contains("duplicate"), "{finding:#?}");
}

#[test]
fn unknown_trustee_signature_is_caught() {
    let mut fixture = happy_path_fixture();
    fixture.tally.signatures[0].trustee_id = "not-a-trustee".into();

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    let finding = signature_finding(&report);
    assert_eq!(finding.status, AuditStatus::Fail);
    assert!(finding.detail.contains("unknown"), "{finding:#?}");
}

#[test]
fn below_threshold_tally_signatures_are_caught() {
    let mut fixture = happy_path_fixture();
    let threshold = fixture.parameters.threshold as usize;
    // Keep one fewer valid signature than the threshold demands.
    fixture.tally.signatures.truncate(threshold - 1);

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    let finding = signature_finding(&report);
    assert_eq!(finding.status, AuditStatus::Fail);
    assert!(finding.detail.contains("threshold"), "{finding:#?}");
}

#[test]
fn malformed_tally_signature_is_caught() {
    let mut fixture = happy_path_fixture();
    fixture.tally.signatures[0].signature.truncate(63);

    let report = audit(fixture.artifacts());
    assert_eq!(report.overall, AuditStatus::Fail);
    assert_eq!(signature_finding(&report).status, AuditStatus::Fail);
}

// ---------------------------------------------------------------------------
// Parallel ballot verification is byte-identical to the serial path
// ---------------------------------------------------------------------------

/// Batch size for the differential tests: a 7-voter x 3-position fixture (21
/// ballots) spans six batches `[0-3] [4-7] [8-11] [12-15] [16-19] [20]`, the
/// last one partial.
const TEST_CHUNK: usize = 4;

/// Everything one audit produces, rendered as JSON: the full report (every
/// finding, in order) and the per-contest evidence (aggregate ciphertext,
/// recovered point, decoded tally). Returns it with the report itself and the
/// `verify_threads` the audit recorded.
fn audit_on(
    f: &ElectionFixture,
    ballots: &[Result<Ballot, String>],
    threads: usize,
    chunk: usize,
) -> (String, AuditReport, usize) {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("thread pool");
    let (report, evidence, timings) = crate::audit_streaming_chunked(
        f.artifacts().inputs(),
        ballots.iter().cloned(),
        Some(&pool),
        chunk,
    );
    let evidence: Vec<_> = evidence
        .iter()
        .map(|e| {
            (
                e.contest_id.clone(),
                e.aggregate_ciphertext.compress().to_bytes(),
                e.recovered_point.map(|p| p.compress().to_bytes()),
                e.decoded,
            )
        })
        .collect();
    let json =
        serde_json::to_string(&serde_json::json!({ "report": report, "evidence": evidence }))
            .expect("audit output serializes");
    (json, report, timings.verify_threads)
}

/// The 1-thread audit is the reference; 8 threads — in the same small batches,
/// in one-ballot batches, in exactly one batch, and in production-size batches —
/// must reproduce it byte for byte. Returns the reference report for the
/// caller's own checks.
fn assert_parallel_matches_serial(
    f: &ElectionFixture,
    ballots: &[Result<Ballot, String>],
) -> AuditReport {
    let (serial, report, used) = audit_on(f, ballots, 1, TEST_CHUNK);
    assert_eq!(used, 1, "verify_threads reports the pool size");
    for chunk in [TEST_CHUNK, 1, ballots.len().max(1), crate::VERIFY_CHUNK] {
        let (parallel, _, used) = audit_on(f, ballots, 8, chunk);
        assert_eq!(used, 8, "verify_threads reports the pool size");
        assert_eq!(
            parallel, serial,
            "8 threads in batches of {chunk} diverged from the 1-thread audit"
        );
    }
    report
}

fn ok_ballots(f: &ElectionFixture) -> Vec<Result<Ballot, String>> {
    f.ballots.iter().cloned().map(Ok).collect()
}

/// Indices of the ballots a failing `check` names (`"ballot[<idx>] ..."`), in
/// report order, one entry per ballot.
fn failed_ballots(report: &AuditReport, check: &str) -> Vec<usize> {
    let mut idxs: Vec<usize> = report
        .findings
        .iter()
        .filter(|x| x.check == check && x.status == AuditStatus::Fail)
        .filter_map(|x| {
            x.detail
                .strip_prefix("ballot[")?
                .split(']')
                .next()?
                .parse()
                .ok()
        })
        .collect();
    idxs.dedup();
    idxs
}

fn seven_by_three() -> ElectionFixture {
    multi_position_fixture(&GenParams::simple(7, 3, 2, SelectionProfile::Uniform))
}

#[test]
fn parallel_verify_matches_serial_on_a_clean_election() {
    let f = seven_by_three();
    let report = assert_parallel_matches_serial(&f, &ok_ballots(&f));
    assert!(report.passed(), "{report:#?}");
}

#[test]
fn parallel_verify_matches_serial_on_an_empty_stream() {
    let report = assert_parallel_matches_serial(&seven_by_three(), &[]);
    assert!(
        report.finding("nullifier.unique").is_some(),
        "an empty stream still reports uniqueness: {report:#?}"
    );
}

#[test]
fn parallel_verify_matches_serial_on_bad_proofs_at_batch_edges() {
    let mut f = seven_by_three();
    // First of a batch, a middle, the last of a batch, and a pair straddling a
    // boundary (20 is also the lone ballot of the final, partial batch).
    let tampered = [4, 9, 15, 19, 20];
    for &i in &tampered {
        f.ballots[i].well_formedness_proofs[0].branches[0].response[0] ^= 0x01;
    }
    let report = assert_parallel_matches_serial(&f, &ok_ballots(&f));
    assert_eq!(report.overall, AuditStatus::Fail);
    assert_eq!(failed_ballots(&report, "ballot.cds_proof"), tampered);
}

#[test]
fn parallel_verify_matches_serial_on_a_duplicate_nullifier_across_batches() {
    let mut f = seven_by_three();
    // Ballot 1 sits in batch 0; its replay lands at index 21, in batch 5.
    let replay = f.ballots[1].clone();
    f.ballots.push(replay);
    let report = assert_parallel_matches_serial(&f, &ok_ballots(&f));
    let dup = report.finding("nullifier.unique").expect("uniqueness ran");
    assert_eq!(dup.status, AuditStatus::Fail);
    assert!(dup.detail.contains("ballots 1 and 21"), "{dup:#?}");
}

#[test]
fn parallel_verify_matches_serial_on_wrong_election_and_position_ballots() {
    let mut f = seven_by_three();
    // A ballot cast in a different election (different keys, issuer and id).
    let other = multi_position_fixture(&GenParams {
        election_id: "another-election".into(),
        ..GenParams::simple(1, 3, 2, SelectionProfile::Uniform)
    });
    f.ballots[6] = other.ballots[0].clone();
    // Ballot 10 is a vice-president record relabelled as a senator one; ballot
    // 13 names a position the election does not have.
    f.ballots[10].position_id = crate::fixtures::ph_position_id(2);
    f.ballots[13].position_id = "no-such-position".into();
    let mut ballots = ok_ballots(&f);
    // And one line the stream could not decode, mid-batch.
    ballots[17] = Err("ballot line 18 is not valid hex".into());

    let report = assert_parallel_matches_serial(&f, &ballots);
    assert_eq!(failed_ballots(&report, "ballot.cds_proof"), [6, 10]);
    assert_eq!(failed_ballots(&report, "ballot.credential"), [6, 10]);
    assert_eq!(failed_ballots(&report, "ballot.shape"), [13]);
    assert!(
        report
            .findings
            .iter()
            .any(|x| x.check == "ballot.decode" && x.detail.contains("line 18")),
        "{report:#?}"
    );
}
