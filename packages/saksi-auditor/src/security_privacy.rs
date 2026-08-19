//! Security (Phase 4) + privacy (Phase 5) suite for the thesis evaluation.
//!
//! One deterministic test per adversary class, **each paired with a positive
//! control** (the same operation minus the attack must still succeed — this
//! guards against a false-green where the test passes only because the attack
//! was malformed). Structural privacy asserts are stated as **structural**, not
//! an empirical unlinkability proof (metadata/timing/submitter-identity linkage
//! is out of scope, per the plan).
//!
//! ## Adversary-class → test traceability (Phase 4)
//!
//! | # | Class                        | Covered by |
//! |---|------------------------------|------------|
//! | 1 | Double-vote (per position)   | [`crate::tests::per_position_double_vote_is_caught`], [`crate::tests::reused_nullifier_is_caught`] |
//! | 2 | Malformed ballot / bad proof | [`crate::tests::tampered_ballot_cds_proof_is_caught`], [`crate::tests::tampered_credential_presentation_proof_is_caught`] |
//! | 3 | Sub-threshold trustees       | [`crate::tests::under_threshold_decryptions_are_caught`] (+ positive control below) |
//! | 4 | Malicious admin (params)     | [`crate::tests::bad_parameters_version_is_caught`], [`crate::tests::wrong_issuer_pk_is_caught`], [`crate::tests::dkg_transcript_trustee_count_mismatch_is_caught`] (+ control below) |
//! | 5 | Malicious BB node (drop/reorder) | [`malicious_bb_node_dropping_a_committed_ballot_is_detected`] + [`malicious_bb_node_reordering_ballots_is_detected_by_ledger_digest`] (this module) |
//! | 6 | Network replay               | [`crate::tests::reused_nullifier_is_caught`] (replay == duplicate nullifier) |
//!
//! The chaincode-side rejections for classes 1/2/6 (on-chain, at endorsement)
//! live in `saksi-bulletin/chaincode/contract_test.go`.
//!
//! ## Privacy checks (Phase 5, structural)
//!
//! - Unlinkability → [`on_chain_ballot_record_carries_no_voter_identity`]
//! - Ballot-secrecy → [`only_the_aggregate_is_decrypted_never_an_individual_ballot`]
//! - Threshold (folds into class 3 above).

use std::collections::HashSet;

use crate::fixtures::{multi_position_fixture, SelectionProfile};
use crate::{audit, AuditStatus};

// ---------------------------------------------------------------------------
// Phase 4 · class 5 — malicious bulletin-board node (drop)
// ---------------------------------------------------------------------------

#[test]
fn malicious_bb_node_dropping_a_committed_ballot_is_detected() {
    // Positive control: the full recorded set audits clean.
    let full = multi_position_fixture(4, 2, 2, SelectionProfile::Uniform);
    assert!(
        audit(full.artifacts()).passed(),
        "positive control: the untampered recorded set must audit clean"
    );

    // Attack: a malicious BB node drops one committed ballot from the published
    // set *after* the tally was computed over the full set. The recorded ballots
    // no longer sum to the published tally, so the auditor's homomorphic-sum
    // check catches it. (1-org framing: the auditor DETECTS tampering; it does
    // not prevent it — that would need live multi-peer BFT, out of thesis scope.)
    let mut tampered = multi_position_fixture(4, 2, 2, SelectionProfile::Uniform);
    tampered.ballots.remove(0); // voter 0's position-0 record
    let report = audit(tampered.artifacts());
    assert_eq!(
        report.overall,
        AuditStatus::Fail,
        "dropping a committed ballot must be detected"
    );
    assert!(
        matches!(
            report.finding("tally.homomorphic_sum").map(|f| &f.status),
            Some(AuditStatus::Fail)
        ),
        "the drop must surface as a tally mismatch, not pass silently"
    );
}

#[test]
fn malicious_bb_node_reordering_ballots_is_detected_by_ledger_digest() {
    // Reordering does NOT change the order-independent homomorphic tally, so the
    // tally check cannot catch it — the paper's "detected by hash verification"
    // path is the order-dependent ledger digest.
    let f = multi_position_fixture(4, 2, 2, SelectionProfile::Uniform);
    let recorded = crate::ledger::ledger_digest(&f.ballots);
    // Positive control: recomputing over the same committed order matches.
    assert_eq!(recorded, crate::ledger::ledger_digest(&f.ballots));

    // Attack: a malicious BB node serves the same ballots in a different order.
    let mut served = f.ballots.clone();
    served.reverse();
    assert_ne!(
        crate::ledger::ledger_digest(&served),
        recorded,
        "reordering must change the ledger digest (hash verification detects it)"
    );

    // And confirm the tally really is order-blind, so the digest is the ONLY
    // detector of a pure reorder: reverse a fresh fixture's ballots and audit.
    let mut reordered = multi_position_fixture(4, 2, 2, SelectionProfile::Uniform);
    reordered.ballots.reverse();
    assert!(
        audit(reordered.artifacts()).passed(),
        "a pure reorder leaves the homomorphic tally clean — only the ledger digest catches it"
    );
}

// ---------------------------------------------------------------------------
// Phase 4 · class 3 — sub-threshold trustees, explicit positive control
// ---------------------------------------------------------------------------

#[test]
fn sub_threshold_decryption_fails_but_full_threshold_succeeds() {
    // Positive control: threshold-many partial decryptions decrypt the tally.
    let full = multi_position_fixture(3, 1, 2, SelectionProfile::Uniform);
    assert!(
        audit(full.artifacts()).passed(),
        "positive control: full threshold must audit clean"
    );

    // Attack: keep fewer than `threshold` (3) partial decryptions per contest so
    // no contest can be recombined. Drop every partial from trustees "3".."5",
    // leaving 2 < threshold.
    let mut starved = multi_position_fixture(3, 1, 2, SelectionProfile::Uniform);
    starved
        .partial_decryptions
        .retain(|p| p.trustee_id == "1" || p.trustee_id == "2");
    starved.tally.partial_decryptions = starved.partial_decryptions.clone();
    let report = audit(starved.artifacts());
    assert_eq!(
        report.overall,
        AuditStatus::Fail,
        "fewer than threshold shares must not decrypt"
    );
    assert!(
        matches!(
            report.finding("decryption.threshold").map(|f| &f.status),
            Some(AuditStatus::Fail)
        ),
        "the shortfall must surface as a threshold failure"
    );
}

// ---------------------------------------------------------------------------
// Phase 4 · class 4 — malicious admin tampering election parameters
// ---------------------------------------------------------------------------

#[test]
fn malicious_admin_altering_a_contest_id_is_detected() {
    // Positive control: honest parameters audit clean.
    let honest = multi_position_fixture(3, 2, 2, SelectionProfile::Uniform);
    assert!(
        audit(honest.artifacts()).passed(),
        "positive control: honest parameters must audit clean"
    );

    // Attack: a malicious admin rewrites a contest id after the ballots were
    // proven against the original. The CDS proofs are bound to the original
    // contest id (binding_context), so the mutated parameters break verification.
    let mut tampered = multi_position_fixture(3, 2, 2, SelectionProfile::Uniform);
    tampered.parameters.contest_ids[0] = "pos0/tampered".to_owned();
    let report = audit(tampered.artifacts());
    assert_eq!(
        report.overall,
        AuditStatus::Fail,
        "rewriting a contest id must be detected"
    );
}

// ---------------------------------------------------------------------------
// Phase 5 · unlinkability (structural)
// ---------------------------------------------------------------------------

#[test]
fn on_chain_ballot_record_carries_no_voter_identity() {
    // Structural unlinkability: a published ballot exposes only anonymous
    // cryptographic material — an ElGamal ciphertext set, a per-position
    // nullifier (a PRF output), a credential commitment (a curve point), and
    // public labels (election_id, position_id). NONE is a voter-roster index or
    // real-world identifier, so on-chain data alone cannot map a ballot to a
    // voter.
    //
    // Acknowledged + out of scope: two ballots from the SAME credential share
    // the commitment, so they are linkable to each other — but not to an
    // identity, and different voters never share a commitment.
    let f = multi_position_fixture(3, 1, 2, SelectionProfile::Uniform);

    let commitments: HashSet<Vec<u8>> = f
        .ballots
        .iter()
        .map(|b| b.voter_credential_commitment.clone())
        .collect();
    assert_eq!(
        commitments.len(),
        3,
        "each voter's on-chain commitment is distinct + anonymous (no identity reuse)"
    );

    for b in &f.ballots {
        // The only voter-derived bytes are a 32-byte curve point and a 32-byte
        // PRF output — neither is a decodable identity.
        assert_eq!(
            b.voter_credential_commitment.len(),
            32,
            "commitment is a 32-byte point, not an id string"
        );
        let nullifier = b
            .credential_presentation
            .as_ref()
            .and_then(|p| p.nullifier.as_ref())
            .expect("ballot carries a nullifier");
        assert_eq!(
            nullifier.value.len(),
            32,
            "nullifier is a 32-byte PRF output, not an id"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 5 · ballot-secrecy (structural)
// ---------------------------------------------------------------------------

#[test]
fn only_the_aggregate_is_decrypted_never_an_individual_ballot() {
    // Ballot-secrecy: the tally reveals ONLY per-contest aggregates. Build an
    // election where voters split their choices and audit it; the published
    // result is contest-granular (the homomorphic aggregate), never a per-ballot
    // plaintext. There is no code path that decrypts a single ciphertext — the
    // Lagrange-combine in `tally.rs` operates on the summed aggregate pad only.
    let f = multi_position_fixture(5, 1, 2, SelectionProfile::Uniform);
    assert!(audit(f.artifacts()).passed());

    // The tally has one total per contest (aggregate granularity), strictly
    // coarser than one-per-ballot when voters > 1.
    assert_eq!(
        f.tally.totals.len(),
        f.parameters.contest_ids.len(),
        "tally is per-contest aggregate, not per-ballot"
    );
    assert!(
        f.tally.totals.len() < f.ballots.len(),
        "aggregate ({} totals) is coarser than the ballot set ({} ballots)",
        f.tally.totals.len(),
        f.ballots.len()
    );
    // The aggregate sums to one selection per voter — an aggregate count, from
    // which no individual voter's choice is recoverable.
    let total: u64 = f.tally.totals.iter().sum();
    assert_eq!(total, 5, "aggregate = one selection per voter, summed");
}

// ---------------------------------------------------------------------------
// Phase 5 · unlinkability as a linkage-ATTEMPT experiment (matrix M16, panel #17)
// ---------------------------------------------------------------------------

#[test]
fn privacy_linkage_attempt_fails_over_the_anonymity_set() {
    // Adversary model (Pfitzmann-Hansen): the adversary holds the FULL on-chain
    // record (all ballots: ciphertexts, nullifiers, credential commitments,
    // public labels) AND the synthetic voter-registration list. Successful
    // linkage = identifying a targeted voter's ballot better than random over the
    // anonymity set. The experiment RUNS the linkage attempt and shows it fails:
    // no on-chain field joins to a registration identifier, so the best the
    // adversary can do is guess, bounded by 1 / (anonymity-set size).
    let voters = 5usize;
    let f = multi_position_fixture(voters, 1, 2, SelectionProfile::Uniform);

    // The registration list (off-chain, synthetic) — the identifiers the
    // adversary tries to attach to on-chain ballots.
    let registration: Vec<&str> = f.voter_ids.iter().map(String::as_str).collect();

    // Attempt linkage: for every ballot, gather ALL bytes the adversary sees
    // on-chain and test whether any registration identifier appears in them.
    let mut linkage_hits = 0usize;
    for ballot in &f.ballots {
        let mut on_chain: Vec<u8> = Vec::new();
        on_chain.extend_from_slice(ballot.election_id.as_bytes());
        on_chain.extend_from_slice(ballot.position_id.as_bytes());
        on_chain.extend_from_slice(&ballot.voter_credential_commitment);
        if let Some(p) = &ballot.credential_presentation {
            if let Some(n) = &p.nullifier {
                on_chain.extend_from_slice(&n.value);
            }
            on_chain.extend_from_slice(&p.credential_commitment);
        }
        for ct in &ballot.ciphertexts {
            on_chain.extend_from_slice(&ct.pad);
            on_chain.extend_from_slice(&ct.data);
        }
        // A "hit" is any registration id whose bytes appear on-chain.
        for id in &registration {
            if on_chain.windows(id.len()).any(|w| w == id.as_bytes()) {
                linkage_hits += 1;
            }
        }
    }
    assert_eq!(
        linkage_hits, 0,
        "no on-chain field may join to a registration identifier"
    );

    // Anonymity set: within a single position, the V ballots carry V DISTINCT
    // credential commitments (no voter reuses another's), so a targeted voter is
    // hidden among all V. The adversary's link probability is therefore bounded
    // by 1/V — the unlinkability hypothesis (structural, no timing/metadata).
    let commitments: std::collections::HashSet<Vec<u8>> = f
        .ballots
        .iter()
        .map(|b| b.voter_credential_commitment.clone())
        .collect();
    assert_eq!(
        commitments.len(),
        voters,
        "anonymity set = {voters}; link probability bounded by 1/{voters}"
    );
    // Acknowledged limit (out of scope): two ballots of the SAME credential share
    // the commitment, so they are linkable to each other — never to an identity.
}
