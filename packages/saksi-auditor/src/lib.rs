//! # saksi-auditor
//!
//! Off-chain auditor for a Saksi election. Takes the public bulletin-board
//! artifacts (election parameters, DKG transcript, ballots, partial
//! decryptions, tally) and emits an [`AuditReport`] cryptographically
//! confirming that the pipeline produced a sound, tamper-evident tally.
//!
//! The auditor:
//!
//! - Verifies the DKG transcript shape and reconstructs the joint election
//!   public key `Y = Σ_d A_{d,0}` plus the per-trustee aggregated share
//!   publics `pub_k = Σ_d eval(A_d, k+1)` used to verify partial-decryption
//!   Chaum-Pedersen proofs.
//! - Verifies every ballot's CDS OR-proof against `choice_set = {0, 1}`
//!   (v1 binary contests only) and the credential presentation under the
//!   election issuer public key.
//! - Enforces nullifier uniqueness across all ballots (the double-vote
//!   check).
//! - Verifies the Chaum-Pedersen proof on each partial decryption against
//!   the aggregate ElGamal pad for its contest and the corresponding
//!   trustee's public share.
//! - Confirms that, per contest, at least `parameters.threshold` distinct
//!   trustees submitted a valid partial decryption.
//! - Recombines the threshold-many partials via Lagrange-at-zero, decodes
//!   the plaintext point with a brute-force discrete log in
//!   `[0, eligible_ballot_count]`, and asserts equality with the published
//!   `tally.totals[c]`.
//!
//! The report collects **every** check, never short-circuits, and flips to
//! `AuditStatus::Fail` if any `Severity::Fatal` finding has `status == Fail`.
//!
//! ## Public input shape
//!
//! The auditor's public input is just an [`ElectionArtifacts`] struct of
//! borrows. The producer of this struct is the bulletin-board client SDK
//! (Phase D); for now the auditor consumes the wire types directly.
//!
//! ## v1 assumptions
//!
//! - Binary contests only (`choice_set = {0, 1}`).
//! - One issuer per election; passed at the artifacts boundary so the
//!   auditor does not need a trust store.
//! - Canonical partial-decryption layout: `contest_count * trustee_count`
//!   entries, with `partial_decryptions[c * trustee_count + t]` being the
//!   trustee at `parameters.trustee_ids[t]` decrypting contest `c`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod ballot;
mod decryption;
mod dkg;
pub mod report;
mod tally;

#[cfg(any(test, feature = "demo"))]
pub(crate) mod fixtures;

#[cfg(feature = "demo")]
pub mod demo;

use std::collections::HashMap;

use saksi_credentials::IssuerPublicKey;
use saksi_crypto::elgamal;
use saksi_protocol::{
    Ballot, DKGTranscript, ElectionParameters, PartialDecryption, TallyResult, WIRE_VERSION,
};

pub use crate::report::{AuditFinding, AuditReport, AuditStatus, Severity};

use crate::report::ReportBuilder;

/// All on-chain state the auditor needs to verify an election.
///
/// The producer of this struct is the bulletin-board client SDK (Phase D).
/// For now the auditor's public input is just a Rust struct — Phase D will
/// later produce it by reading the chain.
pub struct ElectionArtifacts<'a> {
    /// Election parameters: `election_id`, contest ids, trustee ids, threshold.
    pub parameters: &'a ElectionParameters,
    /// The DKG transcript published at setup.
    pub dkg_transcript: &'a DKGTranscript,
    /// Every published ballot.
    pub ballots: &'a [Ballot],
    /// Every published partial decryption (see module docs for the layout).
    pub partial_decryptions: &'a [PartialDecryption],
    /// The published tally totals + (unused here, but on the wire) the
    /// trustees' partial decryptions.
    pub tally: &'a TallyResult,
    /// Bytes the auditor binds into every per-ballot NIZK transcript
    /// (`"contest_id || ballot_serial || ..."`). In the demo this is
    /// `b"saksi-auditor-v1"`; Phase D will wire it to the election parameters.
    pub binding_context: &'a [u8],
    /// The single per-election issuer public key. v1 assumes one issuer per
    /// election; pass it here so the auditor does not need a trust store.
    pub issuer_public_key: &'a IssuerPublicKey,
}

/// Runs every audit check against `artifacts` and returns a structured
/// [`AuditReport`].
///
/// The function never panics on adversarial input — every decoding or
/// soundness failure is converted into a Fatal finding with status `Fail`.
pub fn audit(artifacts: ElectionArtifacts) -> AuditReport {
    let mut builder = ReportBuilder::new();

    // -- 1. Election parameters shape --------------------------------------

    let params_ok = check_parameters(artifacts.parameters, &mut builder);
    if !params_ok {
        return builder.finish();
    }

    // -- 2-4. DKG transcript ----------------------------------------------

    let dkg_verification = crate::dkg::verify_dkg_transcript(
        artifacts.parameters,
        artifacts.dkg_transcript,
        &mut builder,
    );

    // If the DKG transcript could not be rebuilt we cannot meaningfully
    // verify ballots / partial decryptions. Still run nullifier-uniqueness
    // because it doesn't depend on the DKG, then finish.
    let Some(dkg_v) = dkg_verification else {
        check_nullifier_uniqueness(artifacts.ballots, &mut builder);
        return builder.finish();
    };

    let election_public_key = elgamal::PublicKey::from_point(dkg_v.joint_public_key);

    // -- 5. Per-ballot checks ---------------------------------------------

    let eligible = crate::ballot::verify_ballots(
        artifacts.parameters,
        artifacts.ballots,
        &election_public_key,
        artifacts.issuer_public_key,
        artifacts.binding_context,
        &mut builder,
    );

    // -- 6. Nullifier uniqueness ------------------------------------------

    check_nullifier_uniqueness(artifacts.ballots, &mut builder);

    // -- 7. Per-trustee partial decryptions -------------------------------

    let decryption = crate::decryption::verify_partial_decryptions(
        artifacts.parameters,
        &eligible,
        artifacts.partial_decryptions,
        &dkg_v.trustee_share_publics,
        artifacts.binding_context,
        &mut builder,
    );

    // -- 8. Homomorphic-sum tally -----------------------------------------

    if let Some(decryption) = decryption {
        crate::tally::verify_tally(
            artifacts.parameters,
            artifacts.tally,
            &decryption,
            eligible.len(),
            &mut builder,
        );
    }

    builder.finish()
}

/// Global indices (into `contest_ids`) of the contests a ballot in `position_id`
/// covers (ADR-0007 one-record-per-position model). Contests are
/// position-qualified as `"<position_id>/<candidate_idx>"`, so a ballot carries
/// exactly the ciphertexts/proofs for its position's candidates, aligned in
/// order to the returned indices.
///
/// An **empty `position_id`** is the legacy single-position path: the ballot
/// covers *all* contests (the pre-R2 whole-ballot model). The single source of
/// truth for this mapping — the chaincode mirrors it in Go (`contract.go`),
/// and both the auditor's CDS check and its tally aggregation call it, so the
/// prover, verifier, and on-chain gate agree by construction.
pub(crate) fn contest_indices_for_position(
    contest_ids: &[String],
    position_id: &str,
) -> Vec<usize> {
    if position_id.is_empty() {
        return (0..contest_ids.len()).collect();
    }
    let prefix = format!("{position_id}/");
    contest_ids
        .iter()
        .enumerate()
        .filter(|(_, c)| c.starts_with(&prefix))
        .map(|(i, _)| i)
        .collect()
}

/// Shape checks on `parameters`. Returns `false` if any shape check fails
/// in a way that makes downstream verification meaningless.
fn check_parameters(parameters: &ElectionParameters, builder: &mut ReportBuilder) -> bool {
    let mut ok = true;
    if parameters.version != WIRE_VERSION {
        builder.fail(
            "parameters.shape",
            format!(
                "parameters version {} != supported {}",
                parameters.version, WIRE_VERSION
            ),
        );
        ok = false;
    }
    if parameters.contest_ids.is_empty() {
        builder.fail("parameters.shape", "parameters.contest_ids is empty");
        ok = false;
    }
    if parameters.trustee_ids.is_empty() {
        builder.fail("parameters.shape", "parameters.trustee_ids is empty");
        ok = false;
    }
    if parameters.threshold == 0 {
        builder.fail("parameters.shape", "parameters.threshold is zero");
        ok = false;
    }
    if !parameters.trustee_ids.is_empty()
        && (parameters.threshold as usize) > parameters.trustee_ids.len()
    {
        builder.fail(
            "parameters.shape",
            format!(
                "parameters.threshold {} exceeds trustee count {}",
                parameters.threshold,
                parameters.trustee_ids.len()
            ),
        );
        ok = false;
    }
    if ok {
        builder.pass(
            "parameters.shape",
            "election parameters shape is consistent",
        );
    }
    ok
}

/// Cross-ballot nullifier uniqueness. Collects every
/// `ballot.credential_presentation.nullifier.value` and reports the first
/// collision (if any) as a single Fatal finding listing the colliding indices.
fn check_nullifier_uniqueness(ballots: &[Ballot], builder: &mut ReportBuilder) {
    // Map raw nullifier bytes -> first ballot index that used them.
    let mut seen: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut collisions: Vec<(usize, usize, Vec<u8>)> = Vec::new();

    for (idx, ballot) in ballots.iter().enumerate() {
        let Some(presentation) = ballot.credential_presentation.as_ref() else {
            continue;
        };
        let Some(nullifier) = presentation.nullifier.as_ref() else {
            continue;
        };
        let value = nullifier.value.clone();
        match seen.get(&value) {
            None => {
                seen.insert(value, idx);
            }
            Some(&first) => {
                collisions.push((first, idx, value));
            }
        }
    }

    if collisions.is_empty() {
        builder.pass(
            "nullifier.unique",
            format!("all {} nullifiers are pairwise distinct", ballots.len()),
        );
    } else {
        let detail = collisions
            .iter()
            .map(|(a, b, _)| format!("ballots {a} and {b}"))
            .collect::<Vec<_>>()
            .join("; ");
        builder.fail(
            "nullifier.unique",
            format!("duplicate nullifier(s) detected: {detail}"),
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;

#[cfg(test)]
mod security_privacy;
