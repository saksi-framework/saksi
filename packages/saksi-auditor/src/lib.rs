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
//! - Verifies every trustee's Schnorr signature over the published tally
//!   (`tally.signatures`) under a verification key derived from the DKG
//!   transcript alone, and requires at least `threshold` valid ones.
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
pub mod ledger;
pub mod report;
mod tally;

#[cfg(any(test, feature = "demo"))]
pub(crate) mod fixtures;

#[cfg(feature = "demo")]
pub mod demo;

#[cfg(feature = "demo")]
pub mod ground_truth;

#[cfg(feature = "demo")]
pub mod stream;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};

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
    /// Optional seeded ground-truth totals (one per contest, aligned to
    /// `parameters.contest_ids`). When present, the tally check adds the
    /// **accuracy** assertion `E = 0`: the value recovered by real threshold
    /// decryption equals the independently-seeded ground truth (not merely the
    /// published tally). `None` for a real on-chain election with no seeded
    /// truth (e.g. the fabric-adapter read path).
    pub ground_truth: Option<&'a [u64]>,
}

/// How long the auditor spent in each of its four measured stages.
///
/// Measured with [`Instant`] at the stage boundaries of a single audit run:
/// `verify_ballots` (per-ballot CDS + credential verification), `aggregate`
/// (folding eligible ciphertexts into the per-contest homomorphic sum),
/// `combine` (Lagrange-at-zero over the threshold partial decryptions), and
/// `decode` (recovering the integer tally from the plaintext point). The four
/// are disjoint spans of one thread, so their sum is at most the audit's wall
/// time — the rest is DKG, partial-decryption proofs, and reporting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timings {
    /// Per-ballot CDS OR-proof + credential-presentation verification.
    pub verify_ballots: Duration,
    /// Folding eligible ballots into the per-contest aggregate ciphertext.
    pub aggregate: Duration,
    /// Lagrange recombination of the threshold partial decryptions.
    pub combine: Duration,
    /// Discrete-log recovery of the integer tally from the plaintext point.
    pub decode: Duration,
}

/// Everything the auditor needs **except** the ballots: the small, resident part
/// of [`ElectionArtifacts`] that stays in memory while ballots stream past one
/// at a time.
pub(crate) struct AuditInputs<'a> {
    pub(crate) parameters: &'a ElectionParameters,
    pub(crate) dkg_transcript: &'a DKGTranscript,
    pub(crate) partial_decryptions: &'a [PartialDecryption],
    pub(crate) tally: &'a TallyResult,
    pub(crate) binding_context: &'a [u8],
    pub(crate) issuer_public_key: &'a IssuerPublicKey,
    pub(crate) ground_truth: Option<&'a [u64]>,
    /// How many ballots the producer says the stream holds (`header.n`), when
    /// the caller knows. A stream that ends early — a line over the read cap, a
    /// truncated file — otherwise looks exactly like a smaller election, so the
    /// mismatch is reported as a Fatal `stream.completeness` finding. `None` for
    /// an in-memory `&[Ballot]`, where the count is the slice length by
    /// definition.
    pub(crate) expected_ballots: Option<usize>,
}

impl<'a> ElectionArtifacts<'a> {
    /// Borrow everything but the ballots (see [`AuditInputs`]).
    fn inputs(&self) -> AuditInputs<'a> {
        AuditInputs {
            parameters: self.parameters,
            dkg_transcript: self.dkg_transcript,
            partial_decryptions: self.partial_decryptions,
            tally: self.tally,
            binding_context: self.binding_context,
            issuer_public_key: self.issuer_public_key,
            ground_truth: self.ground_truth,
            expected_ballots: None,
        }
    }
}

/// Runs every audit check against `artifacts` and returns a structured
/// [`AuditReport`].
///
/// The function never panics on adversarial input — every decoding or
/// soundness failure is converted into a Fatal finding with status `Fail`.
/// Audit an election and return only the pass/fail report.
pub fn audit(artifacts: ElectionArtifacts) -> AuditReport {
    audit_with_evidence(artifacts).0
}

/// Audit an in-memory `&[Ballot]` election: the thin wrapper over
/// [`audit_streaming`] for callers that already hold every ballot (the one-blob
/// bundle path and the auditor's own tests). Ballots are cloned one at a time
/// into the streaming core and dropped after each is verified.
pub(crate) fn audit_with_evidence(
    artifacts: ElectionArtifacts,
) -> (AuditReport, Vec<crate::tally::ContestEvidence>, Timings) {
    let ballots = artifacts.ballots.iter().cloned().map(Ok);
    audit_streaming(artifacts.inputs(), ballots)
}

/// Audit an election whose ballots arrive as a stream.
///
/// Nothing per-ballot is retained: each item is verified, folded into the
/// running per-contest aggregate ciphertext and the nullifier set, and dropped.
/// Peak memory is therefore the nullifier set plus a constant, not the
/// population — which is what makes the capstone tiers auditable at all.
///
/// A ballot the stream could not produce (`Err`) is recorded as a Fatal
/// `ballot.decode` finding and iteration continues; the report never
/// short-circuits.
pub(crate) fn audit_streaming(
    inputs: AuditInputs<'_>,
    ballots: impl Iterator<Item = Result<Ballot, String>>,
) -> (AuditReport, Vec<crate::tally::ContestEvidence>, Timings) {
    let mut builder = ReportBuilder::new();
    let mut timings = Timings::default();

    // -- 1. Election parameters shape --------------------------------------

    let params_ok = check_parameters(inputs.parameters, &mut builder);
    if !params_ok {
        return (builder.finish(), Vec::new(), timings);
    }

    // -- 2-4. DKG transcript ----------------------------------------------

    let dkg_verification =
        crate::dkg::verify_dkg_transcript(inputs.parameters, inputs.dkg_transcript, &mut builder);

    // If the DKG transcript could not be rebuilt we cannot meaningfully
    // verify ballots / partial decryptions. Still run nullifier-uniqueness
    // because it doesn't depend on the DKG, then finish.
    let Some(dkg_v) = dkg_verification else {
        let mut nullifiers = NullifierTracker::default();
        for (idx, item) in ballots.enumerate() {
            match item {
                Ok(ballot) => nullifiers.observe(idx, &ballot),
                Err(err) => builder.fail("ballot.decode", err),
            }
        }
        nullifiers.report(&mut builder);
        return (builder.finish(), Vec::new(), timings);
    };

    let election_public_key = elgamal::PublicKey::from_point(dkg_v.joint_public_key);

    // -- 5/6. Per-ballot checks + running aggregate + nullifier uniqueness --

    let contest_count = inputs.parameters.contest_ids.len();
    let mut aggregate_pads = vec![RistrettoPoint::identity(); contest_count];
    let mut aggregate_data = vec![RistrettoPoint::identity(); contest_count];
    let mut nullifiers = NullifierTracker::default();
    let mut passes = crate::ballot::BallotPassCounts::default();
    let mut eligible_count = 0usize;
    let mut observed = 0usize;

    for (idx, item) in ballots.enumerate() {
        observed += 1;
        let ballot = match item {
            Ok(b) => b,
            Err(err) => {
                builder.fail("ballot.decode", err);
                continue;
            }
        };

        let started = Instant::now();
        let decoded = crate::ballot::verify_ballot(
            idx,
            &ballot,
            inputs.parameters,
            &election_public_key,
            inputs.issuer_public_key,
            inputs.binding_context,
            &mut passes,
            &mut builder,
        );
        timings.verify_ballots += started.elapsed();

        nullifiers.observe(idx, &ballot);

        if let Some(decoded) = decoded {
            let started = Instant::now();
            for ct in &decoded {
                aggregate_pads[ct.contest] += ct.pad;
                aggregate_data[ct.contest] += ct.data;
            }
            timings.aggregate += started.elapsed();
            eligible_count += 1;
        }
        // `ballot` drops here.
    }

    // A stream that stopped early (a line over the read cap, a truncated file)
    // must not read as a smaller, clean election.
    if let Some(expected) = inputs.expected_ballots {
        if observed != expected {
            builder.fail(
                "stream.completeness",
                format!(
                    "audited {observed} of the {expected} ballot lines the header declares ({} not audited)",
                    expected.saturating_sub(observed)
                ),
            );
        }
    }

    passes.report(&mut builder);
    nullifiers.report(&mut builder);

    // -- 7. Per-trustee partial decryptions -------------------------------

    let decryption = crate::decryption::verify_partial_decryptions(
        inputs.parameters,
        &aggregate_pads,
        aggregate_data,
        inputs.partial_decryptions,
        &dkg_v.trustee_share_publics,
        inputs.binding_context,
        &mut builder,
    );

    // -- 8. Homomorphic-sum tally -----------------------------------------

    let evidence = crate::tally::verify_tally(
        inputs.parameters,
        inputs.tally,
        &decryption,
        eligible_count,
        inputs.ground_truth,
        &mut timings,
        &mut builder,
    );

    // -- 9. Trustee signatures over the published tally --------------------

    crate::tally::verify_tally_signatures(
        inputs.parameters,
        inputs.tally,
        &dkg_v.trustee_share_publics,
        &mut builder,
    );

    (builder.finish(), evidence, timings)
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

/// Incremental cross-ballot nullifier uniqueness (the double-vote check).
///
/// Retains one 32-byte key per ballot and the index that first used it —
/// nothing else about the ballot survives — so the check runs over a streamed
/// population without holding it.
#[derive(Default)]
struct NullifierTracker {
    /// Raw nullifier bytes -> first ballot index that used them.
    seen: HashMap<[u8; 32], usize>,
    /// `(first, repeat)` ballot index pairs.
    collisions: Vec<(usize, usize)>,
    /// Ballots observed, whether or not they carried a nullifier.
    total: usize,
}

impl NullifierTracker {
    fn observe(&mut self, idx: usize, ballot: &Ballot) {
        self.total += 1;
        let Some(nullifier) = ballot
            .credential_presentation
            .as_ref()
            .and_then(|p| p.nullifier.as_ref())
        else {
            return;
        };
        // A nullifier is a compressed ristretto point. A value of any other
        // length cannot verify as a credential presentation, so such a ballot is
        // never eligible for the tally and is not a double-vote vector; skip it
        // rather than widen the key.
        let Ok(key) = <[u8; 32]>::try_from(nullifier.value.as_slice()) else {
            return;
        };
        match self.seen.get(&key) {
            None => {
                self.seen.insert(key, idx);
            }
            Some(&first) => self.collisions.push((first, idx)),
        }
    }

    fn report(&self, builder: &mut ReportBuilder) {
        if self.collisions.is_empty() {
            builder.pass(
                "nullifier.unique",
                format!("all {} nullifiers are pairwise distinct", self.total),
            );
        } else {
            let detail = self
                .collisions
                .iter()
                .map(|(a, b)| format!("ballots {a} and {b}"))
                .collect::<Vec<_>>()
                .join("; ");
            builder.fail(
                "nullifier.unique",
                format!("duplicate nullifier(s) detected: {detail}"),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;

#[cfg(test)]
mod security_privacy;

#[cfg(test)]
mod independent_verification;
