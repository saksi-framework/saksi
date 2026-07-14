//! Demo election generator + bundle (de)serialization (`demo` feature).
//!
//! Builds the same happy-path election the auditor's own tests use and
//! serializes its wire artifacts into a flat JSON **bundle** of hex strings, so
//! an external driver (the Go `saksi-console`) can submit them to a live
//! bulletin board and the auditor can re-verify the published set.
//!
//! Bundle layout:
//!
//! ```json
//! {
//!   "election_id": "election-2026",
//!   "params": "<hex ElectionParameters>",
//!   "dkg": "<hex DKGTranscript>",
//!   "issuer_pk": "<hex compressed ristretto point>",
//!   "binding_context": "<hex>",
//!   "ballots": ["<hex Ballot>", ...],
//!   "partial_decryptions": ["<hex PartialDecryption>", ...],
//!   "tally": "<hex TallyResult>"
//! }
//! ```

use prost::Message;

use saksi_credentials::IssuerPublicKey;
use saksi_crypto::group::{compress_point, point_from_compressed};
use saksi_protocol::{Ballot, DKGTranscript, ElectionParameters, PartialDecryption, TallyResult};

use crate::fixtures::{happy_path_fixture, multi_position_fixture, ElectionFixture};
use crate::{audit, AuditReport, ElectionArtifacts};

/// Serializes a built [`ElectionFixture`] into the pretty-printed JSON bundle of
/// hex-encoded wire messages (the shape the Go `saksi-console` submits). Also
/// carries the seeded `ground_truth` totals so the accuracy harness (Phase 3)
/// can score the decrypted tally without re-deriving them.
fn fixture_to_bundle_json(f: &ElectionFixture, positions: usize, candidates: usize) -> String {
    let art = f.artifacts();
    let ballots: Vec<String> = art
        .ballots
        .iter()
        .map(|b| hex::encode(b.encode_to_vec()))
        .collect();
    let partials: Vec<String> = art
        .partial_decryptions
        .iter()
        .map(|p| hex::encode(p.encode_to_vec()))
        .collect();

    let value = serde_json::json!({
        "election_id": art.parameters.election_id,
        "params": hex::encode(art.parameters.encode_to_vec()),
        "dkg": hex::encode(art.dkg_transcript.encode_to_vec()),
        "issuer_pk": hex::encode(compress_point(art.issuer_public_key.as_point())),
        "binding_context": hex::encode(art.binding_context),
        "ballots": ballots,
        "partial_decryptions": partials,
        "tally": hex::encode(art.tally.encode_to_vec()),
        "ground_truth": f.ground_truth,
        // Ballot-axis labels for the benchmark harness's Appendix-C CSV row.
        "positions": positions,
        "candidates": candidates,
    });
    serde_json::to_string_pretty(&value).expect("bundle serializes")
}

/// Builds the canonical happy-path election (5 trustees / threshold 3, 2
/// contests, 6 voters, legacy whole-ballot model) and returns it as a JSON
/// bundle.
pub fn election_bundle_json() -> String {
    // Legacy whole-ballot fixture: one "position" covering all contests.
    let f = happy_path_fixture();
    let candidates = f.parameters.contest_ids.len();
    fixture_to_bundle_json(&f, 1, candidates)
}

/// Builds a parameterized multi-position election (`voters` × `positions` ×
/// `candidates`, one ballot record per (voter, position); ADR-0007) and returns
/// it as a JSON bundle — **after** the fail-closed validation gate. A population
/// that fails the gate returns `Err` and never reaches the network.
pub fn election_bundle_json_params(
    voters: usize,
    positions: usize,
    candidates: usize,
) -> Result<String, String> {
    let f = multi_position_fixture(voters, positions, candidates);
    validate_population(&f, voters, positions, candidates)?;
    Ok(fixture_to_bundle_json(&f, positions, candidates))
}

/// Fail-closed validation gate (Phase 1): structural invariants that must hold
/// before a generated population is allowed onto the network. Returns `Err` with
/// the first violation found. Catches generator bugs that would otherwise read
/// as clean throughput/accuracy numbers downstream.
///
/// Checks: (1) exactly `voters × positions` ballots, `voters` per position;
/// (2) all nullifiers pairwise distinct; (3) every ballot carries exactly
/// `candidates` ciphertexts/proofs (selection in-range for its position); and
/// (4) per-position ground-truth aggregate == the ballot count for that position
/// (one selection per voter per position).
fn validate_population(
    f: &ElectionFixture,
    voters: usize,
    positions: usize,
    candidates: usize,
) -> Result<(), String> {
    use std::collections::HashSet;

    let expected_ballots = voters * positions;
    if f.ballots.len() != expected_ballots {
        return Err(format!(
            "ballot count {} != voters*positions {expected_ballots}",
            f.ballots.len()
        ));
    }
    if f.ground_truth.len() != positions * candidates {
        return Err(format!(
            "ground_truth len {} != positions*candidates {}",
            f.ground_truth.len(),
            positions * candidates
        ));
    }

    let mut nullifiers: HashSet<Vec<u8>> = HashSet::with_capacity(f.ballots.len());
    let mut per_position_ballots = vec![0usize; positions];
    // Voter-uniqueness per position: a credential commitment must not appear
    // twice within the same position.
    let mut per_position_voters: Vec<HashSet<Vec<u8>>> = vec![HashSet::new(); positions];

    for (i, ballot) in f.ballots.iter().enumerate() {
        if ballot.ciphertexts.len() != candidates
            || ballot.well_formedness_proofs.len() != candidates
        {
            return Err(format!(
                "ballot {i} has {} ciphertexts / {} proofs, expected {candidates} (one per candidate)",
                ballot.ciphertexts.len(),
                ballot.well_formedness_proofs.len()
            ));
        }
        let position = ballot
            .position_id
            .strip_prefix("pos")
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| {
                format!(
                    "ballot {i} has malformed position_id {:?}",
                    ballot.position_id
                )
            })?;
        if position >= positions {
            return Err(format!(
                "ballot {i} position {position} out of range 0..{positions}"
            ));
        }
        per_position_ballots[position] += 1;

        let presentation = ballot
            .credential_presentation
            .as_ref()
            .ok_or_else(|| format!("ballot {i} missing credential presentation"))?;
        let nullifier = presentation
            .nullifier
            .as_ref()
            .ok_or_else(|| format!("ballot {i} missing nullifier"))?
            .value
            .clone();
        if !nullifiers.insert(nullifier) {
            return Err(format!(
                "ballot {i} replays an already-seen nullifier (double vote)"
            ));
        }
        if !per_position_voters[position].insert(ballot.voter_credential_commitment.clone()) {
            return Err(format!(
                "ballot {i} repeats a voter credential within position {position}"
            ));
        }
    }

    for (p, &count) in per_position_ballots.iter().enumerate() {
        if count != voters {
            return Err(format!(
                "position {p} has {count} ballots, expected {voters}"
            ));
        }
        let selected: u64 = f.ground_truth[p * candidates..(p + 1) * candidates]
            .iter()
            .sum();
        if selected != voters as u64 {
            return Err(format!(
                "position {p} ground-truth aggregate {selected} != ballot count {voters} (each voter must select exactly one candidate)"
            ));
        }
    }

    Ok(())
}

/// Parses a bundle produced by [`election_bundle_json`] (or read back from the
/// chain in the same shape) and runs the full audit over it.
pub fn audit_bundle_json(bundle: &str) -> Result<AuditReport, String> {
    let v: serde_json::Value =
        serde_json::from_str(bundle).map_err(|e| format!("parse bundle: {e}"))?;

    let field_bytes = |key: &str| -> Result<Vec<u8>, String> {
        let h = v[key]
            .as_str()
            .ok_or_else(|| format!("bundle missing string field {key:?}"))?;
        hex::decode(h).map_err(|e| format!("field {key:?} is not valid hex: {e}"))
    };
    let array_bytes = |key: &str| -> Result<Vec<Vec<u8>>, String> {
        v[key]
            .as_array()
            .ok_or_else(|| format!("bundle field {key:?} is not an array"))?
            .iter()
            .map(|item| {
                let h = item
                    .as_str()
                    .ok_or_else(|| format!("a {key:?} entry is not a string"))?;
                hex::decode(h).map_err(|e| format!("a {key:?} entry is not valid hex: {e}"))
            })
            .collect()
    };

    let parameters = ElectionParameters::decode(&field_bytes("params")?[..])
        .map_err(|e| format!("decode params: {e}"))?;
    let dkg_transcript =
        DKGTranscript::decode(&field_bytes("dkg")?[..]).map_err(|e| format!("decode dkg: {e}"))?;
    let tally = TallyResult::decode(&field_bytes("tally")?[..])
        .map_err(|e| format!("decode tally: {e}"))?;

    let issuer_pk_bytes: [u8; 32] = field_bytes("issuer_pk")?
        .try_into()
        .map_err(|_| "issuer_pk is not 32 bytes".to_string())?;
    let issuer_point = point_from_compressed(issuer_pk_bytes)
        .map_err(|_| "issuer_pk is not a valid point".to_string())?;
    let issuer_public_key = IssuerPublicKey(issuer_point);

    let binding_context = field_bytes("binding_context")?;

    let ballots: Vec<Ballot> = array_bytes("ballots")?
        .iter()
        .map(|b| Ballot::decode(&b[..]).map_err(|e| format!("decode ballot: {e}")))
        .collect::<Result<_, String>>()?;
    let partial_decryptions: Vec<PartialDecryption> = array_bytes("partial_decryptions")?
        .iter()
        .map(|p| PartialDecryption::decode(&p[..]).map_err(|e| format!("decode partial: {e}")))
        .collect::<Result<_, String>>()?;

    let artifacts = ElectionArtifacts {
        parameters: &parameters,
        dkg_transcript: &dkg_transcript,
        ballots: &ballots,
        partial_decryptions: &partial_decryptions,
        tally: &tally,
        binding_context: &binding_context,
        issuer_public_key: &issuer_public_key,
    };
    Ok(audit(artifacts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditStatus;

    #[test]
    fn generated_bundle_audits_clean() {
        let bundle = election_bundle_json();
        let report = audit_bundle_json(&bundle).expect("bundle audits");
        assert_eq!(
            report.overall,
            AuditStatus::Pass,
            "round-tripped demo bundle must audit clean: {report:#?}"
        );
    }

    #[test]
    fn multi_position_bundle_generates_validates_and_audits() {
        // Passes the fail-closed gate, then re-audits clean off the wire bytes.
        let bundle = election_bundle_json_params(4, 3, 3).expect("gate passes");
        let report = audit_bundle_json(&bundle).expect("bundle audits");
        assert_eq!(report.overall, AuditStatus::Pass, "{report:#?}");
    }

    #[test]
    fn gate_rejects_duplicated_nullifier() {
        // Corrupt the population by forcing two ballots to share a position's
        // nullifier — the gate must reject before anything reaches the network.
        let mut f = multi_position_fixture(3, 2, 2);
        let dup = f.ballots[0].credential_presentation.clone();
        f.ballots[1].credential_presentation = dup;
        let err = validate_population(&f, 3, 2, 2).expect_err("must reject dup nullifier");
        assert!(err.contains("nullifier"), "unexpected error: {err}");
    }

    #[test]
    fn gate_rejects_out_of_range_selection() {
        // A ballot with the wrong number of ciphertexts (selection not in the
        // position's candidate range) fails the gate.
        let mut f = multi_position_fixture(3, 2, 2);
        f.ballots[0].ciphertexts.pop();
        let err = validate_population(&f, 3, 2, 2).expect_err("must reject bad shape");
        assert!(err.contains("ciphertexts"), "unexpected error: {err}");
    }

    #[test]
    fn gate_rejects_tampered_ground_truth() {
        // If the per-position aggregate no longer equals the ballot count, the
        // gate refuses (guards against a generator that miscounts selections).
        let mut f = multi_position_fixture(3, 2, 2);
        f.ground_truth[0] += 1;
        let err = validate_population(&f, 3, 2, 2).expect_err("must reject bad ground truth");
        assert!(err.contains("aggregate"), "unexpected error: {err}");
    }
}
