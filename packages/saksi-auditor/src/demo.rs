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

use crate::fixtures::{
    happy_path_fixture, multi_position_fixture, ph_position_id, ElectionFixture,
};
use crate::{audit, AuditReport, AuditStatus, ElectionArtifacts};

/// Machine-readable per-contest correctness for one contest: the seeded
/// `ground_truth`, the `decoded` tally the auditor verified, `E = decoded −
/// ground_truth`, and whether this contest passed (audit clean AND `E == 0`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContestCorrectness {
    /// Position-qualified contest id.
    pub contest: String,
    /// Seeded ground-truth total for this contest.
    pub ground_truth: u64,
    /// Value recovered by real threshold decryption of the aggregate ciphertext.
    pub decoded: u64,
    /// `decoded − ground_truth` (0 on a correct run).
    #[serde(rename = "E")]
    pub e: i64,
    /// This contest is correct: the overall audit passed AND `E == 0`.
    pub pass: bool,
    /// The published tally total (equals `decoded` when the audit passes).
    #[serde(default)]
    pub published_tally: u64,
    /// Hex of the aggregate (homomorphic-summed) ciphertext component `Σ c2` for
    /// this contest — the encrypted tally the decrypt operates on.
    #[serde(default)]
    pub aggregate_ciphertext: String,
    /// Hex of the recovered plaintext point `M = decoded·G`, the output of
    /// combining the threshold partial decryptions. Empty if the combine could
    /// not run. A reader can confirm `M == decoded·G` to verify the decrypt.
    #[serde(default)]
    pub recovered_point: String,
}

/// Machine-readable result of auditing a **stream run folder** — the structured
/// output the console's Verify phase consumes instead of string-parsing the
/// human-readable audit findings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StreamAudit {
    /// `"pass"` iff the full audit (proofs, threshold, tally, accuracy) passed.
    pub overall: String,
    /// Per-contest correctness rows.
    pub contests: Vec<ContestCorrectness>,
}

impl StreamAudit {
    /// Serialize to pretty JSON — the `saksi-demo audit-stream --json` output the
    /// console's Verify phase parses. Keeps `serde_json` out of `saksi-demo`.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("StreamAudit serializes")
    }
}

/// Re-export the generator's parameter types at the crate's public `demo` surface
/// so the `saksi-demo` CLI (a separate crate) can construct them — the `fixtures`
/// module itself is `pub(crate)`, so these would otherwise be unreachable.
pub use crate::fixtures::{GenParams, SelectionProfile};

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
        // Synthetic voter id per ballot (paper Table 3.1 / Appendix A) — repeats
        // across a voter's positions; off-wire generation metadata.
        "voter_ids": f.voter_ids,
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
pub fn election_bundle_json_params(params: &GenParams) -> Result<String, String> {
    validate_params(params)?;
    let f = multi_position_fixture(params);
    validate_population(&f, params.voters, params.positions, params.candidates)?;
    Ok(fixture_to_bundle_json(
        &f,
        params.positions,
        params.candidates,
    ))
}

/// Fail-closed parameter gate applied BEFORE building the fixture (the fixture
/// itself would panic on `t > n`; this returns a graceful `Err` instead). Checks
/// the population dimensions, the t-of-n shape, and that `trustee_names` aligns
/// with the trustee count.
fn validate_params(p: &GenParams) -> Result<(), String> {
    if p.voters < 1 || p.positions < 1 || p.candidates < 1 {
        return Err("voters, positions, candidates must each be >= 1".into());
    }
    if p.threshold == 0 || p.threshold > p.trustees {
        return Err(format!(
            "threshold must be 1..=trustees (got {}-of-{})",
            p.threshold, p.trustees
        ));
    }
    if p.trustee_names.len() != p.trustees {
        return Err(format!(
            "trustee_names has {} entries, expected {} (one per trustee)",
            p.trustee_names.len(),
            p.trustees
        ));
    }
    Ok(())
}

/// Generates a parameterized multi-position election and writes it as a streamed
/// `header.json` + `ballots.ndjson` under `dir` (bounded memory, for the 483k/1M
/// tiers) — **after** the same fail-closed validation gate as the one-blob path.
/// This is the streaming counterpart of [`election_bundle_json_params`]; the CLI
/// (`saksi-demo gen --stream`) calls it. A population that fails the gate returns
/// `Err` and nothing is written.
pub fn write_election_stream_params(
    dir: &std::path::Path,
    params: &GenParams,
) -> Result<(), String> {
    validate_params(params)?;
    let f = multi_position_fixture(params);
    validate_population(&f, params.voters, params.positions, params.candidates)?;
    crate::stream::write_election_stream(dir, &f, params.positions, params.candidates)?;
    // The Stage-4 ground-truth tables (paper Appendix A) ship alongside every
    // generated run, so the plaintext population that produced these ciphertexts
    // is inspectable without re-running anything. Selections are replayed from
    // the same pure `select_candidate` the fixture used, so the two agree by
    // construction; the replay costs nothing beside the crypto above it.
    crate::ground_truth::write_ground_truth_csvs(dir, params)
}

/// Fail-closed validation gate (Phase 1): structural invariants that must hold
/// before a generated population is allowed onto the network. Returns `Err` with
/// the first violation found. Catches generator bugs that would otherwise read
/// as clean throughput/accuracy numbers downstream.
///
/// Checks (paper §Data Validation): (1) exactly `voters × positions` ballots,
/// `voters` per position; (2) all nullifiers pairwise distinct; (3) every ballot
/// carries exactly `candidates` ciphertexts/proofs (selection in-range); (4)
/// per-position ground-truth aggregate == the ballot count for that position;
/// and (5) voter ids unique per voter and repeated exactly once per position
/// (one record per voter per position, sharing a voter id).
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
    if f.voter_ids.len() != f.ballots.len() {
        return Err(format!(
            "voter_ids len {} != ballot count {}",
            f.voter_ids.len(),
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

    // Map each named position label to its index (President→0, …).
    let label_index: std::collections::HashMap<String, usize> =
        (0..positions).map(|p| (ph_position_id(p), p)).collect();

    let mut nullifiers: HashSet<Vec<u8>> = HashSet::with_capacity(f.ballots.len());
    let mut per_position_ballots = vec![0usize; positions];
    // Each voter id must appear once per position (a voter votes each position
    // exactly once), and its total occurrences must equal `positions`.
    let mut per_position_voter_ids: Vec<HashSet<&str>> = vec![HashSet::new(); positions];
    let mut voter_id_occurrences: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();

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
        let position = *label_index.get(&ballot.position_id).ok_or_else(|| {
            format!(
                "ballot {i} position {:?} is not one of the election's positions",
                ballot.position_id
            )
        })?;
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

        let voter_id = f.voter_ids[i].as_str();
        *voter_id_occurrences.entry(voter_id).or_insert(0) += 1;
        if !per_position_voter_ids[position].insert(voter_id) {
            return Err(format!(
                "ballot {i} repeats voter id {voter_id:?} within position {:?}",
                ballot.position_id
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

    // Every voter id repeats exactly `positions` times (one record per position).
    for (vid, count) in &voter_id_occurrences {
        if *count != positions {
            return Err(format!(
                "voter id {vid:?} appears {count} times, expected {positions} (one record per position)"
            ));
        }
    }
    if voter_id_occurrences.len() != voters {
        return Err(format!(
            "distinct voter ids {} != voter count {voters}",
            voter_id_occurrences.len()
        ));
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

    // Optional seeded ground truth: when the bundle carries it, the audit adds
    // the E=0 accuracy assertion (decoded tally == ground truth). Absent for a
    // real on-chain election that was not generated with a known truth.
    let ground_truth: Option<Vec<u64>> = match v.get("ground_truth") {
        None => None,
        Some(v) => Some(
            v.as_array()
                .ok_or_else(|| "ground_truth is not an array".to_string())?
                .iter()
                .map(|n| {
                    n.as_u64()
                        .ok_or_else(|| "a ground_truth entry is not a u64".to_string())
                })
                .collect::<Result<_, String>>()?,
        ),
    };

    let artifacts = ElectionArtifacts {
        parameters: &parameters,
        dkg_transcript: &dkg_transcript,
        ballots: &ballots,
        partial_decryptions: &partial_decryptions,
        tally: &tally,
        binding_context: &binding_context,
        issuer_public_key: &issuer_public_key,
        ground_truth: ground_truth.as_deref(),
    };
    Ok(audit(artifacts))
}

/// Audits a **stream run folder** (`header.json` + `ballots.ndjson`, the shape
/// [`write_election_stream_params`] writes) and projects the result into
/// [`StreamAudit`] — structured per-contest correctness the console's Verify
/// phase consumes without parsing finding strings.
///
/// Reconstructs the auditor's [`ElectionArtifacts`] by hex-decoding the header's
/// embedded protobuf (params/dkg/issuer_pk/binding_context/partial_decryptions/
/// tally) plus the streamed ballots, runs the full audit, then reports per
/// contest `{ground_truth, decoded, E, pass}`. `decoded` is the published tally
/// the audit verified equals the homomorphic decode; a divergence fails the
/// audit, so `pass` (= overall clean AND `E == 0`) never reports a false green.
pub fn audit_stream_dir(dir: &std::path::Path) -> Result<StreamAudit, String> {
    let header = crate::stream::read_header(dir)?;
    let hexd = |s: &str, what: &str| hex::decode(s).map_err(|e| format!("{what} not hex: {e}"));

    let parameters = ElectionParameters::decode(&hexd(&header.params, "params")?[..])
        .map_err(|e| format!("decode params: {e}"))?;
    let dkg_transcript = DKGTranscript::decode(&hexd(&header.dkg, "dkg")?[..])
        .map_err(|e| format!("decode dkg: {e}"))?;
    let issuer_bytes: [u8; 32] = hexd(&header.issuer_pk, "issuer_pk")?
        .try_into()
        .map_err(|_| "issuer_pk is not 32 bytes".to_string())?;
    let issuer_public_key = IssuerPublicKey(
        point_from_compressed(issuer_bytes).map_err(|_| "issuer_pk is not a valid point")?,
    );
    let binding_context = hexd(&header.binding_context, "binding_context")?;
    let tally = TallyResult::decode(&hexd(&header.tally, "tally")?[..])
        .map_err(|e| format!("decode tally: {e}"))?;
    let partial_decryptions: Vec<PartialDecryption> = header
        .partial_decryptions
        .iter()
        .map(|p| {
            PartialDecryption::decode(&hexd(p, "partial_decryption")?[..])
                .map_err(|e| format!("decode partial: {e}"))
        })
        .collect::<Result<_, String>>()?;

    // Ballots stream from ballots.ndjson (hex-protobuf, one per line).
    let ballots_path = dir.join(crate::stream::BALLOTS_FILE);
    let raw = std::fs::read_to_string(&ballots_path)
        .map_err(|e| format!("read {}: {e}", ballots_path.display()))?;
    let mut ballots: Vec<Ballot> = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let bytes = hex::decode(line).map_err(|e| format!("ballot line {} not hex: {e}", i + 1))?;
        ballots
            .push(Ballot::decode(&bytes[..]).map_err(|e| format!("decode ballot {}: {e}", i + 1))?);
    }

    let ground_truth = header.ground_truth.clone();
    let (report, evidence) = crate::audit_with_evidence(ElectionArtifacts {
        parameters: &parameters,
        dkg_transcript: &dkg_transcript,
        ballots: &ballots,
        partial_decryptions: &partial_decryptions,
        tally: &tally,
        binding_context: &binding_context,
        issuer_public_key: &issuer_public_key,
        ground_truth: Some(&ground_truth),
    });
    let overall_pass = report.overall == AuditStatus::Pass;

    // Index the per-contest crypto evidence by contest id.
    let ev_by_contest: std::collections::HashMap<&str, &crate::tally::ContestEvidence> = evidence
        .iter()
        .map(|e| (e.contest_id.as_str(), e))
        .collect();

    let contests = parameters
        .contest_ids
        .iter()
        .enumerate()
        .map(|(c, contest_id)| {
            let gt = ground_truth.get(c).copied().unwrap_or(0);
            let published = tally.totals.get(c).copied().unwrap_or(0);
            let ev = ev_by_contest.get(contest_id.as_str());
            // `decoded` is the value REAL threshold decryption recovered (the
            // proof), not the published claim; fall back to published if the
            // combine could not run.
            let decoded = ev.and_then(|e| e.decoded).unwrap_or(published);
            let e = decoded as i64 - gt as i64;
            let aggregate_ciphertext = ev
                .map(|e| hex::encode(compress_point(&e.aggregate_ciphertext)))
                .unwrap_or_default();
            let recovered_point = ev
                .and_then(|e| e.recovered_point.as_ref())
                .map(|p| hex::encode(compress_point(p)))
                .unwrap_or_default();
            ContestCorrectness {
                contest: contest_id.clone(),
                ground_truth: gt,
                decoded,
                e,
                // A tampered proof elsewhere fails the whole audit, so a contest
                // is correct only when the audit is clean AND its own E == 0.
                pass: overall_pass && e == 0,
                published_tally: published,
                aggregate_ciphertext,
                recovered_point,
            }
        })
        .collect();

    Ok(StreamAudit {
        overall: if overall_pass { "pass" } else { "fail" }.to_string(),
        contests,
    })
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
        let bundle =
            election_bundle_json_params(&GenParams::simple(4, 3, 3, SelectionProfile::Uniform))
                .expect("gate passes");
        let report = audit_bundle_json(&bundle).expect("bundle audits");
        assert_eq!(report.overall, AuditStatus::Pass, "{report:#?}");
    }

    #[test]
    fn params_entry_generates_and_audits_for_4_of_7() {
        // A non-default 4-of-7 election round-trips through the gate + audits clean
        // — proves DkgConfig::new(t,n) and the threshold combine work off-default.
        let p = GenParams {
            election_id: "e".into(),
            election_name: "E".into(),
            threshold: 4,
            trustees: 7,
            trustee_names: (1..=7).map(|i| format!("T{i}")).collect(),
            voters: 5,
            positions: 1,
            candidates: 2,
            profile: SelectionProfile::Uniform,
        };
        let bundle = election_bundle_json_params(&p).expect("gate passes");
        let report = audit_bundle_json(&bundle).expect("bundle audits");
        assert_eq!(report.overall, AuditStatus::Pass, "{report:#?}");
    }

    #[test]
    fn gate_rejects_threshold_above_trustees() {
        let p = GenParams {
            election_id: "e".into(),
            election_name: "E".into(),
            threshold: 6,
            trustees: 5,
            trustee_names: (1..=5).map(|i| format!("T{i}")).collect(),
            voters: 3,
            positions: 1,
            candidates: 2,
            profile: SelectionProfile::Uniform,
        };
        let err = election_bundle_json_params(&p).expect_err("t>n must be rejected");
        assert!(err.contains("threshold"), "unexpected error: {err}");
    }

    #[test]
    fn audit_stream_dir_reports_zero_error_on_clean_run() {
        let dir = std::env::temp_dir().join("saksi-audit-stream-clean");
        let _ = std::fs::remove_dir_all(&dir);
        let p = GenParams::simple(6, 2, 2, SelectionProfile::Uniform);
        write_election_stream_params(&dir, &p).expect("write stream");

        let sa = audit_stream_dir(&dir).expect("audits");
        assert_eq!(sa.overall, "pass");
        assert_eq!(sa.contests.len(), 2 * 2, "one row per contest slot");
        assert!(
            sa.contests
                .iter()
                .all(|c| c.e == 0 && c.decoded == c.ground_truth && c.pass),
            "clean run: every contest E=0 and pass: {sa:#?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_stream_dir_flags_tampered_ground_truth() {
        let dir = std::env::temp_dir().join("saksi-audit-stream-tamper");
        let _ = std::fs::remove_dir_all(&dir);
        write_election_stream_params(&dir, &GenParams::simple(4, 1, 2, SelectionProfile::Uniform))
            .expect("write stream");

        // Corrupt the seeded ground truth in the header: the accuracy check must
        // now fail and the corresponding contest reports E != 0, pass = false.
        let hp = dir.join(crate::stream::HEADER_FILE);
        let raw = std::fs::read_to_string(&hp).expect("read header");
        let mut v: serde_json::Value = serde_json::from_str(&raw).expect("parse header");
        v["ground_truth"][0] = serde_json::json!(999);
        std::fs::write(&hp, serde_json::to_string_pretty(&v).expect("reser")).expect("rewrite");

        let sa = audit_stream_dir(&dir).expect("audits (and reports a failure)");
        assert_eq!(sa.overall, "fail");
        assert!(
            sa.contests.iter().any(|c| c.e != 0 && !c.pass),
            "a tampered contest must report E != 0 and pass = false: {sa:#?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gate_rejects_duplicated_nullifier() {
        // Corrupt the population by forcing two ballots to share a position's
        // nullifier — the gate must reject before anything reaches the network.
        let mut f = multi_position_fixture(&GenParams::simple(3, 2, 2, SelectionProfile::Uniform));
        let dup = f.ballots[0].credential_presentation.clone();
        f.ballots[1].credential_presentation = dup;
        let err = validate_population(&f, 3, 2, 2).expect_err("must reject dup nullifier");
        assert!(err.contains("nullifier"), "unexpected error: {err}");
    }

    #[test]
    fn gate_rejects_out_of_range_selection() {
        // A ballot with the wrong number of ciphertexts (selection not in the
        // position's candidate range) fails the gate.
        let mut f = multi_position_fixture(&GenParams::simple(3, 2, 2, SelectionProfile::Uniform));
        f.ballots[0].ciphertexts.pop();
        let err = validate_population(&f, 3, 2, 2).expect_err("must reject bad shape");
        assert!(err.contains("ciphertexts"), "unexpected error: {err}");
    }

    #[test]
    fn skewed_distribution_generates_validates_and_audits() {
        // The skewed profile must still pass the gate + audit clean (only the
        // per-candidate distribution differs from uniform).
        let bundle =
            election_bundle_json_params(&GenParams::simple(6, 3, 3, SelectionProfile::Skewed))
                .expect("gate passes");
        let report = audit_bundle_json(&bundle).expect("bundle audits");
        assert_eq!(report.overall, AuditStatus::Pass, "{report:#?}");
    }

    #[test]
    fn audit_scores_e0_accuracy_against_ground_truth() {
        // The generated bundle carries seeded ground truth, so the audit must
        // decode the real tally and confirm it equals that truth (E = 0).
        let bundle =
            election_bundle_json_params(&GenParams::simple(6, 3, 3, SelectionProfile::Uniform))
                .expect("gate passes");
        let report = audit_bundle_json(&bundle).expect("bundle audits");
        assert_eq!(report.overall, AuditStatus::Pass, "{report:#?}");
        assert!(
            matches!(
                report.finding("tally.accuracy").map(|f| &f.status),
                Some(AuditStatus::Pass)
            ),
            "E=0 accuracy check must run and pass: {report:#?}"
        );
    }

    #[test]
    fn tampered_ground_truth_fails_e0() {
        // Flip one ground-truth total after generation. The real decrypt of the
        // (untouched) ballots no longer matches it, so E != 0 and the accuracy
        // check fails — proving E=0 compares against the seeded truth, not just
        // the co-generated published tally.
        let bundle =
            election_bundle_json_params(&GenParams::simple(6, 2, 2, SelectionProfile::Uniform))
                .expect("gate passes");
        let mut v: serde_json::Value = serde_json::from_str(&bundle).unwrap();
        let gt = v["ground_truth"].as_array_mut().unwrap();
        let bumped = gt[0].as_u64().unwrap() + 1;
        gt[0] = serde_json::json!(bumped);
        let tampered = serde_json::to_string(&v).unwrap();

        let report = audit_bundle_json(&tampered).expect("audit runs");
        assert_eq!(report.overall, AuditStatus::Fail, "{report:#?}");
        assert!(
            matches!(
                report.finding("tally.accuracy").map(|f| &f.status),
                Some(AuditStatus::Fail)
            ),
            "tampered ground truth must fail E=0: {report:#?}"
        );
    }

    #[test]
    fn gate_rejects_broken_voter_id_repetition() {
        // Corrupt the synthetic voter ids so one voter appears twice within a
        // position (paper: one record per voter per position) — the gate rejects.
        let mut f = multi_position_fixture(&GenParams::simple(3, 2, 2, SelectionProfile::Uniform));
        // voter_ids are voter-major [v0,v0,v1,v1,v2,v2]; index 0 and 2 are both
        // the "president" position. Point index 0 at voter-1 → voter-1 twice in
        // that position.
        f.voter_ids[0] = f.voter_ids[2].clone();
        let err = validate_population(&f, 3, 2, 2).expect_err("must reject");
        assert!(err.contains("voter id"), "unexpected error: {err}");
    }

    #[test]
    fn gate_rejects_tampered_ground_truth() {
        // If the per-position aggregate no longer equals the ballot count, the
        // gate refuses (guards against a generator that miscounts selections).
        let mut f = multi_position_fixture(&GenParams::simple(3, 2, 2, SelectionProfile::Uniform));
        f.ground_truth[0] += 1;
        let err = validate_population(&f, 3, 2, 2).expect_err("must reject bad ground truth");
        assert!(err.contains("aggregate"), "unexpected error: {err}");
    }
}
