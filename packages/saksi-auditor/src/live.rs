//! Building blocks for the live election's trustee and console steps.
//!
//! The live CLI (`saksi-demo live`) runs every trustee and console step as a
//! separate process with only that party's secrets. The checks those steps
//! need are the auditor's own, so this module exposes them over a live
//! election's public record instead of re-implementing them:
//!
//! - [`LiveElection::load`]: the parameter and DKG-transcript checks of the
//!   audit (`parameters.shape`, `dkg.*`), returning the joint key and every
//!   trustee's verification key exactly as the auditor derives them;
//! - [`LiveElection::verify_and_aggregate`]: the audit's per-ballot checks
//!   (shape, CDS, selection, credential, issuer binding) plus nullifier
//!   uniqueness, folded into the per-contest aggregate;
//! - [`cp_context`] and [`LiveElection::decrypt_totals`]: the partial
//!   decryption context and the generator's combine (`decrypt_totals_bound`);
//! - [`LiveElection::tally_sig_context`]: the bytes a trustee signs;
//! - [`verify_live`] and [`verify_live_dir`]: the full audit with no
//!   generated ground truth.
//!
//! Nothing here changes any existing check or its output.

use std::collections::HashSet;
use std::path::Path;

use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use serde::{Deserialize, Serialize};

use saksi_credentials::IssuerPublicKey;
use saksi_crypto::elgamal::{Ciphertext, PublicKey};
use saksi_live::codec;
use saksi_protocol::{Ballot, DKGTranscript, ElectionParameters, PartialDecryption, TallyResult};

use crate::report::{AuditReport, AuditStatus, ReportBuilder, Severity};

/// The binding context of every live NIZK: the generator's.
pub const BINDING_CONTEXT: &[u8] = crate::fixtures::BINDING_CONTEXT;

fn failures(builder: ReportBuilder) -> Result<(), String> {
    let report = builder.finish();
    let failed: Vec<String> = report
        .findings
        .iter()
        .filter(|f| f.status == AuditStatus::Fail)
        .map(|f| format!("{}: {}", f.check, f.detail))
        .collect();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; "))
    }
}

/// A live election's public parameters and DKG transcript, checked.
pub struct LiveElection {
    /// The election parameters.
    pub parameters: ElectionParameters,
    /// The DKG transcript.
    pub transcript: DKGTranscript,
    /// The issuer key the parameters bind.
    pub issuer_public_key: IssuerPublicKey,
    /// `Y = Σ_d A_{d,0}`.
    pub joint_public_key: RistrettoPoint,
    /// `vk_k` for the trustee at position `k` of `parameters.trustee_ids`.
    pub verification_keys: Vec<RistrettoPoint>,
}

impl LiveElection {
    /// Decodes and checks `params` and `dkg` (both hex protobuf) with the
    /// audit's own parameter and transcript checks. A live election must bind
    /// an issuer key.
    pub fn load(params: &str, dkg: &str) -> Result<Self, String> {
        let parameters: ElectionParameters = codec::message(params, "params")?;
        let transcript: DKGTranscript = codec::message(dkg, "dkg")?;
        Self::from_messages(parameters, transcript)
    }

    /// [`LiveElection::load`] over decoded messages.
    pub fn from_messages(
        parameters: ElectionParameters,
        transcript: DKGTranscript,
    ) -> Result<Self, String> {
        let mut builder = ReportBuilder::new();
        if !crate::check_parameters(&parameters, &mut builder) {
            failures(builder)?;
            return Err("election parameters are malformed".into());
        }
        if transcript.election_id != parameters.election_id {
            return Err(format!(
                "DKG transcript is for election {:?}, not {:?}",
                transcript.election_id, parameters.election_id
            ));
        }
        let dkg = crate::dkg::verify_dkg_transcript(&parameters, &transcript, &mut builder);
        failures(builder)?;
        let dkg = dkg.ok_or("DKG transcript does not verify")?;
        if parameters.issuer_public_key.is_empty() {
            return Err("election parameters bind no issuer key".into());
        }
        let issuer_public_key = IssuerPublicKey(codec::point(
            &hex::encode(&parameters.issuer_public_key),
            "params.issuer_public_key",
        )?);
        Ok(Self {
            parameters,
            transcript,
            issuer_public_key,
            joint_public_key: dkg.joint_public_key,
            verification_keys: dkg.trustee_share_publics,
        })
    }

    /// Position of `trustee_id` in `parameters.trustee_ids`.
    pub fn trustee_index(&self, trustee_id: &str) -> Result<usize, String> {
        self.parameters
            .trustee_ids
            .iter()
            .position(|t| t == trustee_id)
            .ok_or_else(|| format!("{trustee_id:?} is not a trustee of this election"))
    }

    /// Runs the audit's per-ballot checks over `ballots` (hex `Ballot`s) and
    /// nullifier uniqueness, and returns the per-contest aggregate. Refuses
    /// the whole set on the first ballot that fails any check, on a ballot of
    /// another election, and on a repeated nullifier: a trustee never
    /// decrypts an aggregate it could not account for.
    pub fn verify_and_aggregate(&self, ballots: &[String]) -> Result<Vec<Ciphertext>, String> {
        let pk = PublicKey::from_point(self.joint_public_key);
        let zero = Ciphertext::new(RistrettoPoint::identity(), RistrettoPoint::identity());
        let mut aggregate = vec![zero; self.parameters.contest_ids.len()];
        let mut nullifiers = HashSet::new();
        for (idx, hex_ballot) in ballots.iter().enumerate() {
            let ballot: Ballot = codec::message(hex_ballot, &format!("ballots[{idx}]"))?;
            if ballot.election_id != self.parameters.election_id {
                return Err(format!(
                    "ballots[{idx}] is for election {:?}",
                    ballot.election_id
                ));
            }
            let mut builder = ReportBuilder::new();
            let mut passes = crate::ballot::BallotPassCounts::default();
            let decoded = crate::ballot::verify_ballot(
                idx,
                &ballot,
                &self.parameters,
                &pk,
                &self.issuer_public_key,
                BINDING_CONTEXT,
                &mut passes,
                &mut builder,
            );
            failures(builder)?;
            let decoded = decoded.ok_or_else(|| format!("ballots[{idx}] is not eligible"))?;
            let nullifier = crate::ledger::nullifier_of(&ballot).to_vec();
            if !nullifiers.insert(nullifier) {
                return Err(format!(
                    "ballots[{idx}] repeats an earlier ballot's nullifier"
                ));
            }
            for ct in decoded {
                aggregate[ct.contest] += Ciphertext::new(ct.pad, ct.data);
            }
        }
        Ok(aggregate)
    }

    /// Recovers every contest's total from `partials` over `aggregate`, the
    /// generator's combine (`decrypt_totals_bound`): every share's
    /// Chaum-Pedersen proof must verify against the transcript's verification
    /// keys, every contest needs `threshold` distinct verified trustees, and
    /// each total must decode in `[0, max]`.
    pub fn decrypt_totals(
        &self,
        aggregate: &[Ciphertext],
        partials: &[PartialDecryption],
        max: u64,
    ) -> Result<Vec<u64>, String> {
        if aggregate.len() != self.parameters.contest_ids.len() {
            return Err("aggregate does not carry one ciphertext per contest".into());
        }
        crate::fixtures::decrypt_totals_bound(
            &self.parameters,
            aggregate,
            partials,
            &self.verification_keys,
            BINDING_CONTEXT,
            max,
        )
    }

    /// The bytes a trustee signs over `totals`.
    pub fn tally_sig_context(&self, totals: &[u64]) -> Vec<u8> {
        crate::tally::tally_sig_context(&self.parameters.election_id, totals)
    }
}

/// The Chaum-Pedersen context of a partial decryption by `trustee_id` for
/// `contest_id`, under [`BINDING_CONTEXT`].
pub fn cp_context(trustee_id: &str, contest_id: &str) -> Vec<u8> {
    crate::decryption::cp_context_for_test(BINDING_CONTEXT, trustee_id, contest_id)
}

/// A live election's public record, all hex protobuf.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveRecord {
    /// `ElectionParameters`.
    pub params: String,
    /// `DKGTranscript`.
    pub dkg: String,
    /// The issuer key the verifier trusts (point hex).
    pub issuer_public_key: String,
    /// Every recorded `Ballot`.
    pub ballots: Vec<String>,
    /// Every recorded `PartialDecryption`.
    pub partial_decryptions: Vec<String>,
    /// The published `TallyResult`.
    pub tally: String,
}

/// One audit check, summarised over all its findings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckSummary {
    /// Stable check id, e.g. `ballot.cds_proof`.
    pub check: String,
    /// `pass` iff no finding under this id failed.
    pub status: String,
    /// Findings that passed.
    pub passed: usize,
    /// Findings that failed.
    pub failed: usize,
    /// The first failure's detail, or the last pass's.
    pub detail: String,
}

/// One contest's verified total.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiveContest {
    /// Contest id.
    pub contest: String,
    /// The total real threshold decryption recovered (`null` if the combine
    /// could not run).
    pub decoded: Option<u64>,
    /// The total the published tally claims.
    pub published_tally: u64,
}

/// `verify-live` output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiveVerdict {
    /// `pass` iff every fatal check passed.
    pub overall: String,
    /// The five questions the live demo asks, each `pass` or `fail`:
    /// `ballot_proofs`, `nullifiers_unique`, `partial_decryption_proofs`,
    /// `totals_match_tally`, `tally_signatures`.
    pub summary: std::collections::BTreeMap<String, String>,
    /// Every check id, in first-seen order.
    pub checks: Vec<CheckSummary>,
    /// Failed fatal checks, once per id.
    pub failed_checks: Vec<CheckSummary>,
    /// Per-contest totals.
    pub contests: Vec<LiveContest>,
    /// Ballot records audited.
    pub ballots: usize,
    /// The `ledger.order` verdict when a run folder held a ledger dump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger_order: Option<String>,
}

const SUMMARY: &[(&str, &[&str])] = &[
    (
        "ballot_proofs",
        &[
            "ballot.decode",
            "ballot.shape",
            "ballot.cds_proof",
            "ballot.selection_sum",
            "ballot.credential",
            "ballot.issuer_binding",
        ],
    ),
    ("nullifiers_unique", &["nullifier.unique"]),
    (
        "partial_decryption_proofs",
        &[
            "decryption.shape",
            "decryption.duplicate",
            "decryption.share_decode",
            "decryption.cp_decode",
            "decryption.cp_proof",
            "decryption.threshold",
        ],
    ),
    (
        "totals_match_tally",
        &["tally.shape", "tally.homomorphic_sum", "tally.range"],
    ),
    ("tally_signatures", &["tally.signatures"]),
];

fn verdict(
    report: &AuditReport,
    evidence: &[crate::tally::ContestEvidence],
    parameters: &ElectionParameters,
    tally: &TallyResult,
    ballots: usize,
    ledger_order: Option<String>,
) -> LiveVerdict {
    let mut checks: Vec<CheckSummary> = Vec::new();
    for f in &report.findings {
        let i = match checks.iter().position(|c| c.check == f.check) {
            Some(i) => i,
            None => {
                checks.push(CheckSummary {
                    check: f.check.to_string(),
                    status: "pass".into(),
                    passed: 0,
                    failed: 0,
                    detail: String::new(),
                });
                checks.len() - 1
            }
        };
        let c = &mut checks[i];
        if f.status == AuditStatus::Fail {
            if c.failed == 0 {
                c.detail = f.detail.clone();
            }
            c.failed += 1;
            c.status = "fail".into();
        } else {
            c.passed += 1;
            if c.failed == 0 {
                c.detail = f.detail.clone();
            }
        }
    }
    let failed_checks = checks
        .iter()
        .filter(|c| {
            c.failed > 0
                && report.findings.iter().any(|f| {
                    f.check == c.check
                        && f.severity == Severity::Fatal
                        && f.status == AuditStatus::Fail
                })
        })
        .cloned()
        .collect();
    let summary = SUMMARY
        .iter()
        .map(|(name, ids)| {
            let seen: Vec<&CheckSummary> = checks
                .iter()
                .filter(|c| ids.contains(&c.check.as_str()))
                .collect();
            // A question no finding answered (the phase never ran) is a fail.
            let ok = !seen.is_empty() && seen.iter().all(|c| c.failed == 0);
            (
                name.to_string(),
                if ok { "pass" } else { "fail" }.to_string(),
            )
        })
        .collect();
    let contests = parameters
        .contest_ids
        .iter()
        .enumerate()
        .map(|(c, id)| LiveContest {
            contest: id.clone(),
            decoded: evidence
                .iter()
                .find(|e| &e.contest_id == id)
                .and_then(|e| e.decoded),
            published_tally: tally.totals.get(c).copied().unwrap_or(0),
        })
        .collect();
    LiveVerdict {
        overall: if report.overall == AuditStatus::Pass {
            "pass"
        } else {
            "fail"
        }
        .into(),
        summary,
        checks,
        failed_checks,
        contests,
        ballots,
        ledger_order,
    }
}

struct Decoded {
    parameters: ElectionParameters,
    dkg_transcript: DKGTranscript,
    issuer_public_key: IssuerPublicKey,
    partial_decryptions: Vec<PartialDecryption>,
    tally: TallyResult,
}

fn decode(
    params: &str,
    dkg: &str,
    issuer: &str,
    partials: &[String],
    tally: &str,
) -> Result<Decoded, String> {
    Ok(Decoded {
        parameters: codec::message(params, "params")?,
        dkg_transcript: codec::message(dkg, "dkg")?,
        issuer_public_key: IssuerPublicKey(codec::point(issuer, "issuer_public_key")?),
        partial_decryptions: partials
            .iter()
            .enumerate()
            .map(|(i, p)| codec::message(p, &format!("partial_decryptions[{i}]")))
            .collect::<Result<_, _>>()?,
        tally: codec::message(tally, "tally")?,
    })
}

fn run(
    d: &Decoded,
    ballots: impl Iterator<Item = Result<Ballot, String>>,
    expected: Option<usize>,
) -> (AuditReport, Vec<crate::tally::ContestEvidence>, usize) {
    let mut count = 0usize;
    let counted = ballots.inspect(|_| count += 1);
    let (report, evidence, _) = crate::audit_streaming(
        crate::AuditInputs {
            parameters: &d.parameters,
            dkg_transcript: &d.dkg_transcript,
            partial_decryptions: &d.partial_decryptions,
            tally: &d.tally,
            binding_context: BINDING_CONTEXT,
            issuer_public_key: &d.issuer_public_key,
            // The only difference from `audit-stream`: a live election has no
            // generated answer key, so the accuracy comparison is not made.
            ground_truth: None,
            expected_ballots: expected,
        },
        counted,
        None,
    );
    (report, evidence, count)
}

/// Audits a live election's public record held in memory.
pub fn verify_live(record: &LiveRecord) -> Result<LiveVerdict, String> {
    let d = decode(
        &record.params,
        &record.dkg,
        &record.issuer_public_key,
        &record.partial_decryptions,
        &record.tally,
    )?;
    let ballots = record
        .ballots
        .iter()
        .enumerate()
        .map(|(i, b)| codec::message::<Ballot>(b, &format!("ballots[{i}]")));
    let (report, evidence, n) = run(&d, ballots, None);
    Ok(verdict(
        &report,
        &evidence,
        &d.parameters,
        &d.tally,
        n,
        None,
    ))
}

/// Audits a live election's run folder: the `header.json` +
/// `ballots.ndjson` layout `audit-stream` reads (`ground_truth` and
/// `voter_ids` may be empty and are ignored), plus the `ledger.order` check
/// when the folder holds a `ledger/` dump.
pub fn verify_live_dir(dir: &Path) -> Result<LiveVerdict, String> {
    let header = crate::stream::read_header(dir)?;
    let d = decode(
        &header.params,
        &header.dkg,
        &header.issuer_pk,
        &header.partial_decryptions,
        &header.tally,
    )?;
    if codec::bytes(&header.binding_context, "binding_context")? != BINDING_CONTEXT {
        return Err("header binding_context is not the live binding context".into());
    }
    let ballots = crate::stream::BallotLines::open(dir)?;
    let (mut report, evidence, n) = run(&d, ballots, Some(header.n));
    let ledger_dir = dir.join(crate::demo::LEDGER_DIR);
    let mut ledger_order = None;
    if ledger_dir.join(crate::stream::BALLOTS_FILE).exists() {
        let finding = crate::ledger::check_ledger_order(dir, &ledger_dir);
        let fail = finding.status == AuditStatus::Fail;
        if fail {
            report.overall = AuditStatus::Fail;
        }
        ledger_order = Some(format!(
            "{}: {}",
            if fail { "fail" } else { "pass" },
            finding.detail
        ));
        report.findings.push(finding);
    }
    Ok(verdict(
        &report,
        &evidence,
        &d.parameters,
        &d.tally,
        n,
        ledger_order,
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn saksi_live_binds_the_auditor_context() {
        assert_eq!(
            super::BINDING_CONTEXT,
            saksi_live::election::BINDING_CONTEXT
        );
    }
}
