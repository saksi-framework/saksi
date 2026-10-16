//! `saksi-demo audit-canvass`: the national canvass, a verifier-side check of
//! the precinct returns against the precinct ledgers and the national tally.
//!
//! Input layout (`<dir>` is a precinct generation that the driver has run on
//! the chain):
//!
//! ```text
//! <dir>/national/header.json            base election id, national partials, tally, ground truth
//! <dir>/national/registry.json          [{precinct_id, authority_pubkey_hex}]
//! <dir>/national/aggregate.json         the national aggregate the partials decrypt
//! <dir>/national/returns/<pid>.json     the returns as received (what the canvass reads)
//! <dir>/precinct-NN/header.json         precinct election (<base>-pNN)
//! <dir>/precinct-NN/ballots.ndjson      console record (served ballots)
//! <dir>/precinct-NN/ledger/ballots.ndjson  chain read-back after close, nullifier order
//! <dir>/precinct-NN/close.json          {close_block, close_tip_hash}, written by the driver
//! ```
//!
//! The precinct's own `return.json` is the sender's copy and is not read.
//!
//! Seven checks, each `pass` or `fail` with a reason, all run even when an
//! earlier one fails:
//!
//! - `canvass.registry`: every received return names a registered precinct,
//!   carries the election id `<base>-<precinct_id>`, and no precinct has two.
//! - `canvass.completeness`: every registered precinct has a return.
//! - `canvass.signature`: every return verifies under its precinct's
//!   registered authority key.
//! - `canvass.precinct_recompute`: every return's record count, ledger digest
//!   and per-contest `(Σc1, Σc2)` equal the values recomputed from that
//!   precinct's ledger read-back, and its close block and tip hash equal
//!   `close.json`.
//! - `canvass.national_sum`: the product of the returned aggregates equals the
//!   national aggregate the national tally was decrypted from.
//! - `canvass.accuracy`: every precinct passes the stream audit (ledger checks
//!   on) with `E = 0`, and the national partial decryptions verify against the
//!   product of the ledger-recomputed precinct aggregates and decode to the
//!   national ground truth (`E = 0`) and to the published, trustee-signed
//!   national tally.
//! - `canvass.nullifier_unique`: no nullifier appears in two precinct ledgers.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use prost::Message;
use saksi_crypto::elgamal::Ciphertext;
use saksi_crypto::group::{compress_point, point_from_compressed};
use saksi_protocol::{DKGTranscript, ElectionParameters, PartialDecryption, TallyResult};
use serde::{Deserialize, Serialize};

use crate::ledger::{verified_sums, LedgerSums};
use crate::precinct_return::{parse_hex32, PrecinctReturn};
use crate::stream::{
    read_header, AggregateContest, AggregateFile, BallotLines, RegistryEntry, StreamHeader,
    AGGREGATE_FILE, BALLOTS_FILE, NATIONAL_DIR, REGISTRY_FILE,
};

/// Subfolder of `national/` holding the returns as the national server
/// received them, one `<precinct_id>.json` each.
pub const RETURNS_DIR: &str = "returns";
/// The driver's close reference in a precinct folder ([`CloseRef`]).
pub const CLOSE_FILE: &str = "close.json";
/// Check table written by the canvass.
pub const CHECKS_CSV: &str = "canvass-checks.csv";
/// Full canvass result written by the canvass.
pub const CANVASS_JSON: &str = "canvass.json";

/// Check ids, in evaluation order.
pub const CHECKS: [&str; 7] = [
    "canvass.registry",
    "canvass.completeness",
    "canvass.signature",
    "canvass.precinct_recompute",
    "canvass.national_sum",
    "canvass.accuracy",
    "canvass.nullifier_unique",
];

/// `precinct-NN/close.json`: the chain state the read-back was taken at. The
/// driver writes it from Fabric `ChainInfo` right after `CloseElection` and the
/// ledger dump: `close_block` is `ChainInfo.Height` (the block count, i.e. one
/// more than the number of the last block) and `close_tip_hash` is
/// `ChainInfo.CurrentBlockHash` (hex, 32 bytes). The same two values are what
/// the driver passes to `sign-return`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseRef {
    /// `ChainInfo.Height` at close.
    pub close_block: u64,
    /// `ChainInfo.CurrentBlockHash` at close, hex.
    pub close_tip_hash: String,
}

/// One check's verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanvassCheck {
    /// Check id (one of [`CHECKS`]).
    pub check: String,
    /// `pass` or `fail`.
    pub verdict: String,
    /// Why.
    pub reason: String,
}

impl CanvassCheck {
    fn new(check: &str, problems: &[String], ok: impl Into<String>) -> Self {
        let pass = problems.is_empty();
        Self {
            check: check.to_string(),
            verdict: if pass { "pass" } else { "fail" }.to_string(),
            reason: if pass { ok.into() } else { problems.join("; ") },
        }
    }

    /// The verdict is `pass`.
    pub fn passed(&self) -> bool {
        self.verdict == "pass"
    }
}

/// One registered precinct in `canvass.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecinctRow {
    /// `p01`, ...
    pub precinct_id: String,
    /// Records in the ledger read-back (0 if it could not be read).
    pub records: u64,
    /// Records whose proofs and credential verified (the ones summed).
    pub verified: u64,
    /// `(Σc1, Σc2)` per contest recomputed from the ledger read-back.
    pub aggregates: Vec<AggregateContest>,
    /// The return's signature verifies; `None` when no return was received.
    pub signature_ok: Option<bool>,
    /// The return matches the recompute; `None` when no return was received.
    pub recompute_ok: Option<bool>,
    /// Per-contest `E` from the precinct's stream audit (empty if it could not run).
    #[serde(rename = "E")]
    pub e: Vec<i64>,
    /// Stream audit verdict: `pass`, `fail`, or `error: ...`.
    pub audit: String,
}

/// One contest of the national result in `canvass.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NationalContest {
    /// Contest id.
    pub contest_id: String,
    /// Product of the ledger-recomputed precinct `Σc1`, hex.
    pub c1: String,
    /// Product of the ledger-recomputed precinct `Σc2`, hex.
    pub c2: String,
    /// Decoded national total, if the decryption verified.
    pub decoded: Option<u64>,
    /// National ground truth.
    pub ground_truth: u64,
    /// `decoded − ground_truth`, if decoded.
    #[serde(rename = "E")]
    pub e: Option<i64>,
}

/// The national row of `canvass.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NationalRow {
    /// Per contest.
    pub contests: Vec<NationalContest>,
    /// Decryption verified, E = 0 everywhere and the published tally agrees.
    pub pass: bool,
}

/// `canvass.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Canvass {
    /// Base election id (national).
    pub base_election_id: String,
    /// One row per registered precinct, in registry order.
    pub precincts: Vec<PrecinctRow>,
    /// National result.
    pub national: NationalRow,
    /// The seven checks, in [`CHECKS`] order.
    pub checks: Vec<CanvassCheck>,
    /// Every check passed.
    pub pass: bool,
}

impl Canvass {
    /// The check with id `check`.
    pub fn check(&self, check: &str) -> Option<&CanvassCheck> {
        self.checks.iter().find(|c| c.check == check)
    }

    /// Ids of the failed checks, in order.
    pub fn failed(&self) -> Vec<&str> {
        self.checks
            .iter()
            .filter(|c| !c.passed())
            .map(|c| c.check.as_str())
            .collect()
    }
}

/// Folder of precinct `pid` (`p03` -> `precinct-03`).
fn precinct_dir(dir: &Path, pid: &str) -> PathBuf {
    dir.join(format!("precinct-{}", pid.trim_start_matches('p')))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn point(hex32: &[u8; 32], what: &str) -> Result<RistrettoPoint, String> {
    point_from_compressed(*hex32).map_err(|_| format!("{what} is not a valid point"))
}

/// What the canvass recomputes for one registered precinct.
struct PrecinctLedger {
    sums: Result<LedgerSums, String>,
    close: Result<CloseRef, String>,
    audit: Result<crate::demo::StreamAudit, String>,
}

/// Runs the national canvass over `dir`. `Err` only for a missing or
/// unreadable national side (header, registry, aggregate); everything a
/// precinct or a return can get wrong is a failed check.
pub fn canvass(dir: &Path) -> Result<Canvass, String> {
    let ndir = dir.join(NATIONAL_DIR);
    let nheader = read_header(&ndir)?;
    let base = nheader.election_id.clone();
    let registry: Vec<RegistryEntry> = read_json(&ndir.join(REGISTRY_FILE))?;
    let national_agg: AggregateFile = read_json(&ndir.join(AGGREGATE_FILE))?;
    let nparams = ElectionParameters::decode(
        &hex::decode(&nheader.params).map_err(|e| format!("national params not hex: {e}"))?[..],
    )
    .map_err(|e| format!("decode national params: {e}"))?;
    let contest_ids = nparams.contest_ids.clone();

    // -- per registered precinct: ledger recompute, close ref, stream audit --
    let mut nullifiers: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut collisions: Vec<String> = Vec::new();
    let mut ledgers: Vec<PrecinctLedger> = Vec::with_capacity(registry.len());
    for (k, entry) in registry.iter().enumerate() {
        let pdir = precinct_dir(dir, &entry.precinct_id);
        let ledger_file = pdir.join(crate::demo::LEDGER_DIR).join(BALLOTS_FILE);
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let sums = BallotLines::open_file(&ledger_file).and_then(|lines| {
            verified_sums(
                &pdir,
                lines.inspect(|b| {
                    if let Ok(b) = b {
                        seen.push(crate::ledger::nullifier_of(b).to_vec());
                    }
                }),
            )
        });
        for nul in seen {
            match nullifiers.get(&nul) {
                Some(&other) if other != k => collisions.push(format!(
                    "nullifier {} is in the ledgers of {} and {}",
                    hex::encode(&nul),
                    registry[other].precinct_id,
                    entry.precinct_id
                )),
                Some(_) => {}
                None => {
                    nullifiers.insert(nul, k);
                }
            }
        }
        let audit =
            crate::demo::audit_stream_dir_observed(&pdir, true, &mut |_, _| {}).map(|(sa, _)| sa);
        ledgers.push(PrecinctLedger {
            sums,
            close: read_json(&pdir.join(CLOSE_FILE)),
            audit,
        });
    }

    // -- returns as received -------------------------------------------------
    let rdir = ndir.join(RETURNS_DIR);
    let mut files: Vec<PathBuf> = match std::fs::read_dir(&rdir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect(),
        Err(e) => return Err(format!("read {}: {e}", rdir.display())),
    };
    files.sort();
    let index: HashMap<&str, usize> = registry
        .iter()
        .enumerate()
        .map(|(k, e)| (e.precinct_id.as_str(), k))
        .collect();
    // The first return (file-name order) naming a registered precinct is the
    // one counted for it; any further one is a duplicate.
    let mut received: Vec<Option<(String, PrecinctReturn)>> = vec![None; registry.len()];
    let mut registry_problems = Vec::new();
    for path in &files {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let ret: PrecinctReturn = match read_json(path) {
            Ok(r) => r,
            Err(e) => {
                registry_problems.push(format!("{name}: unreadable return ({e})"));
                continue;
            }
        };
        let Some(&k) = index.get(ret.precinct_id.as_str()) else {
            registry_problems.push(format!(
                "{name}: precinct {:?} is not in the registry",
                ret.precinct_id
            ));
            continue;
        };
        let want = format!("{base}-{}", ret.precinct_id);
        if ret.election_id != want {
            registry_problems.push(format!(
                "{name}: election id {:?} is not {want:?}",
                ret.election_id
            ));
        }
        match &received[k] {
            Some((first, _)) => registry_problems.push(format!(
                "{name}: second return for {} (first: {first})",
                ret.precinct_id
            )),
            None => received[k] = Some((name, ret)),
        }
    }
    let mut checks = vec![CanvassCheck::new(
        CHECKS[0],
        &registry_problems,
        format!(
            "{} returns, each for a distinct registered precinct of {base}",
            files.len()
        ),
    )];

    // -- completeness -------------------------------------------------------
    let missing: Vec<&str> = registry
        .iter()
        .zip(&received)
        .filter(|(_, r)| r.is_none())
        .map(|(e, _)| e.precinct_id.as_str())
        .collect();
    let problems = if missing.is_empty() {
        vec![]
    } else {
        vec![format!("no return from {}", missing.join(", "))]
    };
    checks.push(CanvassCheck::new(
        CHECKS[1],
        &problems,
        format!("all {} registered precincts returned", registry.len()),
    ));

    // -- signature ----------------------------------------------------------
    let mut sig_ok: Vec<Option<bool>> = vec![None; registry.len()];
    let mut problems = Vec::new();
    for (k, r) in received.iter().enumerate() {
        let Some((name, ret)) = r else { continue };
        let verdict = parse_hex32(&registry[k].authority_pubkey_hex, "registry key")
            .and_then(|pk| ret.verify(&pk));
        sig_ok[k] = Some(verdict.is_ok());
        if let Err(e) = verdict {
            problems.push(format!("{name} ({}): {e}", ret.precinct_id));
        }
    }
    checks.push(CanvassCheck::new(
        CHECKS[2],
        &problems,
        "every return verifies under its registered authority key",
    ));

    // -- precinct recompute -------------------------------------------------
    let mut rec_ok: Vec<Option<bool>> = vec![None; registry.len()];
    let mut problems = Vec::new();
    for (k, r) in received.iter().enumerate() {
        let Some((_, ret)) = r else { continue };
        let pid = &ret.precinct_id;
        let mut diffs = Vec::new();
        match &ledgers[k].sums {
            Err(e) => diffs.push(format!("ledger read-back: {e}")),
            Ok(s) => {
                if ret.record_count != s.record_count {
                    diffs.push(format!(
                        "record count {} vs ledger {}",
                        ret.record_count, s.record_count
                    ));
                }
                if ret.ledger_digest != s.ledger_digest {
                    diffs.push("ledger digest differs".into());
                }
                let theirs: Vec<_> = ret
                    .contests
                    .iter()
                    .map(|c| (c.contest_id.clone(), c.sum_c1, c.sum_c2))
                    .collect();
                if theirs != s.contests {
                    let which: Vec<&str> = s
                        .contests
                        .iter()
                        .filter(|c| !theirs.contains(c))
                        .map(|c| c.0.as_str())
                        .collect();
                    diffs.push(format!("aggregates differ ({})", which.join(", ")));
                }
            }
        }
        match &ledgers[k].close {
            Err(e) => diffs.push(format!("close reference: {e}")),
            Ok(c) => {
                if ret.close_block != c.close_block {
                    diffs.push(format!(
                        "close block {} vs close.json {}",
                        ret.close_block, c.close_block
                    ));
                }
                if hex::encode(ret.close_tip_hash) != c.close_tip_hash.trim().to_lowercase() {
                    diffs.push("close tip hash differs from close.json".into());
                }
            }
        }
        rec_ok[k] = Some(diffs.is_empty());
        if !diffs.is_empty() {
            problems.push(format!("{pid}: {}", diffs.join(", ")));
        }
    }
    checks.push(CanvassCheck::new(
        CHECKS[3],
        &problems,
        "every return equals the recompute from its ledger read-back and close reference",
    ));

    // -- national sum -------------------------------------------------------
    let national_sum = (|| -> Result<Vec<String>, String> {
        let n = contest_ids.len();
        let mut c1 = vec![RistrettoPoint::identity(); n];
        let mut c2 = vec![RistrettoPoint::identity(); n];
        for (_, ret) in received.iter().flatten() {
            if ret.contests.len() != n {
                return Err(format!(
                    "{}: {} contests, want {n}",
                    ret.precinct_id,
                    ret.contests.len()
                ));
            }
            for (c, rc) in ret.contests.iter().enumerate() {
                c1[c] += point(&rc.sum_c1, &format!("{} Σc1", ret.precinct_id))?;
                c2[c] += point(&rc.sum_c2, &format!("{} Σc2", ret.precinct_id))?;
            }
        }
        if national_agg.contests.len() != n {
            return Err(format!(
                "{AGGREGATE_FILE} has {} contests, want {n}",
                national_agg.contests.len()
            ));
        }
        Ok(national_agg
            .contests
            .iter()
            .enumerate()
            .filter(|(c, a)| {
                hex::encode(compress_point(&c1[*c])) != a.c1.to_lowercase()
                    || hex::encode(compress_point(&c2[*c])) != a.c2.to_lowercase()
            })
            .map(|(_, a)| a.contest_id.clone())
            .collect())
    })();
    let problems = match national_sum {
        Err(e) => vec![e],
        Ok(bad) if bad.is_empty() => vec![],
        Ok(bad) => vec![format!(
            "product of returned aggregates differs from the national aggregate in {}",
            bad.join(", ")
        )],
    };
    checks.push(CanvassCheck::new(
        CHECKS[4],
        &problems,
        format!(
            "product of {} returned aggregates equals the national aggregate",
            received.iter().flatten().count()
        ),
    ));

    // -- accuracy -----------------------------------------------------------
    let mut problems = Vec::new();
    let mut rows = Vec::with_capacity(registry.len());
    for (k, entry) in registry.iter().enumerate() {
        let pl = &ledgers[k];
        let (records, verified, aggregates) = match &pl.sums {
            Ok(s) => (
                s.record_count,
                s.verified,
                s.contests
                    .iter()
                    .map(|(id, a, b)| AggregateContest {
                        contest_id: id.clone(),
                        c1: hex::encode(a),
                        c2: hex::encode(b),
                    })
                    .collect(),
            ),
            Err(_) => (0, 0, vec![]),
        };
        let (e, audit) = match &pl.audit {
            Ok(sa) => {
                let e: Vec<i64> = sa.contests.iter().map(|c| c.e).collect();
                if sa.overall != "pass" || e.iter().any(|&x| x != 0) {
                    let failed: Vec<&str> =
                        sa.failed_checks.iter().map(|f| f.check.as_str()).collect();
                    problems.push(format!(
                        "{}: audit {} (failed: {}; E = {e:?})",
                        entry.precinct_id,
                        sa.overall,
                        failed.join(", ")
                    ));
                }
                (e, sa.overall.clone())
            }
            Err(err) => {
                problems.push(format!("{}: audit error: {err}", entry.precinct_id));
                (vec![], format!("error: {err}"))
            }
        };
        rows.push(PrecinctRow {
            precinct_id: entry.precinct_id.clone(),
            records,
            verified,
            aggregates,
            signature_ok: sig_ok[k],
            recompute_ok: rec_ok[k],
            e,
            audit,
        });
    }
    let national = national_accuracy(&nheader, &nparams, &ledgers);
    if let Err(e) = &national.1 {
        problems.push(format!("national: {e}"));
    }
    checks.push(CanvassCheck::new(
        CHECKS[5],
        &problems,
        format!(
            "{} precinct audits pass with E = 0; national decryption of the ledger product gives E = 0",
            registry.len()
        ),
    ));

    // -- nullifier uniqueness ----------------------------------------------
    checks.push(CanvassCheck::new(
        CHECKS[6],
        &collisions,
        format!(
            "{} nullifiers, none in two precinct ledgers",
            nullifiers.len()
        ),
    ));

    let pass = checks.iter().all(CanvassCheck::passed);
    Ok(Canvass {
        base_election_id: base,
        precincts: rows,
        national: NationalRow {
            pass: national.1.is_ok(),
            contests: national.0,
        },
        checks,
        pass,
    })
}

/// The national half of `canvass.accuracy`: multiply the ledger-recomputed
/// precinct aggregates, verify the national partial decryptions against that
/// product, decode, and compare with the national ground truth and the
/// published, trustee-signed national tally.
fn national_accuracy(
    nheader: &StreamHeader,
    nparams: &ElectionParameters,
    ledgers: &[PrecinctLedger],
) -> (Vec<NationalContest>, Result<(), String>) {
    let n = nparams.contest_ids.len();
    let gt = |c: usize| nheader.ground_truth.get(c).copied().unwrap_or(0);
    let mut agg = vec![
        Ciphertext {
            pad: RistrettoPoint::identity(),
            data: RistrettoPoint::identity(),
        };
        n
    ];
    let mut records = 0u64;
    let mut err = None;
    for (k, pl) in ledgers.iter().enumerate() {
        match &pl.sums {
            Ok(s) => {
                records += s.record_count;
                for (c, (_, a, b)) in s.contests.iter().enumerate().take(n) {
                    match (point(a, "Σc1"), point(b, "Σc2")) {
                        (Ok(a), Ok(b)) => {
                            agg[c].pad += a;
                            agg[c].data += b;
                        }
                        _ => err = Some(format!("precinct #{} sums are not points", k + 1)),
                    }
                }
            }
            Err(e) => err = Some(format!("precinct #{} ledger unreadable: {e}", k + 1)),
        }
    }
    let decoded = match err {
        Some(e) => Err(e),
        None => decrypt_national(nheader, nparams, &agg, records),
    };
    let contests = nparams
        .contest_ids
        .iter()
        .enumerate()
        .map(|(c, id)| {
            let d = decoded.as_ref().ok().and_then(|d| d.get(c).copied());
            NationalContest {
                contest_id: id.clone(),
                c1: hex::encode(compress_point(&agg[c].pad)),
                c2: hex::encode(compress_point(&agg[c].data)),
                decoded: d,
                ground_truth: gt(c),
                e: d.map(|d| d as i64 - gt(c) as i64),
            }
        })
        .collect::<Vec<_>>();
    let verdict = decoded.and_then(|_| {
        let bad: Vec<String> = contests
            .iter()
            .filter(|c| c.e != Some(0))
            .map(|c| format!("{} E = {:?}", c.contest_id, c.e))
            .collect();
        if bad.is_empty() {
            Ok(())
        } else {
            Err(bad.join(", "))
        }
    });
    (contests, verdict)
}

/// Verifies the national partials against `aggregate`, decodes, and requires
/// the published national tally to equal the decoded totals and carry valid
/// trustee signatures.
fn decrypt_national(
    nheader: &StreamHeader,
    nparams: &ElectionParameters,
    aggregate: &[Ciphertext],
    max: u64,
) -> Result<Vec<u64>, String> {
    let hexd = |s: &str, what: &str| hex::decode(s).map_err(|e| format!("{what} not hex: {e}"));
    let dkg = DKGTranscript::decode(&hexd(&nheader.dkg, "dkg")?[..])
        .map_err(|e| format!("decode dkg: {e}"))?;
    let partials: Vec<PartialDecryption> = nheader
        .partial_decryptions
        .iter()
        .map(|p| {
            PartialDecryption::decode(&hexd(p, "partial")?[..])
                .map_err(|e| format!("decode partial: {e}"))
        })
        .collect::<Result<_, String>>()?;
    let tally = TallyResult::decode(&hexd(&nheader.tally, "tally")?[..])
        .map_err(|e| format!("decode tally: {e}"))?;
    let binding = hexd(&nheader.binding_context, "binding_context")?;
    let mut builder = crate::report::ReportBuilder::new();
    let dkg_v = crate::dkg::verify_dkg_transcript(nparams, &dkg, &mut builder)
        .ok_or("national DKG transcript does not verify")?;
    let totals = crate::fixtures::decrypt_totals_bound(
        nparams,
        aggregate,
        &partials,
        &dkg_v.trustee_share_publics,
        &binding,
        max,
    )?;
    if totals != tally.totals {
        return Err(format!(
            "published national tally {:?} differs from the decryption {totals:?}",
            tally.totals
        ));
    }
    crate::tally::verify_tally_signatures(
        nparams,
        &tally,
        &dkg_v.trustee_share_publics,
        &mut builder,
    );
    let report = builder.finish();
    if !report.passed() {
        let f: Vec<String> = report
            .findings
            .iter()
            .filter(|f| f.status == crate::AuditStatus::Fail)
            .map(|f| format!("{}: {}", f.check, f.detail))
            .collect();
        return Err(f.join("; "));
    }
    Ok(totals)
}

/// Writes `canvass-checks.csv` and `canvass.json` into `out`.
pub fn write_outputs(out: &Path, result: &Canvass) -> Result<(), String> {
    std::fs::create_dir_all(out).map_err(|e| format!("create {}: {e}", out.display()))?;
    let mut csv = String::from("check,verdict,reason\n");
    for c in &result.checks {
        let _ = writeln!(
            csv,
            "{},{},\"{}\"",
            c.check,
            c.verdict,
            c.reason.replace('"', "\"\"")
        );
    }
    let path = out.join(CHECKS_CSV);
    std::fs::write(&path, csv).map_err(|e| format!("write {}: {e}", path.display()))?;
    let path = out.join(CANVASS_JSON);
    let json = serde_json::to_string_pretty(result).expect("canvass serialises");
    std::fs::write(&path, json + "\n").map_err(|e| format!("write {}: {e}", path.display()))
}

/// What `audit-canvass --help` prints.
pub const HELP: &str = "\
usage: saksi-demo audit-canvass <dir> [--json] [--out <dir>]

National canvass over a precinct generation <dir> holding national/ and
precinct-NN/ folders. Reads the returns in national/returns/, the registry, the
national header and aggregate, and each precinct's header.json, ballots.ndjson,
ledger/ballots.ndjson and close.json. Runs seven checks (canvass.registry,
canvass.completeness, canvass.signature, canvass.precinct_recompute,
canvass.national_sum, canvass.accuracy, canvass.nullifier_unique), all of them
even after a failure.

Writes canvass-checks.csv and canvass.json to --out (default <dir>). --json
prints canvass.json to stdout; otherwise the check table is printed.
Exit 0 only if every check passes, 1 if any fails, 2 on a usage or input error.";

/// `saksi-demo audit-canvass` entry point.
pub fn cli(args: &[String]) -> ExitCode {
    let (mut dir, mut out, mut json) = (None, None, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--help" | "-h" => {
                println!("{HELP}");
                return ExitCode::SUCCESS;
            }
            "--json" => json = true,
            "--out" => match it.next() {
                Some(v) => out = Some(PathBuf::from(v)),
                None => return usage("--out needs a value"),
            },
            s if s.starts_with("--") => return usage(&format!("unknown flag {s}")),
            s if dir.is_none() => dir = Some(PathBuf::from(s)),
            s => return usage(&format!("unexpected argument {s}")),
        }
    }
    let Some(dir) = dir else {
        return usage("missing <dir>");
    };
    let out = out.unwrap_or_else(|| dir.clone());
    let result = match canvass(&dir).and_then(|r| write_outputs(&out, &r).map(|()| r)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("audit-canvass: {e}");
            return ExitCode::from(2);
        }
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).expect("canvass serialises")
        );
    } else {
        for c in &result.checks {
            println!("{} {}: {}", c.verdict, c.check, c.reason);
        }
        println!("overall: {}", if result.pass { "pass" } else { "fail" });
    }
    if result.pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn usage(msg: &str) -> ExitCode {
    eprintln!("audit-canvass: {msg}\n\n{HELP}");
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{GenParams, SelectionProfile};
    use crate::precinct_return::{read_authority_key, sign_return};
    use crate::stream::{precinct_id, AUTHORITY_KEY_FILE};
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;
    use std::sync::OnceLock;

    const BASE: &str = "cv-test";
    const PRECINCTS: usize = 3;

    fn close_ref(k: usize) -> CloseRef {
        CloseRef {
            close_block: 100 + k as u64,
            close_tip_hash: hex::encode([k as u8 + 1; 32]),
        }
    }

    fn ledger_file(dir: &Path, pid: &str) -> PathBuf {
        precinct_dir(dir, pid)
            .join(crate::demo::LEDGER_DIR)
            .join(BALLOTS_FILE)
    }

    /// Lines of the ndjson file `src`, sorted into the chain's nullifier order.
    fn sorted_lines(src: &Path) -> Vec<String> {
        let raw = std::fs::read_to_string(src).unwrap();
        let mut lines: Vec<(Vec<u8>, String)> = raw
            .lines()
            .map(|l| {
                let b = saksi_protocol::Ballot::decode(&hex::decode(l).unwrap()[..]).unwrap();
                (crate::ledger::nullifier_of(&b).to_vec(), l.to_string())
            })
            .collect();
        lines.sort();
        lines.into_iter().map(|(_, l)| l).collect()
    }

    fn write_lines(path: &Path, lines: &[String]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, lines.join("\n") + "\n").unwrap();
    }

    fn key(dir: &Path, pid: &str) -> Scalar {
        read_authority_key(&precinct_dir(dir, pid).join(AUTHORITY_KEY_FILE)).unwrap()
    }

    /// Signs `pid`'s return over `ledger` with `secret` and the fixture close
    /// reference of that precinct.
    fn sign(dir: &Path, pid: &str, ledger: &Path, secret: &Scalar) -> PrecinctReturn {
        let k: usize = pid[1..].parse::<usize>().unwrap() - 1;
        let c = close_ref(k);
        let tip = parse_hex32(&c.close_tip_hash, "tip").unwrap();
        sign_return(
            &precinct_dir(dir, pid),
            ledger,
            c.close_block,
            tip,
            secret,
            &mut OsRng,
        )
        .unwrap()
        .0
    }

    fn put_return(dir: &Path, file: &str, ret: &PrecinctReturn) {
        let path = dir.join(NATIONAL_DIR).join(RETURNS_DIR).join(file);
        std::fs::write(path, serde_json::to_string_pretty(ret).unwrap()).unwrap();
    }

    fn get_return(dir: &Path, pid: &str) -> PrecinctReturn {
        read_json(
            &dir.join(NATIONAL_DIR)
                .join(RETURNS_DIR)
                .join(format!("{pid}.json")),
        )
        .unwrap()
    }

    /// A clean 3-precinct canvass: `gen --precincts 3` on 30 voters x 2
    /// positions x 3 candidates, ledger read-backs faked as the console record
    /// in nullifier order, `close.json`, signed returns copied to
    /// `national/returns/`.
    fn fixture() -> &'static PathBuf {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("saksi-canvass-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let mut params = GenParams::simple(30, 2, 3, SelectionProfile::Realistic);
            params.election_id = BASE.into();
            crate::demo::write_precinct_streams_params(&dir, &params, PRECINCTS, None, 0)
                .expect("gen --precincts 3");
            std::fs::create_dir_all(dir.join(NATIONAL_DIR).join(RETURNS_DIR)).unwrap();
            for k in 0..PRECINCTS {
                let pid = precinct_id(k);
                let pdir = precinct_dir(&dir, &pid);
                let ledger = ledger_file(&dir, &pid);
                write_lines(&ledger, &sorted_lines(&pdir.join(BALLOTS_FILE)));
                std::fs::write(
                    pdir.join(CLOSE_FILE),
                    serde_json::to_string(&close_ref(k)).unwrap(),
                )
                .unwrap();
                let ret = sign(&dir, &pid, &ledger, &key(&dir, &pid));
                put_return(&dir, &format!("{pid}.json"), &ret);
            }
            dir
        })
    }

    fn copy_dir(src: &Path, dst: &Path) {
        std::fs::create_dir_all(dst).unwrap();
        for e in std::fs::read_dir(src).unwrap() {
            let e = e.unwrap();
            let to = dst.join(e.file_name());
            if e.file_type().unwrap().is_dir() {
                copy_dir(&e.path(), &to);
            } else {
                std::fs::copy(e.path(), to).unwrap();
            }
        }
    }

    /// A private copy of the clean fixture for one mutation.
    fn fresh(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("saksi-canvass-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        copy_dir(fixture(), &dir);
        dir
    }

    /// Runs the canvass and requires exactly the checks in `want` to fail.
    fn expect_failed(dir: &Path, want: &[&str]) -> Canvass {
        let result = canvass(dir).expect("canvass runs");
        assert_eq!(result.checks.len(), CHECKS.len(), "every check runs");
        assert_eq!(result.failed(), want, "checks: {:#?}", result.checks);
        assert_eq!(result.pass, want.is_empty());
        let _ = std::fs::remove_dir_all(dir);
        result
    }

    fn reason<'a>(r: &'a Canvass, check: &str) -> &'a str {
        &r.check(check).unwrap().reason
    }

    #[test]
    fn clean_canvass_passes_and_writes_outputs() {
        let dir = fresh("clean");
        assert_eq!(cli(&[dir.display().to_string()]), ExitCode::SUCCESS);
        let csv = std::fs::read_to_string(dir.join(CHECKS_CSV)).unwrap();
        assert_eq!(csv.lines().count(), 1 + CHECKS.len());
        assert!(csv.lines().skip(1).all(|l| l.contains(",pass,")), "{csv}");
        let result: Canvass = read_json(&dir.join(CANVASS_JSON)).unwrap();
        assert!(result.pass);
        assert_eq!(result.precincts.len(), PRECINCTS);
        for row in &result.precincts {
            assert_eq!((row.records, row.verified), (20, 20));
            assert_eq!(row.signature_ok, Some(true));
            assert_eq!(row.recompute_ok, Some(true));
            assert_eq!(row.audit, "pass");
            assert_eq!(row.e, vec![0; 6]);
        }
        assert!(result.national.pass);
        let total: u64 = result
            .national
            .contests
            .iter()
            .map(|c| c.ground_truth)
            .sum();
        assert_eq!(total, 60);
        assert!(result.national.contests.iter().all(|c| c.e == Some(0)));
        // The ledger product equals the generator's national aggregate.
        let agg: AggregateFile = read_json(&dir.join(NATIONAL_DIR).join(AGGREGATE_FILE)).unwrap();
        for (n, a) in result.national.contests.iter().zip(&agg.contests) {
            assert_eq!((&n.c1, &n.c2), (&a.c1, &a.c2));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn t9_byte_flip_after_signing() {
        let dir = fresh("t9");
        let mut ret = get_return(&dir, "p02");
        ret.contests[0].sum_c2[5] ^= 0x01;
        put_return(&dir, "p02.json", &ret);
        let r = expect_failed(
            &dir,
            &[
                "canvass.signature",
                "canvass.precinct_recompute",
                "canvass.national_sum",
            ],
        );
        assert_eq!(r.precincts[1].signature_ok, Some(false));
    }

    #[test]
    fn t10_duplicate_return() {
        let dir = fresh("t10");
        put_return(&dir, "p02-again.json", &get_return(&dir, "p02"));
        let r = expect_failed(&dir, &["canvass.registry"]);
        assert!(reason(&r, "canvass.registry").contains("second return for p02"));
    }

    #[test]
    fn t11_unregistered_precinct_with_fresh_key() {
        let dir = fresh("t11");
        let mut ret = get_return(&dir, "p02");
        ret.precinct_id = "p09".into();
        ret.election_id = format!("{BASE}-p09");
        ret.sign(&Scalar::random(&mut OsRng), &mut OsRng);
        put_return(&dir, "p09.json", &ret);
        let r = expect_failed(&dir, &["canvass.registry"]);
        assert!(reason(&r, "canvass.registry").contains("not in the registry"));
    }

    #[test]
    fn t12_relabel() {
        // p01's return relabelled p02 and substituted for p02's.
        let dir = fresh("t12");
        let mut ret = get_return(&dir, "p01");
        ret.precinct_id = "p02".into();
        ret.election_id = format!("{BASE}-p02");
        put_return(&dir, "p02.json", &ret);
        expect_failed(
            &dir,
            &[
                "canvass.signature",
                "canvass.precinct_recompute",
                "canvass.national_sum",
            ],
        );
    }

    #[test]
    fn t13_missing_return() {
        let dir = fresh("t13");
        std::fs::remove_file(dir.join(NATIONAL_DIR).join(RETURNS_DIR).join("p02.json")).unwrap();
        let r = expect_failed(&dir, &["canvass.completeness", "canvass.national_sum"]);
        assert_eq!(reason(&r, "canvass.completeness"), "no return from p02");
        assert_eq!(r.precincts[1].signature_ok, None);
    }

    #[test]
    fn t14_wrong_election_id() {
        let dir = fresh("t14a");
        let mut ret = get_return(&dir, "p02");
        ret.election_id = "other-p02".into();
        ret.sign(&key(&dir, "p02"), &mut OsRng);
        put_return(&dir, "p02.json", &ret);
        let r = expect_failed(&dir, &["canvass.registry"]);
        assert!(reason(&r, "canvass.registry").contains("election id"));
    }

    #[test]
    fn t14_stale_close_block() {
        let dir = fresh("t14b");
        let mut ret = get_return(&dir, "p02");
        ret.close_block -= 1;
        ret.sign(&key(&dir, "p02"), &mut OsRng);
        put_return(&dir, "p02.json", &ret);
        let r = expect_failed(&dir, &["canvass.precinct_recompute"]);
        assert!(reason(&r, "canvass.precinct_recompute").contains("close block"));
    }

    #[test]
    fn t15_ballot_omitted_before_signing() {
        let dir = fresh("t15");
        let mut lines = sorted_lines(&ledger_file(&dir, "p02"));
        lines.remove(7);
        let doctored = dir.join("p02-doctored.ndjson");
        write_lines(&doctored, &lines);
        let ret = sign(&dir, "p02", &doctored, &key(&dir, "p02"));
        put_return(&dir, "p02.json", &ret);
        let r = expect_failed(
            &dir,
            &["canvass.precinct_recompute", "canvass.national_sum"],
        );
        let why = reason(&r, "canvass.precinct_recompute");
        assert!(why.contains("record count 19 vs ledger 20"), "{why}");
    }

    #[test]
    fn t16_forged_aggregates_with_the_real_key() {
        let dir = fresh("t16");
        let mut ret = get_return(&dir, "p02");
        let bumped =
            point(&ret.contests[0].sum_c2, "c2").unwrap() + saksi_crypto::group::basepoint();
        ret.contests[0].sum_c2 = compress_point(&bumped);
        ret.sign(&key(&dir, "p02"), &mut OsRng);
        put_return(&dir, "p02.json", &ret);
        let r = expect_failed(
            &dir,
            &["canvass.precinct_recompute", "canvass.national_sum"],
        );
        assert!(reason(&r, "canvass.precinct_recompute").contains("aggregates differ"));
    }

    #[test]
    fn t21_signed_with_another_registered_key() {
        let dir = fresh("t21");
        let mut ret = get_return(&dir, "p02");
        ret.sign(&key(&dir, "p01"), &mut OsRng);
        put_return(&dir, "p02.json", &ret);
        expect_failed(&dir, &["canvass.signature"]);
    }

    #[test]
    fn t24_national_aggregate_altered_after_acceptance() {
        // One accepted aggregate replaced in the national record: p01's
        // contribution to the first contest swapped for p02's.
        let dir = fresh("t24");
        let path = dir.join(NATIONAL_DIR).join(AGGREGATE_FILE);
        let mut agg: AggregateFile = read_json(&path).unwrap();
        let r1 = get_return(&dir, "p01");
        let r2 = get_return(&dir, "p02");
        let c2 = point(&parse_hex32(&agg.contests[0].c2, "c2").unwrap(), "c2").unwrap()
            - point(&r1.contests[0].sum_c2, "p01").unwrap()
            + point(&r2.contests[0].sum_c2, "p02").unwrap();
        agg.contests[0].c2 = hex::encode(compress_point(&c2));
        std::fs::write(&path, serde_json::to_string(&agg).unwrap()).unwrap();
        expect_failed(&dir, &["canvass.national_sum"]);
    }

    #[test]
    fn t19_same_ballot_in_two_precinct_ledgers() {
        // A p01 ballot committed again on p02, and p02's return built over
        // that ledger.
        let dir = fresh("t19");
        let stolen = sorted_lines(&ledger_file(&dir, "p01"))[3].clone();
        let p02 = ledger_file(&dir, "p02");
        let mut lines = sorted_lines(&p02);
        lines.push(stolen);
        write_lines(&p02, &lines);
        write_lines(&p02, &sorted_lines(&p02));
        let ret = sign(&dir, "p02", &p02, &key(&dir, "p02"));
        put_return(&dir, "p02.json", &ret);
        let r = expect_failed(&dir, &["canvass.accuracy", "canvass.nullifier_unique"]);
        assert!(reason(&r, "canvass.nullifier_unique").contains("ledgers of p01 and p02"));
        // p02's own audit refuses the read-back: it no longer matches the record.
        let why = reason(&r, "canvass.accuracy");
        assert!(
            why.starts_with("p02: audit fail") && why.contains("ledger.order"),
            "{why}"
        );
        // Recorded but not summed under p02's election.
        assert_eq!((r.precincts[1].records, r.precincts[1].verified), (21, 20));
    }
}
