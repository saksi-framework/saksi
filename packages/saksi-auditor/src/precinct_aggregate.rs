//! `saksi-demo precinct-aggregate`: re-aggregate an archived run by precinct,
//! without decryption (the paper's "A-additive" re-analysis).
//!
//! One streamed, fully verified pass over a run folder's **console record**
//! (`ballots.ndjson`, line number = ballot index, voter-major) folds, beside the
//! auditor's own region aggregate, a second set of per-contest aggregates
//! `(Σc1, Σc2)` per precinct, where `voter = idx / positions` and
//! `precinct = voter / K`. It then checks:
//!
//! - `combine.product`: the product (group sum) of the precinct aggregates
//!   equals the region aggregate recomputed in the same pass, byte for byte,
//!   for both components;
//! - `combine.audit_fold`: that region `Σc2` equals the aggregate the auditor
//!   itself folded (the one its threshold decryption was verified against);
//! - `combine.correctness_csv` (with `--correctness`): the region `Σc2` equals
//!   the committed `aggregate_ciphertext` column;
//! - `combine.ground_truth` (with `--ground-truth`): the per-precinct ground
//!   truths, a group-by over `ground-truth-ballots.csv`, sum to the region
//!   ground truth in `header.json`;
//! - `audit`: the full stream audit (every ballot proof, the partial
//!   decryptions over `Σc1`, the tally) passed.
//!
//! Per-precinct E is **not available** for an archived record: the election
//! secret key and the trustee shares lived only in the generator's memory and
//! no longer exist (by design), so no precinct aggregate can be decrypted.
//! `precincts.csv` says so in every `e` column.
//!
//! The chain's read-back (`ledger/ballots.ndjson`) is in nullifier order, not
//! index order, so it cannot be partitioned by line; this subcommand reads the
//! console record only and skips the `ledger.order` check.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufRead, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use saksi_crypto::group::compress_point;

/// What `precinct-aggregate --help` prints.
pub const HELP: &str = "\
usage: saksi-demo precinct-aggregate <run dir> --precinct-size K
         [--ground-truth <ground-truth-ballots.csv>] [--correctness <correctness.csv>]
         [--out <dir>] [--json]

Re-aggregates a run's console record (<run dir>/ballots.ndjson, line = ballot
index, voter = line / positions, precinct = voter / K) by precinct in one
verified streaming pass, and checks that the precinct aggregates combine to the
region aggregate. Reads the console record only: the ledger read-back
(ledger/ballots.ndjson) is in nullifier order and is not used.

Writes to --out (default <run dir>/precinct-aggregate/): precincts.csv,
combine.txt, summary.json. --json also prints summary.json to stdout.
Exit 0 only if every check passes.

Per-precinct E is unavailable for archived records: the decryption key and the
trustee shares no longer exist (by design), so precinct aggregates cannot be
decrypted. The e column reads \"n/a (no key)\".";

/// The `e` cell of every precinct row (see the module docs).
pub const NO_KEY: &str = "n/a (no key)";

/// One precinct's fold.
#[derive(Debug, Clone)]
pub struct Precinct {
    /// Eligible (fully verified) ballot records folded into this precinct.
    pub records: usize,
    /// Per contest `Σc1` (pads).
    pub c1: Vec<RistrettoPoint>,
    /// Per contest `Σc2` (data).
    pub c2: Vec<RistrettoPoint>,
}

impl Precinct {
    fn new(contests: usize) -> Self {
        Self {
            records: 0,
            c1: vec![RistrettoPoint::identity(); contests],
            c2: vec![RistrettoPoint::identity(); contests],
        }
    }
}

/// Result of the verified per-precinct pass over one run folder.
#[derive(Debug, Clone)]
pub struct PrecinctFold {
    /// Voters per precinct (`K`).
    pub precinct_size: usize,
    /// Positions per voter (records per voter).
    pub positions: usize,
    /// Candidates per position.
    pub candidates: usize,
    /// Voters in the run (`header.n / positions`).
    pub voters: usize,
    /// Contest ids, in contest order.
    pub contests: Vec<String>,
    /// Per precinct, in precinct order (`ceil(voters / K)` of them).
    pub precincts: Vec<Precinct>,
    /// Region fold recomputed in the same pass, `(Σc1, Σc2)` per contest.
    pub region: Precinct,
    /// The auditor's own `Σc2` per contest, compressed hex (from its evidence).
    pub audit_c2: Vec<String>,
    /// The region ground truth from `header.json`, per contest.
    pub region_ground_truth: Vec<u64>,
    /// `"pass"` / `"fail"` of the full stream audit.
    pub audit_overall: String,
    /// Failed audit check ids with their first detail.
    pub audit_failed: Vec<String>,
}

/// Runs the full stream audit over `dir`'s console record and folds every
/// eligible ballot into its precinct (`(idx / positions) / precinct_size`).
pub fn fold(dir: &Path, precinct_size: usize) -> Result<PrecinctFold, String> {
    if precinct_size < 1 {
        return Err("--precinct-size must be >= 1".to_string());
    }
    let header = crate::stream::read_header(dir)?;
    let positions = header.positions.max(1);
    let voters = header.n / positions;
    let contests = positions * header.candidates;
    let mut precincts: Vec<Precinct> = (0..voters.div_ceil(precinct_size))
        .map(|_| Precinct::new(contests))
        .collect();
    let mut region = Precinct::new(contests);

    let mut observe = |idx: usize, decoded: &[crate::ballot::DecodedCiphertext]| {
        let p = idx / positions / precinct_size;
        // A stream longer than the header fails the audit's
        // `stream.completeness`; growing here keeps the fold total either way.
        if p >= precincts.len() {
            precincts.resize_with(p + 1, || Precinct::new(contests));
        }
        let precinct = &mut precincts[p];
        precinct.records += 1;
        region.records += 1;
        for ct in decoded {
            precinct.c1[ct.contest] += ct.pad;
            precinct.c2[ct.contest] += ct.data;
            region.c1[ct.contest] += ct.pad;
            region.c2[ct.contest] += ct.data;
        }
    };
    let (audit, _) = crate::demo::audit_stream_dir_observed(dir, false, &mut observe)?;
    if audit.contests.len() != contests {
        return Err(format!(
            "header says {positions} positions x {} candidates but the parameters hold {} contests",
            header.candidates,
            audit.contests.len()
        ));
    }

    Ok(PrecinctFold {
        precinct_size,
        positions,
        candidates: header.candidates,
        voters,
        contests: audit.contests.iter().map(|c| c.contest.clone()).collect(),
        precincts,
        region,
        audit_c2: audit
            .contests
            .iter()
            .map(|c| c.aggregate_ciphertext.clone())
            .collect(),
        region_ground_truth: header.ground_truth,
        audit_overall: audit.overall,
        audit_failed: audit
            .failed_checks
            .iter()
            .map(|f| format!("{}: {}", f.check, f.detail))
            .collect(),
    })
}

/// Per-precinct ground truth: a group-by over `ground-truth-ballots.csv`
/// (`voter_id,scale_group,ballot_complexity,<POSITION...>`, `V-000001` = voter
/// 0, cells `CAND_<X>_NN` = candidate NN-1). `precinct_of` maps a voter index
/// to its precinct; voters it maps to `None` are not counted. Contest index is
/// `position * candidates + candidate`, the generator's slot order.
pub fn precinct_ground_truth(
    csv: &Path,
    positions: usize,
    candidates: usize,
    precincts: usize,
    precinct_of: impl Fn(usize) -> Option<usize>,
) -> Result<Vec<Vec<u64>>, String> {
    let file = File::open(csv).map_err(|e| format!("open {}: {e}", csv.display()))?;
    let mut lines = BufReader::new(file).lines();
    let head = lines
        .next()
        .ok_or_else(|| format!("{} is empty", csv.display()))?
        .map_err(|e| format!("read {}: {e}", csv.display()))?;
    if head.split(',').count() != 3 + positions {
        return Err(format!(
            "{}: header has {} columns, expected 3 + {positions} positions",
            csv.display(),
            head.split(',').count()
        ));
    }
    let mut out = vec![vec![0u64; positions * candidates]; precincts];
    for (row, line) in lines.enumerate() {
        let line = line.map_err(|e| format!("read {}: {e}", csv.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let bad = |what: &str| format!("{} row {}: {what}: {line:?}", csv.display(), row + 2);
        let cells: Vec<&str> = line.trim_end().split(',').collect();
        if cells.len() != 3 + positions {
            return Err(bad("wrong column count"));
        }
        let voter = cells[0]
            .strip_prefix("V-")
            .and_then(|n| n.parse::<usize>().ok())
            .and_then(|n| n.checked_sub(1))
            .ok_or_else(|| bad("voter_id is not V-<n>"))?;
        let Some(p) = precinct_of(voter) else {
            continue;
        };
        if p >= precincts {
            continue;
        }
        for (pos, cell) in cells[3..].iter().enumerate() {
            let k = cell
                .rsplit('_')
                .next()
                .and_then(|n| n.parse::<usize>().ok())
                .and_then(|n| n.checked_sub(1))
                .filter(|&k| k < candidates)
                .ok_or_else(|| bad("selection is not CAND_<X>_<n> within the candidates"))?;
            out[p][pos * candidates + k] += 1;
        }
    }
    Ok(out)
}

/// The region `aggregate_ciphertext` per contest from a `correctness.csv`
/// (rows with `source` empty or `local`; an on-chain run adds `ledger` rows).
pub fn correctness_aggregates(
    csv: &Path,
) -> Result<std::collections::HashMap<String, String>, String> {
    let text = std::fs::read_to_string(csv).map_err(|e| format!("read {}: {e}", csv.display()))?;
    let mut lines = text.lines();
    let head: Vec<&str> = lines.next().unwrap_or_default().split(',').collect();
    let col = |name: &str| head.iter().position(|h| h.trim() == name);
    let contest = col("contest").ok_or("correctness.csv has no contest column")?;
    let agg = col("aggregate_ciphertext").ok_or("correctness.csv has no aggregate_ciphertext")?;
    let source = col("source");
    Ok(lines
        .map(|l| l.split(',').collect::<Vec<_>>())
        .filter(|c| c.len() > contest.max(agg))
        .filter(|c| match source {
            None => true,
            Some(s) => matches!(c.get(s).copied(), None | Some("" | "local")),
        })
        .map(|c| (c[contest].to_string(), c[agg].to_string()))
        .collect())
}

/// One check's verdict.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Check {
    /// Check id (`audit`, `combine.product`, ...).
    pub check: String,
    /// Contest id, empty for whole-run checks.
    pub contest: String,
    /// Verdict.
    pub pass: bool,
    /// Why.
    pub detail: String,
}

fn io_err(p: &Path) -> impl Fn(std::io::Error) -> String + '_ {
    move |e| format!("write {}: {e}", p.display())
}

fn hex_point(p: &RistrettoPoint) -> String {
    hex::encode(compress_point(p))
}

/// Every check over a fold, the optional per-precinct ground truth, and the
/// optional committed `correctness.csv` aggregates.
pub fn checks(
    fold: &PrecinctFold,
    ground_truth: Option<&[Vec<u64>]>,
    correctness: Option<&std::collections::HashMap<String, String>>,
) -> Vec<Check> {
    let mut out = vec![Check {
        check: "audit".into(),
        contest: String::new(),
        pass: fold.audit_overall == "pass",
        detail: if fold.audit_failed.is_empty() {
            "every ballot, partial decryption and the tally verified".into()
        } else {
            fold.audit_failed.join("; ")
        },
    }];
    for (c, contest) in fold.contests.iter().enumerate() {
        let mut check = |name: &str, pass: bool, detail: String| {
            out.push(Check {
                check: name.into(),
                contest: contest.clone(),
                pass,
                detail,
            })
        };
        let (c1, c2) = fold.precincts.iter().fold(
            (RistrettoPoint::identity(), RistrettoPoint::identity()),
            |(a, b), p| (a + p.c1[c], b + p.c2[c]),
        );
        let region_c2 = hex_point(&fold.region.c2[c]);
        let same = compress_point(&c1) == compress_point(&fold.region.c1[c])
            && compress_point(&c2) == compress_point(&fold.region.c2[c]);
        check(
            "combine.product",
            same,
            format!(
                "product of {} precinct aggregates (Σc1 {}, Σc2 {}) vs region (Σc1 {}, Σc2 {region_c2})",
                fold.precincts.len(),
                hex_point(&c1),
                hex_point(&c2),
                hex_point(&fold.region.c1[c]),
            ),
        );
        let audit = fold.audit_c2.get(c).cloned().unwrap_or_default();
        check(
            "combine.audit_fold",
            audit == region_c2,
            format!("region Σc2 {region_c2} vs auditor's fold {audit}"),
        );
        if let Some(committed) = correctness {
            let want = committed.get(contest).cloned().unwrap_or_default();
            check(
                "combine.correctness_csv",
                want == region_c2,
                format!("region Σc2 {region_c2} vs correctness.csv {want:?}"),
            );
        }
        if let Some(gt) = ground_truth {
            let sum: u64 = gt.iter().map(|p| p.get(c).copied().unwrap_or(0)).sum();
            let region = fold.region_ground_truth.get(c).copied().unwrap_or(0);
            check(
                "combine.ground_truth",
                sum == region,
                format!("sum of precinct ground truths {sum} vs region {region}"),
            );
        }
    }
    out
}

/// Writes `precincts.csv`, `combine.txt` and `summary.json` into `out`; returns
/// the summary JSON.
pub fn write_outputs(
    out: &Path,
    run_dir: &Path,
    fold: &PrecinctFold,
    ground_truth: Option<&[Vec<u64>]>,
    checks: &[Check],
    run_time_s: f64,
) -> Result<String, String> {
    std::fs::create_dir_all(out).map_err(|e| format!("create {}: {e}", out.display()))?;

    let path = out.join("precincts.csv");
    let mut w = std::io::BufWriter::new(File::create(&path).map_err(io_err(&path))?);
    let mut head = "precinct,voter_start,voter_end,voters,records".to_string();
    for c in &fold.contests {
        if ground_truth.is_some() {
            let _ = write!(head, ",{c}:ground_truth");
        }
        let _ = write!(head, ",{c}:sum_c1_hex,{c}:sum_c2_hex,{c}:e");
    }
    writeln!(w, "{head}").map_err(io_err(&path))?;
    for (k, p) in fold.precincts.iter().enumerate() {
        let start = (k * fold.precinct_size).min(fold.voters);
        let end = ((k + 1) * fold.precinct_size).min(fold.voters);
        let mut row = format!(
            "{},{start},{end},{},{}",
            crate::stream::precinct_id(k),
            end - start,
            p.records
        );
        for c in 0..fold.contests.len() {
            if let Some(gt) = ground_truth {
                let _ = write!(row, ",{}", gt.get(k).and_then(|g| g.get(c)).unwrap_or(&0));
            }
            let _ = write!(
                row,
                ",{},{},{NO_KEY}",
                hex_point(&p.c1[c]),
                hex_point(&p.c2[c])
            );
        }
        writeln!(w, "{row}").map_err(io_err(&path))?;
    }
    w.flush().map_err(io_err(&path))?;

    let pass = checks.iter().all(|c| c.pass);
    let mut text = format!(
        "precinct-aggregate {}\nprecinct size {}, {} precincts, {} voters, {} records, {} contests\n\
         source: console record (ballots.ndjson); ledger read-back not used\n\
         per-precinct E: {NO_KEY} (decryption key and trustee shares no longer exist)\n\n",
        run_dir.display(),
        fold.precinct_size,
        fold.precincts.len(),
        fold.voters,
        fold.region.records,
        fold.contests.len()
    );
    for c in checks {
        let _ = writeln!(
            text,
            "{} {}{}: {} ({})",
            if c.pass { "yes" } else { "no " },
            c.check,
            if c.contest.is_empty() {
                String::new()
            } else {
                format!(" [{}]", c.contest)
            },
            if c.pass { "pass" } else { "FAIL" },
            c.detail
        );
    }
    let _ = writeln!(text, "\noverall: {}", if pass { "pass" } else { "FAIL" });
    let path = out.join("combine.txt");
    std::fs::write(&path, &text).map_err(io_err(&path))?;

    let summary = serde_json::json!({
        "run_dir": run_dir.display().to_string(),
        "source": "console record (ballots.ndjson); ledger read-back not used",
        "precinct_size": fold.precinct_size,
        "precincts": fold.precincts.len(),
        "contests": fold.contests.len(),
        "voters": fold.voters,
        "records": fold.region.records,
        "run_time_s": run_time_s,
        "audit_overall": fold.audit_overall,
        "per_precinct_e": NO_KEY,
        "checks": checks,
        "pass": pass,
        "exit_code": if pass { 0 } else { 1 },
    });
    let json = serde_json::to_string_pretty(&summary).expect("summary serializes");
    let path = out.join("summary.json");
    std::fs::write(&path, &json).map_err(io_err(&path))?;
    Ok(json)
}

/// The `saksi-demo precinct-aggregate` subcommand (`args` after the name).
pub fn cli(args: &[String]) -> ExitCode {
    match run(args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("precinct-aggregate: {e}\n\n{HELP}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<bool, String> {
    let (mut dir, mut size, mut gt, mut corr, mut out, mut json) =
        (None, None, None, None, None, false);
    let mut i = 0;
    while i < args.len() {
        let val = || {
            args.get(i + 1)
                .cloned()
                .ok_or(format!("{} needs a value", args[i]))
        };
        match args[i].as_str() {
            "--help" | "-h" => {
                println!("{HELP}");
                return Ok(true);
            }
            "--precinct-size" => {
                size = Some(
                    val()?
                        .parse::<usize>()
                        .ok()
                        .filter(|&k| k >= 1)
                        .ok_or("--precinct-size needs a positive integer")?,
                );
                i += 1;
            }
            "--ground-truth" => {
                gt = Some(PathBuf::from(val()?));
                i += 1;
            }
            "--correctness" => {
                corr = Some(PathBuf::from(val()?));
                i += 1;
            }
            "--out" => {
                out = Some(PathBuf::from(val()?));
                i += 1;
            }
            "--json" => json = true,
            a if a.starts_with("--") => return Err(format!("unknown flag {a}")),
            a if dir.is_none() => dir = Some(PathBuf::from(a)),
            a => return Err(format!("unexpected argument {a}")),
        }
        i += 1;
    }
    let dir = dir.ok_or("missing <run dir>")?;
    let size = size.ok_or("--precinct-size is required")?;
    let out = out.unwrap_or_else(|| dir.join("precinct-aggregate"));

    let started = Instant::now();
    let fold = fold(&dir, size)?;
    let ground_truth = gt
        .map(|p| {
            precinct_ground_truth(
                &p,
                fold.positions,
                fold.candidates,
                fold.precincts.len(),
                |v| Some(v / size),
            )
        })
        .transpose()?;
    let committed = corr.map(|p| correctness_aggregates(&p)).transpose()?;
    let checks = checks(&fold, ground_truth.as_deref(), committed.as_ref());
    let summary = write_outputs(
        &out,
        &dir,
        &fold,
        ground_truth.as_deref(),
        &checks,
        started.elapsed().as_secs_f64(),
    )?;
    if json {
        println!("{summary}");
    } else {
        print!(
            "{}",
            std::fs::read_to_string(out.join("combine.txt")).unwrap_or_default()
        );
        println!("wrote {}", out.display());
    }
    Ok(checks.iter().all(|c| c.pass))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{GenParams, SelectionProfile};

    #[test]
    fn precincts_combine_to_the_region_and_a_shifted_partition_fails() {
        let dir = std::env::temp_dir().join("saksi-precinct-aggregate-test");
        let _ = std::fs::remove_dir_all(&dir);
        let params = GenParams::simple(30, 2, 3, SelectionProfile::Skewed);
        crate::demo::write_election_stream_params(&dir, &params).expect("gen");
        let csv = dir.join(crate::ground_truth::GROUND_TRUTH_BALLOTS_CSV);

        let fold = fold(&dir, 7).expect("fold");
        assert_eq!(fold.audit_overall, "pass", "{:?}", fold.audit_failed);
        let records: Vec<usize> = fold.precincts.iter().map(|p| p.records).collect();
        assert_eq!(records, [14, 14, 14, 14, 4]);
        let gt = precinct_ground_truth(&csv, 2, 3, 5, |v| Some(v / 7)).expect("gt");
        let voters: Vec<u64> = gt.iter().map(|p| p[..3].iter().sum()).collect();
        assert_eq!(voters, [7, 7, 7, 7, 2], "voters per precinct");

        // The committed correctness.csv shape, built from the real audit.
        let audit = crate::demo::audit_stream_dir(&dir).expect("audit");
        let mut corr = "contest,aggregate_ciphertext,source\n".to_string();
        for c in &audit.contests {
            corr += &format!(
                "{},{},local\n{},deadbeef,ledger\n",
                c.contest, c.aggregate_ciphertext, c.contest
            );
        }
        let corr_path = dir.join("correctness.csv");
        std::fs::write(&corr_path, corr).expect("write correctness");
        let committed = correctness_aggregates(&corr_path).expect("parse");

        let all = checks(&fold, Some(&gt), Some(&committed));
        assert_eq!(all.len(), 1 + 6 * 4);
        assert!(all.iter().all(|c| c.pass), "{all:#?}");

        // Off by one: voter 0 lands nowhere, so the ground truths no longer sum.
        let shifted =
            precinct_ground_truth(&csv, 2, 3, 5, |v| v.checked_sub(1).map(|v| v / 7)).expect("gt");
        let bad = checks(&fold, Some(&shifted), None);
        assert!(bad
            .iter()
            .any(|c| c.check == "combine.ground_truth" && !c.pass));

        // A tampered precinct aggregate breaks the product.
        let mut tampered = fold.clone();
        tampered.precincts[2].c2[0] += curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        assert!(checks(&tampered, None, None)
            .iter()
            .any(|c| c.check == "combine.product" && !c.pass));

        let out = dir.join("out");
        let json = write_outputs(&out, &dir, &fold, Some(&gt), &all, 0.0).expect("write");
        assert!(json.contains("\"exit_code\": 0"));
        let rows = std::fs::read_to_string(out.join("precincts.csv")).expect("csv");
        assert_eq!(rows.lines().count(), 6);
        assert!(rows.lines().nth(5).unwrap().starts_with("p05,28,30,2,4,"));
        assert!(rows.contains(NO_KEY));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
