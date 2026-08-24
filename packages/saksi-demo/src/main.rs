//! `saksi-demo` — generate an election (bundle or stream) and audit one.
//!
//! Subcommands:
//!
//! - `gen [flags] [outfile]` — write a demo election. Flags:
//!   `--voters N --positions P --candidates C --distribution uniform|skewed`
//!   (population), `--election-id S --election-name S --threshold T --trustees N
//!   --trustee-names a,b,c` (identity + t-of-n DKG), and `--stream <dir>` to emit
//!   a streamed `header.json` + `ballots.ndjson` run folder instead of a one-blob
//!   bundle. With no flags, emits the legacy happy-path bundle; any flag switches
//!   to the parameterized generator (after the fail-closed validation gate).
//! - `audit <bundle.json>` — audit a one-blob bundle; exits non-zero on FAIL.
//! - `audit-stream <dir> [--json]` — audit a stream run folder; with `--json`,
//!   prints structured per-contest correctness `{overall, contests:[{contest,
//!   ground_truth, decoded, E, pass}]}`. Exits non-zero on FAIL.

use std::path::Path;
use std::process::ExitCode;

use saksi_auditor::demo::{
    audit_bundle_json, audit_stream_dir, election_bundle_json, election_bundle_json_params,
    write_election_stream_params, GenParams, SelectionProfile,
};
use saksi_auditor::ground_truth::write_ground_truth_csvs;
use saksi_auditor::{AuditReport, AuditStatus};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen") => cmd_gen(&args[2..]),
        Some("gen-ground-truth") => cmd_gen_ground_truth(&args[2..]),
        Some("audit") => cmd_audit(args.get(2).map(String::as_str)),
        Some("audit-stream") => cmd_audit_stream(&args[2..]),
        _ => {
            eprintln!(
                "usage: saksi-demo <gen [--voters N] [--positions P] [--candidates C] \
                 [--distribution uniform|skewed] [--election-id S] [--election-name S] \
                 [--threshold T] [--trustees N] [--trustee-names a,b,c] [--stream DIR] [outfile] \
                 | gen-ground-truth [--voters N] [--positions P] [--candidates C] \
                 [--distribution uniform|skewed] [--election-id S] --out-dir DIR \
                 | audit <bundle.json> | audit-stream <dir> [--json]>"
            );
            ExitCode::FAILURE
        }
    }
}

/// Where `gen` writes: a one-blob bundle (to a file, or stdout when `None`) or a
/// streamed run folder.
#[derive(Debug)]
enum GenTarget {
    Bundle(Option<String>),
    Stream(String),
}

/// Parsed `gen` arguments: the generator parameters, the output target, and
/// whether any parameter flag was set (bare `gen` falls back to the legacy
/// happy-path bundle).
#[derive(Debug)]
struct ParsedGen {
    params: GenParams,
    target: GenTarget,
    parameterized: bool,
}

/// Simple majority threshold for `n` trustees (`⌊n/2⌋ + 1`).
fn default_majority(n: usize) -> usize {
    n / 2 + 1
}

fn parse_gen_args(args: &[String]) -> Result<ParsedGen, String> {
    let (mut voters, mut positions, mut candidates) = (None, None, None);
    let mut skewed = false;
    let (mut election_id, mut election_name) = (None, None);
    let (mut threshold, mut trustees): (Option<usize>, Option<usize>) = (None, None);
    let mut trustee_names: Option<Vec<String>> = None;
    let mut stream: Option<String> = None;
    let mut out: Option<String> = None;

    let parse_usize = |v: Option<&String>, name: &str| -> Result<usize, String> {
        v.and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n >= 1)
            .ok_or_else(|| format!("{name} needs a positive integer"))
    };
    let take = |v: Option<&String>, name: &str| -> Result<String, String> {
        v.map(|s| s.to_string())
            .ok_or_else(|| format!("{name} needs a value"))
    };

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--voters" => {
                voters = Some(parse_usize(args.get(i + 1), "--voters")?);
                i += 2;
            }
            "--positions" => {
                positions = Some(parse_usize(args.get(i + 1), "--positions")?);
                i += 2;
            }
            "--candidates" => {
                candidates = Some(parse_usize(args.get(i + 1), "--candidates")?);
                i += 2;
            }
            "--threshold" => {
                threshold = Some(parse_usize(args.get(i + 1), "--threshold")?);
                i += 2;
            }
            "--trustees" => {
                trustees = Some(parse_usize(args.get(i + 1), "--trustees")?);
                i += 2;
            }
            "--election-id" => {
                election_id = Some(take(args.get(i + 1), "--election-id")?);
                i += 2;
            }
            "--election-name" => {
                election_name = Some(take(args.get(i + 1), "--election-name")?);
                i += 2;
            }
            "--trustee-names" => {
                let raw = take(args.get(i + 1), "--trustee-names")?;
                trustee_names = Some(raw.split(',').map(|s| s.trim().to_string()).collect());
                i += 2;
            }
            "--distribution" => match args.get(i + 1).map(String::as_str) {
                Some("uniform") => {
                    skewed = false;
                    i += 2;
                }
                Some("skewed") => {
                    skewed = true;
                    i += 2;
                }
                _ => return Err("--distribution must be 'uniform' or 'skewed'".into()),
            },
            "--stream" => {
                stream = Some(take(args.get(i + 1), "--stream")?);
                i += 2;
            }
            other => {
                out = Some(other.to_string());
                i += 1;
            }
        }
    }

    let parameterized = voters.is_some()
        || positions.is_some()
        || candidates.is_some()
        || threshold.is_some()
        || trustees.is_some()
        || election_id.is_some()
        || election_name.is_some()
        || trustee_names.is_some()
        || skewed
        || stream.is_some();

    let n = trustees.unwrap_or(5);
    let t = threshold.unwrap_or_else(|| default_majority(n));
    let names =
        trustee_names.unwrap_or_else(|| (1..=n).map(|idx| format!("Trustee {idx}")).collect());
    let eid = election_id.unwrap_or_else(|| "election-2026".to_string());
    let ename = election_name.unwrap_or_else(|| eid.clone());
    let profile = if skewed {
        SelectionProfile::Skewed
    } else {
        SelectionProfile::Uniform
    };

    let params = GenParams {
        election_id: eid,
        election_name: ename,
        threshold: t,
        trustees: n,
        trustee_names: names,
        voters: voters.unwrap_or(6),
        positions: positions.unwrap_or(3),
        candidates: candidates.unwrap_or(3),
        profile,
    };

    let target = match stream {
        Some(dir) => {
            if out.is_some() {
                return Err("--stream and an output file are mutually exclusive".into());
            }
            GenTarget::Stream(dir)
        }
        None => GenTarget::Bundle(out),
    };

    Ok(ParsedGen {
        params,
        target,
        parameterized,
    })
}

/// `gen-ground-truth` — write ONLY the Stage-4 plaintext ground-truth tables
/// (paper Appendix A), running no cryptography.
///
/// This is the same population `gen` would produce, minus every expensive step:
/// no DKG, no blind-signed credentials, no ElGamal ciphertexts, no CDS proofs.
/// That is what makes the capstone tiers (1,921,917 and 3,524,078 voters)
/// reachable here — the cost is linear in `voters × positions` with no crypto
/// in the loop, so the console's offline voter ceiling does not apply.
///
/// Reuses `parse_gen_args`, so the population flags are spelled identically to
/// `gen`; `--out-dir` names the destination and the DKG-shaped flags
/// (`--trustees`, `--threshold`, `--trustee-names`) are accepted but unused,
/// since no key generation happens on this path.
fn cmd_gen_ground_truth(args: &[String]) -> ExitCode {
    let mut out_dir: Option<String> = None;
    let mut rest: Vec<String> = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--out-dir" {
            match args.get(i + 1) {
                Some(v) => out_dir = Some(v.clone()),
                None => {
                    eprintln!("--out-dir needs a value");
                    return ExitCode::FAILURE;
                }
            }
            i += 2;
            continue;
        }
        rest.push(args[i].clone());
        i += 1;
    }

    let Some(dir) = out_dir else {
        eprintln!("--out-dir is required");
        return ExitCode::FAILURE;
    };

    let parsed = match parse_gen_args(&rest) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    if matches!(parsed.target, GenTarget::Stream(_)) {
        eprintln!("gen-ground-truth writes to --out-dir; --stream is not accepted");
        return ExitCode::FAILURE;
    }

    let params = parsed.params;
    match write_ground_truth_csvs(std::path::Path::new(&dir), &params) {
        Ok(()) => {
            eprintln!(
                "wrote ground truth ({} voters × {} positions × {} candidates, {}) -> {dir}",
                params.voters,
                params.positions,
                params.candidates,
                match params.profile {
                    SelectionProfile::Uniform => "uniform",
                    SelectionProfile::Skewed => "skewed",
                }
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ground-truth generation failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_gen(args: &[String]) -> ExitCode {
    let ParsedGen {
        params,
        target,
        parameterized,
    } = match parse_gen_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let summary = format!(
        "{} voters × {} positions × {} candidates ({}-of-{})",
        params.voters, params.positions, params.candidates, params.threshold, params.trustees
    );

    match target {
        GenTarget::Stream(dir) => match write_election_stream_params(Path::new(&dir), &params) {
            Ok(()) => {
                eprintln!("wrote stream ({summary}; gate passed) -> {dir}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("validation gate rejected the population: {e}");
                ExitCode::FAILURE
            }
        },
        GenTarget::Bundle(out) => {
            let json = if parameterized {
                match election_bundle_json_params(&params) {
                    Ok(json) => {
                        eprintln!("generated {summary}; gate passed");
                        json
                    }
                    Err(e) => {
                        eprintln!("validation gate rejected the population: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                election_bundle_json()
            };
            match out {
                Some(path) => match std::fs::write(&path, &json) {
                    Ok(()) => {
                        eprintln!("wrote election bundle -> {path}");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("write {path}: {e}");
                        ExitCode::FAILURE
                    }
                },
                None => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
            }
        }
    }
}

fn cmd_audit(path: Option<&str>) -> ExitCode {
    let Some(path) = path else {
        eprintln!("usage: saksi-demo audit <bundle.json>");
        return ExitCode::FAILURE;
    };
    let bundle = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    match audit_bundle_json(&bundle) {
        Ok(report) => print_report(&report),
        Err(e) => {
            eprintln!("audit error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_audit_stream(args: &[String]) -> ExitCode {
    let mut dir: Option<&str> = None;
    let mut json = false;
    for a in args {
        match a.as_str() {
            "--json" => json = true,
            other => dir = Some(other),
        }
    }
    let Some(dir) = dir else {
        eprintln!("usage: saksi-demo audit-stream <dir> [--json]");
        return ExitCode::FAILURE;
    };
    match audit_stream_dir(Path::new(dir)) {
        Ok(sa) => {
            if json {
                println!("{}", sa.to_json());
            } else {
                for c in &sa.contests {
                    let mark = if c.pass { "PASS" } else { "FAIL" };
                    println!(
                        "[{mark}] {:<24} gt={} decoded={} E={}",
                        c.contest, c.ground_truth, c.decoded, c.e
                    );
                }
                println!("{}", "-".repeat(60));
                println!("AUDIT-STREAM: {}", sa.overall.to_uppercase());
            }
            if sa.overall == "pass" {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("audit-stream error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_report(report: &AuditReport) -> ExitCode {
    for f in &report.findings {
        let mark = match f.status {
            AuditStatus::Pass => "PASS",
            AuditStatus::Fail => "FAIL",
        };
        println!("[{mark}] {:<26} {}", f.check, f.detail);
    }
    println!("{}", "-".repeat(60));
    match report.overall {
        AuditStatus::Pass => {
            println!("AUDIT: PASS");
            ExitCode::SUCCESS
        }
        AuditStatus::Fail => {
            println!("AUDIT: FAIL");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_gen_args_reads_all_flags_and_stream_target() {
        let args = sv(&[
            "--trustees",
            "3",
            "--threshold",
            "2",
            "--election-id",
            "x",
            "--election-name",
            "Midterm",
            "--trustee-names",
            "Alice,Bob,Carol",
            "--stream",
            "/tmp/r",
            "--voters",
            "4",
            "--positions",
            "2",
            "--candidates",
            "2",
            "--distribution",
            "skewed",
        ]);
        let p = parse_gen_args(&args).expect("parses");
        assert_eq!(p.params.trustees, 3);
        assert_eq!(p.params.threshold, 2);
        assert_eq!(p.params.election_id, "x");
        assert_eq!(p.params.election_name, "Midterm");
        assert_eq!(p.params.trustee_names, vec!["Alice", "Bob", "Carol"]);
        assert_eq!(p.params.voters, 4);
        assert!(matches!(p.params.profile, SelectionProfile::Skewed));
        assert!(matches!(p.target, GenTarget::Stream(ref d) if d == "/tmp/r"));
        assert!(p.parameterized);
    }

    #[test]
    fn parse_gen_args_defaults_are_backcompat() {
        let p = parse_gen_args(&sv(&[])).expect("parses");
        assert_eq!(p.params.trustees, 5);
        assert_eq!(p.params.threshold, 3); // default_majority(5)
        assert_eq!(p.params.election_id, "election-2026");
        assert_eq!(p.params.election_name, "election-2026");
        assert!(!p.parameterized);
        assert!(matches!(p.target, GenTarget::Bundle(None)));
    }

    #[test]
    fn parse_gen_args_defaults_trustee_names_to_count() {
        // --trustees without --trustee-names yields exactly n default names.
        let p = parse_gen_args(&sv(&["--trustees", "4"])).expect("parses");
        assert_eq!(p.params.trustee_names.len(), 4);
        assert_eq!(p.params.threshold, 3); // default_majority(4) = 3
    }

    #[test]
    fn parse_gen_args_rejects_stream_with_outfile() {
        let err = parse_gen_args(&sv(&["--stream", "/tmp/r", "out.json"]))
            .expect_err("mutually exclusive");
        assert!(err.contains("mutually exclusive"), "got: {err}");
    }
}
