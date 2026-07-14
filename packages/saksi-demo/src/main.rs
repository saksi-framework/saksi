//! `saksi-demo` — generate a happy-path election bundle and audit one.
//!
//! Two subcommands:
//!
//! - `gen [--voters N] [--positions P] [--candidates C] [--distribution uniform|skewed] [outfile]` — write a
//!   demo election bundle (hex wire artifacts) to `outfile`, or stdout if
//!   omitted. With no `--voters/--positions/--candidates`, emits the legacy
//!   happy-path bundle. With them, emits a parameterized multi-position bundle
//!   (one ballot record per (voter, position); ADR-0007) after the fail-closed
//!   validation gate. The Go `saksi-console` submits the bundle to a live
//!   bulletin board.
//! - `audit <bundle.json>` — run the off-chain auditor over a bundle and print
//!   a pass/fail report. Exits non-zero if the audit fails.

use std::process::ExitCode;

use saksi_auditor::demo::{audit_bundle_json, election_bundle_json, election_bundle_json_params};
use saksi_auditor::{AuditReport, AuditStatus};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen") => cmd_gen(&args[2..]),
        Some("audit") => cmd_audit(args.get(2).map(String::as_str)),
        _ => {
            eprintln!(
                "usage: saksi-demo <gen [--voters N] [--positions P] [--candidates C] [--distribution uniform|skewed] [outfile] | audit <bundle.json>>"
            );
            ExitCode::FAILURE
        }
    }
}

fn cmd_gen(args: &[String]) -> ExitCode {
    // Parse optional --voters/--positions/--candidates/--distribution flags; the
    // lone non-flag argument is the output path.
    let (mut voters, mut positions, mut candidates) = (None, None, None);
    let mut skewed = false;
    let mut out: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        let parse = |v: Option<&String>, name: &str| -> Result<usize, String> {
            v.and_then(|s| s.parse::<usize>().ok())
                .filter(|&n| n >= 1)
                .ok_or_else(|| format!("{name} needs a positive integer"))
        };
        match args[i].as_str() {
            "--voters" => match parse(args.get(i + 1), "--voters") {
                Ok(n) => {
                    voters = Some(n);
                    i += 2;
                }
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            },
            "--positions" => match parse(args.get(i + 1), "--positions") {
                Ok(n) => {
                    positions = Some(n);
                    i += 2;
                }
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            },
            "--candidates" => match parse(args.get(i + 1), "--candidates") {
                Ok(n) => {
                    candidates = Some(n);
                    i += 2;
                }
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            },
            "--distribution" => match args.get(i + 1).map(String::as_str) {
                Some("uniform") => {
                    skewed = false;
                    i += 2;
                }
                Some("skewed") => {
                    skewed = true;
                    i += 2;
                }
                _ => {
                    eprintln!("--distribution must be 'uniform' or 'skewed'");
                    return ExitCode::FAILURE;
                }
            },
            other => {
                out = Some(other);
                i += 1;
            }
        }
    }

    // Any dimension flag switches to the parameterized multi-position generator
    // (defaulting the unspecified dimensions); none = the legacy bundle.
    let json = if voters.is_some() || positions.is_some() || candidates.is_some() {
        let (v, p, c) = (
            voters.unwrap_or(6),
            positions.unwrap_or(3),
            candidates.unwrap_or(3),
        );
        match election_bundle_json_params(v, p, c, skewed) {
            Ok(json) => {
                let dist = if skewed { "skewed" } else { "uniform" };
                eprintln!(
                    "generated {v} voters × {p} positions × {c} candidates ({dist}; gate passed)"
                );
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
        Some(path) => match std::fs::write(path, &json) {
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
