//! `saksi-demo` — generate a happy-path election bundle and audit one.
//!
//! Two subcommands:
//!
//! - `gen [outfile]` — write the demo election bundle (hex wire artifacts) to
//!   `outfile`, or stdout if omitted. The Go `saksi-console` submits this bundle
//!   to a live bulletin board.
//! - `audit <bundle.json>` — run the off-chain auditor over a bundle and print
//!   a pass/fail report. Exits non-zero if the audit fails.

use std::process::ExitCode;

use saksi_auditor::demo::{audit_bundle_json, election_bundle_json};
use saksi_auditor::{AuditReport, AuditStatus};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen") => cmd_gen(args.get(2).map(String::as_str)),
        Some("audit") => cmd_audit(args.get(2).map(String::as_str)),
        _ => {
            eprintln!("usage: saksi-demo <gen [outfile] | audit <bundle.json>>");
            ExitCode::FAILURE
        }
    }
}

fn cmd_gen(out: Option<&str>) -> ExitCode {
    let json = election_bundle_json();
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
