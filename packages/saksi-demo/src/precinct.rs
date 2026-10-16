//! Precinct return subcommands (kept out of `main.rs`):
//!
//! - `ledger-digest <ballots.ndjson>` — print the hex `ledger_digest` of the
//!   file, in file order (the order the chain served it).
//! - `sign-return <precinct dir> --ledger <ballots.ndjson> --close-block N
//!   --tip-hash HEX --key <authority.key> [--out return.json]` — recompute the
//!   record count, digest and per-contest aggregates (verified ballots only)
//!   from the ledger read-back, sign, and write the return (default
//!   `<precinct dir>/return.json`).
//! - `verify-return <return.json> --pubkey HEX` — exit 0 if the signature
//!   verifies under the key, 1 with the reason otherwise.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use saksi_auditor::ledger::ledger_digest_file;
use saksi_auditor::precinct_return::{
    parse_hex32, read_authority_key, sign_return, PrecinctReturn, RETURN_FILE,
};

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::FAILURE
}

pub fn cmd_ledger_digest(args: &[String]) -> ExitCode {
    let [file] = args else {
        return fail("usage: saksi-demo ledger-digest <ledger ballots.ndjson>");
    };
    match ledger_digest_file(Path::new(file)) {
        Ok((_, digest)) => {
            println!("{}", hex::encode(digest));
            ExitCode::SUCCESS
        }
        Err(e) => fail(format!("ledger-digest: {e}")),
    }
}

pub fn cmd_sign_return(args: &[String]) -> ExitCode {
    const USAGE: &str = "usage: saksi-demo sign-return <precinct dir> --ledger <ballots.ndjson> \
                         --close-block N --tip-hash HEX --key <authority.key> [--out return.json]";
    let mut dir = None;
    let (mut ledger, mut block, mut tip, mut key, mut out) = (None, None, None, None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let slot = match a.as_str() {
            "--ledger" => &mut ledger,
            "--close-block" => &mut block,
            "--tip-hash" => &mut tip,
            "--key" => &mut key,
            "--out" => &mut out,
            s if !s.starts_with("--") && dir.is_none() => {
                dir = Some(s.to_string());
                continue;
            }
            other => {
                return fail(format!(
                    "sign-return: unexpected argument {other:?}\n{USAGE}"
                ))
            }
        };
        match it.next() {
            Some(v) => *slot = Some(v.clone()),
            None => return fail(format!("sign-return: {a} needs a value\n{USAGE}")),
        }
    }
    let (Some(dir), Some(ledger), Some(block), Some(tip), Some(key)) =
        (dir, ledger, block, tip, key)
    else {
        return fail(USAGE);
    };
    let block: u64 = match block.parse() {
        Ok(b) => b,
        Err(e) => return fail(format!("sign-return: --close-block {block:?}: {e}")),
    };
    let result = parse_hex32(&tip, "--tip-hash")
        .and_then(|tip| Ok((tip, read_authority_key(Path::new(&key))?)))
        .and_then(|(tip, secret)| {
            sign_return(
                Path::new(&dir),
                Path::new(&ledger),
                block,
                tip,
                &secret,
                &mut rand_core::OsRng,
            )
        });
    let (ret, verified) = match result {
        Ok(v) => v,
        Err(e) => return fail(format!("sign-return: {e}")),
    };
    let out = out.map_or_else(|| Path::new(&dir).join(RETURN_FILE), PathBuf::from);
    let json = serde_json::to_string_pretty(&ret).expect("return serialises");
    if let Err(e) = std::fs::write(&out, json + "\n") {
        return fail(format!("sign-return: write {}: {e}", out.display()));
    }
    println!(
        "signed return {} {}: {} records ({verified} verified), digest {} -> {}",
        ret.election_id,
        ret.precinct_id,
        ret.record_count,
        hex::encode(ret.ledger_digest),
        out.display()
    );
    ExitCode::SUCCESS
}

pub fn cmd_verify_return(args: &[String]) -> ExitCode {
    let [file, flag, key] = args else {
        return fail("usage: saksi-demo verify-return <return.json> --pubkey HEX");
    };
    if flag != "--pubkey" {
        return fail("usage: saksi-demo verify-return <return.json> --pubkey HEX");
    }
    let result = parse_hex32(key, "--pubkey").and_then(|pk| {
        let raw = std::fs::read_to_string(file).map_err(|e| format!("read {file}: {e}"))?;
        let ret: PrecinctReturn =
            serde_json::from_str(&raw).map_err(|e| format!("parse {file}: {e}"))?;
        ret.verify(&pk).map(|()| ret)
    });
    match result {
        Ok(ret) => {
            println!(
                "ok: {} {} signature verifies",
                ret.election_id, ret.precinct_id
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(format!("verify-return: FAIL: {e}")),
    }
}
