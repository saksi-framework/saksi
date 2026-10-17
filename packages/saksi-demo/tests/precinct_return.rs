//! `ledger-digest`, `sign-return` and `verify-return` on a real two-precinct
//! generation: the precinct's run-folder ballots stand in for its ledger
//! read-back.

use std::path::Path;
use std::process::{Command, Output};

use saksi_auditor::ledger::ledger_digest;
use saksi_auditor::precinct_return::PrecinctReturn;
use saksi_auditor::stream::{AggregateFile, BallotLines, RegistryEntry};

const BIN: &str = env!("CARGO_BIN_EXE_saksi-demo");

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("run saksi-demo")
}

fn s(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

#[test]
fn sign_and_verify_a_precinct_return_from_a_generated_ledger() {
    let dir = std::env::temp_dir().join("saksi-demo-it-precinct-return");
    let _ = std::fs::remove_dir_all(&dir);
    let gen = run(&[
        "gen",
        "--voters",
        "12",
        "--positions",
        "2",
        "--candidates",
        "2",
        "--election-id",
        "it-pr",
        "--precincts",
        "2",
        "--stream",
        s(&dir),
    ]);
    assert!(
        gen.status.success(),
        "gen: {}",
        String::from_utf8_lossy(&gen.stderr)
    );
    let p1 = dir.join("precinct-01");
    let ledger = p1.join("ballots.ndjson");

    // ledger-digest prints the slice digest of the same ballots.
    let out = run(&["ledger-digest", s(&ledger)]);
    assert!(out.status.success());
    let ballots: Vec<_> = BallotLines::open(&p1)
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        hex::encode(ledger_digest(&ballots))
    );

    // sign-return recomputes everything from the ledger file.
    let tip = "ab".repeat(32);
    let ret_path = dir.join("p01-return.json");
    let out = run(&[
        "sign-return",
        s(&p1),
        "--ledger",
        s(&ledger),
        "--close-block",
        "77",
        "--tip-hash",
        &tip,
        "--key",
        s(&p1.join("authority.key")),
        "--out",
        s(&ret_path),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let ret: PrecinctReturn =
        serde_json::from_str(&std::fs::read_to_string(&ret_path).unwrap()).unwrap();
    assert_eq!(
        (ret.election_id.as_str(), ret.precinct_id.as_str()),
        ("it-pr-p01", "p01")
    );
    assert_eq!(
        (ret.close_block, ret.record_count),
        (77, ballots.len() as u64)
    );
    assert_eq!(ret.ledger_digest, ledger_digest(&ballots));
    // Every generated ballot verifies, so the sums equal the generator's aggregate.
    let agg: AggregateFile =
        serde_json::from_str(&std::fs::read_to_string(p1.join("aggregate.json")).unwrap()).unwrap();
    assert_eq!(ret.contests.len(), agg.contests.len());
    for (r, a) in ret.contests.iter().zip(&agg.contests) {
        assert_eq!(r.contest_id, a.contest_id);
        assert_eq!(hex::encode(r.sum_c1), a.c1);
        assert_eq!(hex::encode(r.sum_c2), a.c2);
    }

    // verify-return: p01's registered key passes, p02's (T21-style) fails.
    let registry: Vec<RegistryEntry> =
        serde_json::from_str(&std::fs::read_to_string(dir.join("national/registry.json")).unwrap())
            .unwrap();
    let ok = run(&[
        "verify-return",
        s(&ret_path),
        "--pubkey",
        &registry[0].authority_pubkey_hex,
    ]);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let bad = run(&[
        "verify-return",
        s(&ret_path),
        "--pubkey",
        &registry[1].authority_pubkey_hex,
    ]);
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("does not verify"));

    // T12 on the file: relabel p01 -> p02, the signature no longer holds.
    let relabeled = dir.join("relabeled.json");
    std::fs::write(
        &relabeled,
        std::fs::read_to_string(&ret_path)
            .unwrap()
            .replace("\"p01\"", "\"p02\""),
    )
    .unwrap();
    let out = run(&[
        "verify-return",
        s(&relabeled),
        "--pubkey",
        &registry[0].authority_pubkey_hex,
    ]);
    assert!(!out.status.success());

    let _ = std::fs::remove_dir_all(&dir);
}
