//! Real `gen → audit-stream` integration gate (Task 4c).
//!
//! Every Go executor/scenario test uses a fake runner, so nothing there checks
//! that the CLI flags + the `audit-stream --json` schema match the actual
//! binary. This test runs the REAL `saksi-demo` end-to-end and asserts the
//! structured correctness output — it is the Rust↔Go contract gate, and it runs
//! entirely on CI (no Windows, no network).

use std::process::Command;

/// Path to the built binary, provided by Cargo for integration tests.
const BIN: &str = env!("CARGO_BIN_EXE_saksi-demo");

#[test]
fn gen_stream_then_audit_stream_json_is_clean() {
    let dir = std::env::temp_dir().join("saksi-demo-it-gen-audit-stream");
    let _ = std::fs::remove_dir_all(&dir);

    // gen --stream a small 2-of-3 election with every identity flag set.
    let gen = Command::new(BIN)
        .args([
            "gen",
            "--voters",
            "6",
            "--positions",
            "2",
            "--candidates",
            "2",
            "--trustees",
            "3",
            "--threshold",
            "2",
            "--election-id",
            "it",
            "--election-name",
            "IT Election",
            "--trustee-names",
            "A,B,C",
            "--stream",
        ])
        .arg(&dir)
        .status()
        .expect("run gen");
    assert!(gen.success(), "gen --stream should succeed");

    // Both stream files exist.
    assert!(dir.join("header.json").is_file(), "header.json written");
    assert!(
        dir.join("ballots.ndjson").is_file(),
        "ballots.ndjson written"
    );

    // audit-stream --json → structured correctness.
    let out = Command::new(BIN)
        .args(["audit-stream"])
        .arg(&dir)
        .arg("--json")
        .output()
        .expect("run audit-stream");
    assert!(
        out.status.success(),
        "audit-stream should exit 0 on a clean run"
    );

    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("audit-stream emits valid JSON");
    assert_eq!(json["overall"], "pass", "overall must be pass: {json}");

    let contests = json["contests"].as_array().expect("contests array");
    assert_eq!(contests.len(), 2 * 2, "one row per contest slot");
    for c in contests {
        assert_eq!(c["E"], 0, "every contest must have E=0: {c}");
        assert_eq!(c["pass"], true, "every contest must pass: {c}");
        assert_eq!(
            c["decoded"], c["ground_truth"],
            "decoded must equal ground truth: {c}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// `gen --stream <dir> --precincts 2` through the real binary: both precinct
/// folders audit clean with `audit-stream`, and the national folder carries
/// the registry and no ballots.
#[test]
fn gen_precincts_writes_auditable_precinct_folders_and_a_registry() {
    let dir = std::env::temp_dir().join("saksi-demo-it-gen-precincts");
    let _ = std::fs::remove_dir_all(&dir);

    let gen = Command::new(BIN)
        .args([
            "gen",
            "--voters",
            "20",
            "--positions",
            "2",
            "--candidates",
            "2",
            "--election-id",
            "it-pm",
            "--precincts",
            "2",
            "--stream",
        ])
        .arg(&dir)
        .status()
        .expect("run gen");
    assert!(gen.success(), "gen --precincts should succeed");

    for p in ["precinct-01", "precinct-02"] {
        let out = Command::new(BIN)
            .args(["audit-stream"])
            .arg(dir.join(p))
            .arg("--json")
            .output()
            .expect("run audit-stream");
        assert!(out.status.success(), "{p} should audit clean");
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
        assert_eq!(json["overall"], "pass", "{p}: {json}");
    }

    let national = dir.join("national");
    assert!(national.join("header.json").is_file());
    assert!(national.join("aggregate.json").is_file());
    assert!(!national.join("ballots.ndjson").exists());
    let registry: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(national.join("registry.json")).expect("registry"),
    )
    .expect("registry json");
    let ids: Vec<&str> = registry
        .as_array()
        .expect("array")
        .iter()
        .map(|e| e["precinct_id"].as_str().expect("id"))
        .collect();
    assert_eq!(ids, ["p01", "p02"]);

    let _ = std::fs::remove_dir_all(&dir);
}
