//! `saksi-demo precinct-aggregate` end to end: gen a small run, re-aggregate it
//! by precinct, and require every check to pass and every output to exist.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_saksi-demo");

#[test]
fn precinct_aggregate_cli_passes_on_a_generated_run() {
    let dir = std::env::temp_dir().join("saksi-demo-it-precinct-aggregate");
    let _ = std::fs::remove_dir_all(&dir);
    let gen = Command::new(BIN)
        .args([
            "gen",
            "--voters",
            "30",
            "--positions",
            "2",
            "--candidates",
            "3",
        ])
        .arg("--stream")
        .arg(&dir)
        .status()
        .expect("run gen");
    assert!(gen.success());

    let out = Command::new(BIN)
        .arg("precinct-aggregate")
        .arg(&dir)
        .args(["--precinct-size", "7", "--json", "--ground-truth"])
        .arg(dir.join("ground-truth-ballots.csv"))
        .output()
        .expect("run precinct-aggregate");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let summary: serde_json::Value = serde_json::from_str(&stdout).expect("summary json");
    assert_eq!(summary["precincts"], 5);
    assert_eq!(summary["records"], 60);
    assert_eq!(summary["exit_code"], 0);
    for f in ["precincts.csv", "combine.txt", "summary.json"] {
        assert!(dir.join("precinct-aggregate").join(f).is_file(), "{f}");
    }

    let missing = Command::new(BIN)
        .arg("precinct-aggregate")
        .arg(&dir)
        .output()
        .expect("run without --precinct-size");
    assert_eq!(missing.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}
