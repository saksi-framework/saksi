//! `saksi-demo audit-canvass` through the binary: a generation with no returns
//! received exits 1 and names the missing precincts; a missing national side
//! is an input error (exit 2). The full check matrix lives in the auditor's
//! `canvass::tests`.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_saksi-demo");

#[test]
fn audit_canvass_cli_fails_closed_without_returns() {
    let dir = std::env::temp_dir().join(format!("saksi-demo-it-canvass-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let gen = Command::new(BIN)
        .args([
            "gen",
            "--voters",
            "8",
            "--positions",
            "1",
            "--candidates",
            "2",
        ])
        .args(["--precincts", "2", "--election-id", "it-cv", "--stream"])
        .arg(&dir)
        .status()
        .expect("run gen");
    assert!(gen.success());

    // No national/returns/ yet: input error.
    let out = Command::new(BIN)
        .arg("audit-canvass")
        .arg(&dir)
        .output()
        .expect("run audit-canvass");
    assert_eq!(out.status.code(), Some(2));

    std::fs::create_dir_all(dir.join("national").join("returns")).unwrap();
    let out = Command::new(BIN)
        .arg("audit-canvass")
        .arg(&dir)
        .arg("--json")
        .output()
        .expect("run audit-canvass");
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json on stdout");
    assert_eq!(v["pass"], false);
    let completeness = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["check"] == "canvass.completeness")
        .unwrap();
    assert_eq!(completeness["verdict"], "fail");
    assert_eq!(completeness["reason"], "no return from p01, p02");
    assert!(dir.join("canvass.json").exists() && dir.join("canvass-checks.csv").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
