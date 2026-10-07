//! Order-dependent digest over a recorded ballot sequence, and the
//! `ledger.order` check that uses it.
//!
//! An on-chain run carries two copies of its ballots: the console's own
//! `<run>/ballots.ndjson` (submission order) and the chain's read-back in
//! `<run>/ledger/ballots.ndjson`, which the campaign dumps by walking the
//! chaincode's nullifier index (`ListNullifiers`, then `GetBallot(s)` per page).
//! That index is a world-state composite key, so the chain serves its ballots
//! in ascending nullifier order and in no other. The chain does not expose its
//! block (commit) order through this read path, and nothing here claims it.
//!
//! [`check_ledger_order`] holds the read-back to that canonical order: a serving
//! node that permutes, drops, duplicates or rewrites the ballots it returns
//! (paper adversary class 5, a malicious bulletin-board node) changes
//! [`ledger_digest`] of the read-back away from [`ledger_digest`] of the
//! console's record put into the same canonical order. `audit-stream` runs it
//! whenever the run folder holds a ledger dump; a folder without one (an
//! offline run, or a chain that could not be reached) gets no `ledger.order`
//! finding at all.
//!
//! The homomorphic tally is still order-independent, so the stateless crypto
//! audit alone passes a reordered set (see `independent_verification.rs`); the
//! order claim rests on this check and needs the ledger dump.

use saksi_protocol::{domain_hash, Ballot};

/// One ballot's identifying content (position id, nullifier, credential
/// commitment, every ciphertext) as a 32-byte leaf.
fn ballot_leaf(ballot: &Ballot) -> [u8; 32] {
    let nullifier = nullifier_of(ballot);
    let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + ballot.ciphertexts.len() * 2);
    parts.push(ballot.position_id.as_bytes());
    parts.push(nullifier);
    parts.push(&ballot.voter_credential_commitment);
    for ct in &ballot.ciphertexts {
        parts.push(&ct.pad);
        parts.push(&ct.data);
    }
    domain_hash(b"saksi.auditor.ledger.leaf.v2", &parts)
}

fn nullifier_of(ballot: &Ballot) -> &[u8] {
    ballot
        .credential_presentation
        .as_ref()
        .and_then(|p| p.nullifier.as_ref())
        .map(|n| n.value.as_slice())
        .unwrap_or(&[])
}

fn digest_start() -> [u8; 32] {
    domain_hash(b"saksi.auditor.ledger.v2", &[])
}

fn digest_step(acc: &[u8; 32], leaf: &[u8; 32]) -> [u8; 32] {
    domain_hash(b"saksi.auditor.ledger.chain.v2", &[acc, leaf])
}

/// Order-dependent hash chain over `ballots`: each ballot's leaf (position id,
/// nullifier, credential commitment, every ciphertext) is folded into a running
/// SHA-256 digest, so the result depends on both the set **and** its order.
/// Reordering, dropping or altering any ballot changes the output.
pub fn ledger_digest(ballots: &[Ballot]) -> [u8; 32] {
    ballots
        .iter()
        .fold(digest_start(), |acc, b| digest_step(&acc, &ballot_leaf(b)))
}

/// The `ledger.order` check: the chain's read-back in `ledger_dir` must be in
/// the chain's canonical (ascending nullifier) order, and its [`ledger_digest`]
/// must equal the digest of the console's record in `served_dir` put into that
/// order.
///
/// Both files are streamed. The served side keeps one (nullifier, leaf) pair per
/// ballot so it can be sorted.
/// ponytail: ~100 bytes per ballot record held for the sort (about 1 GB at 10M
/// records); an external sort if a tier ever outgrows that.
#[cfg(feature = "demo")]
pub fn check_ledger_order(
    served_dir: &std::path::Path,
    ledger_dir: &std::path::Path,
) -> crate::report::AuditFinding {
    use crate::report::AuditFinding;
    const CHECK: &str = "ledger.order";

    // Chain side, in the order the chain served it.
    let mut chain = digest_start();
    let mut prev: Option<Vec<u8>> = None;
    let mut n_chain = 0usize;
    let lines = match crate::stream::BallotLines::open(ledger_dir) {
        Ok(l) => l,
        Err(e) => return AuditFinding::fatal_fail(CHECK, format!("ledger dump: {e}")),
    };
    for (i, ballot) in lines.enumerate() {
        let ballot = match ballot {
            Ok(b) => b,
            Err(e) => return AuditFinding::fatal_fail(CHECK, format!("ledger dump: {e}")),
        };
        let nul = nullifier_of(&ballot);
        if prev.as_deref().is_some_and(|p| p >= nul) {
            return AuditFinding::fatal_fail(
                CHECK,
                format!(
                    "chain read-back record {} is out of the chain's nullifier order \
                     (not above record {i}): the ledger dump was reordered or duplicated",
                    i + 1
                ),
            );
        }
        prev = Some(nul.to_vec());
        chain = digest_step(&chain, &ballot_leaf(&ballot));
        n_chain += 1;
    }

    // Served side, put into the chain's canonical order.
    let lines = match crate::stream::BallotLines::open(served_dir) {
        Ok(l) => l,
        Err(e) => return AuditFinding::fatal_fail(CHECK, format!("served stream: {e}")),
    };
    let mut served: Vec<(Vec<u8>, [u8; 32])> = Vec::new();
    for ballot in lines {
        match ballot {
            Ok(b) => served.push((nullifier_of(&b).to_vec(), ballot_leaf(&b))),
            Err(e) => return AuditFinding::fatal_fail(CHECK, format!("served stream: {e}")),
        }
    }
    served.sort_unstable();
    let canonical = served
        .iter()
        .fold(digest_start(), |acc, (_, leaf)| digest_step(&acc, leaf));

    if canonical != chain {
        return AuditFinding::fatal_fail(
            CHECK,
            format!(
                "ledger_digest of the chain read-back ({}, {n_chain} records) differs from the \
                 served record in chain order ({}, {} records): a ballot was dropped, added or altered",
                hex::encode(chain),
                hex::encode(canonical),
                served.len()
            ),
        );
    }
    AuditFinding::fatal_pass(
        CHECK,
        format!(
            "{n_chain} records: the chain read-back is in nullifier order and matches the served \
             record (ledger_digest {})",
            hex::encode(chain)
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::ledger_digest;
    use crate::fixtures::{multi_position_fixture, GenParams, SelectionProfile};

    /// Unit test of the digest function alone.
    #[test]
    fn ledger_digest_is_order_dependent() {
        let f = multi_position_fixture(&GenParams::simple(4, 2, 2, SelectionProfile::Uniform));
        let recorded = ledger_digest(&f.ballots);
        assert_eq!(recorded, ledger_digest(&f.ballots), "deterministic");

        let mut reversed = f.ballots.clone();
        reversed.reverse();
        assert_ne!(ledger_digest(&reversed), recorded, "order-dependent");
    }

    #[cfg(feature = "demo")]
    mod order_check {
        use super::super::{check_ledger_order, nullifier_of};
        use crate::fixtures::{multi_position_fixture, GenParams, SelectionProfile};
        use crate::report::AuditStatus;
        use prost::Message;
        use saksi_protocol::Ballot;
        use std::path::{Path, PathBuf};

        fn write(dir: &Path, ballots: &[Ballot]) {
            std::fs::create_dir_all(dir).unwrap();
            let body: String = ballots
                .iter()
                .map(|b| hex::encode(b.encode_to_vec()) + "\n")
                .collect();
            std::fs::write(dir.join(crate::stream::BALLOTS_FILE), body).unwrap();
        }

        /// Served stream in submission order, ledger dump in chain order.
        fn run(name: &str, edit: impl FnOnce(&mut Vec<Ballot>)) -> (PathBuf, AuditStatus, String) {
            let dir = std::env::temp_dir().join(format!("saksi-ledger-order-{name}"));
            let _ = std::fs::remove_dir_all(&dir);
            let f = multi_position_fixture(&GenParams::simple(5, 2, 2, SelectionProfile::Uniform));
            let mut chain = f.ballots.clone();
            chain.sort_by(|a, b| nullifier_of(a).cmp(nullifier_of(b)));
            assert_ne!(
                chain, f.ballots,
                "fixture must not already be in chain order"
            );
            edit(&mut chain);
            write(&dir, &f.ballots);
            write(&dir.join("ledger"), &chain);
            let finding = check_ledger_order(&dir, &dir.join("ledger"));
            (dir, finding.status, finding.detail)
        }

        #[test]
        fn clean_dump_in_chain_order_passes() {
            let (dir, status, detail) = run("clean", |_| {});
            assert_eq!(status, AuditStatus::Pass, "{detail}");
            let _ = std::fs::remove_dir_all(dir);
        }

        #[test]
        fn reordered_dump_fails() {
            let (dir, status, detail) = run("swap", |c| c.swap(0, 1));
            assert_eq!(status, AuditStatus::Fail, "{detail}");
            assert!(
                detail.contains("out of the chain's nullifier order"),
                "{detail}"
            );
            let _ = std::fs::remove_dir_all(dir);
        }

        #[test]
        fn dropped_ballot_in_dump_fails() {
            let (dir, status, detail) = run("drop", |c| {
                c.remove(2);
            });
            assert_eq!(status, AuditStatus::Fail, "{detail}");
            assert!(detail.contains("differs"), "{detail}");
            let _ = std::fs::remove_dir_all(dir);
        }

        #[test]
        fn duplicated_ballot_in_dump_fails() {
            let (dir, status, detail) = run("dup", |c| {
                let b = c[1].clone();
                c.insert(1, b);
            });
            assert_eq!(status, AuditStatus::Fail, "{detail}");
            let _ = std::fs::remove_dir_all(dir);
        }

        #[test]
        fn altered_ciphertext_in_dump_fails() {
            let (dir, status, detail) = run("alter", |c| c[0].ciphertexts[0].pad[0] ^= 1);
            assert_eq!(status, AuditStatus::Fail, "{detail}");
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
