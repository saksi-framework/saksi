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

/// [`ledger_digest`] and record count of an ndjson ballot file, streamed in
/// file order (the order the chain served it, for a ledger read-back). Equal to
/// `ledger_digest` of the same ballots as a slice. A line that does not decode
/// is an error: a corrupt dump has no digest.
#[cfg(feature = "demo")]
pub fn ledger_digest_file(path: &std::path::Path) -> Result<(u64, [u8; 32]), String> {
    let mut acc = digest_start();
    let mut n = 0u64;
    for ballot in crate::stream::BallotLines::open_file(path)? {
        acc = digest_step(&acc, &ballot_leaf(&ballot?));
        n += 1;
    }
    Ok((n, acc))
}

/// What a precinct return carries about its ledger read-back: the record count,
/// [`ledger_digest`], and per-contest `(Σc1, Σc2)` over the ballots that verify.
#[cfg(feature = "demo")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerSums {
    /// Every record in the file, verified or not.
    pub record_count: u64,
    /// [`ledger_digest`] over every record, in file order.
    pub ledger_digest: [u8; 32],
    /// Records whose proofs and credential verified (the ones summed).
    pub verified: u64,
    /// `(contest_id, Σc1, Σc2)` in `contest_ids` order, compressed points.
    pub contests: Vec<(String, [u8; 32], [u8; 32])>,
}

/// [`LedgerSums`] of `ballots` under the election in `header_dir/header.json`
/// (params, DKG, issuer key, binding context).
///
/// The sums are the auditor's homomorphic aggregate: each ballot goes through
/// the same per-ballot verifier the streaming audit uses
/// (`ballot::verify_ballot`, in rayon batches of `VERIFY_CHUNK`), and only a
/// ballot it returns as eligible is folded in, so a forged or malformed record
/// is counted and digested but never summed. Nullifier duplicates are summed,
/// as in the audit's own fold; `audit-stream` and the canvass report them.
/// A line that does not decode is an error.
#[cfg(feature = "demo")]
pub fn verified_sums(
    header_dir: &std::path::Path,
    ballots: impl Iterator<Item = Result<Ballot, String>>,
) -> Result<LedgerSums, String> {
    use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
    use prost::Message;
    use rayon::prelude::*;
    use saksi_credentials::IssuerPublicKey;
    use saksi_crypto::group::{compress_point, point_from_compressed};
    use saksi_protocol::{DKGTranscript, ElectionParameters};

    let header = crate::stream::read_header(header_dir)?;
    let hexd = |s: &str, what: &str| hex::decode(s).map_err(|e| format!("{what} not hex: {e}"));
    let params = ElectionParameters::decode(&hexd(&header.params, "params")?[..])
        .map_err(|e| format!("decode params: {e}"))?;
    let dkg = DKGTranscript::decode(&hexd(&header.dkg, "dkg")?[..])
        .map_err(|e| format!("decode dkg: {e}"))?;
    let issuer_bytes: [u8; 32] = hexd(&header.issuer_pk, "issuer_pk")?
        .try_into()
        .map_err(|_| "issuer_pk is not 32 bytes".to_string())?;
    let issuer = IssuerPublicKey(
        point_from_compressed(issuer_bytes).map_err(|_| "issuer_pk is not a valid point")?,
    );
    let binding = hexd(&header.binding_context, "binding_context")?;
    let mut scratch = crate::report::ReportBuilder::new();
    let joint = crate::dkg::verify_dkg_transcript(&params, &dkg, &mut scratch)
        .ok_or("the DKG transcript in header.json does not rebuild a joint key")?
        .joint_public_key;
    let election_pk = saksi_crypto::elgamal::PublicKey::from_point(joint);

    let n = params.contest_ids.len();
    let mut c1 = vec![RistrettoPoint::identity(); n];
    let mut c2 = vec![RistrettoPoint::identity(); n];
    let (mut acc, mut records, mut verified) = (digest_start(), 0u64, 0u64);
    let mut ballots = ballots.fuse();
    loop {
        let chunk: Vec<Ballot> = ballots
            .by_ref()
            .take(crate::VERIFY_CHUNK)
            .collect::<Result<_, _>>()?;
        if chunk.is_empty() {
            break;
        }
        let base = records as usize;
        let decoded: Vec<_> = chunk
            .par_iter()
            .enumerate()
            .map(|(i, b)| {
                crate::ballot::verify_ballot(
                    base + i,
                    b,
                    &params,
                    &election_pk,
                    &issuer,
                    &binding,
                    &mut Default::default(),
                    &mut crate::report::ReportBuilder::new(),
                )
            })
            .collect();
        for (ballot, dec) in chunk.iter().zip(decoded) {
            acc = digest_step(&acc, &ballot_leaf(ballot));
            records += 1;
            if let Some(dec) = dec {
                verified += 1;
                for ct in dec {
                    c1[ct.contest] += ct.pad;
                    c2[ct.contest] += ct.data;
                }
            }
        }
    }
    Ok(LedgerSums {
        record_count: records,
        ledger_digest: acc,
        verified,
        contests: params
            .contest_ids
            .iter()
            .zip(c1.iter().zip(&c2))
            .map(|(id, (a, b))| (id.clone(), compress_point(a), compress_point(b)))
            .collect(),
    })
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
    mod sums {
        use super::super::{ledger_digest, ledger_digest_file, verified_sums};
        use crate::demo::write_election_stream_params;
        use crate::fixtures::{GenParams, SelectionProfile};
        use crate::stream::{BallotLines, BALLOTS_FILE};
        use prost::Message;

        /// The streamed digest equals the slice digest, and a tampered record is
        /// counted and digested but left out of the sums.
        #[test]
        fn file_digest_matches_and_sums_skip_a_bad_ballot() {
            let dir = std::env::temp_dir().join("saksi-ledger-sums");
            let _ = std::fs::remove_dir_all(&dir);
            write_election_stream_params(
                &dir,
                &GenParams::simple(4, 2, 2, SelectionProfile::Uniform),
            )
            .unwrap();
            let file = dir.join(BALLOTS_FILE);
            let ballots: Vec<_> = BallotLines::open(&dir)
                .unwrap()
                .map(Result::unwrap)
                .collect();
            let (n, d) = ledger_digest_file(&file).unwrap();
            assert_eq!((n as usize, d), (ballots.len(), ledger_digest(&ballots)));

            let clean = verified_sums(&dir, ballots.iter().cloned().map(Ok)).unwrap();
            assert_eq!(clean.record_count, n);
            assert_eq!(clean.verified, n);
            assert_eq!(clean.ledger_digest, d);

            let mut bad = ballots.clone();
            bad[1].ciphertexts[0].data = clean.contests[0].2.to_vec();
            let tampered = verified_sums(&dir, bad.iter().cloned().map(Ok)).unwrap();
            assert_eq!(tampered.record_count, n);
            assert_eq!(tampered.verified, n - 1);
            assert_ne!(tampered.ledger_digest, d);
            assert_ne!(tampered.contests, clean.contests);

            // A corrupt line is an error, not a smaller ledger.
            let body: String = ballots
                .iter()
                .map(|b| {
                    hex::encode(b.encode_to_vec())
                        + "
"
                })
                .collect::<String>()
                + "zz
";
            std::fs::write(&file, body).unwrap();
            assert!(ledger_digest_file(&file).is_err());
            let _ = std::fs::remove_dir_all(&dir);
        }
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
