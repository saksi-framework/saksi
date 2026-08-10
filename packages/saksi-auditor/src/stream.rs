//! Streamed election artifacts: `header.json` + `ballots.ndjson`.
//!
//! The one-blob bundle ([`crate::demo`]) holds every ballot in memory and
//! serializes them into a single JSON array. That is fine at demo scale and
//! impossible at the paper's 483k/1M tiers: a million hex ballots is hundreds of
//! megabytes held twice (built, then serialized).
//!
//! This module splits the artifact in two:
//!
//! ```text
//! <dir>/
//!   header.json      small: params, dkg, issuer_pk, binding_context, tally,
//!                    partial_decryptions, ground_truth, voter_ids, n
//!   ballots.ndjson   one hex-encoded Ballot per line, written incrementally
//! ```
//!
//! Line number == ballot index, which is the integer that threads generation →
//! submission → resume → completeness. Reading is sequential and bounded.
//!
//! **Atomicity.** Both files are written to a `.tmp` sibling and renamed into
//! place only after the full write succeeds, so a disk-full or a killed process
//! never leaves a half-written `ballots.ndjson` that looks complete. The header
//! records `n`; [`verify_stream`] asserts `n` equals the actual line count before
//! any run consumes the directory (the fail-closed N-count gate).
//!
//! ponytail: sequential-only. If random access to ballot K is ever needed, add
//! an offset sidecar; the submission workload is a sequential scan, so it isn't.

use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use prost::Message;

use saksi_crypto::group::compress_point;

use crate::fixtures::ElectionFixture;

/// Filename of the small metadata document.
pub const HEADER_FILE: &str = "header.json";
/// Filename of the line-delimited ballot stream.
pub const BALLOTS_FILE: &str = "ballots.ndjson";

/// The `header.json` document: everything about an election except the ballots.
///
/// Field names are the cross-language wire contract — the Go campaign runner and
/// the Caliper workload parse this same shape. Changing a name here is a
/// breaking change to those readers; the pinned fixture in
/// `saksi-protocol/test-vectors/stream-v1/` exists to make that drift fail a test
/// rather than fail a campaign.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct StreamHeader {
    /// Election id, duplicated out of `params` for cheap identification.
    pub election_id: String,
    /// Hex-encoded `ElectionParameters`.
    pub params: String,
    /// Hex-encoded `DKGTranscript`.
    pub dkg: String,
    /// Hex-encoded compressed ristretto issuer public key.
    pub issuer_pk: String,
    /// Hex-encoded NIZK binding context.
    pub binding_context: String,
    /// Hex-encoded `PartialDecryption` messages.
    pub partial_decryptions: Vec<String>,
    /// Hex-encoded `TallyResult`.
    pub tally: String,
    /// Seeded ground-truth per-contest totals (accuracy scoring, `E = 0`).
    pub ground_truth: Vec<u64>,
    /// Synthetic voter id per ballot, aligned to ballot index. Off-wire
    /// generation metadata — never on the chain, so on-chain unlinkability is
    /// preserved.
    pub voter_ids: Vec<String>,
    /// Ballot-axis label: number of positions per voter.
    pub positions: usize,
    /// Ballot-axis label: number of candidates per position.
    pub candidates: usize,
    /// Number of ballot lines in `ballots.ndjson`. The N-count gate.
    pub n: usize,
}

/// Writes `header.json` + `ballots.ndjson` into `dir`, creating it if needed.
///
/// Ballots stream out one line at a time, so peak memory is one ballot rather
/// than the whole population. Both files land atomically (temp + rename).
///
/// `pub(crate)` because it takes an [`ElectionFixture`] (crate-private); the
/// public streaming entry point is the params wrapper in [`crate::demo`].
pub(crate) fn write_election_stream(
    dir: &Path,
    f: &ElectionFixture,
    positions: usize,
    candidates: usize,
) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;

    let art = f.artifacts();

    // -- ballots.ndjson (streamed) ----------------------------------------
    let ballots_path = dir.join(BALLOTS_FILE);
    let ballots_tmp = tmp_path(&ballots_path);
    {
        let file = fs::File::create(&ballots_tmp)
            .map_err(|e| format!("create {}: {e}", ballots_tmp.display()))?;
        let mut out = BufWriter::new(file);
        for ballot in art.ballots {
            // Encode → hex → line, then drop; nothing accumulates.
            writeln!(out, "{}", hex::encode(ballot.encode_to_vec()))
                .map_err(|e| format!("write ballot line: {e}"))?;
        }
        out.flush().map_err(|e| format!("flush ballots: {e}"))?;
    }

    // -- header.json -------------------------------------------------------
    let header = StreamHeader {
        election_id: art.parameters.election_id.clone(),
        params: hex::encode(art.parameters.encode_to_vec()),
        dkg: hex::encode(art.dkg_transcript.encode_to_vec()),
        issuer_pk: hex::encode(compress_point(art.issuer_public_key.as_point())),
        binding_context: hex::encode(art.binding_context),
        partial_decryptions: art
            .partial_decryptions
            .iter()
            .map(|p| hex::encode(p.encode_to_vec()))
            .collect(),
        tally: hex::encode(art.tally.encode_to_vec()),
        ground_truth: f.ground_truth.clone(),
        voter_ids: f.voter_ids.clone(),
        positions,
        candidates,
        n: art.ballots.len(),
    };
    let header_path = dir.join(HEADER_FILE);
    let header_tmp = tmp_path(&header_path);
    let encoded =
        serde_json::to_string_pretty(&header).map_err(|e| format!("encode header: {e}"))?;
    fs::write(&header_tmp, encoded).map_err(|e| format!("write {}: {e}", header_tmp.display()))?;

    // Rename only after BOTH temps are fully written: a crash between the two
    // renames leaves the older (or no) directory state, never a header claiming
    // ballots that were not durably written.
    fs::rename(&ballots_tmp, &ballots_path)
        .map_err(|e| format!("rename {}: {e}", ballots_path.display()))?;
    fs::rename(&header_tmp, &header_path)
        .map_err(|e| format!("rename {}: {e}", header_path.display()))?;
    Ok(())
}

/// Reads and parses `header.json` from `dir`.
pub fn read_header(dir: &Path) -> Result<StreamHeader, String> {
    let path = dir.join(HEADER_FILE);
    let raw = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// Counts the non-empty lines in `ballots.ndjson`, verifying each decodes as hex.
///
/// Streaming count — never holds the file in memory.
pub fn count_ballots(dir: &Path) -> Result<usize, String> {
    let path = dir.join(BALLOTS_FILE);
    let file = fs::File::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut n = 0usize;
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| format!("read line {}: {e}", i + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        hex::decode(line.trim())
            .map_err(|e| format!("ballot line {} is not valid hex: {e}", i + 1))?;
        n += 1;
    }
    Ok(n)
}

/// Fail-closed N-count gate: the header's `n` must equal the actual ballot-line
/// count, and the ground-truth width must match the declared axes.
///
/// This is what catches a truncated `ballots.ndjson` (disk full, killed mid-run)
/// before a single ballot is submitted. Returns the verified ballot count.
pub fn verify_stream(dir: &Path) -> Result<usize, String> {
    let header = read_header(dir)?;
    let actual = count_ballots(dir)?;
    if actual != header.n {
        return Err(format!(
            "{} has {} ballot lines but header.n is {} — the stream is truncated or the header is stale",
            BALLOTS_FILE, actual, header.n
        ));
    }
    let expected_truth = header.positions * header.candidates;
    if header.ground_truth.len() != expected_truth {
        return Err(format!(
            "ground_truth has {} entries, expected positions*candidates = {}",
            header.ground_truth.len(),
            expected_truth
        ));
    }
    if header.voter_ids.len() != header.n {
        return Err(format!(
            "voter_ids has {} entries but header.n is {} (one per ballot)",
            header.voter_ids.len(),
            header.n
        ));
    }
    Ok(actual)
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{multi_position_fixture, SelectionProfile};

    /// A temp dir under the crate's target dir — no external tempfile dep.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("saksi-stream-test-{name}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn stream_round_trips_and_passes_the_gate() {
        let dir = scratch("roundtrip");
        let f = multi_position_fixture(4, 2, 2, SelectionProfile::Uniform);
        let expected_ballots = f.ballots.len();

        write_election_stream(&dir, &f, 2, 2).expect("write stream");

        let header = read_header(&dir).expect("read header");
        assert_eq!(header.n, expected_ballots, "header.n == ballots written");
        assert_eq!(header.positions, 2);
        assert_eq!(header.candidates, 2);
        assert_eq!(header.ground_truth.len(), 4, "positions*candidates");
        assert_eq!(header.voter_ids.len(), expected_ballots);
        assert!(!header.params.is_empty() && !header.dkg.is_empty());

        assert_eq!(
            verify_stream(&dir).expect("gate passes on an intact stream"),
            expected_ballots
        );

        // Every line decodes back into a Ballot with the expected election id.
        let raw = fs::read_to_string(dir.join(BALLOTS_FILE)).expect("read ndjson");
        let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), expected_ballots);
        for line in &lines {
            let bytes = hex::decode(line).expect("line is hex");
            let ballot =
                saksi_protocol::Ballot::decode(&bytes[..]).expect("line decodes as Ballot");
            assert_eq!(ballot.election_id, header.election_id);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stream_params_entry_gates_then_writes_a_verifiable_stream() {
        // The CLI-facing entry: build → validation gate → streamed write.
        let dir = scratch("params-entry");
        crate::demo::write_election_stream_params(&dir, 3, 2, 2, false)
            .expect("valid population writes a stream");
        // 3 voters × 2 positions = 6 ballots, and the N-count gate passes.
        assert_eq!(verify_stream(&dir).expect("gate passes"), 6);
        assert_eq!(read_header(&dir).expect("header").positions, 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn gate_rejects_a_truncated_ballot_stream() {
        let dir = scratch("truncated");
        let f = multi_position_fixture(4, 2, 2, SelectionProfile::Uniform);
        write_election_stream(&dir, &f, 2, 2).expect("write stream");

        // Simulate a disk-full / killed-mid-write stream: drop the last line
        // while the header still claims the full count.
        let path = dir.join(BALLOTS_FILE);
        let raw = fs::read_to_string(&path).expect("read ndjson");
        let mut lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
        lines.pop();
        fs::write(&path, format!("{}\n", lines.join("\n"))).expect("rewrite truncated");

        let err = verify_stream(&dir).expect_err("truncated stream must fail the gate");
        assert!(
            err.contains("truncated") || err.contains("header.n"),
            "error should name the truncation, got: {err}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn gate_rejects_a_corrupt_hex_line() {
        let dir = scratch("corrupt");
        let f = multi_position_fixture(3, 1, 2, SelectionProfile::Uniform);
        write_election_stream(&dir, &f, 1, 2).expect("write stream");

        let path = dir.join(BALLOTS_FILE);
        let raw = fs::read_to_string(&path).expect("read ndjson");
        let mut lines: Vec<String> = raw.lines().map(String::from).collect();
        lines[0] = "not-hex-at-all".to_owned();
        fs::write(&path, lines.join("\n")).expect("rewrite corrupt");

        let err = verify_stream(&dir).expect_err("corrupt hex must fail the gate");
        assert!(err.contains("not valid hex"), "got: {err}");

        let _ = fs::remove_dir_all(&dir);
    }

    /// E2 cross-language contract: the pinned fixture in
    /// `saksi-protocol/test-vectors/stream-v1/` must parse with the SAME reader
    /// the campaign uses. The Go runner parses this identical directory, so a
    /// field rename or retype on either side fails a test instead of a campaign.
    ///
    /// The fixture's hex payloads are static placeholders, not real ballots —
    /// the generator uses `OsRng`, so ballot bytes cannot be byte-pinned. This
    /// pins the FORMAT; crypto agreement is pinned by `cds-proof-v1.hex` etc.
    #[test]
    fn pinned_fixture_parses_with_the_same_reader() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("saksi-protocol")
            .join("test-vectors")
            .join("stream-v1");

        let header = read_header(&dir).expect("pinned header.json parses");
        assert_eq!(header.election_id, "stream-fixture-election");
        assert_eq!(header.n, 4);
        assert_eq!(header.positions, 2);
        assert_eq!(header.candidates, 2);
        assert_eq!(header.ground_truth, vec![2, 1, 0, 3]);
        assert_eq!(header.voter_ids.len(), 4, "one voter id per ballot");
        assert_eq!(header.partial_decryptions.len(), 2);

        assert_eq!(count_ballots(&dir).expect("count fixture ballots"), 4);
        assert_eq!(
            verify_stream(&dir).expect("pinned fixture passes the N-count gate"),
            4
        );
    }

    #[test]
    fn writing_is_atomic_leaving_no_tmp_files_behind() {
        let dir = scratch("atomic");
        let f = multi_position_fixture(2, 1, 2, SelectionProfile::Uniform);
        write_election_stream(&dir, &f, 1, 2).expect("write stream");

        for entry in fs::read_dir(&dir).expect("read dir") {
            let name = entry.expect("entry").file_name();
            let name = name.to_string_lossy();
            assert!(
                !name.ends_with(".tmp"),
                "temp file {name} survived a successful write"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
