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

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use prost::Message;
use rayon::prelude::*;

use saksi_crypto::group::compress_point;
use saksi_protocol::Ballot;

use crate::fixtures::{
    build_partial_decryptions, build_tally, build_voter, gen_prologue, tally_selections,
    voter_id_for_ballot, CpuTimes, ElectionFixture, GenParams, VoterWork,
};

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
    /// Display-only election name (console/header metadata; NOT bound into any
    /// proof). `#[serde(default)]` so a pre-existing v1 stream without it still
    /// parses — the field is additive within v1, not a wire break.
    #[serde(default)]
    pub election_name: String,
    /// Display-only trustee names, aligned to the election's trustee ids (header
    /// metadata; not on the wire). `#[serde(default)]` for the same reason.
    #[serde(default)]
    pub trustee_names: Vec<String>,
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
        election_name: f.election_name.clone(),
        trustee_names: f.trustee_names.clone(),
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

/// Filename of the generator's stage-timing sidecar.
pub const GEN_TIMINGS_FILE: &str = "gen-timings.json";

/// Voters per generation chunk when the caller does not say otherwise.
pub const DEFAULT_CHUNK_VOTERS: usize = 5_000;

/// Hard cap on one `ballots.ndjson` line. A hex-encoded ballot is a few
/// kilobytes even at wide ballots; 4 MiB is far above any legitimate record and
/// stops a corrupt or hostile file from being read into memory unbounded.
pub const MAX_BALLOT_LINE_BYTES: usize = 4 * 1024 * 1024;

/// What the chunked generator spent, written to [`GEN_TIMINGS_FILE`].
///
/// The three `_cpu_ms` fields are **CPU sums across worker threads** (each
/// voter's own measured time, added up), so on a parallel run they exceed
/// `wall_ms` — that ratio is the point. `wall_ms` is prologue-to-end wall time
/// for the whole write.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GenTimings {
    /// Blind-signature issuance + credential presentation, summed over voters.
    pub credential_cpu_ms: u64,
    /// ElGamal encryption, summed over voters.
    pub encrypt_cpu_ms: u64,
    /// CDS OR-proof generation, summed over voters.
    pub cds_prove_cpu_ms: u64,
    /// Wall time from the start of the prologue to the last byte written.
    pub wall_ms: u64,
    /// Number of chunks the population was generated in.
    pub chunks: usize,
    /// Voters per chunk (the last chunk may be smaller).
    pub chunk_voters: usize,
}

/// Writes `header.json` + `ballots.ndjson` for a whole synthetic population
/// **in chunks**, holding at most `chunk_voters` voters' ballots in memory.
///
/// Each chunk is built with rayon (one `OsRng` per voter, inside the worker),
/// collected back into voter order, appended to `ballots.ndjson`, folded into
/// the running per-contest aggregate + seeded tally, and then dropped. The
/// trustee ceremony at the end runs off that running aggregate, so the header's
/// `tally` / `partial_decryptions` never require the ballots to still exist.
///
/// Memory is therefore `O(chunk_voters × positions × candidates)` for the
/// ballots — plus `header.json`'s `voter_ids`, which the v1 header shape
/// requires to be one string per ballot (see the struct field).
/// Fail-closed structural check over one built chunk, run before a byte of it
/// is written.
///
/// `first_line` is the number of ballot lines already written, so every message
/// names the 1-based line the offending record would have occupied. Nullifier
/// distinctness is checked **within the chunk**: nullifiers derive from
/// distinct credentials, so a cross-chunk collision is a cryptographic
/// impossibility rather than a generator bug, and the auditor's own
/// `nullifier.unique` check covers the whole stream regardless.
fn validate_chunk(
    work: &[VoterWork],
    positions: usize,
    candidates: usize,
    first_line: usize,
) -> Result<(), String> {
    let mut seen: HashSet<&[u8]> = HashSet::with_capacity(work.len() * positions);
    let mut line = first_line;
    for voter in work {
        if voter.ballots.len() != positions {
            return Err(format!(
                "the voter at ballot line {} produced {} records, expected {positions} (one per position)",
                line + 1,
                voter.ballots.len()
            ));
        }
        for ballot in &voter.ballots {
            line += 1;
            if ballot.ciphertexts.len() != candidates
                || ballot.well_formedness_proofs.len() != candidates
            {
                return Err(format!(
                    "ballot line {line} has {} ciphertexts / {} proofs, expected {candidates}",
                    ballot.ciphertexts.len(),
                    ballot.well_formedness_proofs.len()
                ));
            }
            let nullifier = ballot
                .credential_presentation
                .as_ref()
                .and_then(|p| p.nullifier.as_ref())
                .ok_or_else(|| format!("ballot line {line} has no nullifier"))?;
            if !seen.insert(nullifier.value.as_slice()) {
                return Err(format!(
                    "ballot line {line} replays a nullifier from its own chunk (double vote)"
                ));
            }
        }
    }
    Ok(())
}

/// Fail-closed whole-run gate: the checks that only make sense once every chunk
/// has been written, expressed over the two running totals rather than over the
/// population (which is long gone by then).
fn validate_totals(
    lines: usize,
    counts: &[u64],
    voters: usize,
    positions: usize,
    candidates: usize,
) -> Result<(), String> {
    if lines != voters * positions {
        return Err(format!(
            "wrote {lines} ballot lines, expected voters*positions {}",
            voters * positions
        ));
    }
    for p in 0..positions {
        let selected: u64 = counts[p * candidates..(p + 1) * candidates].iter().sum();
        if selected != voters as u64 {
            return Err(format!(
                "position {p} ground-truth aggregate {selected} != voter count {voters} (each voter must select exactly one candidate)"
            ));
        }
    }
    Ok(())
}

pub(crate) fn write_election_stream_chunked(
    dir: &Path,
    params: &GenParams,
    chunk_voters: usize,
) -> Result<(), String> {
    let started = Instant::now();
    let chunk_voters = chunk_voters.clamp(1, params.voters.max(1));
    let positions = params.positions;
    let candidates = params.candidates;
    let contest_count = positions * candidates;

    fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let pro = gen_prologue(params);

    let mut aggregate_pads = vec![RistrettoPoint::identity(); contest_count];
    let mut counts = vec![0u64; contest_count];
    let mut cpu = CpuTimes::default();
    let mut lines = 0usize;
    let mut chunks = 0usize;

    let ballots_path = dir.join(BALLOTS_FILE);
    let ballots_tmp = tmp_path(&ballots_path);
    {
        let file = fs::File::create(&ballots_tmp)
            .map_err(|e| format!("create {}: {e}", ballots_tmp.display()))?;
        let mut out = BufWriter::new(file);

        let mut start = 0usize;
        while start < params.voters {
            let end = (start + chunk_voters).min(params.voters);
            // The only parallel step: every voter is independent, and collecting
            // an indexed parallel iterator preserves voter order, which is what
            // keeps `ballots.ndjson` voter-major.
            let work: Vec<VoterWork> = (start..end)
                .into_par_iter()
                .map(|voter_idx| build_voter(&pro, params, voter_idx))
                .collect();

            validate_chunk(&work, positions, candidates, lines)?;

            let mut selections: Vec<(usize, usize)> = Vec::with_capacity(work.len() * positions);
            for voter in &work {
                for ballot in &voter.ballots {
                    writeln!(out, "{}", hex::encode(ballot.encode_to_vec()))
                        .map_err(|e| format!("write ballot line: {e}"))?;
                    lines += 1;
                }
                for (c, pad) in voter.pads.iter().enumerate() {
                    aggregate_pads[c] += pad;
                }
                selections.extend(voter.selections.iter().copied());
                cpu.add(&voter.cpu);
            }

            // Ground truth stays independent of the ciphertext loop: it is the
            // same pure `tally_selections` the serial fixture uses, folded chunk
            // by chunk instead of over one whole-population vector.
            for (slot, n) in tally_selections(&selections, contest_count, candidates)
                .iter()
                .enumerate()
            {
                counts[slot] += n;
            }

            out.flush().map_err(|e| format!("flush ballots: {e}"))?;
            chunks += 1;
            start = end;
            // `work` (this chunk's ballots) drops here — nothing accumulates.
        }
    }

    // -- fail-closed population gate (what can be checked without the ballots) --

    validate_totals(lines, &counts, params.voters, positions, candidates)?;

    // -- trustee ceremony over the running aggregate ------------------------

    let partial_decryptions = build_partial_decryptions(&pro, &aggregate_pads);
    let tally = build_tally(
        &pro.parameters.election_id,
        counts.clone(),
        partial_decryptions.clone(),
    );

    let header = StreamHeader {
        election_id: pro.parameters.election_id.clone(),
        election_name: params.election_name.clone(),
        trustee_names: params.trustee_names.clone(),
        params: hex::encode(pro.parameters.encode_to_vec()),
        dkg: hex::encode(pro.dkg_transcript.encode_to_vec()),
        issuer_pk: hex::encode(compress_point(pro.issuer_public_key.as_point())),
        binding_context: hex::encode(crate::fixtures::BINDING_CONTEXT),
        partial_decryptions: partial_decryptions
            .iter()
            .map(|p| hex::encode(p.encode_to_vec()))
            .collect(),
        tally: hex::encode(tally.encode_to_vec()),
        ground_truth: counts,
        voter_ids: (0..lines)
            .map(|i| voter_id_for_ballot(i, positions))
            .collect(),
        positions,
        candidates,
        n: lines,
    };
    let header_path = dir.join(HEADER_FILE);
    let header_tmp = tmp_path(&header_path);
    {
        // Serialized straight into the file: `to_string_pretty` would hold a
        // second copy of the header (whose `voter_ids` is one string per ballot)
        // in memory alongside the struct it is copying.
        let file = fs::File::create(&header_tmp)
            .map_err(|e| format!("create {}: {e}", header_tmp.display()))?;
        let mut out = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut out, &header)
            .map_err(|e| format!("encode header: {e}"))?;
        out.flush().map_err(|e| format!("flush header: {e}"))?;
    }

    fs::rename(&ballots_tmp, &ballots_path)
        .map_err(|e| format!("rename {}: {e}", ballots_path.display()))?;
    fs::rename(&header_tmp, &header_path)
        .map_err(|e| format!("rename {}: {e}", header_path.display()))?;

    let timings = GenTimings {
        credential_cpu_ms: cpu.credential.as_millis() as u64,
        encrypt_cpu_ms: cpu.encrypt.as_millis() as u64,
        cds_prove_cpu_ms: cpu.cds_prove.as_millis() as u64,
        wall_ms: started.elapsed().as_millis() as u64,
        chunks,
        chunk_voters,
    };
    let timings_path = dir.join(GEN_TIMINGS_FILE);
    fs::write(
        &timings_path,
        serde_json::to_string_pretty(&timings).map_err(|e| format!("encode timings: {e}"))?,
    )
    .map_err(|e| format!("write {}: {e}", timings_path.display()))?;

    Ok(())
}

/// Streams `ballots.ndjson` one decoded [`Ballot`] at a time.
///
/// The auditor's whole ballot phase runs off this iterator, so a 10M-ballot
/// stream costs one line of memory rather than a `Vec<Ballot>`. Errors are
/// per-line and carry the 1-based line number; a malformed line yields an `Err`
/// item and iteration continues, except when the reader itself failed or a line
/// blew the [`MAX_BALLOT_LINE_BYTES`] cap, which ends the stream.
pub struct BallotLines {
    reader: BufReader<fs::File>,
    line_no: usize,
    done: bool,
}

impl BallotLines {
    /// Opens `<dir>/ballots.ndjson` for streaming.
    pub fn open(dir: &Path) -> Result<Self, String> {
        let path = dir.join(BALLOTS_FILE);
        let file = fs::File::open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
        Ok(Self {
            reader: BufReader::new(file),
            line_no: 0,
            done: false,
        })
    }
}

impl Iterator for BallotLines {
    type Item = Result<Ballot, String>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }
            // Read at most the cap + 1 bytes: a longer line is refused without
            // ever being materialized in full.
            let mut raw: Vec<u8> = Vec::new();
            let read = (&mut self.reader)
                .take(MAX_BALLOT_LINE_BYTES as u64 + 1)
                .read_until(b'\n', &mut raw);
            match read {
                Err(e) => {
                    self.done = true;
                    return Some(Err(format!("read ballot line {}: {e}", self.line_no + 1)));
                }
                Ok(0) => {
                    self.done = true;
                    return None;
                }
                Ok(_) => {}
            }
            self.line_no += 1;
            if !raw.ends_with(b"\n") && raw.len() > MAX_BALLOT_LINE_BYTES {
                self.done = true;
                return Some(Err(format!(
                    "ballot line {} exceeds the {MAX_BALLOT_LINE_BYTES} byte line cap",
                    self.line_no
                )));
            }
            let line = String::from_utf8_lossy(&raw);
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let bytes = match hex::decode(line) {
                Ok(b) => b,
                Err(e) => {
                    return Some(Err(format!(
                        "ballot line {} is not valid hex: {e}",
                        self.line_no
                    )))
                }
            };
            return Some(
                Ballot::decode(&bytes[..])
                    .map_err(|e| format!("ballot line {} did not decode: {e}", self.line_no)),
            );
        }
    }
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
    use crate::fixtures::{multi_position_fixture, GenParams, SelectionProfile};

    /// A temp dir under the crate's target dir — no external tempfile dep.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("saksi-stream-test-{name}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// One chunk's worth of freshly built voters, for the gate tests below to
    /// corrupt. Built through the real generator so the "valid" baseline is the
    /// same thing the writer produces.
    fn built_chunk(voters: usize, positions: usize, candidates: usize) -> Vec<VoterWork> {
        let params = GenParams::simple(voters, positions, candidates, SelectionProfile::Uniform);
        let pro = gen_prologue(&params);
        (0..voters)
            .map(|voter_idx| build_voter(&pro, &params, voter_idx))
            .collect()
    }

    #[test]
    fn the_chunk_gate_rejects_a_voter_with_the_wrong_record_count() {
        let mut work = built_chunk(2, 2, 2);
        work[1].ballots.pop();
        let err = validate_chunk(&work, 2, 2, 0).expect_err("must reject a short voter");
        assert!(err.contains("records"), "got {err}");
        // Voter 1's records would have been lines 3 and 4.
        assert!(
            err.contains("line 3"),
            "the error must name the line: {err}"
        );
    }

    #[test]
    fn the_chunk_gate_rejects_a_ballot_with_the_wrong_ciphertext_count() {
        let mut work = built_chunk(1, 1, 2);
        work[0].ballots[0].ciphertexts.pop();
        let err = validate_chunk(&work, 1, 2, 0).expect_err("must reject a short ballot");
        assert!(err.contains("ciphertexts"), "got {err}");
    }

    #[test]
    fn the_chunk_gate_rejects_a_ballot_with_no_nullifier() {
        let mut work = built_chunk(1, 1, 2);
        work[0].ballots[0]
            .credential_presentation
            .as_mut()
            .expect("presentation")
            .nullifier = None;
        let err = validate_chunk(&work, 1, 2, 0).expect_err("must reject a nullifier-less ballot");
        assert!(err.contains("nullifier"), "got {err}");
    }

    #[test]
    fn the_chunk_gate_rejects_a_replayed_nullifier() {
        let mut work = built_chunk(2, 1, 2);
        let replay = work[0].ballots[0].credential_presentation.clone();
        work[1].ballots[0].credential_presentation = replay;
        let err = validate_chunk(&work, 1, 2, 0).expect_err("must reject a double vote");
        assert!(err.contains("replays"), "got {err}");
    }

    #[test]
    fn the_whole_run_gate_rejects_a_short_stream() {
        // 2 voters x 2 positions = 4 lines; the seeded counts are consistent.
        let counts = [2u64, 0, 1, 1];
        validate_totals(4, &counts, 2, 2, 2).expect("an intact run passes");
        let err = validate_totals(3, &counts, 2, 2, 2).expect_err("must reject a short stream");
        assert!(err.contains("ballot lines"), "got {err}");
    }

    #[test]
    fn the_whole_run_gate_rejects_a_position_that_lost_a_vote() {
        // Position 1 seeds only one selection across two voters.
        let err = validate_totals(4, &[2, 0, 1, 0], 2, 2, 2)
            .expect_err("must reject a per-position aggregate that is not the voter count");
        assert!(err.contains("aggregate"), "got {err}");
    }

    /// A line the auditor cannot decode is reported as its own finding and the
    /// rest of the stream is still audited — the audit never short-circuits.
    #[test]
    fn a_corrupt_ballot_line_fails_the_stream_audit() {
        let dir = scratch("audit-corrupt-line");
        crate::demo::write_election_stream_params_chunked(
            &dir,
            &GenParams::simple(3, 1, 2, SelectionProfile::Uniform),
            2,
        )
        .expect("chunked write");

        let path = dir.join(BALLOTS_FILE);
        let mut lines: Vec<String> = fs::read_to_string(&path)
            .expect("read ndjson")
            .lines()
            .map(String::from)
            .collect();
        lines[1] = "zz-not-hex".to_owned();
        fs::write(&path, format!("{}\n", lines.join("\n"))).expect("rewrite corrupt");

        let (sa, report) = crate::demo::audit_stream_dir_full(&dir).expect("audits");
        assert_eq!(sa.overall, "fail");
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.check == "ballot.decode" && f.status == crate::AuditStatus::Fail),
            "the undecodable line must be reported: {report:#?}"
        );
        assert!(
            report.finding("nullifier.unique").is_some(),
            "the surviving ballots must still be audited"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// The same reporting holds on the DKG-failed path, where the audit stops
    /// after nullifier uniqueness: an undecodable line is still named.
    #[test]
    fn a_corrupt_line_is_reported_even_when_the_dkg_cannot_be_rebuilt() {
        let f = multi_position_fixture(&GenParams::simple(2, 1, 2, SelectionProfile::Uniform));
        // A default transcript fails the very first shape check, so
        // `verify_dkg_transcript` returns None and the audit takes the short path.
        let broken = saksi_protocol::DKGTranscript::default();

        let (report, evidence, _timings) = crate::audit_streaming(
            crate::AuditInputs {
                parameters: &f.parameters,
                dkg_transcript: &broken,
                partial_decryptions: &f.partial_decryptions,
                tally: &f.tally,
                binding_context: crate::fixtures::BINDING_CONTEXT,
                issuer_public_key: &f.issuer_public_key,
                ground_truth: None,
                expected_ballots: None,
            },
            vec![
                Ok(f.ballots[0].clone()),
                Err("ballot line 2 is not valid hex".to_string()),
            ]
            .into_iter(),
        );

        assert!(
            evidence.is_empty(),
            "no tally evidence without a usable DKG transcript"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|x| x.check == "ballot.decode" && x.status == crate::AuditStatus::Fail),
            "{report:#?}"
        );
        assert!(
            report.finding("nullifier.unique").is_some(),
            "nullifier uniqueness still runs when the DKG cannot be rebuilt"
        );
    }

    /// A stream that ends early must not read as a smaller, clean election: the
    /// audit says how many declared lines it never saw.
    #[test]
    fn a_line_over_the_cap_reports_the_lines_it_never_audited() {
        let dir = scratch("cap-completeness");
        crate::demo::write_election_stream_params_chunked(
            &dir,
            &GenParams::simple(3, 1, 2, SelectionProfile::Uniform),
            3,
        )
        .expect("chunked write");

        let path = dir.join(BALLOTS_FILE);
        let lines: Vec<String> = fs::read_to_string(&path)
            .expect("read ndjson")
            .lines()
            .map(String::from)
            .collect();
        // Line 1 audits, line 2 blows the cap and ends the stream, line 3 is
        // never reached.
        let rewritten = format!(
            "{}\n{}\n{}\n",
            lines[0],
            "a".repeat(MAX_BALLOT_LINE_BYTES + 1),
            lines[2]
        );
        fs::write(&path, rewritten).expect("rewrite oversize");

        let (sa, report) = crate::demo::audit_stream_dir_full(&dir).expect("audits");
        assert_eq!(sa.overall, "fail");
        let completeness = report
            .finding("stream.completeness")
            .expect("a truncated stream must be reported");
        assert_eq!(completeness.status, crate::AuditStatus::Fail);
        assert!(
            completeness.detail.contains("audited 2 of the 3")
                && completeness.detail.contains("1 not audited"),
            "got {}",
            completeness.detail
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// The header the chunked writer streams into its file parses back exactly.
    #[test]
    fn the_chunked_header_round_trips_through_read_header() {
        let dir = scratch("header-roundtrip");
        let params = GenParams::simple(4, 2, 3, SelectionProfile::Realistic);
        crate::demo::write_election_stream_params_chunked(&dir, &params, 2).expect("chunked write");

        let header = read_header(&dir).expect("header parses");
        assert_eq!(header.n, 4 * 2, "one record per (voter, position)");
        assert_eq!(header.positions, 2);
        assert_eq!(header.candidates, 3);
        assert_eq!(header.election_id, params.election_id);
        assert_eq!(header.election_name, params.election_name);
        assert_eq!(header.trustee_names, params.trustee_names);
        assert_eq!(header.voter_ids.len(), header.n);
        assert_eq!(header.ground_truth.len(), 2 * 3);
        assert_eq!(
            header.ground_truth.iter().sum::<u64>(),
            4 * 2,
            "one selection per voter per position"
        );
        assert!(
            !header.params.is_empty() && !header.dkg.is_empty() && !header.tally.is_empty(),
            "the embedded protobuf payloads survive the streamed write"
        );
        assert_eq!(verify_stream(&dir).expect("gate passes"), 8);

        let _ = fs::remove_dir_all(&dir);
    }

    /// Every chunk size must describe the same election: the boundary is a
    /// bookkeeping seam, not a cryptographic one. 1 is the degenerate
    /// one-voter-per-chunk case, 7 divides neither the voter count nor the
    /// positions, and 1000 exceeds the electorate (a single clamped chunk).
    #[test]
    fn every_chunk_boundary_audits_clean() {
        let params = GenParams::simple(9, 2, 2, SelectionProfile::Realistic);
        for chunk in [1usize, 7, 1000] {
            let dir = scratch(&format!("chunk-{chunk}"));
            crate::demo::write_election_stream_params_chunked(&dir, &params, chunk)
                .expect("chunked write");
            assert_eq!(
                verify_stream(&dir).expect("gate passes"),
                9 * 2,
                "chunk {chunk}: one record per (voter, position)"
            );
            let sa = crate::demo::audit_stream_dir(&dir).expect("audits");
            assert_eq!(sa.overall, "pass", "chunk {chunk}: {sa:#?}");
            assert!(
                sa.contests.iter().all(|c| c.e == 0 && c.pass),
                "chunk {chunk}: every contest must decode to E = 0"
            );
            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// The streaming auditor is the same auditor: run both over one fixture and
    /// require finding-for-finding equality, not just the same verdict.
    #[test]
    fn streaming_and_in_memory_audits_report_identical_findings() {
        let dir = scratch("same-findings");
        let f = multi_position_fixture(&GenParams::simple(5, 2, 2, SelectionProfile::Skewed));
        let in_memory = crate::audit(f.artifacts());
        write_election_stream(&dir, &f, 2, 2).expect("write stream");

        let (_, streamed) = crate::demo::audit_stream_dir_full(&dir).expect("audits");
        assert_eq!(in_memory.overall, streamed.overall);
        let rows = |r: &crate::AuditReport| -> Vec<(&'static str, String)> {
            r.findings
                .iter()
                .map(|f| (f.check, format!("{:?} {}", f.status, f.detail)))
                .collect()
        };
        assert_eq!(
            rows(&in_memory),
            rows(&streamed),
            "streaming the ballots must not change a single finding"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// A corrupt line yields an `Err` naming its 1-based line number, and the
    /// stream keeps going — the auditor reports the bad line and still audits
    /// the rest.
    #[test]
    fn ballot_lines_names_the_corrupt_line() {
        let dir = scratch("corrupt-line");
        let f = multi_position_fixture(&GenParams::simple(3, 1, 2, SelectionProfile::Uniform));
        write_election_stream(&dir, &f, 1, 2).expect("write stream");

        let path = dir.join(BALLOTS_FILE);
        let mut lines: Vec<String> = fs::read_to_string(&path)
            .expect("read ndjson")
            .lines()
            .map(String::from)
            .collect();
        lines[1] = "zz-not-hex".to_owned();
        fs::write(&path, lines.join("\n")).expect("rewrite corrupt");

        let read: Vec<Result<Ballot, String>> = BallotLines::open(&dir).expect("open").collect();
        assert_eq!(read.len(), 3, "a corrupt line does not end the stream");
        assert!(read[0].is_ok() && read[2].is_ok(), "its neighbours survive");
        let err = read[1].as_ref().expect_err("line 2 is corrupt");
        assert!(
            err.contains("line 2"),
            "the error must name the 1-based line number; got {err:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// A line longer than the cap is refused instead of being read into memory.
    #[test]
    fn ballot_lines_refuses_a_line_over_the_cap() {
        let dir = scratch("oversize-line");
        fs::create_dir_all(&dir).expect("mkdir");
        let mut oversize = "a".repeat(MAX_BALLOT_LINE_BYTES + 1);
        oversize.push('\n');
        fs::write(dir.join(BALLOTS_FILE), oversize).expect("write oversize line");

        let read: Vec<Result<Ballot, String>> = BallotLines::open(&dir).expect("open").collect();
        assert_eq!(read.len(), 1, "the cap ends the stream");
        let err = read[0].as_ref().expect_err("over-cap line is refused");
        assert!(err.contains("cap"), "got {err:?}");

        let _ = fs::remove_dir_all(&dir);
    }

    /// `gen-timings.json` carries every key the console reads, with the chunk
    /// bookkeeping the run actually used.
    #[test]
    fn gen_timings_sidecar_has_every_key() {
        let dir = scratch("gen-timings");
        crate::demo::write_election_stream_params_chunked(
            &dir,
            &GenParams::simple(4, 2, 2, SelectionProfile::Uniform),
            2,
        )
        .expect("chunked write");

        let raw = fs::read_to_string(dir.join(GEN_TIMINGS_FILE)).expect("gen-timings.json exists");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
        for key in [
            "credential_cpu_ms",
            "encrypt_cpu_ms",
            "cds_prove_cpu_ms",
            "wall_ms",
            "chunks",
            "chunk_voters",
        ] {
            assert!(
                v.get(key).and_then(serde_json::Value::as_u64).is_some(),
                "gen-timings.json is missing {key}: {raw}"
            );
        }
        let t: GenTimings = serde_json::from_str(&raw).expect("typed parse");
        assert_eq!(t.chunks, 2, "4 voters at 2 per chunk");
        assert_eq!(t.chunk_voters, 2);
        // The CPU sums measure real cryptographic work, so they cannot all be
        // zero even at millisecond resolution.
        assert!(
            t.credential_cpu_ms + t.encrypt_cpu_ms + t.cds_prove_cpu_ms > 0,
            "no CPU time was recorded: {raw}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// Differential: the chunked writer and the serial writer must describe one
    /// and the same population. Same parameters, chunk size 100 against a single
    /// serial pass — the plaintext ground-truth tables must come out
    /// byte-identical, the ballot streams must be the same length, and both must
    /// audit with `E = 0`.
    #[test]
    fn chunked_writer_matches_the_serial_writer() {
        let params = GenParams::simple(1_000, 3, 4, SelectionProfile::Realistic);
        let serial = scratch("diff-serial");
        let chunked = scratch("diff-chunked");

        crate::demo::write_election_stream_params(&serial, &params).expect("serial write");
        crate::demo::write_election_stream_params_chunked(&chunked, &params, 100)
            .expect("chunked write");

        for csv in [
            crate::ground_truth::GROUND_TRUTH_BALLOTS_CSV,
            crate::ground_truth::GROUND_TRUTH_SUMMARY_CSV,
        ] {
            assert_eq!(
                fs::read(serial.join(csv)).expect("serial csv"),
                fs::read(chunked.join(csv)).expect("chunked csv"),
                "{csv} must be byte-identical across the two writers"
            );
        }

        let n_serial = verify_stream(&serial).expect("serial gate");
        let n_chunked = verify_stream(&chunked).expect("chunked gate");
        assert_eq!(n_serial, n_chunked, "same ballot line count");
        assert_eq!(n_chunked, 1_000 * 3, "one record per (voter, position)");

        let hs = read_header(&serial).expect("serial header");
        let hc = read_header(&chunked).expect("chunked header");
        assert_eq!(
            hs.ground_truth, hc.ground_truth,
            "the two writers seed the same ground truth"
        );

        // The summary CSV is the independent replay of the same selections, so
        // its counts must equal the header's seeded totals (this is what would
        // break if the chunked path folded selections in the wrong order).
        let summary =
            fs::read_to_string(chunked.join(crate::ground_truth::GROUND_TRUTH_SUMMARY_CSV))
                .expect("summary csv");
        let counts: Vec<u64> = summary
            .lines()
            .skip(1)
            .map(|r| r.rsplit(',').next().expect("count column").parse().unwrap())
            .collect();
        assert_eq!(
            counts, hc.ground_truth,
            "summary CSV == header ground truth"
        );

        for dir in [&serial, &chunked] {
            let sa = crate::demo::audit_stream_dir(dir).expect("audits");
            assert_eq!(sa.overall, "pass", "{}: {sa:#?}", dir.display());
            assert!(
                sa.contests.iter().all(|c| c.e == 0 && c.pass),
                "{}: every contest must decode to E = 0",
                dir.display()
            );
        }

        let _ = fs::remove_dir_all(&serial);
        let _ = fs::remove_dir_all(&chunked);
    }

    #[test]
    fn stream_round_trips_and_passes_the_gate() {
        let dir = scratch("roundtrip");
        let f = multi_position_fixture(&GenParams::simple(4, 2, 2, SelectionProfile::Uniform));
        let expected_ballots = f.ballots.len();

        write_election_stream(&dir, &f, 2, 2).expect("write stream");

        let header = read_header(&dir).expect("read header");
        assert_eq!(header.n, expected_ballots, "header.n == ballots written");
        assert_eq!(header.positions, 2);
        assert_eq!(header.candidates, 2);
        // Display metadata carried through (simple() defaults: name = election_id,
        // trustee names "1".."5").
        assert_eq!(header.election_name, "election-2026");
        assert_eq!(header.trustee_names, vec!["1", "2", "3", "4", "5"]);
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
        crate::demo::write_election_stream_params(
            &dir,
            &GenParams::simple(3, 2, 2, SelectionProfile::Uniform),
        )
        .expect("valid population writes a stream");
        // 3 voters × 2 positions = 6 ballots, and the N-count gate passes.
        assert_eq!(verify_stream(&dir).expect("gate passes"), 6);
        assert_eq!(read_header(&dir).expect("header").positions, 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn gate_rejects_a_truncated_ballot_stream() {
        let dir = scratch("truncated");
        let f = multi_position_fixture(&GenParams::simple(4, 2, 2, SelectionProfile::Uniform));
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
        let f = multi_position_fixture(&GenParams::simple(3, 1, 2, SelectionProfile::Uniform));
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
        assert_eq!(header.election_name, "Stream Fixture Election");
        assert_eq!(header.trustee_names.len(), 5);
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
    fn header_without_display_fields_still_parses_v1_compat() {
        // A pre-existing v1 header (written before election_name/trustee_names
        // existed) must still deserialize — the two fields are additive via
        // serde(default), not a wire break.
        let legacy = r#"{
            "election_id":"e","params":"00","dkg":"00","issuer_pk":"00",
            "binding_context":"00","partial_decryptions":[],"tally":"00",
            "ground_truth":[0],"voter_ids":["v"],"positions":1,"candidates":1,"n":1
        }"#;
        let h: StreamHeader = serde_json::from_str(legacy).expect("legacy v1 header parses");
        assert_eq!(h.election_name, "");
        assert!(h.trustee_names.is_empty());
    }

    #[test]
    fn writing_is_atomic_leaving_no_tmp_files_behind() {
        let dir = scratch("atomic");
        let f = multi_position_fixture(&GenParams::simple(2, 1, 2, SelectionProfile::Uniform));
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
