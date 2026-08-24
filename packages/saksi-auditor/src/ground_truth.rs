//! Synthetic ground-truth CSV export — the paper's Stage 4 (DSRM Figure 3.1)
//! artifact, written *before* any cryptography runs.
//!
//! The manuscript's pipeline generates a synthetic population and its known
//! vote-to-candidate counts, passes them through a validation gate, and only
//! then drives the encrypted election (Stage 5, "Demonstration"). Appendix A
//! documents that population. This module writes it out as two CSVs a reader
//! can open and check by eye before trusting anything downstream:
//!
//! - `ground-truth-ballots.csv` — wide: one row per voter, one column per
//!   position, holding that voter's plaintext selection. Every voter casts a
//!   selection in every position (the generator models no abstention).
//! - `ground-truth-summary.csv` — long: one row per (position, candidate) with
//!   the seeded count. This is the `G_i` of the paper's accuracy metric
//!   `E = Σ|T_i − G_i|`, and must equal `correctness.csv`'s `ground_truth`
//!   column for the same parameters.
//!
//! Selections are replayed through [`select_candidate`], the same pure function
//! `multi_position_fixture` uses, so a population written here is bit-identical
//! to the one the cryptographic generator would produce. That is what lets this
//! file stand as independent evidence rather than a second implementation that
//! could silently diverge.
//!
//! Everything streams: one buffered line per voter, never a `Vec` of all rows.
//! The full-ZAMBASULTA tier is 3,524,078 voters × 3 positions ≈ 10.6M
//! selections, which this writes in a single linear pass with no crypto, no
//! network, and bounded memory.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::fixtures::{ph_position_id, select_candidate, GenParams};

/// Filename of the wide, one-row-per-voter plaintext ballot table.
pub const GROUND_TRUTH_BALLOTS_CSV: &str = "ground-truth-ballots.csv";
/// Filename of the per-contest seeded tally.
pub const GROUND_TRUTH_SUMMARY_CSV: &str = "ground-truth-summary.csv";

/// Column header for position `p`: `ph_position_id` uppercased with separators
/// normalised to underscores (`vice-president` → `VICE_PRESIDENT`).
fn position_column(p: usize) -> String {
    ph_position_id(p).to_uppercase().replace('-', "_")
}

/// Candidate-label prefix for position `p`. Readable short forms for the three
/// named Philippine positions (paper §3.4), generic beyond them.
fn candidate_prefix(p: usize) -> String {
    match p {
        0 => "PRES".to_string(),
        1 => "VICE".to_string(),
        2 => "SEN".to_string(),
        n => format!("POS{n}"),
    }
}

/// Candidate label as it appears in both CSVs, e.g. `CAND_PRES_01`. `k` is the
/// zero-based candidate index; labels are 1-based so they read as ballot
/// positions rather than array offsets.
fn candidate_label(p: usize, k: usize) -> String {
    format!("CAND_{}_{:02}", candidate_prefix(p), k + 1)
}

/// Writes both ground-truth CSVs into `dir`.
///
/// Runs no cryptography: no DKG, no credential issuance, no encryption, no
/// proofs. Cost is linear in `voters × positions` and dominated by formatting
/// and I/O, which is why this path carries no voter ceiling.
pub fn write_ground_truth_csvs(dir: &Path, params: &GenParams) -> Result<(), String> {
    if params.voters < 1 || params.positions < 1 || params.candidates < 1 {
        return Err("voters, positions, and candidates must each be >= 1".to_string());
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;

    let positions = params.positions;
    let candidates = params.candidates;
    let complexity = if positions == 1 { "single" } else { "multi" };

    // Precompute the per-position label tables once; the inner loop then only
    // indexes them. At 3.5M voters this saves ~10.6M string constructions.
    let columns: Vec<String> = (0..positions).map(position_column).collect();
    let labels: Vec<Vec<String>> = (0..positions)
        .map(|p| (0..candidates).map(|k| candidate_label(p, k)).collect())
        .collect();

    // Seeded tally, one slot per (position, candidate) — same slot math as
    // `fixtures::tally_selections` (`p * candidates + selected`).
    let mut counts = vec![0u64; positions * candidates];

    let ballots_path = dir.join(GROUND_TRUTH_BALLOTS_CSV);
    let file = File::create(&ballots_path)
        .map_err(|e| format!("create {}: {e}", ballots_path.display()))?;
    let mut out = BufWriter::new(file);

    write!(out, "voter_id,scale_group,ballot_complexity").map_err(io_err(&ballots_path))?;
    for column in &columns {
        write!(out, ",{column}").map_err(io_err(&ballots_path))?;
    }
    writeln!(out).map_err(io_err(&ballots_path))?;

    for voter_idx in 0..params.voters {
        write!(
            out,
            "V-{:06},{},{}",
            voter_idx + 1,
            params.voters,
            complexity
        )
        .map_err(io_err(&ballots_path))?;
        for p in 0..positions {
            let selected = select_candidate(params.profile, voter_idx, p, candidates);
            counts[p * candidates + selected] += 1;
            write!(out, ",{}", labels[p][selected]).map_err(io_err(&ballots_path))?;
        }
        writeln!(out).map_err(io_err(&ballots_path))?;
    }
    out.flush().map_err(io_err(&ballots_path))?;

    let summary_path = dir.join(GROUND_TRUTH_SUMMARY_CSV);
    let file = File::create(&summary_path)
        .map_err(|e| format!("create {}: {e}", summary_path.display()))?;
    let mut out = BufWriter::new(file);
    writeln!(out, "position,candidate,ground_truth_count").map_err(io_err(&summary_path))?;
    for p in 0..positions {
        for k in 0..candidates {
            writeln!(
                out,
                "{},{},{}",
                columns[p],
                labels[p][k],
                counts[p * candidates + k]
            )
            .map_err(io_err(&summary_path))?;
        }
    }
    out.flush().map_err(io_err(&summary_path))?;

    Ok(())
}

fn io_err(path: &Path) -> impl Fn(std::io::Error) -> String + '_ {
    move |e| format!("write {}: {e}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{tally_selections, SelectionProfile};

    fn params(voters: usize, positions: usize, candidates: usize, profile: SelectionProfile) -> GenParams {
        GenParams {
            election_id: "gt-test".to_string(),
            election_name: "gt-test".to_string(),
            threshold: 2,
            trustees: 3,
            trustee_names: vec!["a".into(), "b".into(), "c".into()],
            voters,
            positions,
            candidates,
            profile,
        }
    }

    fn read(dir: &Path, name: &str) -> Vec<String> {
        std::fs::read_to_string(dir.join(name))
            .expect("csv exists")
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The wide file carries exactly one row per voter (not one per
    /// voter-position), with a header built from the position count.
    #[test]
    fn ballots_csv_is_wide_one_row_per_voter() {
        let dir = tempdir();
        let p = params(4, 2, 3, SelectionProfile::Uniform);
        write_ground_truth_csvs(&dir, &p).expect("writes");

        let lines = read(&dir, GROUND_TRUTH_BALLOTS_CSV);
        assert_eq!(
            lines[0], "voter_id,scale_group,ballot_complexity,PRESIDENT,VICE_PRESIDENT",
            "header names one column per position"
        );
        assert_eq!(lines.len(), 1 + p.voters, "one data row per voter");

        let first: Vec<&str> = lines[1].split(',').collect();
        assert_eq!(first[0], "V-000001");
        assert_eq!(first[1], "4", "scale_group is the tier's voter count");
        assert_eq!(first[2], "multi");
        assert!(first[3].starts_with("CAND_PRES_"), "got {}", first[3]);
        assert!(first[4].starts_with("CAND_VICE_"), "got {}", first[4]);
    }

    /// A single-position run emits exactly one selection column and is labelled
    /// `single`, matching the paper's baseline-comparison configuration.
    #[test]
    fn single_position_run_has_one_selection_column() {
        let dir = tempdir();
        write_ground_truth_csvs(&dir, &params(3, 1, 4, SelectionProfile::Skewed)).expect("writes");

        let lines = read(&dir, GROUND_TRUTH_BALLOTS_CSV);
        assert_eq!(lines[0], "voter_id,scale_group,ballot_complexity,PRESIDENT");
        assert!(lines[1].ends_with(",single,CAND_PRES_01") || lines[1].contains(",single,CAND_PRES_"));
    }

    /// The summary must equal the independent tally the cryptographic generator
    /// derives from the same selections — this is what makes the CSV usable as
    /// ground truth for `E = Σ|T_i − G_i|` rather than a parallel guess.
    #[test]
    fn summary_matches_tally_selections_for_both_profiles() {
        for profile in [SelectionProfile::Uniform, SelectionProfile::Skewed] {
            let dir = tempdir();
            let p = params(7, 3, 4, profile);
            write_ground_truth_csvs(&dir, &p).expect("writes");

            // Rebuild the selection record the fixture generator would produce.
            let mut selections = Vec::new();
            for voter_idx in 0..p.voters {
                for position in 0..p.positions {
                    selections.push((
                        position,
                        select_candidate(profile, voter_idx, position, p.candidates),
                    ));
                }
            }
            // `tally_selections`' second argument is the total contest-slot
            // count (positions × candidates), not the position count.
            let expected =
                tally_selections(&selections, p.positions * p.candidates, p.candidates);

            let rows = read(&dir, GROUND_TRUTH_SUMMARY_CSV);
            assert_eq!(rows.len(), 1 + p.positions * p.candidates);
            let got: Vec<u64> = rows[1..]
                .iter()
                .map(|r| r.rsplit(',').next().unwrap().parse().unwrap())
                .collect();
            assert_eq!(got, expected, "profile {profile:?}");

            // Every position's counts must sum to the voter count: one
            // selection per voter per position, no abstention.
            for position in 0..p.positions {
                let slice = &got[position * p.candidates..(position + 1) * p.candidates];
                assert_eq!(slice.iter().sum::<u64>(), p.voters as u64);
            }
        }
    }

    /// Beyond the three named positions the labels fall back to a generic form
    /// rather than panicking or colliding.
    #[test]
    fn positions_beyond_three_get_generic_labels() {
        let dir = tempdir();
        write_ground_truth_csvs(&dir, &params(2, 5, 2, SelectionProfile::Uniform)).expect("writes");
        let lines = read(&dir, GROUND_TRUTH_BALLOTS_CSV);
        assert!(lines[0].ends_with(",POSITION_3,POSITION_4"), "got {}", lines[0]);
        assert!(lines[1].contains("CAND_POS3_"), "got {}", lines[1]);
    }

    fn tempdir() -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "saksi-gt-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).expect("temp dir");
        base
    }
}
