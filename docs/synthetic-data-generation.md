# Synthetic data generation

How BalotaChain/Saksi produces the synthetic voter populations the evaluation
runs on, what each artifact contains, and how to reproduce any of it.

This is **Stage 4** of the thesis methodology (DSRM Figure 3.1): seed a
population and its known vote-to-candidate counts, pass a validation gate, and
only then hand the data to **Stage 5**, the encrypted election. The separation
matters — it is what lets a reader inspect the input *before* any cryptography
touches it, and what gives the accuracy metric `E = Σ|Tᵢ − Gᵢ|` an independent
`G` to compare against.

---

## 1. The two paths

Both produce the same population. They differ only in whether the expensive
cryptography runs.

```
                    ┌─ gen --stream ────────► header.json + ballots.ndjson
saksi-demo ─────────┤                         (real ElGamal ciphertexts,
                    │                          CDS proofs, DKG, credentials)
                    │                              +
                    │                         ground-truth-*.csv
                    │
                    └─ gen-ground-truth ────► ground-truth-*.csv only
                                              (no crypto at all)
```

`gen --stream` is the full generator: it issues a blind-signed credential per
voter, runs the DKG, encrypts every selection under the joint key, and attaches
a CDS OR-proof per candidate. It also writes the ground-truth CSVs.

`gen-ground-truth` writes **only** the plaintext tables. No DKG, no credentials,
no ciphertexts, no proofs. This is what makes the capstone tiers tractable:
3,524,078 voters × 3 positions generates in **0.6 seconds**, where the same
population through the full cryptographic path is hours of work.

Both replay the identical selection function, so the populations are
bit-identical — verified by `diff`, not by assumption.

---

## 2. How a vote is chosen

Every selection comes from one pure function. No RNG, no stored seed:

```rust
// packages/saksi-auditor/src/fixtures.rs

/// Scrambles `(voter_idx, position)` into a well-spread pseudorandom number.
/// SplitMix64's finalizer: four operations, no state, no seed.
fn mix(voter_idx: usize, p: usize) -> u64 {
    let mut x = (voter_idx as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ (p as u64).wrapping_add(1);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Deterministic 1-of-C selection under a fixed profile (reproducible).
pub(crate) fn select_candidate(
    profile: SelectionProfile,
    voter_idx: usize,
    p: usize,
    candidates: usize,
) -> usize {
    if candidates <= 1 {
        return 0;
    }
    let h = mix(voter_idx, p);
    match profile {
        SelectionProfile::Uniform => (h % candidates as u64) as usize,
        SelectionProfile::Skewed => {
            if h & 1 == 0 {
                0
            } else {
                1 + ((h >> 8) % (candidates as u64 - 1)) as usize
            }
        }
    }
}
```

**Reproducibility.** Because the choice is derived arithmetically from the voter
index, position index, and profile, a population is reproduced exactly by
restating its four generation parameters. There is no seed to record, lose, or
mistranscribe — a stronger guarantee than seeded pseudorandomness, not a weaker
one.

**Why a hash and not plain arithmetic.** An earlier version selected with
`(voter_idx + p) % candidates`. That is deterministic too, but it is a
round-robin: every position ended up with a near-identical set of totals,
differing by a vote or two. Totals that interchangeable mean the accuracy check
cannot discriminate — a component that confused one contest for another would
still have satisfied `E = 0`. Mixing gives each contest its own distinctive
totals, so the check has something to catch.

**The two profiles:**

| Profile | Shape |
|---|---|
| `uniform` | every candidate equally likely |
| `skewed` | candidate 1 takes roughly half; the rest share the remainder |

At the full ZAMBASULTA tier the skew lands near half without being suspiciously
exact, and no two positions agree:

```
PRESIDENT       1,762,232   585,899   588,562   587,385
VICE_PRESIDENT  1,762,295   586,840   586,650   588,293
SENATOR         1,763,309   586,042   587,193   587,534
```

---

## 3. The ballot model, and its limits

The current model is **one selection per position, per voter**:

- Every voter votes in **every** position. Abstention is not modelled.
- Every position has the **same** number of candidates (`--candidates C`).
- Every position is **single-winner** — the voter picks exactly one.

This matches the manuscript's Appendix A (*"three positions: President, Vice
President, Senator, single-winner each"*, *"fixed set of K candidates"*).

**What it does not model**, stated plainly because it is a real scope limit:

- Different candidate counts per position. A real Philippine ballot has roughly
  ten presidential candidates and dozens of senatorial ones.
- Multi-winner races. The actual Senate race elects 12 of ~37. Supporting that
  needs more than a config flag: the CDS proof proves each ciphertext encrypts
  0 or 1, and the validation gate asserts each position's ground-truth total
  equals its ballot count. A 12-winner contest needs a proof that a voter's
  selections *sum to 12* — new cryptography, and a rework of the gate.
- Abstention / undervoting.

None of these affect the properties under evaluation (integrity, privacy,
threshold decryption, verifiability), which is why the simplification is
acceptable — but it should be declared, not discovered.

---

## 4. Contest indexing

A "contest" is one (position, candidate) slot. Ground truth is a flat vector
over those slots:

```rust
// packages/saksi-auditor/src/fixtures.rs
//
// Each entry is `(position_index, selected_candidate)`; it contributes `+1` to
// contest slot `position_index * candidates + selected_candidate`.
pub(crate) fn tally_selections(
    selections: &[(usize, usize)],
    contest_count: usize,
    candidates: usize,
) -> Vec<u64> {
    let mut totals = vec![0u64; contest_count];
    for &(p, selected) in selections {
        totals[p * candidates + selected] += 1;
    }
    totals
}
```

So for `positions = 3, candidates = 4`:

```
contest_count = positions × candidates = 12

slot  0..3   president/cand0 … president/cand3
slot  4..7   vice-president/cand0 … vice-president/cand3
slot  8..11  senator/cand0 … senator/cand3
```

Contest ids are position-qualified strings (`"president/cand0"`), built in the
same order, so `contest_ids[i]` names slot `i`.

**Crucially, the ground truth is derived from a separate record of what each
voter chose — never accumulated inside the ciphertext-building loop.** If a bug
made the crypto encrypt a different bit than the voter selected, the decrypted
tally would diverge from this vector and `E = 0` would fail, instead of both
sharing the same wrong value and passing.

---

## 5. The output files

### `ground-truth-ballots.csv` — wide, one row per voter

```csv
voter_id,scale_group,ballot_complexity,PRESIDENT,VICE_PRESIDENT,SENATOR
V-000001,3524078,multi,CAND_PRES_01,CAND_VICE_01,CAND_SEN_01
V-000002,3524078,multi,CAND_PRES_02,CAND_VICE_03,CAND_SEN_04
V-000003,3524078,multi,CAND_PRES_01,CAND_VICE_01,CAND_SEN_01
```

| Column | Meaning |
|---|---|
| `voter_id` | `V-%06d`, 1-based |
| `scale_group` | the tier's voter count (constant per file) |
| `ballot_complexity` | `single` when `positions == 1`, else `multi` |
| one column per position | that voter's selection, `CAND_{PRES\|VICE\|SEN\|POS<n>}_{NN}` |

The header is built from `--positions`, so a single-position run emits one
selection column named `PRESIDENT`.

### `ground-truth-summary.csv` — long, one row per contest slot

```csv
position,candidate,ground_truth_count
PRESIDENT,CAND_PRES_01,1762232
PRESIDENT,CAND_PRES_02,585899
PRESIDENT,CAND_PRES_03,588562
PRESIDENT,CAND_PRES_04,587385
VICE_PRESIDENT,CAND_VICE_01,1762295
...
```

Each position's counts sum to the voter count. This column is the `Gᵢ` that
`correctness.csv` compares the decrypted tally against.

### Streaming

Rows are written one at a time through a `BufWriter`; no run ever holds all rows
in memory. Label tables are precomputed once per run rather than formatted per
row — at 3.5M voters that avoids ~10.6M redundant string constructions.

---

## 6. Reproducing any tier

### From the CLI

```bash
# Ground truth only — no crypto, any scale
saksi-demo gen-ground-truth \
  --voters 3524078 \
  --positions 3 \
  --candidates 4 \
  --distribution skewed \
  --election-id zambasulta-mp \
  --out-dir ./out

# Full cryptographic generation (also writes the ground-truth CSVs)
saksi-demo gen --stream ./run \
  --voters 1000 --positions 3 --candidates 4 \
  --trustees 3 --threshold 2 \
  --trustee-names COMELEC,Watchdog,University \
  --election-id demo --election-name "Demo Election" \
  --distribution skewed
```

### From the console

Pick **ground truth only** as the mode. Because that path runs no cryptography,
the 10,000-voter offline ceiling does not apply to it and the capstone presets
(1,921,917 and 3,524,078) are selectable:

```go
// packages/saksi-campaign/config.go
//
// OfflineVoterCeiling caps offline-mode voters. Offline generation is not
// parallelized, so the 50k/483k/1M tiers are on-chain/perf mode only […]
const OfflineVoterCeiling = 10000

// The check is scoped to offline, so ground-truth runs are unaffected:
if c.Mode == "offline" && c.Voters > OfflineVoterCeiling {
    return fmt.Errorf(
        "offline mode is capped at %d voters (got %d); select on-chain/perf mode for larger tiers",
        OfflineVoterCeiling, c.Voters)
}
```

Both CSVs then appear as download chips on the run.

---

## 7. The data-validation gate

The methodology (Figure 3.1) places an *"all records valid?"* decision between
generation and the encrypted demonstration: only data confirmed complete,
well-formed, and internally consistent proceeds. That gate exists in two halves.

**Inside the generator (Rust, fail-closed).** `validate_population` refuses to
emit a population unless: there are exactly `voters × positions` ballots with
`voters` per position; every nullifier is pairwise distinct; every ballot carries
exactly `candidates` ciphertexts and proofs; each position's ground-truth
aggregate equals its ballot count; and voter ids are unique per voter and
repeated once per position. A violation returns `Err` and nothing is written.

**Over the written tables (Go, visible).** `GET /api/check/<runID>` re-audits
what actually landed on disk — recounting the per-voter ballot table from
scratch and holding the result against the published summary. This catches what
the in-process gate cannot: a truncated file, a torn write, an edited CSV, a
summary that no longer matches its ballots.

| Check | Catches |
|---|---|
| Ballot table shape | wrong column count for the declared positions |
| Voter ids unique and sequential | a duplicated row, a gap, a copied voter |
| Every selection is a real candidate | a selection outside the declared set |
| Every voter accounted for | a truncated or padded table |
| Recount matches the published tally | a summary that disagrees with its own ballots |
| No votes lost or invented | a position whose votes don't sum to the voter count |
| Population fingerprinted | records SHA-256 of both tables |

The recount streams the file a line at a time and tracks voter ordinals against
the row number, so memory stays flat regardless of scale — auditing all
3,524,078 rows takes **under a second**:

```
VERDICT: PASS | rows audited: 3,524,078
  OK  Voter ids unique and sequential: V-000001 through V-3524078, no duplicates or gaps
  OK  Recount matches the published tally: all 12 contests agree, recounted from the ballot table
  OK  No votes lost or invented: each of the 3 positions totals exactly 3,524,078
```

The report is written to `ground-truth-check.json` in the run folder and is a
downloadable artifact. **A population that fails the gate cannot advance to
encryption in the wizard** — that is what fail-closed means.

### Why the fingerprint matters

Encryption is randomized: the same population encrypted twice produces different
ciphertexts, by design. So the ciphertexts cannot prove which plaintext
population an encrypted run was built from. The digests recorded here can — a
published ground-truth table and a later encrypted run are linked by re-running
the check and comparing hashes, without re-running the generator.

---

## 8. Verifying the generator is honest

Three checks, all reproducible.

**a. The two paths agree.** Same parameters through both generators must produce
byte-identical tables:

```bash
saksi-demo gen --stream ./crypto --voters 50 --positions 3 --candidates 4 \
  --trustees 3 --threshold 2 --election-id x --election-name x \
  --trustee-names a,b,c --distribution skewed
saksi-demo gen-ground-truth --out-dir ./gtonly --voters 50 --positions 3 \
  --candidates 4 --election-id x --distribution skewed

diff ./crypto/ground-truth-ballots.csv  ./gtonly/ground-truth-ballots.csv
diff ./crypto/ground-truth-summary.csv  ./gtonly/ground-truth-summary.csv
```

**b. The plaintext matches what decryption recovers.** Audit the encrypted run
and compare against the CSV written before encryption:

```bash
saksi-demo audit-stream ./crypto --json
```

```
overall: pass
  president/cand0        ground_truth= 25  decoded= 25  E=0  pass=True
  president/cand1        ground_truth=  9  decoded=  9  E=0  pass=True
  ...
```

The `ground_truth` column is the same number as `ground-truth-summary.csv`, and
`decoded` is what real threshold decryption of the ElGamal ciphertexts produced.
`E = 0` on every contest means the encryption round-tripped the population
exactly.

**c. Totals are internally consistent.** Every position's counts must sum to the
voter count:

```bash
awk -F, 'NR>1 {s[$1]+=$3} END {for (p in s) print p, s[p]}' ground-truth-summary.csv
```

```
PRESIDENT 3524078
VICE_PRESIDENT 3524078
SENATOR 3524078
```

---

## 9. Scale reference

Measured on the development machine, multi-position (3 positions × 4
candidates), ground-truth-only path:

| Tier | Voters | Rows | `ground-truth-ballots.csv` | Time |
|---|---|---|---|---|
| Precinct | 1,000 | 1,000 | ~60 KB | instant |
| Barangay | 10,000 | 10,000 | ~600 KB | instant |
| Municipal | 50,000 | 50,000 | ~3 MB | instant |
| Zamboanga City | 483,000 | 483,000 | ~30 MB | < 1 s |
| Provincial | 1,000,000 | 1,000,000 | ~62 MB | < 1 s |
| Capstone | 1,921,917 | 1,921,917 | ~119 MB | < 1 s |
| **Full ZAMBASULTA** | **3,524,078** | **3,524,078** | **217 MB** | **0.6 s** |

Note the largest file exceeds Excel's 1,048,576-row limit. Use the summary CSV
for review, or read the ballots file with `pandas`, `awk`, or PowerShell.

The full cryptographic path is **not** comparable — it does per-voter credential
issuance and per-candidate proofs, and is the subject of the separate
performance evaluation.

---

## 10. Where the code lives

| Concern | File |
|---|---|
| Selection rule, contest indexing, fixture generation | `packages/saksi-auditor/src/fixtures.rs` |
| Ground-truth CSV writer | `packages/saksi-auditor/src/ground_truth.rs` |
| Stream writer (`header.json`, `ballots.ndjson`) | `packages/saksi-auditor/src/stream.rs` |
| Validation gate | `packages/saksi-auditor/src/demo.rs` (`validate_population`) |
| CLI entry points | `packages/saksi-demo/src/main.rs` |
| Console modes and phase orchestration | `packages/saksi-campaign/{config,executor}.go` |
| Derived study CSVs | `packages/saksi-campaign/csvexport.go` |

## 11. Related

- `docs/appendix-a-replacement-draft.md` (balotachain) — the manuscript text
  these artifacts back.
- The validation gate that every generated population must pass before it may be
  used: exactly `voters × positions` ballots, pairwise-distinct nullifiers,
  in-range selections, per-position ground truth equal to the ballot count, and
  voter ids unique per voter and repeated once per position.
