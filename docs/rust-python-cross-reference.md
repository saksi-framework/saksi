# Rust ↔ Python cross-reference

The selection rules in both languages. The Python is a runnable reference
implementation at `reference_generator.py`; the Rust is the real generator at
`packages/saksi-auditor/src/fixtures.rs`.

**Verified equivalent**: both produce byte-identical `ground-truth-ballots.csv`
and `ground-truth-summary.csv` across all three profiles at nine
`(voters, positions, candidates)` combinations, including 1000 × 3 × 12 and
500 × 3 × 4.

```bash
python reference_generator.py --voters 1000 --positions 3 --candidates 12 \
    --distribution realistic --out-dir ./py
saksi-demo gen-ground-truth --voters 1000 --positions 3 --candidates 12 \
    --distribution realistic --election-id x --out-dir ./rust
diff ./py/ground-truth-ballots.csv ./rust/ground-truth-ballots.csv   # no output
```

That silence is the point: anyone can check a published ground-truth table
against this Python without Rust, without the repository, and without trusting
the researchers.

---

## Does anything translate awkwardly?

Two places, both handled.

**Integer division.** Rust's `/` on integers truncates; Python's produces a
float. `voter_idx / 2` must become `voter_idx // 2`. Using `/` fails on the
following `%`.

**Nothing is floating point.** The `realistic` profile apportions with `u128`
integer arithmetic and compares remainders as integers. This is not a stylistic
choice — a float would make the output depend on the machine's rounding, so an
Apple Silicon run could produce a different population from an x86 one. The
Python mirrors it exactly, using `//` and `%` on Python's arbitrary-precision
integers.

---

## `select_candidate` — the round-robin profiles

| # | Rust | Python | Note |
|---|---|---|---|
| 1 | `if candidates <= 1 { return 0; }` | `if candidates <= 1: return 0` | Also stops `candidates - 1` below being zero |
| 2 | `Uniform => (voter_idx + p) % candidates` | `if profile == "uniform": return (voter_idx + p) % candidates` | Walk the list; `+ p` rotates per position |
| 3 | `if voter_idx % 2 == 0 { 0 }` | `if voter_idx % 2 == 0: return 0` | Skewed: every even voter takes the front-runner — exactly half |
| 4 | `1 + ((voter_idx / 2 + p) % (candidates - 1))` | `1 + ((voter_idx // 2 + p) % (candidates - 1))` | **`/` vs `//`** — the one place a careless translation breaks |

## `realistic_quotas` — the profile that decides an election

| # | Rust | Python | Note |
|---|---|---|---|
| 1 | `let ladder = c * (c - 1) / 2;` | `ladder = c * (c - 1) // 2` | Smallest budget that funds C distinct counts |
| 2 | `if voters < ladder { … }` | `if voters < ladder: …` | Below it, distinct counts are impossible; fund top ranks first |
| 3 | `let s = 3 - (p % 3);` | `s = 3 - (p % 3)` | Weight steepness per position: 3 steep, 2 moderate, 1 linear |
| 4 | `((c - k) as u128).pow(s)` | `(c - k) ** s` | The weight curve |
| 5 | `(bulk * x / total) as usize` | `bulk * x // total` | Integer apportionment |
| 6 | `(bulk * w[k]) % total` | `(bulk * w[k]) % total` | Remainders compared as integers, never floats |
| 7 | `a.sort_unstable_by(\|x, y\| y.cmp(x));` | `a.sort(reverse=True)` | Sorting first is what makes the next line strict |
| 8 | `a[k] + (c - 1 - k)` | `a[k] + (c - 1 - k)` | The ladder: guarantees `q[k] > q[k+1]` |

Rust uses `u128` for the apportionment products; Python's integers are
arbitrary-precision, so the arithmetic agrees with no special handling. At the
capstone tier the largest product is about `3.5e6 × 37³ ≈ 1.8e11`, comfortably
inside both.

**Side by side:**

```rust
pub(crate) fn realistic_quotas(voters: usize, candidates: usize, p: usize) -> Vec<usize> {
    let c = candidates;
    let ladder = c * (c - 1) / 2;
    if voters < ladder {
        let mut q = vec![0usize; c];
        let mut left = voters;
        let mut k = 0;
        while left > 0 && k < c {
            let take = left.min(c - k);
            q[k] = take;
            left -= take;
            k += 1;
        }
        return q;
    }

    let bulk = (voters - ladder) as u128;
    let s = 3 - (p % 3) as u32;
    let w: Vec<u128> = (0..c).map(|k| ((c - k) as u128).pow(s)).collect();
    let total: u128 = w.iter().sum();

    let mut a: Vec<usize> = w.iter().map(|&x| (bulk * x / total) as usize).collect();
    let mut rem = (voters - ladder) - a.iter().sum::<usize>();

    let mut order: Vec<usize> = (0..c).collect();
    order.sort_by_key(|&k| (std::cmp::Reverse((bulk * w[k]) % total), k));
    for &k in order.iter() {
        if rem == 0 { break; }
        a[k] += 1;
        rem -= 1;
    }

    a.sort_unstable_by(|x, y| y.cmp(x));
    (0..c).map(|k| a[k] + (c - 1 - k)).collect()
}
```

```python
def realistic_quotas(voters: int, candidates: int, p: int):
    c = candidates
    ladder = c * (c - 1) // 2
    if voters < ladder:
        q = [0] * c
        left, k = voters, 0
        while left > 0 and k < c:
            take = min(left, c - k)
            q[k] = take
            left -= take
            k += 1
        return q

    bulk = voters - ladder
    s = 3 - (p % 3)
    w = [(c - k) ** s for k in range(c)]
    total = sum(w)
    a = [bulk * x // total for x in w]
    rem = bulk - sum(a)
    frac = [(bulk * w[k]) % total for k in range(c)]
    for k in sorted(range(c), key=lambda k: (-frac[k], k))[:rem]:
        a[k] += 1
    a.sort(reverse=True)
    return [a[k] + (c - 1 - k) for k in range(c)]
```

The tie-break in step 7 matters for equivalence: Rust sorts by
`(Reverse(remainder), index)` and Python by `(-frac, index)`. Both are total
orders on the same keys, so the same candidates receive the leftover votes. A
tie-break on remainder alone would leave the order unspecified and the two
implementations free to disagree.

## `SelectionPlan` — placing voters in the brackets

| Rust | Python | Note |
|---|---|---|
| `(voters * 61803 / 100000).max(1)` | `max(voters * 61803 // 100000, 1)` | Golden-ratio stride, integer |
| `while gcd(s, voters) != 1 { s += 1; … }` | same loop | Coprime keeps the multiply a permutation |
| `cum.partition_point(\|&c\| c <= r)` | hand-rolled bisect | First bracket strictly greater than `r` |

`partition_point` has no direct Python equivalent that matches on the boundary
condition, so the reference spells out the bisect rather than reaching for
`bisect_right` — the explicit loop is easier to check against the Rust.

---

## Worked example

Real output, 4 candidates, position 0. Candidate indices are 0-based here; the
CSV labels them 1-based (`CAND_PRES_01` is index 0).

```python
>>> [sc("uniform", v, 0, 4) for v in range(6)]
[0, 1, 2, 3, 0, 1]
>>> [sc("skewed", v, 0, 4) for v in range(6)]
[0, 1, 0, 2, 0, 3]
>>> plan = SelectionPlan("realistic", 1000, 3, 4)
>>> [plan.select(v, 0) for v in range(8)]
[0, 0, 0, 1, 0, 0, 1, 0]
```

Totals at 1000 voters, 4 candidates:

```
uniform     250  250  250  250      four-way tie
skewed      500  167  167  166      winner, but two losers tied
realistic   639  270   81   10      every rank distinct
```

## The properties these rules preserve

1. **Reproduce from parameters alone.** No seed to store, ship, or lose. State
   `voters`, `positions`, `candidates`, `distribution` and the population is
   fully determined.
2. **Agree across generator paths.** `gen --stream` (full cryptography) and
   `gen-ground-truth` (none) build the same plan and produce byte-identical
   tables.
3. **Reproduce on any machine.** Integer-only arithmetic means an Apple Silicon
   run and an x86 run produce the same bytes.
4. **Allow independent verification.** Point 3 is what makes point 4 worth
   anything: a published table can be checked by someone who has only this file.
