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

**Nothing is floating point.** The `realistic` profile apportions its reserved
slice with plain integer division. This is not a stylistic choice — a float
would make the output depend on the machine's rounding, so an Apple Silicon run
could produce a different population from an x86 one. The Python mirrors it
using `//`, so both agree exactly.

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
| 1 | `let pct = 10 + 5 * (p % 3);` | `pct = 10 + 5 * (p % 3)` | Reserved share widens per position |
| 2 | `(voters * pct / 100).max(c*(c+1)).min(voters)` | `min(max(voters * pct // 100, c*(c+1)), voters)` | Floor `C(C+1)` keeps the spread above the round-robin's one-vote wobble |
| 3 | `q[select_candidate(Skewed, v, p, c)] += 1` | same | Most voters use the **old rule, unchanged** |
| 4 | `(0..c).map(\|k\| c - k)` | `[c - k for k in range(c)]` | Descending weights: 4, 3, 2, 1 |
| 5 | `reserve * x / total` | `reserve * x // total` | Integer apportionment of the reserved slice |
| 6 | `a[k % c] += 1` | same | Leftovers go to the top ranks in order |
| 7 | `if q[0] <= q[1] { … }` | same | Winner guard: moves one vote up, keeping the sum exact |

Both are integer arithmetic end to end, so an Apple Silicon run and an x86 run
produce the same bytes.

**Side by side:**

```rust
pub(crate) fn realistic_quotas(voters: usize, candidates: usize, p: usize) -> Vec<usize> {
    let c = candidates;
    if c == 0 { return Vec::new(); }

    let pct = 10 + 5 * (p % 3);
    let reserve = (voters * pct / 100).max(c * (c + 1)).min(voters);

    let mut q = vec![0usize; c];
    for v in 0..(voters - reserve) {
        q[select_candidate(SelectionProfile::Skewed, v, p, c)] += 1;
    }

    let w: Vec<usize> = (0..c).map(|k| c - k).collect();
    let total: usize = w.iter().sum();
    let mut a: Vec<usize> = w.iter().map(|&x| reserve * x / total).collect();
    let assigned: usize = a.iter().sum();
    for k in 0..(reserve - assigned) { a[k % c] += 1; }
    for k in 0..c { q[k] += a[k]; }

    if c > 1 && q[0] <= q[1] {
        for k in (1..c).rev() {
            if q[k] > 0 { q[k] -= 1; q[0] += 1; break; }
        }
    }
    q
}
```

```python
def realistic_quotas(voters, candidates, p):
    c = candidates
    if c == 0:
        return []

    pct = 10 + 5 * (p % 3)
    reserve = min(max(voters * pct // 100, c * (c + 1)), voters)

    q = [0] * c
    for v in range(voters - reserve):
        q[select_candidate("skewed", v, p, c)] += 1

    w = [c - k for k in range(c)]
    total = sum(w)
    a = [reserve * x // total for x in w]
    for k in range(reserve - sum(a)):
        a[k % c] += 1
    for k in range(c):
        q[k] += a[k]

    if c > 1 and q[0] <= q[1]:
        for k in range(c - 1, 0, -1):
            if q[k] > 0:
                q[k] -= 1
                q[0] += 1
                break
    return q
```

Step 3 is the reason the translation is easy to trust: it calls the same
`select_candidate` both languages already agreed on, so the only new code is a
plain integer apportionment.

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
[0, 1, 0, 3, 0, 0, 2, 0]
```

Totals at 1000 voters, 4 candidates:

```
uniform     250  250  250  250      four-way tie
skewed      500  167  167  166      winner, but two losers tied
realistic   490  180  170  160      every rank distinct
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
