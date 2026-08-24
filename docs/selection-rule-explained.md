# The selection rules, explained

How the generator decides which candidate each synthetic voter picks. Written
for someone who wants to follow the arithmetic rather than take it on trust.

The code lives at `packages/saksi-auditor/src/fixtures.rs`. A runnable Python
translation is in `reference_generator.py`; every number here was produced by
running it, not written from memory.

There are three profiles. **Only one of them can decide an election**, and the
reason the other two cannot is worth understanding before using them.

| Profile | Shape | Decides a winner? |
|---|---|---|
| `uniform` | even split across all candidates | **No** — ties at rank one |
| `skewed` | candidate 1 takes half, rest split the remainder evenly | Winner yes; **losers all tie** |
| `realistic` | strictly decreasing, different shape per position | **Yes** |

---

## Part 1 — the two round-robin profiles

```rust
pub(crate) fn select_candidate(
    profile: SelectionProfile,
    voter_idx: usize,
    p: usize,
    candidates: usize,
) -> usize {
    if candidates <= 1 {
        return 0;
    }
    match profile {
        SelectionProfile::Uniform => (voter_idx + p) % candidates,
        SelectionProfile::Skewed => {
            if voter_idx % 2 == 0 {
                0
            } else {
                1 + ((voter_idx / 2 + p) % (candidates - 1))
            }
        }
    }
}
```

Four inputs, one output — a 0-based candidate index. **Nothing else goes in:**
no clock, no random number generator, no seed. That is what "pure function"
means, and it is why the same four numbers always produce the same vote.

### The guard

```rust
if candidates <= 1 { return 0; }
```

Two jobs. The obvious one: a one-candidate contest has only one possible vote.
The real one: the skewed branch divides by `candidates - 1`, so without this
line a single-candidate contest would be **division by zero**. Guards that look
redundant often are not.

### Uniform — walk the list

```rust
(voter_idx + p) % candidates
```

`%` is remainder, so this counts around the ballot in a loop:

```python
>>> [select_candidate("uniform", v, 0, 4) for v in range(8)]
[0, 1, 2, 3, 0, 1, 2, 3]
```

`+ p` rotates the starting point per position, so voter 0 does not pick the
first candidate in every race.

**Why it cannot decide anything.** Across 1000 voters and 4 candidates this
gives 250, 250, 250, 250 — an exact four-way tie, every time. Not bad luck:
dividing the electorate evenly is precisely what the profile does.

### Skewed — half to the front-runner

```rust
if voter_idx % 2 == 0 { 0 } else { 1 + ((voter_idx / 2 + p) % (candidates - 1)) }
```

Every even-numbered voter picks candidate 0 — exactly half the electorate. The
odd voters share the rest: `voter_idx / 2` renumbers them into a clean counting
sequence (1, 3, 5, 7 → 0, 1, 2, 3), `% (candidates - 1)` wraps that across the
remaining candidates, and `1 +` steps over candidate 0.

```python
>>> [select_candidate("skewed", v, 0, 4) for v in range(8)]
[0, 1, 0, 2, 0, 3, 0, 1]
```

> **Translation hazard.** Rust's `/` on integers truncates; Python's produces a
> float and must be written `//`. It is the one place this translation can go
> wrong.

**Why it still cannot decide a multi-seat race.** It gives a clear winner, but
the losers are split evenly among themselves. At 1000 voters and 12 candidates:
500, then 46 repeated. At the 3,524,078 capstone tier: 1762039, then 160186
repeated. A top-N cut lands in the middle of identical numbers **at every
scale** — more voters does not help, because the remainder is divided evenly on
purpose.

---

## Part 2 — `realistic`, the profile that decides

The goal: counts that **strictly decrease**, sum to exactly the voter count, and
differ in shape from one position to the next.

### Step 1 — the ladder floor

```rust
let ladder = c * (c - 1) / 2;
```

To give `C` candidates distinct non-negative counts, the smallest possible
budget is `0 + 1 + … + (C-1)`. Below that, distinct counts are **arithmetically
impossible**, not merely inconvenient — so that case falls back to funding the
top ranks first, which still leaves the winner unambiguous.

### Step 2 — a weight curve whose steepness depends on the position

```rust
let s = 3 - (p % 3);                 // 3 = steep, 2 = moderate, 1 = linear
let w: Vec<u128> = (0..c).map(|k| ((c - k) as u128).pow(s)).collect();
```

`w_k = (C - k)^s`. A high exponent concentrates votes at the top; `s = 1` is a
straight line. President gets the steep curve, Vice President moderate, Senator
linear — flat enough that a multi-seat race is genuinely contested.

### Step 3 — apportion the bulk, largest remainder

```rust
let mut a: Vec<usize> = w.iter().map(|&x| (bulk * x / total) as usize).collect();
// … the leftover votes go to the largest fractional remainders
```

Standard largest-remainder apportionment, exactly as seats are allocated to
parties under proportional representation.

**All of it is integer arithmetic**, and that is deliberate. Floating point
would be a reproducibility hazard: a last-bit difference between an x86 machine
and an Apple Silicon one could flip a remainder comparison and produce a
*different population on a different computer* — destroying the one property
this generator exists to have.

### Step 4 — sort, then add the ladder

```rust
a.sort_unstable_by(|x, y| y.cmp(x));
(0..c).map(|k| a[k] + (c - 1 - k)).collect()
```

This is the trick. Sorting descending guarantees `a[k] >= a[k+1]`. Adding the
descending ladder `(C-1-k)` then gives

```
q[k] - q[k+1] = (a[k] - a[k+1]) + 1  >=  1
```

so the counts are **strictly decreasing by construction, not by luck**. And
since the ladder sums to exactly the amount subtracted from the budget in step
1, the quotas sum to exactly the voter count — no vote invented, none lost.

### What it produces

```
V=1000, C=4     President  639  270   81   10
                Vice Pres  533  300  134   33
                Senator    401  300  200   99

V=3,524,078, C=12
                President  1000914  770960  579235  422264  296571  198681 …
                Vice Pres   780715  656018  542165  439154  346987  265662 …
                Senator     542167  496986  451805  406625  361444  316263 …
```

Every race has one winner. Every rank is distinct, so a cut at any N is clean.
And the three positions have visibly different shapes — a decisive presidential
race, a closer VP race, a broad Senate field.

### Step 5 — placing voters in the brackets

Quotas say *how many* votes each candidate gets; the stride decides *which*
voters cast them.

```rust
let r = (voter_idx.wrapping_mul(self.stride) + p) % self.voters;
cum.partition_point(|&c| c <= r).min(self.candidates - 1)
```

The stride is coprime with the voter count, which makes multiplying by it a
**permutation** — it reorders voters without ever colliding two onto one slot,
so the realized counts equal the quotas exactly. Without it the first 639 rows
of the export would all read `CAND_PRES_01` and the table would look like a
sorted list rather than an electorate.

```python
>>> plan = SelectionPlan("realistic", 1000, 3, 4)
>>> [plan.select(v, 0) for v in range(8)]
[0, 0, 0, 1, 0, 0, 1, 0]
>>> [plan.select(v, 2) for v in range(8)]
[0, 1, 0, 2, 1, 0, 2, 0]
```

Position 0 leans heavily on candidate 0, as its steep curve should; position 2
spreads. Both are the intended shapes, arriving voter by voter.

### Why a plan object rather than a pure function

`realistic` cannot answer "who does voter 7 pick?" without first computing the
whole position's quotas. Doing that per voter would be `O(V·C log C)` — hopeless
at 3.5M. `SelectionPlan` computes the brackets once and answers each voter with
a binary search.

Both generator paths — the cryptographic one and the plaintext one — build the
same plan from the same parameters, which is what keeps their tables
byte-identical.

---

## What this fixed

Under the round-robin profiles, the position index only *rotated* the
assignment, so every position carried the **same multiset of totals**. President
and Vice President came out with identical numbers in a different order, and a
component that confused one contest for another would still have satisfied
`E = 0`.

`realistic` gives each position a different weight curve, so the shapes genuinely
differ and that gap closes. It needs enough voters to express the difference —
measured, the boundary is around `C(C-1)/2 + 2C`: 12 voters at 4 candidates, 73
at 12, 685 at 37. Below it there is only one way to distribute and all three
curves land on it.

`uniform` and `skewed` are unchanged, byte for byte. They back the manuscript's
performance comparisons, where an even split is a perfectly reasonable load and
the tie is irrelevant.

## Related

- `synthetic-data-generation.md` — the full pipeline: schemas, the validation
  gate, reproducing any tier.
- `rust-python-cross-reference.md` — both languages side by side.
- `reference_generator.py` — runnable; verified byte-identical to the Rust
  generator across all three profiles.
