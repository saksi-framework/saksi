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
| `realistic` | skewed, plus a reserved slice spread down the ranks | **Yes** |

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

The goal was narrow: keep the old distribution, just stop it tying. So this
profile is the skewed rule with a correction bolted on, not a new rule.

### The whole idea in three lines

```
1. most voters vote by the OLD skewed rule, untouched
2. a reserved slice is handed out down the ranks, 4:3:2:1
3. add the two together
```

Traced for real, 1000 voters and 4 candidates, President:

```
reserve = max(10% of 1000, C(C+1)) = 100

  900 voters, old skewed rule   [450, 150, 150, 150]   <- the tie
  100 reserved, split 4:3:2:1   [ 40,  30,  20,  10]   <- the fix
                                ---------------------
  total                         [490, 180, 170, 160]   sums to 1000
```

The old rule left three candidates level on 150. The reserved slice separates
them by 10 votes each, and the totals still come to exactly 1000 because the
reserved voters were taken *out* of the round-robin rather than invented.

That last point matters: **you cannot simply add a vote to break a tie.** Every
voter votes exactly once, and the validation gate checks that each position's
counts sum to the electorate. Extra votes have to come from somewhere, so they
are held back at the start.

### The code

```rust
let pct = 10 + 5 * (p % 3);
let reserve = (voters * pct / 100).max(c * (c + 1)).min(voters);

let mut q = vec![0usize; c];
for v in 0..(voters - reserve) {
    q[select_candidate(SelectionProfile::Skewed, v, p, c)] += 1;   // unchanged
}

let w: Vec<usize> = (0..c).map(|k| c - k).collect();               // 4,3,2,1
let total: usize = w.iter().sum();
let mut a: Vec<usize> = w.iter().map(|&x| reserve * x / total).collect();
for k in 0..(reserve - a.iter().sum::<usize>()) { a[k % c] += 1; }
for k in 0..c { q[k] += a[k]; }
```

### The two floors, and why each exists

**`.max(c * (c + 1))`** — the reserved slice must be big enough that its spread
exceeds the round-robin's own wobble. A round-robin can leave adjacent
candidates one vote apart in either direction; if the spread were also one vote,
it could cancel out and leave them level anyway. `C(C+1)` guarantees at least
two votes of separation per rank.

**The winner guard** — with a very small electorate even that can fail, so a
final check moves one vote up if the top two are level:

```rust
if c > 1 && q[0] <= q[1] {
    for k in (1..c).rev() {
        if q[k] > 0 { q[k] -= 1; q[0] += 1; break; }
    }
}
```

Taking the vote from the lowest-ranked candidate holding one keeps the sum
exact. This makes **a clear winner unconditional** — true at every voter count
from 1 upward, not merely at demo scale.

### Why the reserve widens by position

`pct = 10 + 5 * (p % 3)` — President reserves 10%, Vice President 15%, Senator
20%. Without it all three races would come out identical, since they would
differ only by the round-robin's one-vote rotation.

```
V=1000, C=4     President  490  180  170  160
                Vice Pres  485  186  172  157
                Senator    480  193  173  154

V=3,524,078, C=12
                President  1640053  193866  189348  184829  180311 …
                Vice Pres  1579059  210705  203929  197152  190375 …
                Senator    1518066  227545  218509  209474  200438 …
```

The front-runner still takes roughly half, so it still reads as the old skewed
shape — the losers are simply no longer tied, and the Senate cut at any rank is
clean.

### Placing voters in the brackets

Quotas say *how many* votes each candidate gets; a stride decides *which* voters
cast them. The stride is coprime with the voter count, which makes multiplying
by it a **permutation** — it reorders voters without collapsing two onto one
slot, so the realized counts equal the quotas exactly. Without it the first 490
rows of the export would all read `CAND_PRES_01`.

---

## What this fixes, and what it does not

**Fixed: ties.** Every race has one winner, at every voter count. Every rank is
distinct once the electorate can afford it — measured, from 8 voters at 4
candidates and 72 at 12. A multi-seat cut at any rank N is therefore clean.

**Not fixed: contest-mixing.** The three positions usually differ, but this
design does **not** guarantee it. At certain voter counts the different reserve
percentages happen to land on the same multiset of totals — measured at about
8.6% of configurations at 12 candidates, scattered rather than below a
threshold. On such a configuration a component that confused one contest for
another would still satisfy `E = 0`.

That is a deliberate trade. Guaranteeing distinct shapes needs a per-position
weight curve — materially more code, and further from the distribution the
manuscript already describes. Contest-mixing is not a failure mode this
evaluation probes, so it stays declared rather than closed.

`uniform` and `skewed` are unchanged, byte for byte. They back the manuscript's
performance comparisons, where an even split is a reasonable load and the tie is
irrelevant.

## Related

- `synthetic-data-generation.md` — the full pipeline: schemas, the validation
  gate, reproducing any tier.
- `rust-python-cross-reference.md` — both languages side by side.
- `reference_generator.py` — runnable; verified byte-identical to the Rust
  generator across all three profiles.
