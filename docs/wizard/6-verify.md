# Step 6 — Verify

An independent verifier re-derives the result from the published record alone and
holds it against the ground truth seeded before the election began. This is the
step that produces the accuracy metric the thesis reports.

It shows two things, in this order: **the result**, then **the proof of the
result**.

## What runs

`POST /verify` shells the auditor over the run's stream:

```
saksi-demo audit-stream <run-dir> --json
```

The auditor is a separate program reading the published artifacts. It does not
share state with the generator; it re-verifies every proof, homomorphically
aggregates the ciphertexts per contest, and recovers each total from the
threshold decryption. The structured output is written to `correctness.csv`.

## The bulletin board

The upper panel is the **declared result**: for each position, every candidate's
vote count, its share, and the leader marked.

Every number there is the `decoded` column of `correctness.csv` — the value
**threshold decryption recovered from the homomorphic aggregate**. No individual
ballot is decrypted to produce it. That distinction is the privacy claim, and it
is stated on the panel itself.

Contest ids arrive as `<position>/cand<k>` (e.g. `president/cand0`) and are
grouped by the part before the slash. Candidate indices are rendered 1-based, to
match the `CAND_PRES_01` convention the ground-truth tables use.

### Seats: the Senate elects several

President and Vice President elect one candidate each. The Senate elects its top
`senate_seats`, marked `ELECTED` with a cut line drawn beneath the last of them.

Each voter still cast exactly one senatorial vote — the seats decide how the
counts are read, not how they were produced. See [1-setup.md](1-setup.md).

### Ties are reported, not resolved

If more than one candidate holds the top count — or, in a multi-seat race, if
more candidates are level at the cut than there are seats left — the board says
so and awards nothing.

This is not defensive padding. Under `uniform` a 20-voter, 4-candidate election
decrypts to exactly **5/5/5/5**, verified against real threshold-decrypted
output. Sorting the rows and printing the first as "winner" would invent a result
the data does not support.

The `realistic` profile produces strictly decreasing counts, so its races always
decide and the cut is always clean. **Use it for a demonstration**; the tie path
exists for the round-robin profiles, which cannot decide a result at all.

## The correctness table

Below the board, one row per contest:

| Column | Meaning |
|---|---|
| `contest` | `<position>/cand<k>` |
| `ground_truth` | What the generator seeded, counted from the recorded selections |
| `decoded` | What threshold decryption recovered |
| `E` | `\|decoded − ground_truth\|` |
| `pass` | `E == 0` |

The reported metric is `E = Σ|Tᵢ − Gᵢ|`, and it must be **zero**.

`correctness.csv` additionally carries the evidence needed to re-verify each row
independently: the recovered plaintext point, the aggregate ciphertext it came
from, and the run's artifact hashes (DKG, tally, ballot set). Each row is
self-contained proof rather than an assertion.

## Why E = 0 has teeth

The ground truth is derived from an **explicit record of what each voter chose**,
in a separate pass from the encryption loop — never accumulated as a side effect
of building ciphertexts.

That separation is the whole point. If the cryptography ever encrypted a
different value than the voter selected, the decrypted tally and the recorded
selections would disagree and `E` would be non-zero. If both were driven by one
shared counter, they would carry the same wrong value and the check would pass
while being wrong.

## What this step does not prove

- **Not contest-mixing.** Every position carries the same multiset of totals, so
  a component that confused one contest for another would still satisfy `E = 0`.
  A limitation of the test data, declared in [2-ballots.md](2-ballots.md).
- **Not resistance to tampering.** `E = 0` says an untouched run decrypts
  correctly. That an *attacked* run gets rejected is a different claim, and it is
  what step 7 tests.
