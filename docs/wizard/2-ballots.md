# Step 2 — Ballots

Generates the synthetic voter population and, in the cryptographic modes,
encrypts it. This is **Stage 4** of the methodology (DSRM Figure 3.1).

The generator itself is documented in full in
[`../synthetic-data-generation.md`](../synthetic-data-generation.md) — selection
rule, output schemas, contest indexing, and how to reproduce any tier. This page
covers only what the wizard step does with it.

## What runs

`POST /generate` creates the run folder and shells the Rust generator.

```
saksi-demo gen --stream <run-dir> --voters N --positions P --candidates C \
    --trustees N --threshold T --election-id <run-id> --distribution realistic
```

In `groundtruth` mode it shells `gen-ground-truth` instead, which writes only the
plaintext tables and runs no cryptography.

Progress streams to the page over SSE as it goes.

## What it writes

| File | Contents |
|---|---|
| `ground-truth-ballots.csv` | One row per voter: `voter_id, scale_group, ballot_complexity`, then one column per position holding the chosen candidate label |
| `ground-truth-summary.csv` | `position, candidate, ground_truth_count` — the seeded totals |
| `header.json` | Election parameters, DKG transcript, published tally |
| `ballots.ndjson` | One encrypted ballot per line |

The two CSVs are the **plaintext population, exported before anything is
encrypted**. That ordering is the point: a reader can inspect exactly what went
in, independently of anything the cryptography later claims came out.

## The property everything downstream depends on

Every selection comes from one pure function of `(profile, voter_index,
position_index, candidate_count)`. There is no seed, no clock, and no random
number generator involved in *choosing* a vote.

Consequences worth stating to a panel:

1. **The population is reproducible from its four parameters.** There is no seed
   file to publish, ship, or lose.
2. **The two generator paths agree byte for byte.** `gen --stream` (full
   cryptography) and `gen-ground-truth` (none) replay the same function, so the
   plaintext tables are identical — verified by `diff`, not assumed.
3. **Anyone can reproduce a published table without this repository.** A runnable
   Python reference implementation is included alongside the docs.

## Where the randomness actually is

The *selections* are deterministic. The **cryptography is not** — key material,
ElGamal blinding factors, and proof nonces all come from `OsRng`. That is
required for semantic security: encrypting the same vote twice must produce
different ciphertexts, or the ciphertexts would leak the plaintext by comparison.

So two runs with identical parameters produce **identical ground-truth tables and
completely different ciphertexts**. Both facts are load-bearing, and they are not
in tension: what must be reproducible is the population, and what must be
unpredictable is the encryption of it.

One practical consequence: the bundle built in step 4 is a *separate* encryption
of the same plaintext population as the stream written here. Same counts, different
ciphertexts. This is why step 4 must never silently regenerate a bundle
mid-ceremony — see [4-encrypt.md](4-encrypt.md).

## A stated limitation, now narrowed

Under `uniform` and `skewed` the position index only *rotates* the assignment, so
every position ends up with the same multiset of totals:

```
PRESIDENT       1762039  587347  587346  587346
VICE_PRESIDENT  1762039  587346  587347  587346
SENATOR         1762039  587346  587346  587347
```

A component that confused one contest for another would still satisfy `E = 0`.

**The `realistic` profile does not have this weakness** — each position gets a
different weight curve, so the shapes genuinely differ and contest-mixing becomes
detectable. The limitation now applies only to the two round-robin profiles,
which are retained for the performance comparisons rather than for deciding
results.
