# Step 3 — Check

Audits the generated population **against itself**, before any of it is trusted
downstream. This is the *"Data Validation: all records valid?"* decision the
methodology (Figure 3.1) places between Stage 4 and Stage 5.

The Rust generator already enforces a fail-closed structural gate over the
ballots it builds, but nothing showed that to the operator, and nothing at all
re-checked the ground-truth CSVs *after they were written*. A writer bug, a
truncated file, or a torn write would have surfaced later as a clean-looking
tally. This step turns that into a visible, failing gate.

## What runs

`GET /api/check/<runID>` → `RunCheck` (`packages/saksi-campaign/check.go`).

It re-reads `ground-truth-ballots.csv` from disk and **recounts it from
scratch**, then holds that independent recount against the published
`ground-truth-summary.csv`. It does not consult the generator, the ciphertexts,
or anything held in memory from step 2.

The table is streamed a line at a time and voter ordinals are checked against the
row number rather than collected into a set, so the capstone tier — 3.5M rows,
about 217 MB — audits in bounded memory rather than loading the population.

## The seven checks

| Check | Passes when | Catches |
|---|---|---|
| **Ballot table shape** | Header has `3 + positions` columns | A file written for a different configuration |
| **Voter ids unique and sequential** | Row *n* carries `V-<n>` | A duplicated, missing, or out-of-order voter |
| **Every selection is a real candidate** | Every cell parses to `1..candidates` | A malformed label or an out-of-range candidate |
| **Every voter accounted for** | Row count equals the configured voter count | A truncated file or a short write |
| **Recount matches the published tally** | Independent recount equals `ground-truth-summary.csv` | Disagreement between the population and its own summary |
| **No votes lost or invented** | Each position totals exactly the row count | A vote dropped or double-counted within a position |
| **Population fingerprinted** | SHA-256 recorded for both tables | — (records provenance rather than testing) |

The fifth is the one the step exists for. The rest are the structural
preconditions that make it meaningful: comparing a recount to a summary proves
nothing if the file being recounted is malformed.

The report is written to `ground-truth-check.json` and the wizard will not
advance while the gate is failing — a population that fails cannot proceed to be
encrypted, which is exactly what Figure 3.1 specifies.

## Why fingerprint the tables

The final check records a SHA-256 of both CSVs. This is provenance, not
validation.

The encryption is randomized, so **the ciphertexts cannot serve as a link back to
the plaintext population** — two runs over the same population produce entirely
different ciphertexts. The digest is what lets a published ground-truth table
later be shown to be the exact population a given encrypted run was built from.

## What this step does not prove

It proves the population is internally consistent and complete. It does **not**
prove the population is *correct* in the sense of matching the selection rule —
a generator that consistently applied the wrong rule would produce a table that
agrees with its own summary perfectly and pass every check here.

That is not a gap in the gate; it is a different question, answered elsewhere.
The independent Python reference implementation reproduces any published table
from its four parameters, so anyone can confirm the rule itself was applied
correctly, without this code and without trusting it.

Nor does it say anything about the cryptography — no ciphertext is read at this
step. That is step 6's job.
