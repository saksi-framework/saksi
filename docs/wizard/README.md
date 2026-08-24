# The Election Wizard, step by step

The wizard at `/wizard` walks one election through the protocol in the order the
protocol actually happens. This directory documents what each step does — what
the operator sees, what runs underneath, which files it writes, and what it does
*not* prove.

Written to be read before demonstrating the console, and to answer the questions
a panel asks while watching it.

| # | Step | What it is | Doc |
|---|---|---|---|
| 1 | Set up | Declare the election; the only gate on parameters | [1-setup.md](1-setup.md) |
| 2 | Ballots | Generate the synthetic population and encrypt it | [2-ballots.md](2-ballots.md) |
| 3 | Check | Audit the population against itself before any crypto is trusted | [3-check.md](3-check.md) |
| 4 | Encrypt | Build the cryptographic bundle; record the lifecycle on the ledger | [4-encrypt.md](4-encrypt.md) |
| 5 | Trustees | Threshold decryption ceremony — *t* of *n* must act | [5-trustees.md](5-trustees.md) |
| 6 | Verify | Independent audit, the declared result, and E = 0 | [6-verify.md](6-verify.md) |
| 7 | Attacks | Seven attacks, one step each, each run live | [7-attacks.md](7-attacks.md) |

**In depth:** [`deep-dive.md`](deep-dive.md) covers all seven steps in one
document, naming the functions each one runs, the artifacts each writes, and
where every guarantee is enforced. Read that before defending the demonstration;
the per-step files above are the gentler version.

## The one-paragraph version

A population of synthetic voters is generated from four parameters with no
randomness, so it is reproducible from those parameters alone. It is then
**recounted against itself** before anything is encrypted — the methodology's
data-validation gate. Only then is it encrypted, closed, and decrypted by a
threshold of trustees. An independent verifier re-derives the result from the
published record and compares it to the ground truth seeded at the start; the
total disagreement `E` must be zero. Finally the run is attacked seven ways, and
each attack must be rejected.

## Where the guarantees live

The single most useful thing to understand before demonstrating this: **not
every guarantee is enforced in the same place.**

| Guarantee | Enforced by | Visible at |
|---|---|---|
| Ballot well-formedness | CDS proof, checked on-chain at endorsement and by the auditor | Steps 4, 7 |
| No double voting | per-position nullifier | Steps 4, 7 |
| Data completeness | the console's validation gate | Step 3 |
| Threshold *t*-of-*n* | the **auditor**, at verification time — *not* the chaincode | Steps 5, 6 |
| Ledger ordering | the **chaincode**, at endorsement — the offline auditor cannot see it | Step 7 |
| Tally correctness | `E = Σ\|Tᵢ − Gᵢ\| = 0` | Step 6 |

Two rows there are deliberately awkward, and both are stated in the UI rather
than hidden. See [5-trustees.md](5-trustees.md) and [7-attacks.md](7-attacks.md).

## Modes

Set in step 1; it changes which later steps apply.

- **offline** — everything runs locally, no ledger. This is the presentation
  path. Capped at 10,000 voters.
- **onchain** — the same, plus the lifecycle is committed to Hyperledger Fabric
  with real ledger receipts. Needs a reachable peer.
- **groundtruth** — generates the plaintext population *only*, no cryptography.
  Steps 4–7 do not apply and the wizard marks them skipped. This is the path
  that makes the 3,524,078-voter tier tractable.

## Run artifacts

Every step writes into the run folder (`~/.saksi/campaign/runs/<run-id>/`), and
all of it is downloadable from the wizard's file chips.

| File | Written by | Contents |
|---|---|---|
| `ground-truth-ballots.csv` | 2 | one row per voter, the plaintext selections |
| `ground-truth-summary.csv` | 2 | per-candidate seeded totals |
| `header.json`, `ballots.ndjson` | 2 | the encrypted run the auditor reads |
| `ground-truth-check.json` | 3 | the validation report |
| `bundle.json` | 4 | the cryptographic bundle the ceremony submits |
| `ceremony.json` | 5 | which trustees have contributed |
| `trail.json`, `receipts.csv` | 4, 5 | ledger receipts (on-chain only) |
| `correctness.csv` | 6 | per-contest ground truth vs decoded, with E |
| `negative-tests.csv`, `scenarios.json` | 7 | attack verdicts |

## Related

- [`../synthetic-data-generation.md`](../synthetic-data-generation.md) — the
  generator in full: selection rules, schemas, reproducing any tier.
- [`../selection-rule-explained.md`](../selection-rule-explained.md) — the three
  selection profiles walked through line by line, with traced values.
- [`../rust-python-cross-reference.md`](../rust-python-cross-reference.md) —
  both languages side by side.
- [`../research-election-console-runbook.md`](../research-election-console-runbook.md)
  — building and running the console.
