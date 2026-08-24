# Step 7 — Attacks

Step 6 shows that an untouched election decrypts correctly. This step shows that
a *tampered* one is rejected — the negative half of the argument, and the one a
verifiability claim actually rests on.

Seven attacks, each its own wizard step, each briefed before it runs and run
live.

## What each step shows

Before running:

- **What the attacker does** — the mutation, e.g. *"copy ballot 0's nullifier onto ballot 1"*
- **What Saksi should do** — the expected rejection, e.g. *"auditor rejects: duplicate nullifier"*
- **Guarantee at stake** — the security property, e.g. *"no double voting (per-position nullifier)"*

This text is served from the scenario registry in Go, not written into the page,
so what the audience reads cannot drift away from the code that performs the
mutation.

After running: the verdict. **PASS means the attack was rejected.**

## What runs

`POST /scenarios` with a single-scenario list, then
`GET /api/scenarios/<runID>` for the verdict. For each attack:

```
copy the run  ->  audit the untouched copy  ->  mutate  ->  audit again
```

The original run is never modified; each attack works on its own copy.

### The positive control

The first audit — of the **unmutated** copy — must pass before the mutation is
applied. If it does not, the scenario fails outright.

This is what makes the result attributable. Without it, a rejection after
mutation could be caused by some unrelated pre-existing fault in the run, and the
attack would appear to have been caught when nothing of the sort happened. The
wizard surfaces this as its own tick, because it is the part of the design that
makes the verdict mean something.

## The catalog

| # | Attack | Property | Layer |
|---|---|---|---|
| 1 | `tamper-ballot-proof` | ballot well-formedness (CDS proof) | offline |
| 2 | `reused-nullifier` | no double voting (per-position nullifier) | offline |
| 3 | `dropped-ballot` | ballot-box completeness | offline |
| 4 | `reordered-ballots` | ledger integrity (ordering) | **chaincode** |
| 5 | `corrupted-ballot-bytes` | wire integrity | offline |
| 6 | `tamper-partial-decryption` | threshold-decryption integrity | offline |
| 7 | `tamper-dkg-transcript` | DKG transcript integrity | offline |

Each is grounded in an existing auditor tamper test, so the offline auditor is
independently proven to reject it.

## Attack 4 does not run offline — on purpose

`reordered-ballots` is a **chaincode-layer** attack. Ordering is enforced at
endorsement, and the offline record carries no ordering for the offline auditor
to check. Running it here would prove nothing, so the step shows the briefing and
a neutral *"not run offline"* state instead of a verdict.

Asserting it against the offline auditor would produce a **false FAIL** — a
reported security failure that did not happen. Reporting it as PASS would be
worse. It is shown rather than hidden because the boundary between the two
verifiers is a real property of the design, and a panel is entitled to ask about
it. It is exercised for real by the `fabric` CI job against a live network.

## Reading a FAIL

A `FAIL` verdict means a **mutated run audited clean** — a gate that should have
rejected did not. That is a genuine finding about the system, not a flaky test,
and the wizard says so rather than colouring it neutrally.

## Cost

Each attack copies the run's ballot file and runs the auditor twice. At demo
scale that is seconds. At the capstone tier it is not viable — the copy alone
reads the entire ballot file into memory, and there are seven of them.

**Attack a small election.** Twenty voters is plenty; the mutations target
specific ballots and proofs, and nothing about the result improves with
population size.

## Artifacts

Verdicts accumulate in `scenarios.json`, and `negative-tests.csv` is regenerated
in full from it after every run. Running attacks one at a time therefore leaves a
complete export — the CSV holds all seven, in registry order, regardless of the
sequence that produced them.
