# Step 7 — Attacks

Step 6 shows that an untouched election decrypts correctly. This step shows that
a *tampered* one is rejected — the negative half of the argument, and the one a
verifiability claim actually rests on.

Seven attacks, each its own wizard step, each briefed before it runs and run
live.

> **Attacks also happen during the election.** An attacker does not wait for the
> count to finish, so each attack is additionally offered *at the point in the
> lifecycle it belongs to* — inside steps 4 and 5 — where on a live network it
> is a **real** submission the chaincode refuses. See
> [Attacks during the election](#attacks-during-the-election) below. This step
> remains the full catalogue and is what writes a complete
> `negative-tests.csv`.

## What each step shows

Before running:

- **What the attacker does** — the mutation, e.g. *"copy ballot 0's nullifier onto ballot 1"*
- **What Saksi should do** — the expected rejection, e.g. *"auditor rejects: duplicate nullifier"*
- **Guarantee at stake** — the security property, e.g. *"no double voting (per-position nullifier)"*

This text is served from the scenario registry in Go, not written into the page,
so what the audience reads cannot drift away from the code that performs the
mutation.

After running: the verdict. **PASS means the attack was rejected by the gate it
declares** — the auditor check named in `gate_expected`. A rejection by any
other check is `INCONCLUSIVE`, shown amber, and left out of the rejection rate.

## What runs

`POST /scenarios` with a single-scenario list, then
`GET /api/scenarios/<runID>` for the verdict. For each attack:

```
copy the run  ->  audit the untouched copy  ->  mutate  ->  audit again
```

The original run is never modified; each attack works on its own copy.

### The positive control

The first audit — of the **unmutated** copy — must pass before the mutation is
applied. If it does not, the scenario is `INCONCLUSIVE` (`not mounted: positive
control did not pass`): nothing was tested, so it is neither a pass nor a
failure of the gate.

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


---

## Attacks during the election

Running every attack after the count reads as a test suite bolted onto the end.
Each attack therefore also appears at its own lifecycle stage, in an
**Attacks at this stage** panel inside the step that owns it.

| Stage | Wizard step | Attacks |
|---|---|---|
| `dkg` — before any ballot is cast | 4 | `tamper-dkg-transcript` |
| `ballots` — during submission | 4 | `tamper-ballot-proof`, `reused-nullifier`, `corrupted-ballot-bytes` |
| `close` — on the sealed ballot box | 4 | `dropped-ballot`, `reordered-ballots` |
| `ceremony` — during decryption | 5 | `tamper-partial-decryption` |

The stage is a field on `Scenario` (`scenarios.go`), beside `Action` and
`Expected`, so the page never hardcodes which attack happens when.

### When the attacks run: the timeline

A single election with an `attack_plan` is a **security run**. Its lifecycle
**pauses** at each stage the plan ticks, and the stage's panel waits for
**Run**, **Run all attacks at this stage** or **Skip this stage**. If nobody
decides before the stage's timeout (`timeout_s`, default 300 s), every attack
at that stage runs and the election continues.

| Stage | Where the lifecycle holds |
|---|---|
| `dkg` | after `CreateElection`, before the real `PublishDKGTranscript` |
| `ballots` | `ballots_at` × N ballots dispatched and committed; the rest not yet sent |
| `close` | after `CloseElection` |
| `ceremony` | trustees have acted; the tally is not yet published |

This is what makes a verdict about the gate it names. Mounted after the
election closed, a tampered ballot is refused by the closed-election gate
before the proof check ever runs; that is recorded as `INCONCLUSIVE`, never as
a pass. A security run's throughput is marked perturbed (`perf.csv`
`security_run`).

### Simulated versus real

**Real (on-chain).** Only attacks with an on-chain gate that leaves no state
behind are submitted to the live election, at the `ballots` pause: a tampered
copy of the first ballot not yet sent (`tamper-ballot-proof`, gate `cds`;
`corrupted-ballot-bytes`, gate `decode`), and that ballot carrying the
nullifier of one already committed (`reused-nullifier`, gate `nullifier`). The
refused copy leaves nothing on the ledger, and the real ballot is submitted
when the window resumes. The chaincode's error names its gate (`gate=cds: …`).

**Simulated.** Everything else mutates a copy of the run and re-audits it,
offline or on-chain. `tamper-dkg-transcript` and `tamper-partial-decryption`
are simulated even on a live network, because the chaincode would *accept*
them — it checks the transcript's shape and that a proof is present, not the
points or the proof — and the real election would be poisoned. Their rows say
so: "on-chain: accepted by design …; caught by the auditor".

`reordered-ballots` stays `SKIPPED`: ordering is a ledger property no single
submission and no stateless audit expresses.

### Skipping

- **Skip this stage** on a paused panel continues without running the rest.
- Unticking a stage in step 1 removes that pause; **Skip attacks** removes the
  whole timeline for a clean end-to-end run (no pauses, not a security run).

Skipping is not recorded as a pass. A stage that was never run simply has no
verdict.

### One catalogue, two places

A verdict earned inline is upserted into `scenarios.json` by
`mergeScenarioResults`, so step 7 shows it as already decided rather than
re-running it, and `negative-tests.csv` stays complete however the verdicts were
obtained. The CSV carries the mount context (`mounted_stage`,
`election_status`, `ballots_committed`, `block_height`, `live`) and the gates
(`gate_expected`, `gate_observed`) so the manuscript can tell a simulated
rejection from a real one, and a rejection by the gate under test from one by
another.
