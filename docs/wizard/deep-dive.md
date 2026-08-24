# The Election Wizard — technical deep dive

Every step of the wizard, in depth: what the operator does, which endpoint it
hits, which functions run, what gets written to disk, and what each step does
and does not prove.

This is the single document to read before defending the demonstration. The
per-step files in this directory cover the same ground more gently; this one
names the code.

---

## Architecture in one picture

```
  browser (web/wizard.html)
        │  fetch / POST, and one EventSource for progress
        ▼
  Go console  ── packages/saksi-campaign
        │        server.go     routing, Host-header guard, dispatch lock
        │        executor.go   phase pipeline, shells the Rust binary
        │        ceremony.go   trustee ceremony state
        │        check.go      the data-validation gate
        │        scenarios.go  attack catalog + runner
        ▼
  Rust CLI  ── packages/saksi-demo  (saksi-demo)
        │        gen --stream        full crypto + ground truth
        │        gen-ground-truth    plaintext tables only
        │        audit-stream --json independent verification
        ▼
  saksi-auditor / saksi-crypto / saksi-credentials / saksi-protocol
        │
        ▼
  Hyperledger Fabric (on-chain mode only) ── saksi-bulletin/chaincode
```

Three languages, one direction of travel. The Go console never implements
protocol logic — it orchestrates, and shells out to the Rust for anything
cryptographic. That separation is why the auditor can be called independent: it
is a different program reading published files.

### Cross-cutting machinery

| Concern | Where | Note |
|---|---|---|
| Per-run busy lock | `dispatch` (`server.go`) | Returns 202 on accept, **409** if that run is already working |
| Progress | `Hub`, `publish` (`sse.go`, `executor.go`) | `Event{Phase, Level, Msg}`, 64-deep buffer, drops rather than blocks |
| Shelling out | `execRunner` (`executor.go`) | Returns stdout even on non-zero exit — Verify inspects stdout regardless |
| Run folder | `RunStore` (`store.go`) | One directory per run; every artifact lands there |
| Config gate | `ElectionConfig.Validate` (`config.go`) | Server-side; the form cannot bypass it |

---

## Step 1 — Set up

**Operator:** names the election, the trustees, the ballot shape, the
distribution, the Senate seats, and the mode.

**Path:** the form builds a JSON body in `config()` (wizard.html). Nothing is
sent until step 2 — this step is local until then.

**Functions**

| Function | File | Job |
|---|---|---|
| `config()` | `web/wizard.html` | Collect the form into the request body |
| `ElectionConfig.Validate` | `config.go` | The only gate; rejects every malformed run |
| `ElectionConfig.Seats(p)` | `config.go` | How many candidates win position `p` |
| `ElectionConfig.TrusteeNames` | `config.go` | Display names, in order |

**Rules enforced.** Non-empty election and trustee names; trustees within
`1..MaxTrustees`; threshold within `1..n`; positions, candidates and voters each
≥ 1; distribution one of `uniform` / `skewed` / `realistic`; senate seats within
`0..candidates-1`; mode one of `offline` / `onchain` / `groundtruth`.

**The offline ceiling.** `OfflineVoterCeiling` (10,000) applies **only** when
`Mode == "offline"`, because the cost that justifies it — a credential, DKG
share, ElGamal encryption and CDS proof per voter per candidate — does not exist
on the `groundtruth` path. That scoping is what makes the 3,524,078-voter tier
reachable.

**Choose `realistic`.** `uniform` divides the electorate evenly and therefore
ties at rank one; `skewed` gives a front-runner but leaves the losers level, so
a multi-seat cut ties at every scale. Only `realistic` decides a race.

---

## Step 2 — Ballots (Stage 4 of the methodology)

**Operator:** presses start; watches the log.

**Path:** `POST /generate` → `handleGenerate` → `RunStore.Create` →
`dispatch` → `Executor.Generate`.

**Functions**

| Function | File | Job |
|---|---|---|
| `handleGenerate` | `server.go` | Decode + validate, create the run, dispatch |
| `Executor.Generate` | `executor.go` | Shell `saksi-demo gen --stream` |
| `Executor.generateGroundTruth` | `executor.go` | Ground-truth mode: shell `gen-ground-truth` |
| `groundTruthOnly` | `executor.go` | Mode test used across the pipeline |
| `multi_position_fixture` | `fixtures.rs` | The whole cryptographic election |
| `write_ground_truth_csvs` | `ground_truth.rs` | The two plaintext tables |
| `SelectionPlan::new` / `.select` | `fixtures.rs` | Who each voter picks |
| `select_candidate` | `fixtures.rs` | `uniform` / `skewed` arithmetic |
| `realistic_quotas` | `fixtures.rs` | Per-position vote quotas |
| `interleave_stride` | `fixtures.rs` | Coprime stride, so brackets don't block |
| `tally_selections` | `fixtures.rs` | Ground truth, from the recorded selections |
| `ph_position_id` / `candidate_label` | `fixtures.rs`, `ground_truth.rs` | `president/cand0`, `CAND_PRES_01` |

**What the cryptography does.** Per voter: a blind-signed credential via the
Pointcheval-Stern issuance ceremony (`saksi-credentials`). Once per election: a
Pedersen DKG (`run_in_memory`) yielding trustee shares and a joint key. Per
voter per candidate: an ElGamal ciphertext under that key plus a **CDS OR-proof**
that it encrypts 0 or 1. Per ballot: a credential presentation carrying a
per-position **nullifier**, which is what makes double voting detectable without
linking a ballot to a voter.

**Artifacts:** `ground-truth-ballots.csv`, `ground-truth-summary.csv`,
`header.json`, `ballots.ndjson`.

**The separation that matters.** Selections are pushed into a `selections`
vector and the ground truth is computed from *that*, by `tally_selections`,
after the loop. It is never accumulated as a side effect of building
ciphertexts. If it were, a crypto bug that encrypted the wrong value would
corrupt both sides equally and `E = 0` would still pass.

---

## Step 3 — Check (the validation gate)

**Operator:** reads a list of checks; cannot advance if any fails.

**Path:** `GET /api/check/<runID>` → `handleCheck` → `Executor.RunCheck`.

**Functions**

| Function | File | Job |
|---|---|---|
| `handleCheck` | `server.go` | Resolve the run, call the gate, return JSON |
| `Executor.RunCheck` | `check.go` | Assemble the report, decide pass/fail |
| `recountBallots` | `check.go` | Stream the table; recount independently |
| `compareToSummary` | `check.go` | Recount vs the published tally |
| `candidateOrdinal` | `check.go` | Parse `NN` out of `CAND_PRES_NN` |
| `fileDigest` | `check.go` | SHA-256 of each table |
| `pass` / `fail` / `withCommas` | `check.go` | Report construction and formatting |

**The seven checks.** Table shape · voter ids unique and sequential · every
selection a real candidate · every voter accounted for · **recount matches the
published tally** · no votes lost or invented · population fingerprinted.

The fifth is what the step exists for; the rest are the preconditions that make
it meaningful.

**Bounded memory.** `recountBallots` uses a `bufio.Scanner` with a 4 MB line cap
and checks voter ordinals against the row counter rather than collecting ids
into a set — so the 3.5M-row, ~217 MB table audits without loading.

**Fail-closed.** `next2b.disabled = !rep.pass` in the page. A population that
fails cannot be encrypted, which is exactly what Figure 3.1 specifies.

**Artifact:** `ground-truth-check.json`.

**Limit.** It proves the population is internally consistent — not that the
selection rule was applied correctly. A generator that consistently applied the
wrong rule would pass every check here. That question is answered instead by the
Python reference implementation, which reproduces any published table from its
parameters.

---

## Step 4 — Encrypt & record

**Operator:** watches the lifecycle; on-chain, watches ledger receipts arrive.

**Path:** `POST /ceremony/start` → `handleCeremonyStart` → `CeremonyStart`.

**Functions**

| Function | File | Job |
|---|---|---|
| `CeremonyStart` | `ceremony.go` | Generate the bundle, then drive the ledger |
| `Executor.generateBundle` | `ceremony.go` | Shell `saksi-demo gen` → `bundle.json` |
| `Executor.readBundle` / `bundlePath` | `ceremony.go` | Read the cached bundle |
| `Executor.lifecycle` | `executor.go` | Connect; return a `lifecycleStep` closure |
| `Executor.setupOnChain` | `executor.go` | Create → DKG → Ballots → **Close**, stop |
| `writeCeremony` / `newCeremony` | `ceremony.go` | Initial ceremony state |
| `buildTrail` | `trail.go` | Ledger receipts per transaction |

**On-chain order:** `CreateElection` → `PublishDKGTranscript` →
`SubmitBallot × N` → `CloseElection`. Partials and the tally are deliberately
**not** submitted here — those belong to the trustees, which is what makes the
threshold visible instead of automatic.

Offline, `CeremonyStart` returns after generating the bundle and reports *"local
ceremony ready — no ledger."*

**Two encryptions, one population.** Step 2 wrote `ballots.ndjson`; this step
writes `bundle.json`. Both encrypt the *same plaintext population* — the
selection rule is deterministic — but share no ciphertexts, because encryption
draws from `OsRng`. The auditor reads the stream; the ceremony submits the
bundle.

**Never regenerate mid-ceremony.** A regenerated bundle contains different
trustee shares, so partials already submitted would correspond to nothing, and
on-chain `CreateElection` would reject the election as a duplicate. The bundle
is generated once, here, and read from cache thereafter.

---

## Step 5 — Trustee ceremony

**Operator:** submits from each trustee card; watches publish stay locked until
the threshold is met.

**Path:** `POST /ceremony/submit` and `/ceremony/publish`;
`GET /api/ceremony/<runID>` for state.

**Functions**

| Function | File | Job |
|---|---|---|
| `CeremonySubmit` | `ceremony.go` | Submit exactly one trustee's partials |
| `CeremonyPublish` | `ceremony.go` | **409 below threshold**, else `PublishTally` |
| `CeremonyStatus` | `ceremony.go` | Roster + counts for the UI |
| `partialsByTrustee` | `ceremony.go` | Group by decoded `trustee_id`, not array index |
| `refreshFromChain` | `ceremony.go` | On-chain, the ledger is authoritative |
| `firstContestID` | `ceremony.go` | A contest to probe for submission state |
| `markSubmitted` / `markPublished` | `ceremony.go` | Offline state in `ceremony.json` |
| `trusteeDisplayName` | `ceremony.go` | Map trustee id → institution name |

**Grouping by field, not index.** `partialsByTrustee` decodes each
`PartialDecryption` and groups on its `trustee_id`. The canonical layout is
`partial_decryptions[c * trustee_count + t]`, but relying on that arithmetic
would break silently if the layout ever changed.

**Where the threshold is enforced — state this accurately.** The chaincode
validates every partial it receives (trustee in the declared set, contest
exists, Chaum-Pedersen proof present, election closed, no duplicate submission)
but **does not count partials before accepting `PublishTally`**. The *t*-of-*n*
gate here is enforced by the console.

That does not make the property unproven: the independent auditor verifies it at
audit time, counting distinct verified trustees per contest and Lagrange-
interpolating only over the submitted subset. Threshold integrity is a
**verification-time** guarantee, not an endorsement-time one.

**Also honest:** the published tally is the generator's seeded result, not a
recomputation from whichever shares were clicked. The ceremony gates
*publication*; the auditor proves enough trustees contributed.

---

## Step 6 — Verify

**Operator:** reads the bulletin board, then the correctness table.

**Path:** `POST /verify` → `handleVerify` → `Executor.Verify` → shells
`saksi-demo audit-stream <dir> --json`.

**Functions**

| Function | File | Job |
|---|---|---|
| `Executor.Verify` | `executor.go` | Shell the auditor, parse, write the CSV |
| `writeCorrectnessCSV` | `executor.go` | Per-contest proof rows |
| `StreamAudit` / `ContestCorrectness` | `executor.go` | The auditor's JSON shape |
| `loadResults` | `web/wizard.html` | Fetch and render `correctness.csv` |
| `renderBoard` | `web/wizard.html` | The bulletin board, seats, ties |
| `posLabel` / `candLabel` | `web/wizard.html` | `president/cand0` → President, Candidate 1 |

**What the auditor does.** Re-verifies every CDS proof and credential
presentation, checks nullifiers for duplicates, homomorphically aggregates the
ciphertexts per contest, verifies each Chaum-Pedersen proof on the partial
decryptions, Lagrange-interpolates the threshold subset, and recovers each total
by solving the small discrete log of the lifted `m·G`.

**The bulletin board.** Groups `correctness.csv` by the part of `contest` before
the `/`. President and Vice President elect one; the Senate elects
`senate_seats` and draws a cut line. Where more candidates are level at the cut
than there are seats, it reports a tie and awards nothing — under `uniform` a
20-voter, 4-candidate race really does decrypt to 5/5/5/5.

**The metric.** `E = Σ|Tᵢ − Gᵢ|`, required to be **zero**. `correctness.csv`
also carries the recovered plaintext point, the aggregate ciphertext it came
from, and the DKG / tally / ballot-set hashes — so each row is self-contained
proof rather than an assertion.

**Artifact:** `correctness.csv`.

---

## Step 7 — Attacks

**Operator:** walks seven steps; each briefs, then runs live.

**Path:** `POST /scenarios` with a one-element list;
`GET /api/scenarios/<runID>` for briefings and verdicts.

**Functions**

| Function | File | Job |
|---|---|---|
| `Registry` | `scenarios.go` | The attack catalog — id, property, action, expected |
| `RunScenarios` | `scenarios.go` | Run the selection, merge, export |
| `runOneScenario` | `scenarios.go` | Copy → control audit → mutate → audit |
| `selectScenarios` | `scenarios.go` | Filter the registry by id |
| `copyStream` | `scenarios.go` | Isolate each attack on its own copy |
| `auditStream` | `scenarios.go` | Shell `audit-stream --json` |
| `mutateBallot` / `mutateHeader` | `scenarios.go` | Apply one mutation |
| `flipBytes` / `flipHexString` | `scenarios.go` | The corruptions themselves |
| `mergeScenarioResults` | `scenarios.go` | Accumulate verdicts across calls |
| `writeNegativeTestsCSV` | `scenarios.go` | Regenerate the export in full |
| `ScenarioListings` | `scenarios.go` | Registry joined with verdicts |
| `handleScenarioList` | `server.go` | `GET /api/scenarios/<id>` |

**Briefing text comes from the code.** `Scenario.Action`, `.Expected` and
`.Property` are served from `Registry()`, not written into the page, so what the
audience reads cannot drift from what the mutation does.

**The positive control.** `runOneScenario` audits the **unmutated** copy first
and fails the scenario outright if it does not pass. Without it a rejection
after mutation could be caused by some unrelated pre-existing fault, and the
attack would look caught when nothing was.

**PASS means the attack was rejected.** A `FAIL` means a mutated run audited
clean — a real finding about the system.

**Accumulation.** Verdicts are upserted into `scenarios.json` and
`negative-tests.csv` is regenerated in full from it. Running attacks one at a
time therefore still leaves a complete export.

**One attack does not run offline.** `reordered-ballots` is `LayerChaincode`:
ordering is enforced at endorsement and the offline record carries no ordering
to check. Asserting it against the offline auditor would produce a false FAIL.
It is shown and labelled rather than hidden.

---

## Where each guarantee is enforced

| Guarantee | Enforced by | Seen at |
|---|---|---|
| Ballot well-formedness | CDS proof — chaincode at endorsement, and the auditor | 4, 7 |
| No double voting | per-position nullifier | 4, 7 |
| Data completeness | the console's gate (`RunCheck`) | 3 |
| Threshold *t*-of-*n* | the **auditor**, at verification time | 5, 6 |
| Ledger ordering | the **chaincode**, at endorsement | 7 |
| Tally correctness | `E = 0` | 6 |

The two italicised rows are the awkward ones, and both are stated in the UI
rather than hidden.

## Declared limitations

- **Threshold is console-enforced**, verified by the auditor rather than
  refused by the chaincode. Adding an endorsement-time count is a real
  improvement; it needs a chaincode redeploy.
- **Contest-mixing.** The three positions usually differ under `realistic`, but
  not guaranteed — measured at ~8.6% of configurations they share a multiset of
  totals, and on those `E = 0` could not tell one contest from another.
- **Single selection per position.** Multi-seat races are decided by plurality
  over one vote each (SNTV). A ballot marking several candidates for one
  position needs a proof that selections sum to N.
- **Attack cost.** Each scenario copies the whole ballot file and audits twice;
  attack a small election.
