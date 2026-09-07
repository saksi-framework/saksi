# Development log — the Research Election Console

What was built, why, and what is actually verified. Written as a record for the
thesis and for whoever picks this up next, so it includes the things that went
wrong and the limits that remain open.

Covers commits `b87a21b` … `954122e`. **5,107 lines added across 26 files**, of
which 10 are new. Tests: **89 Go**, **48 Rust**, all green.

---

## 1. What existed before, and what was missing

The console at `/` could already drive a full election: generate a population,
submit it, verify it, and run seven attack scenarios. What it could not do was
*show* the protocol. Everything lived on one dense page — config panel, phase
buttons, log, results — all visible at once and clickable in any order.

A viewer could not tell from looking at it that an election has stages, which
stage they were in, or that the tally genuinely requires several independent
parties to act. The attacks were a single button that produced a CSV.

Everything below is about making the system's own guarantees legible, and
fixing the things that turned out to be wrong once they were.

---

## 2. The dashboard: a guided wizard

**`packages/saksi-campaign/web/wizard.html`** — 1,138 lines, new, served at
`/wizard`. The original console at `/` is untouched and still works, which was
deliberate: it was the fallback if the wizard was not ready in time.

Seven steps, in the order the protocol actually happens:

| # | Step | What it demonstrates |
|---|---|---|
| 1 | Set up | The parameters, and the only gate on them |
| 2 | Ballots | Generation + encryption (methodology Stage 4) |
| 3 | Check | The population audited against itself, before any crypto is trusted |
| 4 | Encrypt | The lifecycle onto the ledger, stopping at close |
| 5 | Trustees | Threshold decryption — *t* of *n* must act |
| 6 | Verify | Independent audit, the declared result, `E = 0` |
| 7 | Attacks | Seven attacks, each briefed and run |

### Pieces built for it

- **The trustee ceremony** (`ceremony.go`, 480 lines, new). One card per
  institution, each with its own submit button, and a quorum meter. Below the
  threshold the tally is hidden and publish is disabled; on reaching *t* it
  unlocks. `partialsByTrustee` groups shares by decoding each
  `PartialDecryption` and reading its own `trustee_id` rather than by index
  arithmetic, so a future layout change cannot silently break it.

- **The validation gate** (`check.go`, 306 lines, new). The methodology's
  *"Data Validation: all records valid?"* decision, made visible and
  fail-closed. Seven checks; the load-bearing one recounts the population from
  disk and holds it against its own published summary. It streams and checks
  voter ordinals against the row counter, so the 3.5M tier audits in bounded
  memory.

- **The bulletin board.** The Verify step proved correctness but never showed
  the *result*. It now renders per-position counts, shares, and the winner —
  from the `decoded` column already fetched, so no new endpoint and no second
  audit.

- **A `/trail` index.** The run id *is* the election id, and it was only ever
  visible as grey text in step 2. There is now a persistent id chip with copy
  and a trail link, and `/trail` lists every election the console recorded,
  each probed against the ledger.

- **Ground-truth-only mode** — generates the plaintext tables with no
  cryptography at all, which is what makes the 3,524,078-voter tier reachable.
  The 10,000-voter ceiling is scoped to `offline` because the cost that
  justifies it does not exist on that path.

---

## 3. The attacks

### Before: all after the count

Seven scenarios behind one button, fired in a batch, reported as a refreshed
file chip. Nothing explained what each attack *was*, what it aimed at, or what
the system was supposed to do about it — which is the entire security argument.

### First change: one step per attack

Each attack became its own wizard step with a briefing *before* it runs:

- **What the attacker does** — the mutation
- **What Saksi should do** — the expected rejection
- **Guarantee at stake** — the security property

That text is served from the `Scenario` registry in Go, never written into the
page, so what an audience reads cannot drift from what the mutation does.

The **positive control** is surfaced too: `runOneScenario` audits the
*unmutated* copy first and fails the scenario outright if it does not pass.
Without it, a rejection after mutation could be caused by an unrelated
pre-existing fault, and the attack would look caught when nothing was.

> **A data-loss bug this uncovered.** `RunScenarios` rebuilt
> `negative-tests.csv` from only the scenarios that call had selected, using a
> truncating `os.Create`. Running attacks one at a time — which is exactly what
> the new per-step UI does — would have left the manuscript's export holding a
> single row. Verdicts now accumulate in `scenarios.json` and the CSV is
> regenerated in full. Confirmed both ways: reintroducing the bug fails the new
> test with precisely that data loss, and a live run of four separate calls
> leaves four rows.

### Second change: attacks *during* the election

An attacker does not wait for the count to finish before forging a ballot. Each
attack now also appears at the lifecycle stage it belongs to:

| Stage | Attacks | Wizard step |
|---|---|---|
| `dkg` — before any ballot is cast | `tamper-dkg-transcript` | 4 |
| `ballots` — during submission | `tamper-ballot-proof`, `reused-nullifier`, `corrupted-ballot-bytes` | 4 |
| `close` — on the sealed box | `dropped-ballot`, `reordered-ballots` | 4 |
| `ceremony` — during decryption | `tamper-partial-decryption` | 5 |

`Stage` is a field on `Scenario`, beside `Action` and `Expected`, so the page
never hardcodes which attack happens when. Tests assert every scenario declares
a stage and that the stages partition the catalogue.

**Simulated versus real.** Offline, an attack mutates a copy and re-audits —
labelled `simulated`, recorded `on_chain=false`. On a live network it is real:
the tampered artifact is submitted to the peer and the **chaincode refuses it
at endorsement**, its own error text becoming the result.

```go
if submitErr != nil {
    res.Verdict = "PASS"
    res.Actual = "chaincode rejected: " + truncateErr(submitErr.Error())
} else {
    res.Verdict = "FAIL"
    res.Actual = "NOT rejected — the ledger accepted a tampered artifact"
}
```

**The verdict inverts on that path**, and it is the whole epistemics of the
step: a rejection is the gate working, and an *accepted* tampered artifact is a
genuine finding. Getting it backwards would report a broken gate as green — so
it is tested in both directions, and the tests were confirmed to fail when the
two verdicts are swapped.

`close`-stage attacks stay simulated in both modes: they describe something
missing or reordered across the whole ballot set, which no single submission
can express. `Scenario.LiveCapable()` encodes that and a test asserts it.

**Skipping.** Attacks are opt-in — nothing runs until pressed. Each stage has a
**Skip**, and step 1 has a **Skip attacks** checkbox for a clean end-to-end run.
Skipping is never recorded as a pass.

Step 7 remains the full catalogue and is what writes a complete
`negative-tests.csv`. Because `mergeScenarioResults` upserts by id, a verdict
earned inline is shown there as already decided rather than re-run.

---

## 4. The selection rule: two rewrites

The bulletin board exposed a problem in the data itself.

**The diagnosis**, measured against the real generator:

```
uniform  V=1000  C=4    250 250 250 250          four-way tie, no winner
skewed   V=3.5M  C=12   1762039 160186 160186…   winner, but every loser tied
```

`uniform` divides the electorate evenly by construction. `skewed` gives a clear
front-runner but splits the losers evenly, so a multi-seat cut is tied **at
every scale** — 3.5M voters does not help. And because the position index only
*rotated* the assignment, President and Vice President came out with the same
numbers reordered.

**First attempt** replaced the distribution outright with a per-position weight
curve `(C-k)^s`. It worked, but it discarded the skewed shape the manuscript
describes.

**Second attempt, kept**: most of the electorate votes by the existing skewed
rule *unchanged*; a reserved slice is held back and apportioned down the ranks.

```
1000 voters, 4 candidates, President — reserve = 10%
  900 voters, old skewed rule   [450, 150, 150, 150]   <- the tie
  100 reserved, split 4:3:2:1   [ 40,  30,  20,  10]   <- the fix
                                ---------------------
  total                         [490, 180, 170, 160]
```

The reserved voters are taken *out* of the round-robin, not invented — every
voter votes once and the validation gate checks each position's total against
the ballot count. A tie cannot simply be nudged.

Two floors keep it honest: the reserve is at least `C(C+1)` so its spread
exceeds the round-robin's own one-vote wobble, and a final guard moves one vote
up if a very small electorate still leaves the top two level — making a clear
winner unconditional from one voter upward.

The arithmetic is **integer throughout**. Floating point would make the output
depend on the machine's rounding, so an Apple Silicon run could produce a
different population from an x86 one — which would defeat the reproducibility
the generator exists to provide.

`uniform` and `skewed` are byte-identical to before, checked against goldens
captured prior to the change.

**Multi-seat Senate.** The top *N* candidates are elected, each voter still
selecting exactly one — single non-transferable vote. That costs no
cryptography: the CDS proof still shows each ciphertext encrypts 0 or 1, and the
auditor's gate still requires each position's aggregate to equal the ballot
count. Seats decide how the result is *read*, never how it is produced, so the
value never reaches the generator.

---

## 5. Bugs found and fixed

Four were real, and three of them were mine.

### On-chain mode ran offline while claiming otherwise

Selecting on-chain with no Fabric network **did not fail**. `CeremonyStart`
tested `fabric.Enabled()`, published *"local ceremony ready — no ledger"*, and
returned success — so the run completed locally while the mode chip read
*"committing to Fabric"*. It also bypassed the 10,000-voter ceiling, which is
scoped to `offline`, so a 3.5M-voter "on-chain" run would be admitted and then
executed on the box.

Fixed three ways: the fallback is now mode-aware, `handleGenerate` refuses the
case at step 1, and a new `GET /api/capabilities` lets the wizard disable the
option instead of offering something the server cannot honour.

### The in-lifecycle attack panels never rendered

`renderStages` and `skippedStages` were called but never defined. A patch
anchored on a comment banner whose dash count was off by one, so the
replacement silently no-oped while every other edit in the same script applied.

The result was valid JavaScript that threw a `ReferenceError` at runtime — the
panels never appeared and `POST /attack` had no UI caller at all. The backend
had been verified end to end and passed, which is exactly why it survived:
`node --check` accepts undefined functions, and an element-id sweep only covers
ids. **Found by a subagent reading the file, not by any check I had.**

`TestWizardDefinesEveryFunctionItCalls` now asserts every function the wizard
calls is also defined; confirmed it bites by renaming a definition.

### negative-tests.csv truncated to the last subset

Described in §3.

### A test that read a column by index

`TestScenarioRerunUpdatesRowInPlace` asserted `rows[1][5]`, which the new
`stage` column shifted. Fixed to look the column up by header name, so the next
schema change fails honestly instead of reading the wrong field.

---

## 6. Infrastructure

**`tools/up.sh`** (196 lines, new) — one command brings up the whole stack:
installs Fabric if missing, starts the network, deploys the chaincode, builds
both binaries, and serves the wizard with on-chain enabled.

It wraps the existing `packages/saksi-bulletin/network/network.sh` — the same
path CI proves green — rather than defining its own Fabric topology, so a local
bring-up and the CI job cannot drift apart.

Preflight fails early and says what to do, because each of these has cost an
hour: Docker not running, Go or Rust missing, and above all **a space in the
repo path**, which breaks `fabric-samples` with an error pointing nowhere near
the cause.

**`cmd/dumpwire`** (217 lines, new) — a read-only decoder that dumps a run's
wire artifacts field by field with their real values. Documentation about what
is inside a hex blob is only trustworthy if the values come out of a real run.

---

## 7. What is verified, and what is not

### Verified — a full offline run, 1,100 voters × 3 positions × 12 candidates

| Stage | Result |
|---|---|
| Validation gate | 7 of 7 checks, 1,100 rows, all 36 contests agree |
| Staged attacks | all four stages rejected |
| Threshold gate | `409` at 0/2 **and** 1/2, `202` at 2/2 |
| President | 496 · 65 · 63 · 61 · 59 … |
| Vice President | 494 · 66 · 65 · 63 · 60 … |
| Senator, 3 seats | 474 · 72 · 69 · 66 … — cut clean, 69 > 66 |
| Accuracy | **E = 0** across every contest |
| Full sweep | 6 PASS, 1 SKIPPED (chaincode-only) |

Also verified: `uniform`/`skewed` byte-identical to pre-change goldens; both
generator paths agree; the Python reference reproduces all three profiles
byte-for-byte; the console cross-builds for `darwin/arm64` and `darwin/amd64`.

### Not verified

- **The on-chain path has never executed.** No Docker daemon was available on
  the development machine. `tools/up.sh` is proven only as far as its preflight
  guards; the network bring-up, chaincode deploy, and a real ledger-refused
  attack all remain untested against live Fabric.
- **`mountLiveAttack`** is covered by unit tests with a fake submitter, which
  prove the verdict logic including the inversion — but not that a real
  chaincode rejection arrives in the shape expected.

---

## 8. Declared limitations

Recorded rather than discovered. Each is stated in the UI and the docs.

- **Threshold is console-enforced.** The chaincode validates every partial it
  receives but does not count them before accepting `PublishTally`, and checks
  only that the Chaum-Pedersen proof is *present*, not that it verifies. The
  auditor re-proves both at verification time. Adding an endorsement-time count
  is a real improvement; it needs a chaincode redeploy.
- **Contest-mixing is narrowed, not closed.** The three positions usually
  differ under `realistic`, but at roughly 8.6% of configurations they land on
  the same multiset of totals. On those, `E = 0` could not tell one contest
  from another. The first weight-curve design guaranteed distinctness; this one
  trades that for staying close to the manuscript's distribution.
- **Distinct races need enough voters.** Below roughly 1,000 voters at 12
  candidates the reserve hits its floor and all three races come out identical.
  Valid, still decided — they just look alike.
- **One vote per position.** Multi-seat races are plurality over a single
  selection. A ballot marking several candidates needs a proof that selections
  sum to *N* — new cryptography, not configuration.
- **Immutability is single-org.** The chaincode has no `DelState` anywhere and
  every write is guarded against overwrite, so the record is append-only and
  tamper-evident. Distributed immutability additionally requires independent
  organisations, which a one-org test network does not provide.

---

## 9. Documentation produced

| Document | Covers |
|---|---|
| `docs/wizard/README.md` + seven step files | What each step does, writes, and does not prove |
| `docs/wizard/deep-dive.md` | All steps in one document, naming every function |
| `docs/synthetic-data-generation.md` | The generator: profiles, schemas, reproducing any tier |
| `docs/selection-rule-explained.md` | The three profiles walked through with traced values |
| `docs/rust-python-cross-reference.md` | The rule in both languages, side by side |
| `docs/onchain-quickstart.md` | `tools/up.sh`, and how to confirm a record is really on the ledger |
| `docs/research-election-console-runbook.md` | Building and running, including macOS |

All mirrored into `balotachain/docs/saksi/`, where `saksi/docs/` stays
canonical. Six of them are also rendered to PDF handouts.

---

## 10. Next steps

1. **Run the on-chain path.** `./tools/up.sh` on a machine with Docker and a
   space-free path. That closes the largest open gap in §7.
2. **Endorsement-time threshold check** in `PublishTally` — turns a
   verification-time guarantee into an endorsement-time one. Needs a redeploy.
3. **`ListElections` in the chaincode** — a paginated range query over the
   `election` composite key, mirroring `ListNullifiers`. Would let `/trail`
   enumerate the ledger rather than the console's own run store.
4. **Appendix A and B manuscript edits** — drafted in
   `balotachain/docs/appendix-*-change-prompt.md`, not yet applied. Appendix B's
   prompt was rewritten once the multi-seat Senate became supportable.
