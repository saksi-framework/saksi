# Step 4 — Encrypt & record

Builds the cryptographic bundle for the election and, on-chain, drives the
lifecycle onto the ledger up to the point where voting closes.

## What runs

`POST /ceremony/start` → `CeremonyStart` (`packages/saksi-campaign/ceremony.go`).

Two things happen, in this order:

**1. Generate the bundle (both modes).** Shells `saksi-demo gen` to produce
`bundle.json` in the run folder: election parameters, the DKG transcript, every
encrypted ballot, every trustee's partial decryptions, and the tally.

**2. Drive the ledger (on-chain only).** `setupOnChain` submits, in order:

```
CreateElection  ->  PublishDKGTranscript  ->  SubmitBallot × N  ->  CloseElection
```

and stops. Partial decryptions and the tally are deliberately *not* submitted
here — those belong to the trustees in step 5, which is what makes the threshold
visible rather than automatic.

Offline, step 2 is skipped and the step reports *"local ceremony ready — no
ledger; the threshold gate is enforced by this console."*

## What the encryption actually is

Each ballot carries, per candidate, an ElGamal ciphertext under the joint
election key on ristretto255, plus a **CDS OR-proof** that the encrypted value is
either 0 or 1 and that the whole ballot sums to exactly one selection. The
chaincode verifies that proof at endorsement (ADR-0007); the offline auditor
verifies it too.

Voter eligibility rides on a blind-signed anonymous credential, and each ballot
carries a **per-position nullifier** derived by PRF, which is what makes double
voting detectable without linking a ballot to a voter.

On-chain, each committed transaction yields a real ledger receipt — block number,
transaction id, block hash — polled into the page as it goes and recorded in
`trail.json` / `receipts.csv`.

## Two encryptions of one population

This is the subtlety most likely to cause confusion when reading the artifacts.

Step 2 wrote `header.json` + `ballots.ndjson` — a complete encrypted run. This
step writes `bundle.json` — **another** complete encrypted run. Both encrypt the
*same plaintext population*, because the selection rule is deterministic. Neither
contains the same ciphertexts as the other, because encryption draws from
`OsRng`.

So:

- The **stream** (`ballots.ndjson`) is what the independent auditor reads in step 6.
- The **bundle** (`bundle.json`) is what the ceremony submits in step 5.
- Their plaintext tallies are identical; their ciphertexts share nothing.

### The consequence: never regenerate mid-ceremony

Because `gen` draws fresh randomness every time, a regenerated bundle contains
**different trustee shares**. Partial decryptions already submitted against the
old bundle would no longer correspond to anything, and on-chain `CreateElection`
would additionally reject the election as a duplicate.

The ceremony therefore generates the bundle **once**, here, and every later step
reads the cached file. Any change to this code path must preserve that. It is
called out in the source for the same reason.

## Ground-truth mode

This step does not apply. That mode produces no ciphertexts, the server answers
409 for the phase, and the wizard marks steps 4–7 as skipped.

## What this step does not do

It does not decrypt anything, and it does not produce a result. After
`CloseElection` the election is sealed and the tally is still encrypted — no one,
including the operator, can read it until a threshold of trustees acts in step 5.
