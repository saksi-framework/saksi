# Step 5 — Trustee ceremony

Threshold decryption. The election is closed and its tally is encrypted; it stays
that way until *t* of *n* trustees contribute their share.

This is the step that shows the system's central custody claim: **no single
party can read the result.**

## What the operator sees

One card per trustee institution, each with its own **Submit partial
decryption** button, and a quorum meter reading *k of t*. Below the threshold the
tally is hidden and **Publish tally** is disabled. On reaching *t* it unlocks and
the result is revealed.

Submitting from fewer trustees than the threshold and watching publish stay
locked is the demonstration. It is worth doing deliberately rather than clicking
straight through.

## What runs

| Action | Endpoint | Does |
|---|---|---|
| Page load / poll | `GET /api/ceremony/<runID>` | Roster and submission counts |
| Trustee submits | `POST /ceremony/submit` | That trustee's partials, one per contest |
| Publish | `POST /ceremony/publish` | **409 unless `submitted >= threshold`**, then `PublishTally` |

Each click is its own short dispatch, so a ceremony spanning many clicks never
holds the run's busy lock between them.

Which partials belong to trustee *t* is decided by **decoding each
`PartialDecryption` and grouping on its `trustee_id` field**, not by index
arithmetic over the array. Same result, and it survives any future change to the
bundle's layout.

On-chain, the roster is read back **from the chain**, which is authoritative: for
one fixed contest, `GetPartialDecryption(eid, contest0, "1".."n")` is called per
trustee and an error means "not yet submitted". Offline there is no chain, so
state lives in `ceremony.json` in the run folder, labelled *"local ceremony — no
ledger."*

## What the chaincode does and does not enforce

**Read this before presenting the step.** It is the most likely question and the
UI is deliberately worded to be accurate about it.

The chaincode **does** validate every partial decryption it receives: the trustee
must be in the election's declared trustee set, the contest must exist, the
Chaum-Pedersen proof must be present, the election must be closed, and a repeat
submission from the same trustee for the same contest is rejected.

The chaincode **does not** count how many partial decryptions exist before
accepting `PublishTally`. Its checks there are status-closed, tally version,
election id, totals length, and no-existing-tally. **So the *t*-of-*n* gate in
this ceremony is enforced by the console, not by the ledger.**

That does not make the property unproven. The **independent auditor verifies it
at audit time**: it counts distinct verified trustees per contest and fails below
threshold, and Lagrange-interpolates only over the submitted subset. The
manuscript's own verifier checklist carries this as item 8 — *"that at least
three of the five trustees contributed."*

So threshold integrity is a **verification-time guarantee, not an
endorsement-time one**. Adding an endorsement-time check to `PublishTally` is a
genuine improvement and is recommended; it needs a chaincode redeploy and is
tracked as out of scope rather than done.

## One more honest scope note

The published tally is the generator's **seeded** result. It is not recomputed
from whichever shares happened to be submitted.

The ceremony gates *publication*; the auditor is what proves enough trustees
actually contributed. The UI is written not to imply the displayed numbers were
reconstructed live from the clicked cards, because they were not.

## Ground-truth mode

Does not apply — no ciphertexts exist to decrypt.
