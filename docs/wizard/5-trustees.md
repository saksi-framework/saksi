# Step 5 — Trustee ceremony

Threshold decryption. The election is closed and its tally is encrypted; it stays
that way until *t* of *n* trustees contribute their share.

This is the step that shows the system's central custody claim: **no single
party can read the result.**

## What the operator sees

One card per trustee institution, each with its own **Submit partial
decryption** button, and a quorum meter reading *k of t*. Below the threshold the
tally is hidden and the publish button reads **Attempt decryption**. It stays
clickable: a click sends the real `POST /ceremony/publish`, and the server's
`409` refusal appears in a red **Decryption refused below the threshold** panel,
in the server's own words, with the time of the attempt and the share count, for
example *"Decryption refused: 2 of 5 shares recorded, the threshold is 3. The
tally cannot be decrypted until a third trustee submits."* On-chain the message
adds that a chaincode with the signature gate would refuse it too: `PublishTally` rejects a tally endorsed by fewer than
*t* trustee signatures. The panel keeps every attempt. On reaching *t* the button
becomes **Publish tally**, the panel notes the threshold is now met, and the
publish proceeds.

The refusal demo: submit two of five shares, click **Attempt decryption** and
show the refusal, then submit the third share and publish. It is worth doing
deliberately rather than clicking straight through.

## What runs

| Action | Endpoint | Does |
|---|---|---|
| Page load / poll | `GET /api/ceremony/<runID>` | Roster and submission counts |
| Trustee submits | `POST /ceremony/submit` | That trustee's partials, one per contest |
| Publish / attempt decryption | `POST /ceremony/publish` | **409 `Decryption refused: k of n shares recorded, the threshold is t. …` unless `submitted >= threshold`**, then `PublishTally` |

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
accepting `PublishTally`. It **does** count signatures: `PublishTally` verifies
each trustee's Schnorr signature over the totals and refuses a tally fewer than
*t* distinct trustees endorsed (`tally has k valid trustee signatures, threshold
is t`; `TestPublishTallyRejectsBelowThreshold` in the chaincode). The console
sends only the submitted trustees' signatures, so on a chaincode with that gate
the ledger refuses a below-threshold tally too. The console refuses first, with
a `409`, so nothing is sent. A chaincode built before the signature gate accepts
any tally; there the *t*-of-*n* gate is the console's alone.

That does not make the property unproven. The **independent auditor verifies it
at audit time**: it counts distinct verified trustees per contest and fails below
threshold, and Lagrange-interpolates only over the submitted subset. The
manuscript's own verifier checklist carries this as item 8 — *"that at least
three of the five trustees contributed."*

So threshold integrity is a **verification-time guarantee**, and on a
chaincode with the signature gate an **endorsement-time** one as well.

## One more honest scope note

The published totals are the **decrypted** result: at generation time the
generator Lagrange-combines a threshold set of the trustees' partial
decryptions (the first `t` whose Chaum-Pedersen proofs verify, the same subset
the auditor uses), decodes each contest, checks the result against the seeded
ground truth (a mismatch fails the run), and only then has the trustees sign
those totals. They are not recomputed live from whichever shares happened to be
clicked in the console; any `t` valid shares decrypt to the same numbers.

The ceremony gates *publication*; the auditor is what proves enough trustees
actually contributed. The UI is written not to imply the displayed numbers were
reconstructed live from the clicked cards, because they were not.

## Attacks at this stage

The ceremony carries its own **Attacks at this stage** panel with
`tamper-partial-decryption` — a trustee submitting a share whose
Chaum-Pedersen proof does not verify. On a live network this is a real
`SubmitPartialDecryption` the chaincode refuses; offline it is simulated.
See [7-attacks.md](7-attacks.md).

## Ground-truth mode

Does not apply — no ciphertexts exist to decrypt.
