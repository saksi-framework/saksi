# Step 1 — Set up

Declares the election. Nothing has been generated yet; this step only decides
what *will* be generated.

## What the operator sets

| Field | Meaning | Notes |
|---|---|---|
| Election name | Label carried into the artifacts | Must not be empty |
| Trustees | Named key-holding institutions | 1..`MaxTrustees`; each needs a name |
| Threshold | How many trustees must act to decrypt | `1 ≤ t ≤ n` |
| Positions | Races on the ballot | ≥ 1 |
| Candidates | Candidates per position | ≥ 1 |
| Voters | Population size | ≥ 1; presets for each paper tier |
| Distribution | `realistic`, `uniform`, or `skewed` | Decides whether the election has a winner — see below |
| Senate seats | How many senators are elected | `0` = single-winner; `1..candidates-1` for a multi-seat race |
| Mode | `offline`, `onchain`, `groundtruth` | Decides which later steps apply |

Trustee names are real inputs, not decoration: they become the institutions on
the ceremony cards in step 5 (`COMELEC`, `Civil Society Watch`, `University IT`
by default).

## Which distribution to pick

This choice decides whether the election has a winner at all.

```
1000 voters, 4 candidates
  uniform     250  250  250  250      exact four-way tie
  skewed      500  167  167  166      winner, but two losers tied
  realistic   490  180  170  160      every rank distinct
```

**Use `realistic`.** It is the only profile that decides a result: counts
strictly decrease, so a single-winner race has one winner and a multi-seat race
cuts cleanly at rank N. It keeps the skewed shape — the front-runner still takes
roughly half — and reserves a different share per position so the three races
usually do not read as the same race three times.

`uniform` divides the electorate evenly by construction and therefore **ties at
rank one, always**. `skewed` gives a clear front-runner but splits the losers
evenly, so a top-N cut is tied at every scale — 3.5M voters does not help.

Both are kept because the manuscript's performance comparisons are stated in
terms of them, and for a throughput measurement an even split is a perfectly
reasonable load. Neither is a sensible choice for demonstrating a result.

All three are documented in `../synthetic-data-generation.md` and walked through
in `../selection-rule-explained.md`.

## Senate seats

The Senate is a multi-seat race: the top `senate_seats` candidates are elected,
while President and Vice President stay single-winner. `0` makes the Senate
single-winner too.

Each voter still selects **exactly one** senator — this is Single
Non-Transferable Vote, not a ballot on which a voter marks twelve names. That
distinction is what makes it free: the CDS proof still shows each ciphertext
encrypts 0 or 1, and the auditor's gate still requires each position's aggregate
to equal the ballot count. Seats decide how the result is *read*, never how it
is produced, so the value never reaches the generator.

Must be `0 <= senate_seats < candidates`: a cut needs at least one candidate
below it, or every candidate is elected and the race decides nothing.

## Validation

`ElectionConfig.Validate` (`packages/saksi-campaign/config.go`) is the only gate,
and it runs server-side — the form cannot talk the backend into an invalid run.
It rejects: an empty election or trustee name, a trustee count outside
1..`MaxTrustees`, a threshold outside `1..n`, any of positions / candidates /
voters below 1, a distribution that is not `uniform`, `skewed`, or `realistic`, a senate-seat
count outside `0..candidates-1`, and a mode that is not one of the three.

### The 10,000-voter offline ceiling

```go
if c.Mode == "offline" && c.Voters > OfflineVoterCeiling { ... }
```

Offline runs are capped at 10,000 voters because the full cryptographic path —
credential issuance, DKG, an ElGamal encryption and a CDS proof per candidate per
voter — is genuinely expensive, and a runaway run would hang the console rather
than fail.

The cap is scoped to `offline` on purpose. **`groundtruth` mode has no ceiling**,
because it runs no cryptography at all: the cost that justifies the cap does not
exist on that path. That is what lets the 3,524,078-voter capstone tier generate
in well under a second.

## What this step does not do

Nothing is written to disk. The run folder is created when step 2 starts. Going
back and changing a parameter here starts a different run — parameters are not
editable once a population exists, because the ground truth is derived from them.
