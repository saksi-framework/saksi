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
| Distribution | `uniform` or `skewed` | Shapes the result — see below |
| Mode | `offline`, `onchain`, `groundtruth` | Decides which later steps apply |

Trustee names are real inputs, not decoration: they become the institutions on
the ceremony cards in step 5 (`COMELEC`, `Civil Society Watch`, `University IT`
by default).

## Which distribution to pick

This choice decides whether the election has a winner at all.

```
uniform   1000 voters, 4 candidates -> 250, 250, 250, 250   (exact 4-way tie)
skewed    1000 voters, 4 candidates -> 500, 167, 167, 166   (candidate 1 wins)
```

`uniform` assigns candidates round-robin, so it divides the electorate **exactly
evenly** whenever the voter count is a multiple of the candidate count. That is
not a quirk of a particular run — it is what the profile means. A 20-voter,
4-candidate uniform election decrypts to 5/5/5/5, and the bulletin board in step
6 correctly reports it as a tie rather than nominating a winner.

**For a demonstration, choose `skewed`.** It produces a clear front-runner with
exactly half the vote, which is what an audience expects an election to look
like. Use `uniform` deliberately if you want to show the tie handling.

Both profiles are documented in
[`../synthetic-data-generation.md`](../synthetic-data-generation.md).

## Validation

`ElectionConfig.Validate` (`packages/saksi-campaign/config.go`) is the only gate,
and it runs server-side — the form cannot talk the backend into an invalid run.
It rejects: an empty election or trustee name, a trustee count outside
1..`MaxTrustees`, a threshold outside `1..n`, any of positions / candidates /
voters below 1, a distribution that is not `uniform` or `skewed`, and a mode that
is not one of the three.

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
