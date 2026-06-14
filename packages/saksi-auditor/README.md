# saksi-auditor

Off-chain auditor for a Saksi election. Verifies that a published election
(election parameters + DKG transcript + ballots + partial decryptions + final
tally) was produced by a sound, tamper-evident pipeline, and emits a
structured pass/fail [`AuditReport`].

The auditor never talks to the bulletin board itself. Its public input is an
[`ElectionArtifacts`] struct of borrows; the bulletin-board client SDK
(Phase D) is the producer of that struct once it lands.

## What it checks

1. **Election parameters shape** — version, non-empty contest/trustee lists,
   `1 ≤ threshold ≤ trustee_count`.
2. **DKG transcript shape and decoding** — version, threshold match,
   per-trustee `coefficient_commitments` count, every commitment a valid
   ristretto255 point.
3. **Joint election public key reconstruction** — `Y = Σ_d A_{d,0}`.
4. **Per-trustee aggregated public share** —
   `pub_k = Σ_d Σ_j (k+1)^j · A_{d,j}`. Used to verify each partial-decryption
   Chaum-Pedersen proof.
5. **Per-ballot checks** — wire shape, CDS OR-proof against `{0, 1}` (v1:
   binary contests only), credential presentation under the supplied issuer
   public key, and the embedded `issuer_public_key` field matches the
   trust anchor.
6. **Nullifier uniqueness** — collects every ballot's
   `credential_presentation.nullifier.value` and fails on duplicates (the
   double-vote check).
7. **Per-trustee partial decryptions** — shape, share-point decode,
   Chaum-Pedersen verify against
   `bases (G, H = aggregate_pad_c)` and `statements (pub_k, share)`,
   plus the per-contest **threshold count** of distinct verified trustees.
8. **Homomorphic-sum tally** — for each contest, Lagrange-combine the
   first `threshold` verified partial decryptions, brute-force decode the
   resulting plaintext point in `[0, eligible_ballot_count]`, and compare
   against `tally.totals[c]`.

The report collects **every** check (pass or fail) and never short-circuits.
The bottom-line `overall` verdict flips to `Fail` iff any `Severity::Fatal`
finding has `status == Fail`.

## How to invoke

```rust,no_run
use saksi_auditor::{audit, ElectionArtifacts};

let report = audit(ElectionArtifacts {
    parameters,
    dkg_transcript,
    ballots,
    partial_decryptions,
    tally,
    binding_context: b"saksi-auditor-v1",
    issuer_public_key,
});

if report.passed() {
    // Tally is cryptographically sound under all v1 assumptions.
} else {
    for finding in &report.findings {
        // Inspect each `finding.check` / `finding.detail` pair to triage.
    }
}
```

## v1 assumptions

- **Binary contests only.** The CDS choice set is fixed to `{0, 1}`.
- **Single issuer per election.** The issuer public key is passed at the
  artifacts boundary so the auditor does not need a trust store.
- **Canonical partial-decryption layout.**
  `partial_decryptions.len() == contest_count * trustee_count`, with
  `partial_decryptions[c * trustee_count + t]` being the trustee
  `parameters.trustee_ids[t]` decrypting contest `c`. A mismatch is a
  shape failure.
