# ADR-0007: On-chain CDS Ballot-Well-Formedness Verification

## Status

Accepted (supersedes the CDS portion of [ADR-0005](0005-hybrid-verification-split.md))

## Context

[ADR-0005](0005-hybrid-verification-split.md) kept the heavy zero-knowledge
proofs off-chain: the chaincode verified the credential signature + nullifier
uniqueness + ciphertext shape, and an off-chain auditor verified the CDS
OR-proof of ballot well-formedness.

The BalotaChain thesis (the evaluation study this work targets) specifies a
different design: the chaincode verifies the credential, the nullifier, **and
the validity proof** at submission — only ballots that pass all three gates are
committed (Figure 3.3, §Chaincode). The paper's throughput model is built on
that assumption (on-chain proof verification is the dominant per-ballot cost).
Reproducing the paper's numbers, and matching its stated design, requires moving
CDS verification on-chain.

Two problems had to be resolved to make on-chain CDS verification correct under
Fabric's execute-order-validate model:

1. **The election public key was not on-chain.** The chaincode stored the raw
   DKG transcript but never derived the joint ElGamal key the CDS proof is
   verified against.
2. **The CDS Fiat-Shamir context bound the ballot's positional serial**
   (its index in the published list). Chaincode runs at *endorsement*, before
   ordering — it cannot know a ballot's final commit position, so a
   serial-based binding is unreconstructible on-chain.

## Decision

Verify the CDS OR-proof of ballot well-formedness **on-chain**, at submission,
for every contest ciphertext. `SubmitBallot`'s gate becomes: wire version +
lifecycle state + ciphertext shape + **credential signature** + **nullifier
uniqueness** + **CDS validity proof**.

To make this well-defined:

- **Rebind the CDS context to be serial-free and endorsement-reconstructible.**
  The context is now the canonical
  `binding_context(election_id, contest_id, nullifier)` — length-prefixed
  `election_id || contest_id || nullifier` (`saksi_crypto::nizk::cds::binding_context`).
  All three fields are available at endorsement (`election_id` and `nullifier`
  travel in the ballot; `contest_id` comes from the on-chain election
  parameters). The nullifier is a per-ballot unique tag that serves the same
  anti-transplantation role the positional serial did, and it is
  order-independent — so verification stays valid under concurrent submission
  (required by the Phase 2 benchmark harness).

- **Derive the joint election public key on-chain from the published DKG
  transcript** as the sum of each trustee's constant-term coefficient
  commitment (`deriveElectionPublicKey`), mirroring the Rust DKG combine. The
  published transcript already contains only qualified commitments, so no
  complaint filtering is needed on-chain. `SubmitBallot` therefore requires a
  published DKG transcript.

- **Endorsement determinism.** The Go verifier (`cdsverify`) decodes every
  point/scalar with canonical-only decoders (rejects non-canonical encodings
  identically to Rust), returns errors on every failure path (never panics
  conditionally), and has no map-iteration-order dependence. Two endorsing peers
  reach the same verdict. Byte-agreement with the Rust prover/verifier is pinned
  by a cross-language golden vector
  (`saksi-protocol/test-vectors/cds-proof-v1.hex`).

The off-chain auditor still re-verifies the CDS proof (and the heavier NIZKs
that remain off-chain per ADR-0005: the presentation Chaum-Pedersen and the
per-trustee Chaum-Pedersen) using the **same** binding, so on-chain and
off-chain agree.

## Consequences

- The chaincode gains a ristretto255 + Merlin CDS verification surface
  (`cdsverify`) and a DKG→pubkey derivation (`electionpk.go`), both byte-exact
  with Rust and pinned by golden vectors.
- Submission cost rises (CDS verification runs at endorsement on every endorsing
  peer) — this is the intended, paper-modelled cost.
- A ballot can only be submitted after its election's DKG transcript is
  published.
- The CDS binding changed from the auditor's positional-serial context to the
  nullifier context; the auditor and fixture prover were updated in lockstep.
- **Not yet aligned:** the Flutter FFI prover (`generate_cds_proof_v2`) still
  binds `contest_id` only. It must adopt the canonical binding before the voter
  app submits real ballots to the chaincode (deferred with the rest of the app
  wiring, Phase 7).

## What stays off-chain (unchanged from ADR-0005)

The credential presentation Chaum-Pedersen NIZK, the per-trustee Chaum-Pedersen
decryption proofs, and the homomorphic-sum-vs-tally check remain the auditor's
job. Only the CDS well-formedness proof moves on-chain.
