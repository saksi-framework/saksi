# Roadmap — Finishing Saksi to a verifiable end-to-end election

Status: planning → execution. See [`../CLAUDE.md`](../CLAUDE.md) for current state
and environment setup. This document is the build plan to take Saksi from its
current core (ElGamal + DKG + bulletin board with `SubmitBallot`/`GetBallot`,
proven live) to a **complete framework that runs and cryptographically audits a
whole election**: DKG → encrypted votes with validity proofs → bulletin board →
close → threshold decryption with proofs → tally → independent audit.

## Scope (decided)

- **In:** framework crypto-complete (all NIZKs + credentials), full election
  lifecycle (chaincode + SDK), an off-chain **auditor** crate, and a runnable
  end-to-end election on the minimal 1-org dev network. Go wire types via
  **protoc-gen-go** (ADR-0003).
- **Out:** the 5-org production network (additive later); the Flutter/Tauri apps
  (they live in the `balotachain` repo).

## Locked invariants

ristretto255 everywhere; Merlin Fiat-Shamir (ADR-0004) with the `saksi.*`
transcript labels; Protocol Buffers wire format (ADR-0003); hybrid verification
split (on-chain: credential sig + nullifier + shape; off-chain: heavy NIZKs).
Keep every commit green; keep the live tx working.

## Delivery model

Bottom-up, dependency-ordered, **one logical PR per piece, each CI-green**
(squash merges). Rust verified locally; Go verified in WSL + CI; the e2e election
verified on the live network. Independent Rust primitives parallelize cleanly via
**git worktrees** (one isolated checkout/branch per agent); integrate between waves.

---

## Phase A — Crypto primitives (`saksi-crypto`)

All NIZKs wire into Merlin via `src/transcript.rs` (the `saksi.*` labels are
currently defined but orphaned). Each proof needs completeness + **soundness
(tamper)** + transcript-binding tests. Reuse `group.rs` and `error.rs`.

- **A1 `nizk/schnorr.rs`** — proof of knowledge of a discrete log `P = x·B`.
- **A2 `nizk/chaum_pedersen.rs`** — equality of two discrete logs
  (`A = x·G ∧ B = x·H`); proves correct threshold partial decryption. Maps to the
  wire `ChaumPedersenProof`.
- **A3 `commitment.rs`** — Pedersen commitment `m·G + r·H` (H from hash-to-point),
  open/verify, homomorphic add.
- **A4 `nizk/cds.rs`** — Cramer-Damgård-Schoenmakers OR-proof: a ciphertext
  encrypts a value in a small set (e.g. {0,1}) without revealing which → ballot
  well-formedness. Builds on A1/A2; emits the wire `CDSProof`/`CDSProofBranch`.
- **A5 `benaloh.rs`** — cast-or-challenge (cast-as-intended): commit to encryption
  randomness; a challenge reveals it to re-verify, else cast.

## Phase B — Anonymous credentials (`saksi-credentials`)

Blind-Schnorr style on ristretto255 (no pairings):
- **B1** blind issuance (voter blinds → issuer signs → voter unblinds).
- **B2** presentation NIZK (unlinkable proof of a valid credential) + a
  **deterministic nullifier** = PRF(credential, election_id). Emits the wire
  `CredentialPresentation` + `Nullifier`. Reuses A1/A2.

## Phase C — Protocol: protoc-gen-go (ADR-0003) — parallel with A/B

Replace the hand-written `go/wire.go` with generated Go types: add `protoc` +
`protoc-gen-go` to a generate step + CI; generate all 14 messages into
`go/saksiprotocolv1/`; update Go consumers (chaincode, `wire_vector_test.go`);
delete the hand codec; keep the golden cross-check (Rust prost bytes == Go bytes);
**commit `go.sum`**. Unblocks Go access to `DKGTranscript`, `PartialDecryption`,
`TallyResult`, `ElectionParameters`.

## Phase D — Election lifecycle (chaincode + SDK)

Extend `saksi-bulletin/chaincode/contract.go` (keep `SubmitBallot`/`GetBallot`):
- **D1** `CreateElection`/`GetElection` (`ElectionParameters`; open state).
- **D2** `PublishDKGTranscript`/`GetDKGTranscript`.
- **D3** `CloseElection` + gate `SubmitBallot` to open elections.
- **D4** `SubmitPartialDecryption` (w/ Chaum-Pedersen proof; on-chain: shape +
  trustee membership + closed) and `PublishTally` + queries.
- **D5** on-chain **credential-signature verification** — needs ristretto255 in Go
  (e.g. `github.com/gtank/ristretto255`). **Open sub-decision:** do on-chain (honors
  the hybrid split) vs. keep off-chain in the auditor for now. Confirm before adding
  the Go crypto dep.
- **SDK**: extend `client-sdk` + `cmd/` for every new tx + an election driver.
  Commit `go.sum` for chaincode + client-sdk.

## Phase E — Off-chain auditor (`saksi-auditor`, new Rust crate)

The *counted-as-recorded* keystone. Input: election params + all on-chain
artifacts. Verifies, returning a structured pass/fail report:
- every ballot's **CDS** proof (A4);
- **credential presentation** + **nullifier uniqueness** (B2);
- DKG transcript commitment consistency;
- each trustee partial decryption's **Chaum-Pedersen** proof (A2);
- **homomorphic sum** of ciphertexts == published tally (reuses
  `dkg::combine_partial_decryptions`).
New workspace member `packages/saksi-auditor/`; tested against a full synthetic
election fixture.

## Phase F — FFI: replace placeholder digests with real crypto

- `saksi-ffi-flutter/src/api.rs`: real `generate_cds_proof`,
  `perform_benaloh_challenge`, `derive_nullifier`, `present_credential`.
- `saksi-ffi-tauri/src/commands.rs`: real DKG transcript + partial decryption with
  Chaum-Pedersen proof, encoding `PartialDecryption`.

## Phase G — End-to-end election demo + repro/governance

- **G1 capstone**: a driver running a full election on the live minimal network —
  DKG → `CreateElection` → `PublishDKGTranscript` → encrypt N votes (CDS +
  credential + nullifier) → `SubmitBallot`×N → `CloseElection` →
  `SubmitPartialDecryption`×threshold → `PublishTally` → **run `saksi-auditor`** →
  all checks pass.
- **G2 repro/governance**: fix `network.sh` (split `up`/`createChannel`; default
  Org1 endorsement for dev; document the `jq` prereq); a protocol-spec +
  threat-model doc; ADRs for the hybrid-verification split and the election lifecycle.

---

## Sequencing & dependencies

```
A (crypto NIZKs) ─┬─> E (auditor)      C (protoc-gen-go) ──> D (lifecycle chaincode+SDK)
B (credentials) ──┘   F (FFI)                                        │
        └──────────────┴───────────────> G (e2e election + audit) <─┘
```
A & C interleave (Rust vs Go). B follows A1/A2. D follows C. E/F follow A+B. G last.

## Verification (per phase)

- **Rust (A,B,E,F):** `cargo test --workspace` (completeness + soundness/tamper +
  transcript-binding), `cargo fmt --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`.
- **Go (C,D):** `go build/test/vet` per module (WSL + CI); golden vector
  cross-check Rust↔Go; chaincode unit tests with the in-memory fake stub;
  committed `go.sum`.
- **E2E (G):** full election on the live WSL Fabric network ends with the auditor
  reporting **all checks pass**; a replayed nullifier still rejected.

## Risks

- NIZK correctness is the crux — soundness tests are mandatory.
- protoc-gen-go must keep the live chaincode tx byte-compatible — verify on the
  running network after the C→D refactor.
- Large effort; deliver incrementally with green checkpoints.
