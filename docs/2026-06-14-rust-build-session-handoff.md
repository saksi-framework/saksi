# Saksi Rust build session — handoff (2026-06-14)

Status snapshot at the end of the session that took Saksi from "framework
core + stubs" to "all Rust phases complete, real proofs end-to-end". The
remaining roadmap work is Go-only and waits on a WSL environment with the
Go toolchain available.

## What landed (10 PRs, all squash-merged to `main`)

| PR | Roadmap phase | Summary |
|---|---|---|
| [#11](https://github.com/saksi-framework/saksi/pull/11) | **A1** | Schnorr NIZK over ristretto255 — Sigma protocol for proof-of-knowledge of a discrete log, Merlin Fiat-Shamir bound to `TRANSCRIPT_LABEL_SCHNORR`, canonical 64-byte serialization. |
| [#12](https://github.com/saksi-framework/saksi/pull/12) | **A2** | Chaum-Pedersen NIZK — equality of two discrete logs `A = x·G ∧ B = x·H`, maps to wire `ChaumPedersenProof`. The proof trustees attach to `PartialDecryption`. |
| [#13](https://github.com/saksi-framework/saksi/pull/13) | **A5** | Benaloh cast-or-challenge — voter-side cast-as-intended; `commit()` binds `(ciphertext, plaintext_label, context, public_key)` into a Merlin digest, `cast()` discards randomness, `challenge()` reveals it for re-encryption verification. |
| [#14](https://github.com/saksi-framework/saksi/pull/14) | **A3** | Pedersen commitment — `C = m·G + r·H`, `H` hashed to point from `b"saksi.commitment.pedersen.H.v1"`, homomorphic add, deterministic test vector pins the `H` derivation. |
| [#15](https://github.com/saksi-framework/saksi/pull/15) | **A4** | CDS OR-proof — Cramer-Damgård-Schoenmakers ballot well-formedness, Chaum-Pedersen on the honest branch + simulation on false branches, Fiat-Shamir binds `Σ c_i` to `TRANSCRIPT_LABEL_CDS + (pk, ciphertext, choice_set, context, branch commitments)`. |
| [#16](https://github.com/saksi-framework/saksi/pull/16) | **B** | Anonymous credentials — Pointcheval-Stern blind-Schnorr issuance, presentation NIZK (Chaum-Pedersen tying `C = s_cred·G` to `Nullifier = s_cred·H_e`), deterministic PRF nullifier. Same `(s_cred, election_id)` → same nullifier (double-vote detection); different election → independent nullifier (cross-election unlinkability). |
| [#17](https://github.com/saksi-framework/saksi/pull/17) | **E** | New `saksi-auditor` crate — `audit(ElectionArtifacts) -> AuditReport` runs every check (parameters shape, DKG transcript, per-ballot CDS + credential presentation, nullifier uniqueness, per-trustee Chaum-Pedersen, threshold count, homomorphic-sum-equals-tally with Lagrange combine + brute-force discrete-log decode) without short-circuiting. |
| [#18](https://github.com/saksi-framework/saksi/pull/18) | **F** | FFI v2 — `saksi-ffi-flutter` and `saksi-ffi-tauri` now expose `*_v2` entry points that emit real proofs instead of SHA-256-of-inputs handles. v1 stubs kept and marked `#[deprecated]` so BalotaChain can migrate without breakage. |
| [#19](https://github.com/saksi-framework/saksi/pull/19) | **F follow-up** | `Credential::from_parts(s_cred, R', s_sig)` and `pub presentation_context` exposed from `saksi-credentials` so external builders (the FFI bridge) can reuse the canonical context bytes instead of duplicating them. |
| [#20](https://github.com/saksi-framework/saksi/pull/20) | **F cleanup** | `present_credential_v2` rewritten to call `Credential::from_parts` + `Credential::present`. Removes the byte-format duplication seam flagged in #18. −41 net lines. |

## Test totals in `main`

```
saksi-crypto         84
saksi-credentials    25
saksi-auditor        13
saksi-ffi-flutter    11
saksi-ffi-tauri       7
saksi-protocol        3
                ──────
total               143
```

Every NIZK has the mandated completeness + tampered-soundness + transcript-binding tests. The auditor has a happy-path fixture (5 trustees, threshold 3, 2 contests, 6 ballots) plus 12 mutant cases that each must produce overall `Fail` with a named finding.

## What's left in the roadmap

- **C — `protoc-gen-go`** (ADR-0003). Replace the hand-written `go/wire.go` with generated Go types for all 14 messages. Go-only. **Blocked on a Go toolchain** — the mac dev box doesn't have Go. Pick up on WSL (`install-fabric.sh` already sets that up).
- **D — Election lifecycle**: extend `saksi-bulletin/chaincode` and `client-sdk` with `CreateElection`/`PublishDKGTranscript`/`CloseElection`/`SubmitPartialDecryption`/`PublishTally`. **Blocked on C** — chaincode needs the generated Go types.
- **G — End-to-end demo + repro/governance**: full election driven on the live minimal Fabric network, audited by `saksi-auditor`, plus the `network.sh` fixes from the roadmap's G2.

The roadmap dependency graph is unchanged:

```
A (crypto NIZKs) ─┬─> E (auditor) ✓      C (protoc-gen-go) ──> D (lifecycle chaincode+SDK)
B (credentials) ──┘   F (FFI) ✓                                       │
        └──────────────┴───────────────> G (e2e election + audit) <─┘
```

Where ✓ = landed this session.

## Architectural flags surfaced for Phase D

Two design questions were uncovered by the auditor and FFI work. Phase D should decide before the chaincode + SDK ossify.

1. **Wire `PartialDecryption` has no `contest_id`.** The current schema is
   `{ version, trustee_id, share, proof }`. The auditor in PR #17 assumes a
   canonical layout for the on-chain partial decryptions: `contest_count *
   trustee_count`, contest-major, in the input order. If Phase D wants
   per-contest decryptions on the wire, the schema needs a `contest_id`
   field on `PartialDecryption`; otherwise the canonical-layout assumption
   needs to be encoded in the chaincode-side queries.
2. **Auditor reimplements Lagrange-at-zero from wire types.** `dkg::combine_partial_decryptions`
   exists in `saksi-crypto`, but it takes in-memory types
   (`(usize, RistrettoPoint)` shares + `Ciphertext` with `RistrettoPoint`
   fields). The auditor takes wire types (`Vec<u8>` shares + wire `Ciphertext`).
   The reimplementation in `saksi-auditor/src/decryption.rs::lagrange_coefficient_at_zero`
   is a deliberate decoupling — the auditor can verify a published election
   without depending on in-memory crypto types — but Phase D could add a
   thin wire→in-memory shim if that's preferable.

## Known FFI debt

The Tauri side's `partial_decrypt_v2` does the same construct-and-verify
pattern that the Flutter `present_credential_v2` had until #20 cleaned it
up. It does **not** reuse a `Credential`-like type because trustees don't
have a credentials-style API yet. If Phase F gets extended with a
`saksi-trustee` helper crate (analogous to `saksi-credentials`), that's the
natural place to close the remaining seam.

## Workflow notes (for whoever picks this up)

Worked via parallel general-purpose subagents on isolated `git worktree`
checkouts, one branch per phase unit. Pattern that worked:

1. Create one worktree per independent piece off the latest `origin/main`.
2. Brief each subagent with: the worktree path, the file(s) it owns, the
   wire shape it maps to, the existing helpers it can reuse, the test
   matrix (completeness + soundness on every field + transcript binding),
   and the explicit `cargo fmt --check && cargo clippy --workspace
   --all-targets -- -D warnings && cargo test --workspace` bar before
   pushing. Each subagent commits, pushes, opens a PR via `gh pr create`,
   and reports the PR URL.
3. Once CI is green, squash-merge with `--delete-branch`, remove the
   worktree, pull `main` in the canonical checkout, then start the next
   wave.

Wave sequencing this session:
- **Wave 1** (4 parallel): A1 Schnorr, A2 Chaum-Pedersen, A3 Pedersen
  commitment, A5 Benaloh — all independent.
- **Wave 2** (2 parallel): A4 CDS + B credentials — both depend on A1+A2
  being in `main`.
- **Wave 3** (2 parallel): E auditor + F FFI v2 — both depend on A+B.
- **Tail** (sequential): F follow-up (credentials API), F cleanup (FFI
  deduplication) — each touches files the previous PR also touched.

Nothing in the roadmap forces this exact wave shape; it just minimized
cross-PR conflicts. The only Cargo.lock collision risk was A3 (added
`sha2` to `saksi-crypto`); merging A3 last in Wave 1 sidestepped it.
