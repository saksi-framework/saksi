# CLAUDE.md — Saksi framework working notes & handoff

Guidance for AI assistants (and humans) picking up work on the Saksi framework.
Read this first, then [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full build plan.

## What Saksi is

Saksi is a reusable, open-source cryptographic framework for **end-to-end
verifiable** systems (voting and beyond), on **ristretto255**, with a
**Hyperledger Fabric** bulletin board. It is consumed by the BalotaChain voting
app (separate repo `saksi-framework/balotachain`). Permissioned chain — **no
cryptocurrency, no gas, no wallets**; identity is X.509 MSP.

## Current state (as of this handoff)

**Implemented + tested:**
- `saksi-crypto`: ElGamal threshold encryption (homomorphic, constant-time,
  zeroizing) and Pedersen DKG (dealer commitments, complaints, partial decrypt,
  Lagrange combine / threshold decryption). `group.rs`, `transcript.rs` labels,
  `error.rs`.
- `saksi-protocol`: Rust `prost` types for all 14 wire messages; a **hand-written
  Go codec** (`go/wire.go`) covering 6 of 14 messages; golden vector
  `test-vectors/ballot-v1.hex` cross-checked Rust↔Go.
- `saksi-bulletin/chaincode`: Fabric chaincode `SubmitBallot` + `GetBallot`
  (on-chain checks: wire version, ciphertext shape, **nullifier uniqueness =
  no double vote**). Unit-tested with an in-memory fake stub.
- `saksi-bulletin/client-sdk`: `BulletinClient` (Submit/Get) over fabric-gateway,
  `Connect` (TLS/MSP), `cmd/submit-ballot`.
- `saksi-bulletin/network`: minimal Fabric `test-network` wrapper + runbook.
- FFI: real `keygen`/`encrypt` (flutter), real `partial_decrypt` (tauri).

**PROVEN LIVE:** a full ballot transaction ran end-to-end on a real Fabric
network (submit → endorse → order → commit → read-back identical; a replayed
ballot was rejected by the nullifier guard).

**Still STUB / missing** (the work in the roadmap): all NIZKs (Schnorr,
Chaum-Pedersen, CDS OR-proof, Pedersen commitment, Benaloh) — wired to Merlin;
`saksi-credentials` (blind issuance + presentation + nullifier) is empty; Go
codec for 8 messages; election-lifecycle chaincode/SDK (create/close election,
DKG publication, partial decryption, tally); the off-chain **auditor**; real FFI
crypto; reproducibility (`go.sum`) and `network.sh` fixes.

## The plan (decided)

Finish Saksi to a **runnable, audited end-to-end election**. Scope: framework
crypto-complete + full election lifecycle + an off-chain auditor, on the minimal
1-org dev network. Go wire types via **protoc-gen-go** (ADR-0003). 5-org network
and the Flutter/Tauri apps are out of scope (apps live in balotachain).
Full phased plan with dependencies + verification: **[`docs/ROADMAP.md`](docs/ROADMAP.md)**.

Recommended execution: bottom-up, one CI-green PR per piece, parallelize
independent Rust primitives via **git worktrees** (each agent/branch isolated),
integrate between waves. Wave 1 = Schnorr+Chaum-Pedersen foundation, Pedersen
commitment, Benaloh (all Rust, parallel). Then credentials, CDS, protoc-gen-go,
lifecycle, auditor, FFI, e2e.

## Environment to run/build (important — Windows + WSL specifics)

The earlier dev machine was Windows; the Fabric network only works under **WSL**
(Linux), from a **space-free path** (Fabric scripts break on paths with spaces,
and Windows `.exe` Fabric binaries mangle paths in git-bash — both avoided in WSL).

- **Rust**: `cargo` on Windows or WSL. `cargo test --workspace`, `cargo fmt
  --check`, `cargo clippy --workspace --all-targets -- -D warnings`.
- **Go**: install in WSL (e.g. go1.23.4 to `/usr/local/go`). Each module needs a
  committed `go.sum` for chaincode vendoring (`go mod tidy`).
- **Fabric** (WSL): Docker Desktop with **WSL integration enabled** for the
  distro; fetch `fabric-samples` + Linux binaries via the official
  `install-fabric.sh samples binary`; pull images (`docker` / `fabric-*` 2.5.x,
  `fabric-ca` 1.5.x).
- **Running the live election demo** (once built): copy `packages/` to a
  space-free WSL path (e.g. `~/saksi`), put `fabric-samples` as a sibling, then
  bring up the network with **cryptogen (no `-ca`)** to avoid needing
  `fabric-ca-client`, deploy the chaincode with a single-org endorsement policy
  for dev (`-ccep "OR('Org1MSP.peer')"`), then run the client. The current
  `network.sh` has known quirks (the combined `up createChannel` only creates the
  channel, not the network; default endorsement needs both orgs; `jq` required) —
  these are tracked as G2 repro fixes in the roadmap.

## Repo conventions

- **Merges:** squash-only (no rebase/merge-commit on the remote). One logical PR
  per piece; CI must be green.
- **CI:** Rust (fmt/clippy/test/build/audit) + Go (gofmt/vet/staticcheck/test/
  build) on ubuntu+macos. `govulncheck` is **advisory** (Fabric drags old
  transitive deps not reachable from first-party code). Go toolchain pinned to a
  patched line in `.github/workflows/ci.yml`.
- **Commits:** Conventional Commits.
- **Decisions:** Architecture Decision Records in `docs/adr/`. Locked invariants:
  ristretto255 everywhere; Merlin Fiat-Shamir (ADR-0004) with the `saksi.*`
  transcript labels; Protocol Buffers wire format (ADR-0003); hybrid verification
  split (on-chain: credential sig + nullifier + shape; off-chain: heavy NIZKs).
- **Crypto correctness bar:** every NIZK needs completeness + **soundness
  (tampered proofs must fail)** + transcript-binding tests. Not optional.
