# CLAUDE.md — Saksi framework working notes & handoff

Guidance for AI assistants (and humans) picking up work on the Saksi framework.
Read this first, then [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full build plan.

## What Saksi is

Saksi is a reusable, open-source cryptographic framework for **end-to-end
verifiable** systems (voting and beyond), on **ristretto255**, with a
**Hyperledger Fabric** bulletin board. It is consumed by the BalotaChain voting
app (separate repo `saksi-framework/balotachain`). Permissioned chain — **no
cryptocurrency, no gas, no wallets**; identity is X.509 MSP.

## Current state (2026-06-14, end of lifecycle + parity session)

Phases **A–F complete**, the full **election lifecycle (D1–D5) complete**, and
**G2 governance docs complete**. A parity check against the locked architecture
confirmed the framework is in line; its one real deviation (on-chain
credential-signature verification) is now **fixed (D5)**. Remaining: **G1** (live
e2e election + audit) and the `network.sh` repro fixes. Spec + threat model live
in [`spec/`](spec/); see [ROADMAP](docs/ROADMAP.md) Progress section.

**Implemented + tested (143 tests in `main`):**
- `saksi-crypto` (84 tests): ElGamal threshold encryption, Pedersen DKG,
  **all five NIZKs landed this session** — Schnorr (A1), Chaum-Pedersen
  (A2), Pedersen commitment (A3), CDS OR-proof (A4), Benaloh
  cast-or-challenge (A5). Each NIZK has completeness + tamper-soundness
  on every field + transcript binding.
- `saksi-credentials` (25 tests): Pointcheval-Stern blind-Schnorr
  issuance, presentation NIZK (Chaum-Pedersen tying `C = s_cred·G` to
  `nullifier = s_cred·H_e`), deterministic PRF nullifier. `Credential::from_parts`
  and `pub presentation_context` exposed for external builders.
- `saksi-auditor` (13 tests): off-chain auditor crate; `audit(ElectionArtifacts)
  -> AuditReport` runs every check (DKG, per-ballot CDS + credential
  presentation, nullifier uniqueness, per-trustee Chaum-Pedersen, threshold
  count, homomorphic sum vs published tally) without short-circuiting.
- `saksi-protocol`: Rust `prost` types for all 14 wire messages; **Go types
  generated via protoc-gen-go** (Phase C), Go↔Rust byte-identity pinned by a
  golden vector. `PartialDecryption` carries `contest_id`.
- `saksi-bulletin/chaincode`: full election lifecycle — `CreateElection`,
  `PublishDKGTranscript`, `SubmitBallot`, `CloseElection`,
  `SubmitPartialDecryption`, `PublishTally` (+ queries). On-chain checks:
  wire version, lifecycle gating, ciphertext shape, **on-chain credential
  Schnorr-signature verification** (`credverify`, byte-exact with Rust),
  **nullifier uniqueness**. Unit-tested with an in-memory fake stub.
- `saksi-bulletin/client-sdk`: `BulletinClient` over fabric-gateway,
  `Connect` (TLS/MSP), `cmd/submit-ballot`.
- `saksi-bulletin/network`: minimal Fabric `test-network` wrapper + runbook.
- `saksi-ffi-flutter` (11 tests) and `saksi-ffi-tauri` (7 tests): real-crypto
  `*_v2` entry points (real CDS proof, real Benaloh challenge, real PRF
  nullifier, real credential presentation, real Chaum-Pedersen on partial
  decryption). v1 SHA-256 stubs kept and marked `#[deprecated]` so
  BalotaChain can migrate softly.

**PROVEN LIVE:** a full ballot transaction ran end-to-end on a real Fabric
network (submit → endorse → order → commit → read-back identical; a replayed
ballot was rejected by the nullifier guard).

**Done — full demo runs live:**
- **G1 capstone** — the whole election cycle runs end-to-end on the live Fabric
  test-network (DKG → `CreateElection` → `PublishDKGTranscript` →
  `SubmitBallot`×N passing the on-chain credential-signature check →
  `CloseElection` → `SubmitPartialDecryption`×t → `PublishTally` →
  `saksi-auditor` → `AUDIT: PASS`). Driven by `packages/saksi-demo` (bundle
  generator + auditor CLI), `client-sdk/cmd/saksi-console` (live lifecycle
  driver), and `tools/saksi-demo.sh` (top-level menu). Setup for Windows + macOS:
  [`DEMO.md`](DEMO.md).
- **`network.sh` repro fixes** — cryptogen (no `-ca`), single-org Org1
  endorsement for dev.

**Resolved (were Phase-D flags):**
1. `PartialDecryption` now carries `contest_id`; the auditor routes shares by id
   (no positional layout). See [ADR-0006](docs/adr/0006-election-lifecycle.md).
2. Auditor's wire-side Lagrange-at-zero is intentionally decoupled from
   `dkg::combine_partial_decryptions`; left as-is.

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
