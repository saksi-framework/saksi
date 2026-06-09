# ADR-0002: Rename the framework to Saksi and split it into its own repository

## Status

Accepted

## Context

This repository began as a single monorepo, `tala-blockchain/balotachain`,
holding two distinct things:

- **BalotaChain** — an end-to-end verifiable cryptographic voting *application*
  (an undergraduate thesis at Western Mindanao State University), whose role
  clients live under `apps/{voter,trustee,admin,auditor}`.
- The reusable cryptographic *framework* underneath it, which lived under
  `packages/tala-*` and was named **Tala**.

The initial architecture record
(`docs/architecture/2026-05-20-initial-architecture-decisions.md`) committed to
the framework outliving BalotaChain as reusable Philippine open-source
cryptographic infrastructure. Two facts about that record have since changed and
need a durable decision:

1. The framework's intended public name is **Saksi**, not Tala. Everything on
   disk still said `tala-*` (crate names, directories, Go module paths, the
   GitHub org, proto package, transcript labels, and prose).
2. If the framework is meant to be consumed independently by systems other than
   BalotaChain, keeping it inside the application monorepo couples its release,
   versioning, and issue tracking to the thesis application.

A complication is that some `tala` strings are **load-bearing on cryptographic
wire identity** — Merlin transcript domain-separation labels, the protobuf
package `tala.protocol.v1` and its directory, the domain-hash prefix
`b"tala-protocol-v1"`, and the golden test vector `ballot-v1.hex`. Renaming
those changes hashed/serialized bytes and invalidates fixtures, so they cannot
be treated as a blind find/replace.

## Decision

1. **Rename the framework from Tala to Saksi.** The mechanical identity rename
   (crate and library names, package directories, Rust `use` paths, Go module
   paths, the GitHub organization `tala-blockchain` → `saksi-framework`, CI
   configuration, ownership, and all prose) is performed first, in-place on a
   branch in this repository, keeping the build green at every commit.

2. **Defer the wire-identity migration.** The load-bearing tokens
   (transcript labels including the FFI labels, the proto package
   `tala.protocol.v1` and its directory, and the domain-hash prefix
   `b"tala-protocol-v1"`) are migrated to `saksi.*` in a separate, clearly
   marked, breaking change that regenerates `ballot-v1.hex` and proves the new
   vectors round-trip on both the Rust and Go sides. Until then these tokens
   remain `tala.*` so fixtures stay valid.

3. **Split into two repositories under the new `saksi-framework` GitHub org:**
   - `github.com/saksi-framework/saksi` — the standalone framework
     (`saksi-crypto`, `saksi-credentials`, `saksi-protocol`, `saksi-bulletin`,
     `saksi-ffi-flutter`, `saksi-ffi-tauri`, plus proto, test vectors, and the
     Go modules).
   - `github.com/saksi-framework/balotachain` — the application repository.

   The rename lands and merges in the existing repository first; the framework
   is extracted afterward. Because the in-place rename already adopts the final
   Saksi identities (Go module paths and Cargo `repository` URL point at
   `saksi-framework/saksi`), the extraction is a file move with no further
   import rewrites.

4. **BalotaChain consumes Saksi as a Cargo `git` dependency**, not a git
   submodule. Tauri desktop apps depend on `saksi-ffi-tauri` via a Cargo `git`
   dependency; the Flutter voter app consumes `saksi-ffi-flutter` through
   `flutter_rust_bridge`; Go callers import
   `github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk`.

## Consequences

- Saksi can be versioned, released, and issue-tracked independently of the
  BalotaChain thesis application, supporting its goal of outliving it.
- Separating the mechanical rename from the wire-identity migration keeps every
  commit building and every cryptographic fixture valid until the bytes are
  deliberately, verifiably changed.
- After extraction, BalotaChain temporarily has no compilable Rust or Go (its
  app clients are not yet scaffolded). Its empty Cargo workspace is removed and
  reintroduced when the Tauri app crates land, each declaring the Saksi `git`
  dependency.
- A Cargo `git` dependency pins Saksi by revision without publishing to
  crates.io, at the cost of consumers needing network access to the Saksi repo
  and the framework repo having to exist and be pushed before any consumer
  builds against it.
- This ADR supersedes the framework-naming (Tala) and single-repository-layout
  portions of
  `docs/architecture/2026-05-20-initial-architecture-decisions.md`; that record
  is left intact as history, per the ADR process.
