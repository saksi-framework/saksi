# Contributing to Saksi

Thanks for helping with Saksi. This project is still early research-grade
cryptographic software, so contributions should make the codebase clearer,
safer, and easier to review.

## Goals

- Grow Saksi as reusable open-source cryptographic infrastructure for
  end-to-end verifiable systems.
- Keep protocol, implementation, and operational decisions reviewable.
- Favor correctness, auditability, and explicit tradeoffs over speed.

## Non-Goals

- Do not treat the current codebase as production-ready.
- Do not merge cryptographic changes without clear references, tests, and
  review context.

## Prerequisites

Use stable toolchains unless a file in the repository pins a narrower version.

- **Rust** stable, with the minimum supported version documented in
  `rust-toolchain.toml` (currently stable, 1.78+). Used by every crate in the
  Cargo workspace under `packages/saksi-*`.
- **Go** matching the `go` directive in the bulletin and protocol modules
  (currently 1.22). Used inside `packages/saksi-bulletin/` and
  `packages/saksi-protocol/go/`.
- **Git** and the **GitHub CLI** for the branch and pull request workflow.

## Test Commands

Rust (all crates in the Cargo workspace):

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

Go (per Go module — there are three):

```sh
for d in packages/saksi-protocol/go packages/saksi-bulletin/chaincode packages/saksi-bulletin/client-sdk; do
  (cd "$d" && gofmt -l . && go vet ./... && go test ./... && go build ./...)
done
```

## Wire Identity

Some strings are load-bearing on cryptographic wire identity: Merlin transcript
domain-separation labels, the Protocol Buffers package and its directory, the
domain-hash prefix in `saksi-protocol`, and the golden vectors under
`packages/saksi-protocol/test-vectors/`. Changing any of these alters
hashed/serialized bytes and invalidates fixtures. Treat such changes as
deliberate, breaking, and accompanied by regenerated, cross-checked Rust + Go
vectors — never as an incidental rename.

## Style

- Follow `.editorconfig` for whitespace and line endings.
- Use `cargo fmt` for Rust formatting and `gofmt` for Go formatting.
- Keep public cryptographic APIs small, documented, and testable.

## Commits

Use Conventional Commits:

```text
feat(crypto): add ElGamal encryption on ristretto255
fix(ci): run cargo clippy on all targets
docs(adr): record workspace layout decision
```

Common scopes include `repo`, `ci`, `docs`, `crypto`, `credentials`,
`bulletin`, `chaincode`, `protocol`, `ffi`.

## Branch and Pull Request Workflow

1. Create a topic branch from `main`.
2. Keep each pull request focused on one coherent change.
3. Link related issues and ADRs in the pull request description.
4. Run the relevant checks before requesting review.
5. Include cryptographic or security notes when the change touches protocols,
   primitives, credentials, trustees, bulletin board behavior, or threat models.
6. Wait for review and required status checks before merge.

## Architectural Changes

Architectural decisions are captured as ADRs in `docs/adr/`. Write or update an
ADR when a change affects long-term structure, protocol choices, security
assumptions, major dependencies, or operational behavior. Start from
`docs/adr/template.md` and follow the process in `docs/adr/README.md`.

## Security Reports

Do not open public issues for vulnerabilities. Follow the private disclosure
process in [SECURITY.md](SECURITY.md).
