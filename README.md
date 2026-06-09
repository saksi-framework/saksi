# Saksi

[![CI](https://github.com/saksi-framework/saksi/actions/workflows/ci.yml/badge.svg)](https://github.com/saksi-framework/saksi/actions/workflows/ci.yml)

*A reusable cryptographic framework for end-to-end verifiable systems.*

## What is Saksi

Saksi is an open-source cryptographic application framework for building
end-to-end verifiable systems — voting and beyond. It composes ElGamal
threshold encryption with Pedersen distributed key generation, Chaum-Pedersen
and Cramer-Damgård-Schoenmakers zero-knowledge proofs, anonymous credentials,
commitment schemes, and a Hyperledger Fabric chaincode bulletin board operated
by mutually-independent trustee nodes.

The framework is designed so that no single party — and no proper subset of
trustees below the threshold — can decrypt individual records, forge entries, or
tamper with the recorded ledger. Saksi is the cryptographic foundation beneath
[BalotaChain](https://github.com/saksi-framework/balotachain), a verifiable
voting application, and is intended to outlive any single application as reusable
Philippine open-source cryptographic infrastructure.

> *Saksi* is Filipino for *witness*.

## Status

Saksi is early research-grade software under active development. Most components
are scaffolds; cryptographic primitives are landing incrementally. It has not
undergone a third-party security audit and is not production-ready.

## Packages

The framework is a Cargo workspace plus mirrored Go modules under `packages/`:

| Package | Language | Purpose |
| --- | --- | --- |
| `saksi-crypto` | Rust | Primitives over ristretto255 — ElGamal threshold encryption, Pedersen DKG, Chaum-Pedersen / CDS / Schnorr NIZKs, Pedersen commitments, Benaloh challenge. |
| `saksi-credentials` | Rust | Blind-signature anonymous credentials for unlinkable eligibility tokens. |
| `saksi-protocol` | Rust + Go | Canonical Protocol Buffers wire types, serialized identically by the Rust stack and the Go chaincode (golden vectors cross-check both). |
| `saksi-bulletin` | Go | Hyperledger Fabric chaincode, client SDK, and network definitions for the bulletin board. |
| `saksi-ffi-flutter` | Rust | `flutter_rust_bridge` surface exposing the core to a Flutter client. |
| `saksi-ffi-tauri` | Rust | Tauri command surface exposing the core to TypeScript desktop clients. |

## Consuming Saksi

Saksi is consumed as a Cargo `git` dependency (not a submodule). For example, a
Tauri app depends on the FFI surface:

```toml
[dependencies]
saksi-ffi-tauri = { git = "https://github.com/saksi-framework/saksi", package = "saksi-ffi-tauri" }
```

Flutter clients consume `saksi-ffi-flutter` via `flutter_rust_bridge`; Go callers
import `github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk`.

## Build

```sh
# Rust
cargo build --workspace
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings

# Go (per module)
for d in packages/saksi-protocol/go packages/saksi-bulletin/chaincode packages/saksi-bulletin/client-sdk; do
  (cd "$d" && gofmt -l . && go vet ./... && go test ./... && go build ./...)
done
```

## License

Saksi is released under the Apache License 2.0. See [LICENSE](LICENSE).

## Security

For responsible disclosure of security vulnerabilities, see
[SECURITY.md](SECURITY.md). Architectural decisions are recorded in
[`docs/adr/`](docs/adr/).
