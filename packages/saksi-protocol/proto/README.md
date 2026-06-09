# Protocol Schema

`tala/protocol/v1/wire.proto` is the canonical schema for bytes that cross a
trust boundary between BalotaChain clients, Saksi cryptographic code, and the
bulletin board.

Rust bindings are generated with `prost`. Go bindings should be generated with
`protoc-gen-go` from the same schema when the Fabric packages start consuming
these messages directly.

