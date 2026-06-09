// Package saksiprotocol mirrors the Rust saksi-protocol crate so that the Go
// chaincode and Fabric client SDK serialize the same wire types byte-for-byte.
// The schema is defined once in ../proto/tala/protocol/v1/wire.proto and
// compiled here via protoc-gen-go (ADR-0003). External test code uses package
// name saksiprotocol_test against this package.
package saksiprotocol
