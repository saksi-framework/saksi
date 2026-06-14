// Package saksiprotocolv1 contains the canonical Saksi wire types, generated
// from proto/saksi/protocol/v1/wire.proto by protoc-gen-go (ADR-0003).
//
// Regenerate with `./scripts/codegen.sh` (runs protoc in a pinned container);
// do not edit wire.pb.go by hand. The Rust `prost` types in ../../rust and these
// Go types serialize byte-for-byte identically — wire_golden_test.go pins that
// against ../../test-vectors/ballot-v1.hex.
package saksiprotocolv1

// WireVersion is the current wire-format version. Every top-level message that
// crosses the trust boundary carries a version field set to this constant.
const WireVersion uint32 = 1
