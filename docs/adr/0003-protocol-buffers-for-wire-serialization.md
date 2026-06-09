# ADR-0003: Protocol Buffers for Wire Serialization

## Status

Accepted

## Context

BalotaChain and Saksi pass election parameters, ballots, ciphertexts, proofs,
credential presentations, DKG transcripts, partial decryptions, and tally
results across trust boundaries. The Rust crypto implementation and Go bulletin
board code must agree on these bytes exactly.

Hand-mirrored types in multiple languages are easy to drift as the protocol
evolves. A schema-first format gives each language a shared source of truth and
keeps protocol upgrades visible in versioned fields.

## Decision

BalotaChain will use Protocol Buffers as the canonical wire schema. Rust types
are generated with `prost`, and Go types should be generated from the same
schema with `protoc-gen-go` when Go packages consume protocol messages
directly.

Every top-level wire message includes a `version` field. Transcript-based
hashing uses domain-separated helpers in `saksi-protocol` so NIZK protocols can
share a consistent convention.

## Consequences

Rust and Go implementations can be checked against shared test vectors generated
from a single schema.

Protocol changes require schema updates and careful field-number management.
Fields must not be renumbered once published; future incompatible changes should
use a new message version.

