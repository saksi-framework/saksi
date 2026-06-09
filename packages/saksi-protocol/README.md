# saksi-protocol

Canonical wire types and serialization shared between the Rust crypto stack, the Go chaincode, and the application clients.

**Status:** empty skeleton. Real types and serialization land in issue [#7](https://github.com/saksi-framework/balotachain/issues/7).

## Layout

```
saksi-protocol/
├── rust/      # Rust crate (member of the root Cargo workspace)
│   └── src/lib.rs
└── go/        # Go module mirroring the Rust types byte-for-byte
    └── go.mod
```

The two sides MUST agree on every wire format byte-for-byte. The recommended approach (decided in #7) is to define the schema once — most likely Protocol Buffers — and generate both Rust types (via `prost`) and Go types (via `protoc-gen-go`) from it. Hand-mirroring is an acceptable fallback if `prost` codegen friction outweighs the safety benefit; the decision is recorded in an ADR.

## What lives here

The following types cross the trust boundary between voter device, trustee device, admin device, auditor device, and chaincode:

- `Ballot`, `Ciphertext`, `EncryptionRandomness`
- `ChaumPedersenProof`, `CDSProof`, `SchnorrProof`
- `PedersenCommitment`
- `CredentialRequest`, `BlindSignature`, `Credential`, `CredentialPresentation`, `Nullifier`
- `DKGTranscript`, `TrusteeShare`, `TrusteePublicKey`, `JointPublicKey`
- `PartialDecryption`, `TallyResult`
- `ElectionParameters`, `RaceDefinition`, `OptionDefinition`

Every wire type carries a `version: u16` (or equivalent) so the protocol can evolve without breaking already-published ballots.
