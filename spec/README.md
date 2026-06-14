# Saksi specification

Reference documents for the Saksi protocol (v1, `WIRE_VERSION = 1`).

- [protocol.md](protocol.md) — the cryptographic setting, primitives, wire
  messages, the on-chain credential-signature check, the credential presentation,
  the end-to-end election flow, and the three verifiability properties. Byte-level
  details needed for cross-implementation are marked **stable**.
- [threat-model.md](threat-model.md) — assets, parties and trust assumptions,
  adversary capabilities, mitigations (on-chain vs off-chain), and the known
  limitations of the v1 demo.

Governing decisions live in [`../docs/adr/`](../docs/adr/): ADR-0003 (wire
format), ADR-0004 (Merlin Fiat-Shamir), ADR-0005 (hybrid verification split),
ADR-0006 (election lifecycle).
