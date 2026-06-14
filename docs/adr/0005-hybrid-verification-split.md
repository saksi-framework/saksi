# ADR-0005: Hybrid On-chain / Off-chain Verification Split

## Status

Accepted

## Context

A Saksi ballot carries several cryptographic objects: an ElGamal ciphertext per
contest, a CDS OR-proof of ballot well-formedness per ciphertext, an anonymous
credential presentation (issuer signature + a Chaum-Pedersen NIZK), and a
deterministic per-election nullifier. Threshold decryption later adds a
Chaum-Pedersen proof per trustee per contest, and the final tally is published.

Every one of these objects *could* be verified on the bulletin board (the
Hyperledger Fabric chaincode). But chaincode runs inside endorsement on every
peer for every transaction, and the heavy zero-knowledge proofs (CDS OR-proofs,
the presentation NIZK, per-trustee Chaum-Pedersen) are expensive and would
require a substantial ristretto255 + Merlin verification surface to live in Go,
duplicating the Rust reference implementation and widening the trusted compute
that must stay byte-identical across two languages.

At the same time, end-to-end verifiability does not *require* the chaincode to
check the heavy proofs: any independent auditor can recompute them from the
public bulletin-board contents. What the chaincode must enforce are the checks
that protect the integrity of the append-only log itself — the ones that cannot
be repaired after the fact by an off-chain observer (most importantly, that a
nullifier is not spent twice, which is a property of *ordering* and can only be
enforced at write time).

## Decision

Split verification into two tiers.

**On-chain (chaincode, enforced at submission):**

- wire-format version is supported;
- the referenced election exists and is in the correct lifecycle state;
- ciphertext **structural shape** (each pad/data a 32-byte ristretto255
  compressed point; correct count);
- **credential-signature verification** — the issuer Schnorr signature on the
  credential commitment, recomputed over a Merlin transcript and checked as
  `s·G == R' + e·Pk_i` (see the `credverify` package), byte-identical to the
  Rust `saksi-credentials` signer;
- **nullifier uniqueness** (no double vote) and, for decryption shares,
  one-share-per-(contest, trustee).

**Off-chain (the `saksi-auditor` crate, recomputed from bulletin contents):**

- every ballot's **CDS OR-proof** of well-formedness;
- the **credential presentation NIZK** (Chaum-Pedersen tying the commitment and
  the nullifier to the same credential secret);
- DKG transcript commitment consistency;
- each trustee partial decryption's **Chaum-Pedersen** proof;
- the **homomorphic sum** of ciphertexts decrypting to the published tally.

The dividing line: the chaincode performs cheap, deterministic checks plus the
one integrity property that only write-time ordering can enforce (nullifier
uniqueness); everything that an independent party can recompute later from the
public log is left to the auditor.

## Consequences

- The chaincode stays small and its Go cryptographic surface is limited to one
  signature check (`credverify`), pinned to the Rust signer by a cross-language
  golden vector (`saksi-protocol/test-vectors/credential-sig-v1.hex`). A
  divergence between the Go and Rust verifiers is caught in CI.
- *Counted-as-recorded* verifiability rests on the auditor, not the chain. This
  is by design: anyone may run the auditor against the public bulletin board and
  does not have to trust the peers. The chain guarantees *recorded-as-cast*
  (append-only, signature-gated, no double spend); the auditor guarantees the
  rest.
- A ballot with an invalid heavy proof can be *recorded* on-chain (it passes the
  cheap checks) but will be *rejected by the auditor* and excluded from the
  count. Observers must run the auditor to obtain the final, correct tally; the
  raw on-chain set is not the certified result.
- This split is a locked invariant referenced by the BalotaChain architecture
  record and is the reason the credential signature (and not the presentation
  NIZK) is the credential check that lives on-chain.
