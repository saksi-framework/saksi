# ADR-0004: Merlin Fiat-Shamir Transcripts

## Status

Accepted

## Context

Saksi uses transcript-based non-interactive zero-knowledge proofs for encrypted
ballots, trustee key material, decryption shares, commitments, and credential
presentations. These protocols need a shared Fiat-Shamir convention with clear
domain separation.

Hand-rolled hash chains are easy to make inconsistent between proofs and can
omit context accidentally. Merlin provides a transcript API designed for
interactive-to-non-interactive proof transforms and makes domain-separated
message binding explicit.

## Decision

Saksi cryptographic proofs will use Merlin transcripts throughout. Transcript
labels are defined centrally in `saksi-crypto::transcript` and include protocol,
purpose, and version information.

## Consequences

Proof implementations share one transcript convention, reducing the chance that
challenge derivation drifts between modules.

Each proof must append all public statement material, commitments, and protocol
context to the transcript before deriving challenges. New proof systems must add
a versioned transcript label before implementation.

