# Saksi Protocol Specification (v1)

This document specifies the Saksi end-to-end verifiable election protocol as
implemented in this repository. It is descriptive of the v1 wire version
(`WIRE_VERSION = 1`) and is the reference for cross-implementation work. Where a
detail is load-bearing for byte-compatibility it is marked **stable**.

Related records: [ADR-0003](../docs/adr/0003-protocol-buffers-for-wire-serialization.md)
(wire format), [ADR-0004](../docs/adr/0004-merlin-fiat-shamir-transcripts.md)
(Fiat-Shamir), [ADR-0005](../docs/adr/0005-hybrid-verification-split.md)
(verification split), [ADR-0006](../docs/adr/0006-election-lifecycle.md)
(lifecycle). Adversary model and guarantees: [threat-model.md](threat-model.md).

## 1. Cryptographic setting

- **Group:** ristretto255 (the prime-order group over Curve25519), via
  `curve25519-dalek` in Rust and `gtank/ristretto255` in Go. `G` is the
  ristretto255 basepoint; `ℓ` is the group order. No pairings; a single group
  throughout. **Stable:** points are the 32-byte canonical ristretto255
  encoding; scalars are 32-byte canonical little-endian.
- **Fiat-Shamir:** all NIZK challenges derive from **Merlin** transcripts
  (STROBE-128). Transcript labels are domain-separated and versioned under the
  `saksi.*` namespace. A Go port (`gtank/merlin`) reproduces the challenge bytes
  exactly; this is exercised by a cross-language golden vector.
- **Hashing to the group:** election-specific points (e.g. the nullifier
  generator `H_e`) are derived by hash-to-ristretto from a labelled input.

## 2. Primitives

- **Additive ElGamal** over ristretto255. A message `m` is encoded as `m·G`;
  ciphertext `(pad, data) = (r·G, m·G + r·Pk)`. Homomorphic: componentwise
  addition of ciphertexts adds plaintexts, enabling a homomorphic tally. Small
  plaintexts are recovered by brute-force discrete log over the expected range.
- **Pedersen / Feldman DKG** producing a joint public key `Pk` with a
  `t`-of-`n` threshold; includes complaint handling, Lagrange combination, and
  threshold decryption. Default threshold **3-of-5**.
- **Schnorr NIZK** — proof of knowledge of a discrete log.
- **Chaum-Pedersen NIZK** — equality of two discrete logs (`A = x·G ∧ B = x·H`);
  used for correct threshold partial decryption and inside credential
  presentation.
- **CDS OR-proof** (Cramer–Damgård–Schoenmakers) — a ciphertext encrypts a value
  in `{0,1}` without revealing which; ballot well-formedness.
- **Pedersen commitment** `m·G + r·H`, open/verify, homomorphic.
- **Benaloh cast-or-challenge** — cast-as-intended assurance.
- **Pointcheval–Stern blind-Schnorr credentials** — anonymous voter credentials
  (no pairings); issuance is unlinkable from presentation. A **deterministic
  PRF nullifier** `n = s_cred · H_e` gives one-ballot-per-election enforcement and
  cross-election unlinkability.

Every NIZK ships with completeness, soundness (tamper) and transcript-binding
tests.

## 3. Wire messages

Protocol Buffers, package `saksi.protocol.v1`, 14 messages, generated for Rust
(`prost`) and Go (`protoc-gen-go`); byte-identity is pinned by a golden vector.
Key messages: `ElectionParameters`, `DKGTranscript` (`TrusteeCommitment[]`),
`Ballot` (`Ciphertext[]`, `CDSProof[]`, `CredentialPresentation`),
`CredentialPresentation` (+ `Nullifier`), `PartialDecryption` (with `contest_id`),
`TallyResult`, and the proof messages `SchnorrProof`, `ChaumPedersenProof`,
`CDSProof`/`CDSProofBranch`. Every message carries a `version` field.

The credential `presentation_proof` is an opaque envelope, **stable**:

```text
[ R' (32, compressed point) || s (32, canonical scalar) || ChaumPedersenProof (protobuf) ]
```

The first 64 bytes are the issuer signature `(R', s)`; the remainder is the
presentation NIZK.

## 4. Issuer credential signature (the on-chain check)

The issuer holds `(x_i, Pk_i = x_i·G)`. A credential is a Schnorr signature
`(R', s)` on the commitment `C = s_cred·G` under `Pk_i`, produced by the
Pointcheval–Stern blinded issuance. Verification, **stable**:

```text
e  = H(transcript)      # Merlin, label "saksi.credentials.issuance.v1"
        append "issuer-pk"   = compress(Pk_i)
        append "commitment"  = compress(C)
        append "r-prime"     = compress(R')
        challenge "challenge" -> 64 bytes -> e = reduce_wide(bytes) mod ℓ
accept iff  s·G == R' + e·Pk_i
```

The challenge binds **only** `(Pk_i, C, R')` — no election id or context — so a
verifier can recompute it from the signature alone. This is what the chaincode
verifies on-chain (`credverify`); the Go and Rust verifiers agree byte-for-byte
(golden vector `test-vectors/credential-sig-v1.hex`).

## 5. Credential presentation

To vote, the holder publishes `CredentialPresentation { credential_commitment C,
issuer_public_key Pk_i, presentation_proof, nullifier n }` where the proof is the
envelope of §3. Beyond the issuer signature, the presentation NIZK is a
Chaum-Pedersen proof that `C = s_cred·G ∧ n = s_cred·H_e` for the *same* secret —
binding the published nullifier to the signed credential. The NIZK transcript is
bound to `presentation_context(election_id, context)`, **stable**:

```text
"saksi.credentials.presentation.v1" || u64_be(len(election_id)) || election_id
                                     || u64_be(len(context))     || context
```

`H_e = hash_to_ristretto(election_id)`, so `n` is deterministic in
`(s_cred, election_id)` — identical for two ballots of one credential in one
election (double-vote detection) and unlinkable across elections.

## 6. Election flow

1. **Setup.** Trustees run the DKG → joint key `Pk`. The admin calls
   `CreateElection(ElectionParameters{ election_id, contest_ids, trustee_ids,
   threshold })` (status `open`) and `PublishDKGTranscript`.
2. **Vote.** For each contest a voter encrypts their choice under `Pk`, attaches
   a CDS OR-proof of `{0,1}` well-formedness, presents a credential (signature +
   NIZK + nullifier), and calls `SubmitBallot`. The chaincode runs the on-chain
   checks (§4, ADR-0005) and rejects a reused nullifier.
3. **Close.** `CloseElection` sets status `closed`; no further ballots.
4. **Tally.** Each trustee homomorphically sums the contest's ciphertexts,
   partial-decrypts with a Chaum-Pedersen proof, and calls
   `SubmitPartialDecryption` (carrying `contest_id`). After `≥ threshold` shares,
   the result is combined (Lagrange) and decoded; `PublishTally` posts the totals.
5. **Audit.** Anyone runs `saksi-auditor` over the public bulletin contents.

## 7. Verifiability

- **Cast-as-intended** — Benaloh cast-or-challenge (client side).
- **Recorded-as-cast** — the append-only, signature-gated, nullifier-unique
  chaincode log (on-chain, §4 / ADR-0005).
- **Counted-as-recorded** — `saksi-auditor` recomputes every heavy proof and
  checks the homomorphic sum decrypts to the published tally (off-chain).

## 8. Transcript labels (stable)

- `saksi.credentials.issuance.v1` — issuer signature challenge.
- `saksi.credentials.presentation.v1` — presentation-context prefix.
- the `saksi.*` NIZK labels in `saksi-crypto` for Schnorr / Chaum-Pedersen / CDS.

Changing any labelled byte layout in this section is a breaking wire change and
bumps the relevant `v*` suffix.
