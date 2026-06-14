# Saksi Threat Model (v1)

Scope: the Saksi framework as implemented — ristretto255 primitives, anonymous
credentials, the Fabric bulletin board, and the off-chain auditor — driving a
one-election demo. Companion to [protocol.md](protocol.md). This is a working
threat model for the demo, not a certification.

## 1. Assets and security goals

- **Tally integrity** — the published result equals the homomorphic sum of the
  well-formed ballots actually recorded.
- **Eligibility** — only holders of a valid issuer credential can have a ballot
  counted.
- **One-vote-per-voter-per-election** — at most one ballot per credential counts.
- **Ballot secrecy** — no party below the trustee threshold learns how anyone
  voted.
- **Universal verifiability** — anyone can check the result from public data,
  without trusting the peers, trustees, or issuer.

## 2. Parties and trust assumptions

- **Voter** — holds `s_cred` and a credential; may be honest or adversarial.
- **Issuer (election authority)** — issues credentials. Trusted for
  *eligibility* (it decides who gets a credential) but **not** for secrecy or
  tally integrity. Issuance is blinded, so the issuer cannot link a credential to
  the issuance session.
- **Trustees (n, threshold t)** — jointly hold the decryption key via DKG.
  Secrecy holds as long as **fewer than `t`** trustees collude; liveness of the
  tally needs **at least `t`** honest-and-available trustees. Default 3-of-5.
- **Bulletin board (Fabric peers / orderer)** — a permissioned, append-only log
  under X.509 MSP identity. Trusted to be append-only and to enforce the on-chain
  checks; **not** trusted for any property an auditor can independently recompute.
- **Auditor** — untrusted code anyone can run; correctness rests on the public
  data and the open verification logic, not on who runs it.

There is **no cryptocurrency, gas, or wallet**; identity is X.509 MSP. This
removes the entire class of fee/wallet/key-custody attacks present in
public-blockchain voting designs.

## 3. Adversary capabilities considered

- Submit malformed or invalid ballots (bad ciphertext shape, invalid CDS proof,
  forged credential signature, replayed nullifier).
- Replay or reorder transactions at submission time.
- A minority (`< t`) of trustees colluding, or posting a bad decryption share.
- A malicious issuer attempting to link issuance to a later presentation.
- An observer of the bulletin board attempting to learn votes or deanonymize
  voters from public data.

## 4. How the design addresses them

| Threat | Mitigation | Tier |
| --- | --- | --- |
| Forged / wrong-issuer credential | On-chain issuer Schnorr signature check `s·G == R'+e·Pk_i` (`credverify`) | on-chain |
| Malformed ciphertext | Structural shape check (32-byte point pairs, count) | on-chain |
| Double vote | Deterministic nullifier + uniqueness guard at write time | on-chain |
| Ballot not `{0,1}` / ballot stuffing by value | CDS OR-proof | off-chain (auditor) |
| Nullifier not tied to the signed credential | Presentation Chaum-Pedersen NIZK | off-chain |
| Bad trustee decryption share | Per-trustee Chaum-Pedersen proof; `≥ t` distinct verified shares | off-chain |
| Wrong tally published | Auditor recomputes homomorphic sum → published totals | off-chain |
| Issuance↔presentation linkage | Pointcheval–Stern blinding `(b, α, β)` | crypto |
| Vote secrecy | Threshold ElGamal; `< t` trustees learn nothing | crypto |

A ballot that passes the on-chain checks but fails a heavy proof is *recorded*
but *excluded by the auditor*; the certified result is the auditor's, not the raw
on-chain set (see [ADR-0005](../docs/adr/0005-hybrid-verification-split.md)).

## 5. Known limitations (in scope to state, out of scope to fix for the demo)

- **Cross-presentation linkability.** The holder reveals the commitment `C`
  directly at presentation time, so two presentations of the *same* credential
  are linkable to each other (only issuance↔presentation is unlinkable). The
  per-election nullifier already enforces single-ballot; full cross-presentation
  unlinkability would need presentation-time commitment re-randomization or a
  structure-preserving signature (BBS+/PS). Acceptable under the spec's
  "one-shot eligibility token" model.
- **Coercion / receipt-freeness.** Not provided. A voter knows their own
  randomness and nullifier. Receipt-freeness and coercion-resistance are out of
  scope for the demo.
- **Network-level anonymity.** Linking a submitting network identity to a ballot
  is outside the cryptographic model; deployments needing it must add transport
  anonymity.
- **Trustee threshold availability.** Fewer than `t` available trustees blocks
  the tally (a liveness, not integrity, failure).
- **Brute-force tally decode range.** Plaintext recovery assumes totals fall in
  the expected small range; parameters must bound the electorate accordingly.
- **Demo network topology.** The reference runs a minimal 1-org dev network with
  single-org endorsement; a production deployment needs the multi-org topology
  (additive, out of scope here).

## 6. Out of scope

Side-channel resistance of the host, key-ceremony operational security, long-term
key management, voter-registration policy, and the client UI applications (which
live in the BalotaChain repo).
