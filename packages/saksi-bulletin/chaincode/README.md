# saksi-bulletin/chaincode

Hyperledger Fabric chaincode (Contract API) for the BalotaChain bulletin board.

**Status:** implemented. The `SmartContract` covers the full election lifecycle:

| Transaction | Kind | Purpose |
| --- | --- | --- |
| `CreateElection` / `GetElection` | submit / query | record + read election parameters |
| `PublishDKGTranscript` / `GetDKGTranscript` | submit / query | record + read the DKG transcript |
| `SubmitBallot` / `GetBallot` | submit / query | cast + read a ballot |
| `CloseElection` / `GetElectionStatus` | submit / query | end voting + read lifecycle status |
| `SubmitPartialDecryption` / `GetPartialDecryption` | submit / query | record + read a trustee decryption share |
| `PublishTally` / `GetTally` | submit / query | publish + read the final tally |

## Hybrid verification split (locked)

The chaincode does NOT verify NIZK well-formedness proofs. On submission it performs
only cheap, deterministic checks and records the data; everything heavier — CDS OR
proofs, Chaum-Pedersen proofs, Lagrange combination — is verified off-chain by the
[`saksi-auditor`](../../saksi-auditor/) crate, reachable from clients via
[`packages/saksi-ffi-tauri`](../../saksi-ffi-tauri/).

On-chain checks today: wire version, election existence/lifecycle gating, ciphertext
structural shape (ristretto-compressed point pairs), share shape, and nullifier
uniqueness (no double vote).

> **Parity note.** The locked architecture also places **credential-signature
> verification** on-chain. That check is not yet in `SubmitBallot` — it currently runs
> client-side in the FFI. Moving it on-chain needs a ristretto255 + Merlin-compatible
> verifier in Go and is the tracked parity item.
