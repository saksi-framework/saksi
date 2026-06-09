# saksi-bulletin/chaincode

Hyperledger Fabric chaincode (Contract API) for the BalotaChain bulletin board.

**Status:** empty Go module. Real chaincode lands in:

- [#25](https://github.com/saksi-framework/balotachain/issues/25) — scaffold the package with the Fabric Contract API.
- [#27](https://github.com/saksi-framework/balotachain/issues/27) — `SubmitBallot` (signature + nullifier + ciphertext shape).
- [#28](https://github.com/saksi-framework/balotachain/issues/28) — trustee registration and DKG transcript publication.
- [#29](https://github.com/saksi-framework/balotachain/issues/29) — `CloseElection`, `SubmitPartialDecryption`, `PublishTally`.

## Hybrid verification split (locked)

The chaincode does NOT verify NIZK well-formedness proofs. It verifies, on-chain:

1. The credential presentation's signature under the registrar's public key for the election.
2. The nullifier is not already present in the per-election nullifier set.
3. The ballot ciphertext has the correct structural shape (correct number of options, each a valid ristretto-compressed point pair, total byte size within bounds).

Everything heavier — CDS OR proofs, Chaum-Pedersen proofs, Lagrange combination — is verified off-chain by [`apps/auditor`](../../../apps/auditor/), which links the Rust crypto core directly via [`packages/saksi-ffi-tauri`](../../saksi-ffi-tauri/).
