# saksi-bulletin

The bulletin board on Hyperledger Fabric. Three subdirectories:

| Subdirectory | Language | Purpose | Lead issue |
|---|---|---|---|
| [`chaincode/`](chaincode/) | Go | Hyperledger Fabric chaincode (Contract API). Per the locked hybrid-verification split: chaincode verifies credential signatures, nullifier uniqueness, and ciphertext structural shape; NIZK proofs are verified off-chain by the auditor client. | #25, #27, #28, #29 |
| [`network/`](network/) | Docker Compose + scripts | Local development Fabric network with 5 trustee organizations matching the 3-of-5 threshold. | #26 |
| [`client-sdk/`](client-sdk/) | Go | Wrapper around `fabric-gateway` used by every non-chaincode caller (admin, trustee, auditor, voter-side relay). | #30 |

## Why Hyperledger Fabric

Locked by the thesis architecture chapter and PRD. The literature comparison and the permissioned-blockchain integrity argument both depend on Fabric. Alternative substrates (CometBFT, Trillian, custom signed log) are out of scope; the lock-in is documented in [`docs/architecture/2026-05-20-initial-architecture-decisions.md`](../../docs/architecture/2026-05-20-initial-architecture-decisions.md).

## Why Go

Locked. The Fabric Contract API is first-class in Go; the chaincode is the only Go code in the repository. Rust crypto code does not run inside the chaincode — all NIZK verification happens off-chain on auditor clients that link the Rust core directly.
