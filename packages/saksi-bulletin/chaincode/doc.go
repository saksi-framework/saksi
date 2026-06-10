// Package chaincode is a Hyperledger Fabric chaincode implementing the BalotaChain
// bulletin board. Per the locked hybrid-verification split, this chaincode verifies
// credential signatures, nullifier uniqueness, and ciphertext structural shape on
// submission; heavier NIZK well-formedness proofs are verified off-chain by the
// auditor client.
//
// The SmartContract currently implements ballot submission (SubmitBallot) and
// retrieval (GetBallot). Remaining transactions land in later issues: trustee
// registration + DKG transcripts (#28) and tally publication (#29). The
// entrypoint that wraps the contract in a Fabric chaincode server is under
// cmd/saksi-bulletin.
package chaincode
