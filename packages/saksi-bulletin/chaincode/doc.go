// Command saksi-bulletin is the Hyperledger Fabric chaincode implementing the BalotaChain
// bulletin board. Per the locked hybrid-verification split, this chaincode verifies
// credential signatures, nullifier uniqueness, and ciphertext structural shape on
// submission; heavier NIZK well-formedness proofs are verified off-chain by the
// auditor client.
//
// The SmartContract currently implements ballot submission (SubmitBallot) and
// retrieval (GetBallot). Remaining transactions land in later issues: trustee
// registration + DKG transcripts (#28) and tally publication (#29). main wraps
// the contract in a Fabric chaincode server; the module root is the package the
// Fabric peer builds and deploys.
package main
