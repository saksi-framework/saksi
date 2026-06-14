// Command saksi-bulletin is the Hyperledger Fabric chaincode implementing the BalotaChain
// bulletin board. Per the locked hybrid-verification split, this chaincode performs the
// cheap, deterministic on-submission checks — wire version, ciphertext structural shape,
// credential-signature verification, and nullifier uniqueness — and records the data.
// Heavier NIZK well-formedness proofs are verified off-chain by the auditor client.
//
// Credential-signature verification (the issuer Schnorr signature on the credential
// commitment) runs on-chain in the credverify package, byte-identical to the Rust
// saksi-credentials signer and pinned by a cross-language golden vector.
//
// The SmartContract implements the election lifecycle end to end: CreateElection/GetElection,
// PublishDKGTranscript/GetDKGTranscript, CloseElection/GetElectionStatus, SubmitBallot/GetBallot,
// SubmitPartialDecryption/GetPartialDecryption, and PublishTally/GetTally. main wraps the
// contract in a Fabric chaincode server; the module root is the package the Fabric peer
// builds and deploys.
package main
