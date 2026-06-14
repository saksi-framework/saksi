// Command saksi-bulletin is the Hyperledger Fabric chaincode implementing the BalotaChain
// bulletin board. Per the locked hybrid-verification split, this chaincode performs the
// cheap, deterministic on-submission checks — wire version, ciphertext structural shape,
// and nullifier uniqueness — and records the data. Heavier NIZK well-formedness proofs are
// verified off-chain by the auditor client.
//
// Note: the locked architecture also places credential-signature verification on-chain.
// That check is not yet performed here (it currently lives in the client-side FFI); moving
// it into SubmitBallot requires a ristretto255 + Merlin-compatible verifier in Go and is
// the tracked parity item.
//
// The SmartContract implements the election lifecycle end to end: CreateElection/GetElection,
// PublishDKGTranscript/GetDKGTranscript, CloseElection/GetElectionStatus, SubmitBallot/GetBallot,
// SubmitPartialDecryption/GetPartialDecryption, and PublishTally/GetTally. main wraps the
// contract in a Fabric chaincode server; the module root is the package the Fabric peer
// builds and deploys.
package main
