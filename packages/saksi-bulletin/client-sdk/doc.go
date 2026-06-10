// Package clientsdk wraps fabric-gateway and is the single Go library every
// non-chaincode caller uses to talk to the BalotaChain bulletin board. Admin,
// trustee, auditor, and voter-side relays all consume this SDK.
//
// It exposes Connect, which dials a peer gateway with an MSP identity, and a
// BulletinClient with SubmitBallot/GetBallot. The cmd/submit-ballot program
// runs a single end-to-end transaction against a live network.
package clientsdk
