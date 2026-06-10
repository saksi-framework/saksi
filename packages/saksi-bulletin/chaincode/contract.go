package main

import (
	"encoding/hex"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	saksiprotocol "github.com/saksi-framework/saksi/packages/saksi-protocol/go"
)

const (
	// ballotIndex keys stored ballots by (electionID, nullifier).
	ballotIndex = "ballot"
	// nullifierIndex records spent nullifiers by (electionID, nullifier).
	nullifierIndex = "nullifier"
	// ciphertextLen is the expected ristretto255 compressed-point length, in
	// bytes, for both the pad and data components of an ElGamal ciphertext.
	ciphertextLen = 32
)

// SmartContract implements the BalotaChain bulletin board.
//
// Per the locked hybrid-verification split (the architecture record and
// ADR set), the chaincode performs only the cheap, deterministic checks on
// submission — wire version, ciphertext structural shape, and nullifier
// uniqueness — and records the ballot. The heavy NIZK well-formedness proofs
// are verified off-chain by auditor clients reading the bulletin board.
type SmartContract struct {
	contractapi.Contract
}

// SubmitBallot validates and records a single ballot. The argument is the
// hex-encoded canonical protobuf encoding of a saksi.protocol.v1.Ballot.
//
// On-chain checks:
//   - the wire version is supported;
//   - an election id is present;
//   - at least one ciphertext, each with a correctly shaped pad and data;
//   - a credential-presentation nullifier is present;
//   - the nullifier has not already been spent in this election (no double
//     vote).
//
// The ballot is stored keyed by (electionID, nullifier), and the nullifier is
// marked spent in the same transaction.
func (s *SmartContract) SubmitBallot(ctx contractapi.TransactionContextInterface, ballotHex string) error {
	raw, err := hex.DecodeString(ballotHex)
	if err != nil {
		return fmt.Errorf("ballot is not valid hex: %w", err)
	}

	ballot, err := saksiprotocol.UnmarshalBallot(raw)
	if err != nil {
		return fmt.Errorf("decode ballot: %w", err)
	}

	if ballot.Version != saksiprotocol.WireVersion {
		return fmt.Errorf("unsupported ballot version %d, want %d", ballot.Version, saksiprotocol.WireVersion)
	}
	if ballot.ElectionID == "" {
		return fmt.Errorf("ballot is missing an election id")
	}
	if len(ballot.Ciphertexts) == 0 {
		return fmt.Errorf("ballot has no ciphertexts")
	}
	for i, ciphertext := range ballot.Ciphertexts {
		if len(ciphertext.Pad) != ciphertextLen || len(ciphertext.Data) != ciphertextLen {
			return fmt.Errorf(
				"ciphertext %d is malformed: pad=%d data=%d bytes, want %d each",
				i, len(ciphertext.Pad), len(ciphertext.Data), ciphertextLen,
			)
		}
	}

	presentation := ballot.CredentialPresentation
	if presentation == nil || presentation.Nullifier == nil || len(presentation.Nullifier.Value) == 0 {
		return fmt.Errorf("ballot is missing a credential-presentation nullifier")
	}
	nullifier := hex.EncodeToString(presentation.Nullifier.Value)

	stub := ctx.GetStub()

	nullifierKey, err := stub.CreateCompositeKey(nullifierIndex, []string{ballot.ElectionID, nullifier})
	if err != nil {
		return fmt.Errorf("build nullifier key: %w", err)
	}
	spent, err := stub.GetState(nullifierKey)
	if err != nil {
		return fmt.Errorf("read nullifier state: %w", err)
	}
	if spent != nil {
		return fmt.Errorf("nullifier already spent in election %q (double vote)", ballot.ElectionID)
	}

	ballotKey, err := stub.CreateCompositeKey(ballotIndex, []string{ballot.ElectionID, nullifier})
	if err != nil {
		return fmt.Errorf("build ballot key: %w", err)
	}
	if err := stub.PutState(ballotKey, raw); err != nil {
		return fmt.Errorf("store ballot: %w", err)
	}
	if err := stub.PutState(nullifierKey, []byte{1}); err != nil {
		return fmt.Errorf("mark nullifier spent: %w", err)
	}
	return nil
}

// GetBallot returns the hex-encoded ballot recorded for an (electionID,
// nullifier) pair, or an error if no such ballot exists.
func (s *SmartContract) GetBallot(ctx contractapi.TransactionContextInterface, electionID string, nullifier string) (string, error) {
	stub := ctx.GetStub()

	ballotKey, err := stub.CreateCompositeKey(ballotIndex, []string{electionID, nullifier})
	if err != nil {
		return "", fmt.Errorf("build ballot key: %w", err)
	}
	raw, err := stub.GetState(ballotKey)
	if err != nil {
		return "", fmt.Errorf("read ballot state: %w", err)
	}
	if raw == nil {
		return "", fmt.Errorf("no ballot found for election %q nullifier %q", electionID, nullifier)
	}
	return hex.EncodeToString(raw), nil
}
