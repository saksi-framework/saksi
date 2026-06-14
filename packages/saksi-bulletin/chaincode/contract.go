package main

import (
	"encoding/hex"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

const (
	// electionIndex keys stored election parameters by electionID.
	electionIndex = "election"
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

	var ballot saksiprotocolv1.Ballot
	if err := proto.Unmarshal(raw, &ballot); err != nil {
		return fmt.Errorf("decode ballot: %w", err)
	}

	if ballot.GetVersion() != saksiprotocolv1.WireVersion {
		return fmt.Errorf("unsupported ballot version %d, want %d", ballot.GetVersion(), saksiprotocolv1.WireVersion)
	}
	if ballot.GetElectionId() == "" {
		return fmt.Errorf("ballot is missing an election id")
	}
	if len(ballot.GetCiphertexts()) == 0 {
		return fmt.Errorf("ballot has no ciphertexts")
	}
	for i, ciphertext := range ballot.GetCiphertexts() {
		if len(ciphertext.GetPad()) != ciphertextLen || len(ciphertext.GetData()) != ciphertextLen {
			return fmt.Errorf(
				"ciphertext %d is malformed: pad=%d data=%d bytes, want %d each",
				i, len(ciphertext.GetPad()), len(ciphertext.GetData()), ciphertextLen,
			)
		}
	}

	presentation := ballot.GetCredentialPresentation()
	if presentation == nil || presentation.GetNullifier() == nil || len(presentation.GetNullifier().GetValue()) == 0 {
		return fmt.Errorf("ballot is missing a credential-presentation nullifier")
	}
	nullifier := hex.EncodeToString(presentation.GetNullifier().GetValue())

	stub := ctx.GetStub()

	nullifierKey, err := stub.CreateCompositeKey(nullifierIndex, []string{ballot.GetElectionId(), nullifier})
	if err != nil {
		return fmt.Errorf("build nullifier key: %w", err)
	}
	spent, err := stub.GetState(nullifierKey)
	if err != nil {
		return fmt.Errorf("read nullifier state: %w", err)
	}
	if spent != nil {
		return fmt.Errorf("nullifier already spent in election %q (double vote)", ballot.GetElectionId())
	}

	ballotKey, err := stub.CreateCompositeKey(ballotIndex, []string{ballot.GetElectionId(), nullifier})
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

// CreateElection records the parameters of a new election. The argument is the
// hex-encoded canonical protobuf encoding of a saksi.protocol.v1.ElectionParameters.
//
// On-chain checks: supported wire version, a non-empty election id, at least one
// contest and one trustee, and a threshold in 1..=trustee_count. The election id
// must be new — re-creating an existing election is rejected.
func (s *SmartContract) CreateElection(ctx contractapi.TransactionContextInterface, paramsHex string) error {
	raw, err := hex.DecodeString(paramsHex)
	if err != nil {
		return fmt.Errorf("election parameters are not valid hex: %w", err)
	}

	var params saksiprotocolv1.ElectionParameters
	if err := proto.Unmarshal(raw, &params); err != nil {
		return fmt.Errorf("decode election parameters: %w", err)
	}

	if params.GetVersion() != saksiprotocolv1.WireVersion {
		return fmt.Errorf("unsupported election parameters version %d, want %d", params.GetVersion(), saksiprotocolv1.WireVersion)
	}
	electionID := params.GetElectionId()
	if electionID == "" {
		return fmt.Errorf("election parameters are missing an election id")
	}
	if len(params.GetContestIds()) == 0 {
		return fmt.Errorf("election has no contests")
	}
	trustees := len(params.GetTrusteeIds())
	if trustees == 0 {
		return fmt.Errorf("election has no trustees")
	}
	threshold := int(params.GetThreshold())
	if threshold < 1 || threshold > trustees {
		return fmt.Errorf("election threshold %d is out of range 1..%d", threshold, trustees)
	}

	stub := ctx.GetStub()
	key, err := stub.CreateCompositeKey(electionIndex, []string{electionID})
	if err != nil {
		return fmt.Errorf("build election key: %w", err)
	}
	existing, err := stub.GetState(key)
	if err != nil {
		return fmt.Errorf("read election state: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("election %q already exists", electionID)
	}
	if err := stub.PutState(key, raw); err != nil {
		return fmt.Errorf("store election: %w", err)
	}
	return nil
}

// GetElection returns the hex-encoded ElectionParameters recorded for an
// election id, or an error if no such election exists.
func (s *SmartContract) GetElection(ctx contractapi.TransactionContextInterface, electionID string) (string, error) {
	stub := ctx.GetStub()

	key, err := stub.CreateCompositeKey(electionIndex, []string{electionID})
	if err != nil {
		return "", fmt.Errorf("build election key: %w", err)
	}
	raw, err := stub.GetState(key)
	if err != nil {
		return "", fmt.Errorf("read election state: %w", err)
	}
	if raw == nil {
		return "", fmt.Errorf("no election found with id %q", electionID)
	}
	return hex.EncodeToString(raw), nil
}
