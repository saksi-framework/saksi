package clientsdk

import "fmt"

// Contract is the subset of the Fabric Gateway contract API the bulletin client
// uses. *github.com/hyperledger/fabric-gateway/pkg/client.Contract satisfies it,
// and tests substitute a fake to exercise the call marshaling without a network.
type Contract interface {
	SubmitTransaction(name string, args ...string) ([]byte, error)
	EvaluateTransaction(name string, args ...string) ([]byte, error)
}

// BulletinClient is a thin, Saksi-specific wrapper over a Fabric Gateway
// contract. It maps bulletin-board operations to chaincode transactions.
type BulletinClient struct {
	contract Contract
}

// NewBulletinClient wraps a connected contract.
func NewBulletinClient(contract Contract) *BulletinClient {
	return &BulletinClient{contract: contract}
}

// SubmitBallot submits a single ballot to the bulletin board. ballotHex is the
// hex-encoded canonical protobuf encoding of a saksi.protocol.v1.Ballot. The
// transaction is endorsed, ordered, and committed before this returns.
func (b *BulletinClient) SubmitBallot(ballotHex string) error {
	if ballotHex == "" {
		return fmt.Errorf("ballot hex is empty")
	}
	if _, err := b.contract.SubmitTransaction("SubmitBallot", ballotHex); err != nil {
		return fmt.Errorf("submit ballot: %w", err)
	}
	return nil
}

// GetBallot evaluates the GetBallot query and returns the recorded ballot as a
// hex string, or an error if it is absent.
func (b *BulletinClient) GetBallot(electionID, nullifier string) (string, error) {
	out, err := b.contract.EvaluateTransaction("GetBallot", electionID, nullifier)
	if err != nil {
		return "", fmt.Errorf("get ballot: %w", err)
	}
	return string(out), nil
}

// CreateElection records a new election on the bulletin board. paramsHex is the
// hex-encoded canonical protobuf encoding of a saksi.protocol.v1.ElectionParameters.
func (b *BulletinClient) CreateElection(paramsHex string) error {
	if paramsHex == "" {
		return fmt.Errorf("election parameters hex is empty")
	}
	if _, err := b.contract.SubmitTransaction("CreateElection", paramsHex); err != nil {
		return fmt.Errorf("create election: %w", err)
	}
	return nil
}

// GetElection evaluates the GetElection query and returns the recorded election
// parameters as a hex string, or an error if the election is absent.
func (b *BulletinClient) GetElection(electionID string) (string, error) {
	out, err := b.contract.EvaluateTransaction("GetElection", electionID)
	if err != nil {
		return "", fmt.Errorf("get election: %w", err)
	}
	return string(out), nil
}

// PublishDKGTranscript records the DKG transcript for an election. transcriptHex
// is the hex-encoded canonical protobuf encoding of a saksi.protocol.v1.DKGTranscript.
func (b *BulletinClient) PublishDKGTranscript(transcriptHex string) error {
	if transcriptHex == "" {
		return fmt.Errorf("DKG transcript hex is empty")
	}
	if _, err := b.contract.SubmitTransaction("PublishDKGTranscript", transcriptHex); err != nil {
		return fmt.Errorf("publish DKG transcript: %w", err)
	}
	return nil
}

// GetDKGTranscript evaluates the GetDKGTranscript query and returns the recorded
// transcript as a hex string, or an error if none has been published.
func (b *BulletinClient) GetDKGTranscript(electionID string) (string, error) {
	out, err := b.contract.EvaluateTransaction("GetDKGTranscript", electionID)
	if err != nil {
		return "", fmt.Errorf("get DKG transcript: %w", err)
	}
	return string(out), nil
}
