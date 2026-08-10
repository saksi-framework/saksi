package clientsdk

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// nullifierPageSize is the per-page cap for ListNullifiers. It matches the
// chaincode's maxNullifierPageSize so a single page never trips the peer's
// totalQueryLimit.
const nullifierPageSize = 10000

// NullifierPage is one page of committed nullifiers for an election, mirroring
// the chaincode's ListNullifiers JSON response.
type NullifierPage struct {
	Nullifiers   []string `json:"nullifiers"`
	NextBookmark string   `json:"next_bookmark"`
}

// ListNullifiers evaluates one page of the committed nullifiers for an election.
func (b *BulletinClient) ListNullifiers(electionID string, pageSize int, bookmark string) (NullifierPage, error) {
	var page NullifierPage
	out, err := b.contract.EvaluateTransaction(
		"ListNullifiers", electionID, strconv.Itoa(pageSize), bookmark,
	)
	if err != nil {
		return page, fmt.Errorf("list nullifiers: %w", err)
	}
	if err := json.Unmarshal(out, &page); err != nil {
		return page, fmt.Errorf("decode nullifier page: %w", err)
	}
	return page, nil
}

// CountCommittedBallots returns the number of ballots committed on-chain for an
// election by paging through ListNullifiers (one nullifier == one committed
// ballot). This is the chain-authoritative committed count the campaign runner
// reconciles against the submitted count — the pagination is mandatory so the
// count does not silently truncate at the peer's totalQueryLimit at scale.
func (b *BulletinClient) CountCommittedBallots(electionID string) (int, error) {
	total := 0
	bookmark := ""
	for {
		page, err := b.ListNullifiers(electionID, nullifierPageSize, bookmark)
		if err != nil {
			return 0, err
		}
		total += len(page.Nullifiers)
		if page.NextBookmark == "" {
			return total, nil
		}
		bookmark = page.NextBookmark
	}
}

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

// CloseElection transitions an election from open to closed, after which no
// further ballots are accepted.
func (b *BulletinClient) CloseElection(electionID string) error {
	if _, err := b.contract.SubmitTransaction("CloseElection", electionID); err != nil {
		return fmt.Errorf("close election: %w", err)
	}
	return nil
}

// GetElectionStatus evaluates the GetElectionStatus query and returns the
// lifecycle status ("open" or "closed"), or an error if the election is absent.
func (b *BulletinClient) GetElectionStatus(electionID string) (string, error) {
	out, err := b.contract.EvaluateTransaction("GetElectionStatus", electionID)
	if err != nil {
		return "", fmt.Errorf("get election status: %w", err)
	}
	return string(out), nil
}

// SubmitPartialDecryption records one trustee's partial decryption share for a
// contest of the given election. partialHex is the hex-encoded canonical protobuf
// encoding of a saksi.protocol.v1.PartialDecryption.
func (b *BulletinClient) SubmitPartialDecryption(electionID, partialHex string) error {
	if electionID == "" {
		return fmt.Errorf("election id is empty")
	}
	if partialHex == "" {
		return fmt.Errorf("partial decryption hex is empty")
	}
	if _, err := b.contract.SubmitTransaction("SubmitPartialDecryption", electionID, partialHex); err != nil {
		return fmt.Errorf("submit partial decryption: %w", err)
	}
	return nil
}

// GetPartialDecryption evaluates the GetPartialDecryption query and returns the
// recorded partial decryption as a hex string, or an error if it is absent.
func (b *BulletinClient) GetPartialDecryption(electionID, contestID, trusteeID string) (string, error) {
	out, err := b.contract.EvaluateTransaction("GetPartialDecryption", electionID, contestID, trusteeID)
	if err != nil {
		return "", fmt.Errorf("get partial decryption: %w", err)
	}
	return string(out), nil
}

// PublishTally records the final tally for an election. tallyHex is the
// hex-encoded canonical protobuf encoding of a saksi.protocol.v1.TallyResult.
func (b *BulletinClient) PublishTally(tallyHex string) error {
	if tallyHex == "" {
		return fmt.Errorf("tally hex is empty")
	}
	if _, err := b.contract.SubmitTransaction("PublishTally", tallyHex); err != nil {
		return fmt.Errorf("publish tally: %w", err)
	}
	return nil
}

// GetTally evaluates the GetTally query and returns the published tally as a hex
// string, or an error if none has been published.
func (b *BulletinClient) GetTally(electionID string) (string, error) {
	out, err := b.contract.EvaluateTransaction("GetTally", electionID)
	if err != nil {
		return "", fmt.Errorf("get tally: %w", err)
	}
	return string(out), nil
}
