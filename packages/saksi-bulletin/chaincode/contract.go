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
	// dkgIndex keys the stored DKG transcript by electionID (one per election).
	dkgIndex = "dkg"
	// statusIndex keys the election lifecycle status by electionID.
	statusIndex = "status"
	// ballotIndex keys stored ballots by (electionID, nullifier).
	ballotIndex = "ballot"
	// nullifierIndex records spent nullifiers by (electionID, nullifier).
	nullifierIndex = "nullifier"
	// partialDecIndex keys stored trustee partial decryptions by
	// (electionID, contestID, trusteeID) — one per trustee per contest.
	partialDecIndex = "partialdec"
	// tallyIndex keys the published tally by electionID (one per election).
	tallyIndex = "tally"
	// ciphertextLen is the expected ristretto255 compressed-point length, in
	// bytes, for both the pad and data components of an ElGamal ciphertext.
	ciphertextLen = 32
)

// Election lifecycle status values stored under statusIndex.
const (
	electionStatusOpen   = "open"
	electionStatusClosed = "closed"
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

	// The election must exist and be open for ballots.
	statusKey, err := stub.CreateCompositeKey(statusIndex, []string{ballot.GetElectionId()})
	if err != nil {
		return fmt.Errorf("build status key: %w", err)
	}
	status, err := stub.GetState(statusKey)
	if err != nil {
		return fmt.Errorf("read election status: %w", err)
	}
	if status == nil {
		return fmt.Errorf("election %q does not exist", ballot.GetElectionId())
	}
	if string(status) != electionStatusOpen {
		return fmt.Errorf("election %q is not open for ballots", ballot.GetElectionId())
	}

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

	statusKey, err := stub.CreateCompositeKey(statusIndex, []string{electionID})
	if err != nil {
		return fmt.Errorf("build status key: %w", err)
	}
	if err := stub.PutState(statusKey, []byte(electionStatusOpen)); err != nil {
		return fmt.Errorf("set election status: %w", err)
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

// PublishDKGTranscript records the distributed-key-generation transcript for an
// election. The argument is the hex-encoded canonical protobuf encoding of a
// saksi.protocol.v1.DKGTranscript.
//
// On-chain checks: supported wire version, a non-empty election id whose
// election already exists, at least one trustee commitment, and consistency with
// the election parameters (threshold and trustee count must match). Exactly one
// transcript may be published per election.
func (s *SmartContract) PublishDKGTranscript(ctx contractapi.TransactionContextInterface, transcriptHex string) error {
	raw, err := hex.DecodeString(transcriptHex)
	if err != nil {
		return fmt.Errorf("DKG transcript is not valid hex: %w", err)
	}

	var transcript saksiprotocolv1.DKGTranscript
	if err := proto.Unmarshal(raw, &transcript); err != nil {
		return fmt.Errorf("decode DKG transcript: %w", err)
	}

	if transcript.GetVersion() != saksiprotocolv1.WireVersion {
		return fmt.Errorf("unsupported DKG transcript version %d, want %d", transcript.GetVersion(), saksiprotocolv1.WireVersion)
	}
	electionID := transcript.GetElectionId()
	if electionID == "" {
		return fmt.Errorf("DKG transcript is missing an election id")
	}
	if len(transcript.GetTrusteeCommitments()) == 0 {
		return fmt.Errorf("DKG transcript has no trustee commitments")
	}

	stub := ctx.GetStub()

	// The election must exist, and the transcript must match its parameters.
	electionKey, err := stub.CreateCompositeKey(electionIndex, []string{electionID})
	if err != nil {
		return fmt.Errorf("build election key: %w", err)
	}
	electionRaw, err := stub.GetState(electionKey)
	if err != nil {
		return fmt.Errorf("read election state: %w", err)
	}
	if electionRaw == nil {
		return fmt.Errorf("no election found with id %q", electionID)
	}
	var params saksiprotocolv1.ElectionParameters
	if err := proto.Unmarshal(electionRaw, &params); err != nil {
		return fmt.Errorf("decode stored election parameters: %w", err)
	}
	if transcript.GetThreshold() != params.GetThreshold() {
		return fmt.Errorf("DKG transcript threshold %d does not match election threshold %d", transcript.GetThreshold(), params.GetThreshold())
	}
	if got, want := len(transcript.GetTrusteeCommitments()), len(params.GetTrusteeIds()); got != want {
		return fmt.Errorf("DKG transcript has %d trustee commitments, election has %d trustees", got, want)
	}

	dkgKey, err := stub.CreateCompositeKey(dkgIndex, []string{electionID})
	if err != nil {
		return fmt.Errorf("build DKG key: %w", err)
	}
	existing, err := stub.GetState(dkgKey)
	if err != nil {
		return fmt.Errorf("read DKG state: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("a DKG transcript is already published for election %q", electionID)
	}
	if err := stub.PutState(dkgKey, raw); err != nil {
		return fmt.Errorf("store DKG transcript: %w", err)
	}
	return nil
}

// GetDKGTranscript returns the hex-encoded DKG transcript recorded for an
// election id, or an error if none has been published.
func (s *SmartContract) GetDKGTranscript(ctx contractapi.TransactionContextInterface, electionID string) (string, error) {
	stub := ctx.GetStub()

	key, err := stub.CreateCompositeKey(dkgIndex, []string{electionID})
	if err != nil {
		return "", fmt.Errorf("build DKG key: %w", err)
	}
	raw, err := stub.GetState(key)
	if err != nil {
		return "", fmt.Errorf("read DKG state: %w", err)
	}
	if raw == nil {
		return "", fmt.Errorf("no DKG transcript found for election %q", electionID)
	}
	return hex.EncodeToString(raw), nil
}

// CloseElection transitions an election from open to closed, after which no
// further ballots are accepted and threshold decryption may begin. The election
// must exist and not already be closed.
func (s *SmartContract) CloseElection(ctx contractapi.TransactionContextInterface, electionID string) error {
	stub := ctx.GetStub()

	statusKey, err := stub.CreateCompositeKey(statusIndex, []string{electionID})
	if err != nil {
		return fmt.Errorf("build status key: %w", err)
	}
	status, err := stub.GetState(statusKey)
	if err != nil {
		return fmt.Errorf("read election status: %w", err)
	}
	if status == nil {
		return fmt.Errorf("no election found with id %q", electionID)
	}
	if string(status) == electionStatusClosed {
		return fmt.Errorf("election %q is already closed", electionID)
	}
	if err := stub.PutState(statusKey, []byte(electionStatusClosed)); err != nil {
		return fmt.Errorf("close election: %w", err)
	}
	return nil
}

// GetElectionStatus returns the lifecycle status ("open" or "closed") of an
// election, or an error if no such election exists.
func (s *SmartContract) GetElectionStatus(ctx contractapi.TransactionContextInterface, electionID string) (string, error) {
	stub := ctx.GetStub()

	statusKey, err := stub.CreateCompositeKey(statusIndex, []string{electionID})
	if err != nil {
		return "", fmt.Errorf("build status key: %w", err)
	}
	status, err := stub.GetState(statusKey)
	if err != nil {
		return "", fmt.Errorf("read election status: %w", err)
	}
	if status == nil {
		return "", fmt.Errorf("no election found with id %q", electionID)
	}
	return string(status), nil
}

// loadElection reads and decodes the stored ElectionParameters for an election
// id, returning an error if the election does not exist.
func loadElection(stub interface {
	CreateCompositeKey(string, []string) (string, error)
	GetState(string) ([]byte, error)
}, electionID string) (*saksiprotocolv1.ElectionParameters, error) {
	key, err := stub.CreateCompositeKey(electionIndex, []string{electionID})
	if err != nil {
		return nil, fmt.Errorf("build election key: %w", err)
	}
	raw, err := stub.GetState(key)
	if err != nil {
		return nil, fmt.Errorf("read election state: %w", err)
	}
	if raw == nil {
		return nil, fmt.Errorf("no election found with id %q", electionID)
	}
	var params saksiprotocolv1.ElectionParameters
	if err := proto.Unmarshal(raw, &params); err != nil {
		return nil, fmt.Errorf("decode stored election parameters: %w", err)
	}
	return &params, nil
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// SubmitPartialDecryption records a single trustee's partial decryption share
// for a contest. The arguments are the election id and the hex-encoded canonical
// protobuf encoding of a saksi.protocol.v1.PartialDecryption.
//
// Per the hybrid-verification split, the chaincode performs only the cheap,
// deterministic checks: supported wire version, the election exists and is
// closed (decryption begins after the poll closes), the contest id and trustee
// id belong to this election, the share is correctly shaped, and a Chaum-Pedersen
// proof is attached. The proof itself is verified off-chain by auditor clients.
// A trustee may submit at most one share per contest.
func (s *SmartContract) SubmitPartialDecryption(ctx contractapi.TransactionContextInterface, electionID string, partialHex string) error {
	if electionID == "" {
		return fmt.Errorf("missing election id")
	}
	raw, err := hex.DecodeString(partialHex)
	if err != nil {
		return fmt.Errorf("partial decryption is not valid hex: %w", err)
	}

	var partial saksiprotocolv1.PartialDecryption
	if err := proto.Unmarshal(raw, &partial); err != nil {
		return fmt.Errorf("decode partial decryption: %w", err)
	}

	if partial.GetVersion() != saksiprotocolv1.WireVersion {
		return fmt.Errorf("unsupported partial decryption version %d, want %d", partial.GetVersion(), saksiprotocolv1.WireVersion)
	}
	if partial.GetTrusteeId() == "" {
		return fmt.Errorf("partial decryption is missing a trustee id")
	}
	if partial.GetContestId() == "" {
		return fmt.Errorf("partial decryption is missing a contest id")
	}
	if len(partial.GetShare()) != ciphertextLen {
		return fmt.Errorf("partial decryption share is %d bytes, want %d", len(partial.GetShare()), ciphertextLen)
	}
	if partial.GetProof() == nil {
		return fmt.Errorf("partial decryption is missing a Chaum-Pedersen proof")
	}

	stub := ctx.GetStub()

	// The election must exist and be closed before decryption.
	statusKey, err := stub.CreateCompositeKey(statusIndex, []string{electionID})
	if err != nil {
		return fmt.Errorf("build status key: %w", err)
	}
	status, err := stub.GetState(statusKey)
	if err != nil {
		return fmt.Errorf("read election status: %w", err)
	}
	if status == nil {
		return fmt.Errorf("election %q does not exist", electionID)
	}
	if string(status) != electionStatusClosed {
		return fmt.Errorf("election %q is not closed; partial decryption is not yet allowed", electionID)
	}

	params, err := loadElection(stub, electionID)
	if err != nil {
		return err
	}
	if !contains(params.GetContestIds(), partial.GetContestId()) {
		return fmt.Errorf("contest %q is not part of election %q", partial.GetContestId(), electionID)
	}
	if !contains(params.GetTrusteeIds(), partial.GetTrusteeId()) {
		return fmt.Errorf("trustee %q is not part of election %q", partial.GetTrusteeId(), electionID)
	}

	partialKey, err := stub.CreateCompositeKey(partialDecIndex, []string{electionID, partial.GetContestId(), partial.GetTrusteeId()})
	if err != nil {
		return fmt.Errorf("build partial decryption key: %w", err)
	}
	existing, err := stub.GetState(partialKey)
	if err != nil {
		return fmt.Errorf("read partial decryption state: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("trustee %q already submitted a partial decryption for contest %q in election %q", partial.GetTrusteeId(), partial.GetContestId(), electionID)
	}
	if err := stub.PutState(partialKey, raw); err != nil {
		return fmt.Errorf("store partial decryption: %w", err)
	}
	return nil
}

// GetPartialDecryption returns the hex-encoded partial decryption recorded for an
// (electionID, contestID, trusteeID) triple, or an error if none exists.
func (s *SmartContract) GetPartialDecryption(ctx contractapi.TransactionContextInterface, electionID string, contestID string, trusteeID string) (string, error) {
	stub := ctx.GetStub()

	partialKey, err := stub.CreateCompositeKey(partialDecIndex, []string{electionID, contestID, trusteeID})
	if err != nil {
		return "", fmt.Errorf("build partial decryption key: %w", err)
	}
	raw, err := stub.GetState(partialKey)
	if err != nil {
		return "", fmt.Errorf("read partial decryption state: %w", err)
	}
	if raw == nil {
		return "", fmt.Errorf("no partial decryption found for election %q contest %q trustee %q", electionID, contestID, trusteeID)
	}
	return hex.EncodeToString(raw), nil
}

// PublishTally records the final tally for an election. The argument is the
// hex-encoded canonical protobuf encoding of a saksi.protocol.v1.TallyResult.
//
// On-chain checks: supported wire version, the election exists and is closed, one
// total per contest, and no tally has been published yet. The tally's correctness
// (that the totals match the homomorphic sum decrypted by the partial decryptions)
// is verified off-chain by auditor clients.
func (s *SmartContract) PublishTally(ctx contractapi.TransactionContextInterface, tallyHex string) error {
	raw, err := hex.DecodeString(tallyHex)
	if err != nil {
		return fmt.Errorf("tally is not valid hex: %w", err)
	}

	var tally saksiprotocolv1.TallyResult
	if err := proto.Unmarshal(raw, &tally); err != nil {
		return fmt.Errorf("decode tally: %w", err)
	}

	if tally.GetVersion() != saksiprotocolv1.WireVersion {
		return fmt.Errorf("unsupported tally version %d, want %d", tally.GetVersion(), saksiprotocolv1.WireVersion)
	}
	electionID := tally.GetElectionId()
	if electionID == "" {
		return fmt.Errorf("tally is missing an election id")
	}

	stub := ctx.GetStub()

	statusKey, err := stub.CreateCompositeKey(statusIndex, []string{electionID})
	if err != nil {
		return fmt.Errorf("build status key: %w", err)
	}
	status, err := stub.GetState(statusKey)
	if err != nil {
		return fmt.Errorf("read election status: %w", err)
	}
	if status == nil {
		return fmt.Errorf("election %q does not exist", electionID)
	}
	if string(status) != electionStatusClosed {
		return fmt.Errorf("election %q is not closed; a tally cannot be published yet", electionID)
	}

	params, err := loadElection(stub, electionID)
	if err != nil {
		return err
	}
	if got, want := len(tally.GetTotals()), len(params.GetContestIds()); got != want {
		return fmt.Errorf("tally has %d totals, election has %d contests", got, want)
	}

	tallyKey, err := stub.CreateCompositeKey(tallyIndex, []string{electionID})
	if err != nil {
		return fmt.Errorf("build tally key: %w", err)
	}
	existing, err := stub.GetState(tallyKey)
	if err != nil {
		return fmt.Errorf("read tally state: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("a tally is already published for election %q", electionID)
	}
	if err := stub.PutState(tallyKey, raw); err != nil {
		return fmt.Errorf("store tally: %w", err)
	}
	return nil
}

// GetTally returns the hex-encoded TallyResult published for an election id, or
// an error if none has been published.
func (s *SmartContract) GetTally(ctx contractapi.TransactionContextInterface, electionID string) (string, error) {
	stub := ctx.GetStub()

	tallyKey, err := stub.CreateCompositeKey(tallyIndex, []string{electionID})
	if err != nil {
		return "", fmt.Errorf("build tally key: %w", err)
	}
	raw, err := stub.GetState(tallyKey)
	if err != nil {
		return "", fmt.Errorf("read tally state: %w", err)
	}
	if raw == nil {
		return "", fmt.Errorf("no tally found for election %q", electionID)
	}
	return hex.EncodeToString(raw), nil
}
