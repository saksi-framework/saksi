package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/saksi-framework/saksi/packages/saksi-bulletin/chaincode/cdsverify"
	"github.com/saksi-framework/saksi/packages/saksi-bulletin/chaincode/credverify"
	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// contestIndicesForPosition returns the indices into contestIDs of the contests
// a ballot in positionID covers (ADR-0007 one-record-per-position). Contests are
// position-qualified as "<position_id>/<candidate_idx>", so a ballot carries
// exactly its position's candidate ciphertexts, aligned in order to the returned
// indices. An empty positionID is the legacy single-position path: the ballot
// covers all contests. This mirrors the Rust auditor's
// `contest_indices_for_position` (packages/saksi-auditor/src/lib.rs) byte-for-
// byte so the prover, off-chain auditor, and this endorsement gate agree.
// Order-preserving and allocation-deterministic — endorsement-safe.
func contestIndicesForPosition(contestIDs []string, positionID string) []int {
	if positionID == "" {
		idxs := make([]int, len(contestIDs))
		for i := range contestIDs {
			idxs[i] = i
		}
		return idxs
	}
	prefix := positionID + "/"
	idxs := make([]int, 0, len(contestIDs))
	for i, c := range contestIDs {
		if strings.HasPrefix(c, prefix) {
			idxs = append(idxs, i)
		}
	}
	return idxs
}

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
	// signaturePrefixLen is the length of the issuer-signature prefix at the
	// start of a credential presentation_proof: R' (32) || s (32).
	signaturePrefixLen = 64
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
// submission — wire version, ciphertext structural shape, credential-signature
// verification, and nullifier uniqueness — and records the ballot. The heavy
// NIZK well-formedness proofs are verified off-chain by auditor clients reading
// the bulletin board.
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
//   - the issuer Schnorr signature on the credential commitment verifies
//     (ristretto255 + a Merlin-compatible challenge, byte-identical to the Rust
//     saksi-credentials signer — see the credverify package);
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

	// Verify the issuer Schnorr signature on the credential commitment on-chain
	// (the locked hybrid-verification split puts credential-signature checks on
	// the bulletin board). The presentation_proof envelope begins with the
	// 64-byte signature prefix R' (32) || s (32); the remaining bytes (the
	// Chaum-Pedersen NIZK) are verified off-chain by the auditor.
	proof := presentation.GetPresentationProof()
	if len(proof) < signaturePrefixLen {
		return fmt.Errorf(
			"ballot credential presentation_proof is %d bytes, shorter than the %d-byte signature prefix",
			len(proof), signaturePrefixLen,
		)
	}
	if err := credverify.VerifyIssuerSignature(
		presentation.GetIssuerPublicKey(),
		presentation.GetCredentialCommitment(),
		proof[:ciphertextLen],
		proof[ciphertextLen:signaturePrefixLen],
	); err != nil {
		return fmt.Errorf("credential signature verification failed: %w", err)
	}

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

	// Verify each contest's CDS well-formedness OR-proof on-chain (ADR-0007,
	// superseding the off-chain-only split). The joint election public key is
	// derived from the published DKG transcript; the CDS Fiat-Shamir context is
	// bound to (election_id, contest_id, nullifier) — all reconstructible here
	// at endorsement, so verification is deterministic and order-independent.
	params, err := loadElection(stub, ballot.GetElectionId())
	if err != nil {
		return err
	}
	contestIDs := params.GetContestIds()
	// The contests this record's position covers (ADR-0007 one-record-per-
	// position; empty position_id = legacy whole-ballot). Ciphertexts/proofs
	// align in order to these indices.
	contestIdxs := contestIndicesForPosition(contestIDs, ballot.GetPositionId())
	if len(contestIdxs) == 0 {
		return fmt.Errorf(
			"ballot position %q matches no contest in election %q",
			ballot.GetPositionId(), ballot.GetElectionId(),
		)
	}
	if len(ballot.GetCiphertexts()) != len(contestIdxs) || len(ballot.GetWellFormednessProofs()) != len(contestIdxs) {
		return fmt.Errorf(
			"ballot (position %q) has %d ciphertexts / %d well-formedness proofs, expected %d for that position in election %q",
			ballot.GetPositionId(), len(ballot.GetCiphertexts()), len(ballot.GetWellFormednessProofs()), len(contestIdxs), ballot.GetElectionId(),
		)
	}

	dkgKey, err := stub.CreateCompositeKey(dkgIndex, []string{ballot.GetElectionId()})
	if err != nil {
		return fmt.Errorf("build DKG key: %w", err)
	}
	dkgRaw, err := stub.GetState(dkgKey)
	if err != nil {
		return fmt.Errorf("read DKG transcript state: %w", err)
	}
	if dkgRaw == nil {
		return fmt.Errorf("election %q has no published DKG transcript; ballot well-formedness cannot be verified", ballot.GetElectionId())
	}
	var transcript saksiprotocolv1.DKGTranscript
	if err := proto.Unmarshal(dkgRaw, &transcript); err != nil {
		return fmt.Errorf("decode stored DKG transcript: %w", err)
	}
	electionPK, err := deriveElectionPublicKey(&transcript)
	if err != nil {
		return fmt.Errorf("derive election public key: %w", err)
	}

	nullifierBytes := presentation.GetNullifier().GetValue()
	for local, globalIdx := range contestIdxs {
		contestID := contestIDs[globalIdx]
		ciphertext := ballot.GetCiphertexts()[local]
		proofMsg := ballot.GetWellFormednessProofs()[local]
		if proofMsg.GetVersion() != saksiprotocolv1.WireVersion {
			return fmt.Errorf(
				"contest %q: unsupported CDS proof version %d, want %d",
				contestID, proofMsg.GetVersion(), saksiprotocolv1.WireVersion,
			)
		}
		wireBranches := proofMsg.GetBranches()
		branches := make([]cdsverify.Branch, len(wireBranches))
		for j, b := range wireBranches {
			branches[j] = cdsverify.Branch{
				CommitmentA: b.GetCommitmentA(),
				CommitmentB: b.GetCommitmentB(),
				Challenge:   b.GetChallenge(),
				Response:    b.GetResponse(),
			}
		}
		if err := cdsverify.VerifyBinaryCDS(
			ballot.GetElectionId(), contestID, nullifierBytes,
			electionPK, ciphertext.GetPad(), ciphertext.GetData(), branches,
		); err != nil {
			return fmt.Errorf("contest %q CDS well-formedness proof failed: %w", contestID, err)
		}
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

// maxNullifierPageSize caps a single ListNullifiers page. Fabric peers refuse
// range queries larger than core.yaml's `totalQueryLimit` (default 100000);
// this cap keeps every page well under that default so the resume path works on
// an unmodified peer, on every box, without config drift.
const maxNullifierPageSize = 10000

// NullifierPage is one page of the nullifiers committed for an election.
// NextBookmark is the cursor that starts the following page, and is empty
// exactly when this page is the last one.
type NullifierPage struct {
	Nullifiers   []string `json:"nullifiers"`
	NextBookmark string   `json:"next_bookmark"`
}

// ListNullifiers returns one page of the nullifiers committed for electionID,
// in lexical key order, plus the bookmark for the next page.
//
// This is the chain-authoritative source the campaign runner uses to resume an
// interrupted submission run: the chain — not a local file — decides which
// ballots are already committed, so a resumed run never re-submits a committed
// ballot (a re-submit is nullifier-rejected and would falsely count as a drop).
//
// Pagination is mandatory, not a nicety. An unpaginated range query silently
// truncates at the peer's totalQueryLimit, which would under-report committed
// ballots at the 483k/1M tiers and make resume redo work it already did.
//
//	page 1            page 2            page 3
//	[n0 n1]  --bm-->  [n2 n3]  --bm-->  [n4]  --""--> done
func (s *SmartContract) ListNullifiers(
	ctx contractapi.TransactionContextInterface, electionID string, pageSize int32, bookmark string,
) (string, error) {
	if pageSize <= 0 {
		return "", fmt.Errorf("pageSize must be positive, got %d", pageSize)
	}
	if pageSize > maxNullifierPageSize {
		return "", fmt.Errorf(
			"pageSize %d exceeds the %d cap (peer totalQueryLimit)", pageSize, maxNullifierPageSize,
		)
	}

	stub := ctx.GetStub()
	iter, meta, err := stub.GetStateByPartialCompositeKeyWithPagination(
		nullifierIndex, []string{electionID}, pageSize, bookmark,
	)
	if err != nil {
		return "", fmt.Errorf("query nullifiers for election %q: %w", electionID, err)
	}
	defer func() { _ = iter.Close() }()

	// Non-nil empty slice so an exhausted election marshals as [], not null.
	page := NullifierPage{Nullifiers: []string{}}
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return "", fmt.Errorf("read nullifier record: %w", err)
		}
		_, attrs, err := stub.SplitCompositeKey(kv.GetKey())
		if err != nil {
			return "", fmt.Errorf("split nullifier key: %w", err)
		}
		if len(attrs) != 2 {
			return "", fmt.Errorf("nullifier key has %d attributes, want 2 (electionID, nullifier)", len(attrs))
		}
		page.Nullifiers = append(page.Nullifiers, attrs[1])
	}
	if meta != nil {
		page.NextBookmark = meta.GetBookmark()
	}

	raw, err := json.Marshal(page)
	if err != nil {
		return "", fmt.Errorf("encode nullifier page: %w", err)
	}
	return string(raw), nil
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
