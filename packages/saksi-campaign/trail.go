package campaign

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// chainReader is what the trail needs from the chain. *clientsdk.BulletinClient
// satisfies it.
type chainReader interface {
	GetElectionStatus(electionID string) (string, error)
	GetElection(electionID string) (string, error)
	GetDKGTranscript(electionID string) (string, error)
	GetTally(electionID string) (string, error)
	ListNullifiers(electionID string, pageSize int, bookmark string) (clientsdk.NullifierPage, error)
}

var _ chainReader = (*clientsdk.BulletinClient)(nil)

// trailResponse is the /api/trail/<electionID> JSON body.
type trailResponse struct {
	Sealed   bool         `json:"sealed"`
	Status   string       `json:"status,omitempty"`
	Election string       `json:"election_id"`
	Events   []TrailEvent `json:"events,omitempty"` // from trail.json (recorded receipts)
	Live     *liveProof   `json:"live,omitempty"`   // fresh chain reads proving the records exist NOW
	// Results is the decoded tally: contest id -> candidate label -> vote
	// count. Only ever populated alongside a non-empty Live.TallyHex (never
	// on a sealed response); nil (never an empty map) if decoding failed —
	// the failure is instead surfaced as Live.Partial/PartialReason.
	Results map[string]map[string]uint64 `json:"results,omitempty"`
}

// liveProof is a fresh, on-chain-only re-read taken at render time (never
// stale, never carries voter identity — none exists on-chain). Partial marks
// that one of the underlying reads failed, so NullifierRows/ChainHeight/TipHash
// may be stale zero-values rather than a real chain state of zero — without
// this flag those are indistinguishable.
type liveProof struct {
	StatusNow     string `json:"status_now"`
	NullifierRows int    `json:"nullifier_count"`
	TallyHex      string `json:"tally_hex,omitempty"`
	ChainHeight   uint64 `json:"chain_height"`
	TipHash       string `json:"tip_hash"`
	Partial       bool   `json:"partial,omitempty"`
	PartialReason string `json:"partial_reason,omitempty"`
}

const trailJSONFile = "trail.json"

// nullifierListPageSize mirrors client-sdk's own page cap; the trail's live
// proof only needs the count, so one page is enough for the demo scale this
// console targets.
const nullifierListPageSize = 10000

// buildTrail assembles the trail view for an election. The gate is fail-closed
// on the tally, not the lifecycle status: the chaincode never sets a "tallied"
// status (PublishTally requires — and leaves — status "closed"), so "has a
// tally been published" is answered by reader.GetTally succeeding with a
// non-empty result. GetElectionStatus is display-only (the Status /
// liveProof.StatusNow string), never the gate. operator bypasses the gate
// (handler already restricted it to loopback callers); any read error still
// fails closed for non-operator callers.
func buildTrail(reader chainReader, led clientsdk.Ledger, runDir, electionID string, operator bool) (trailResponse, error) {
	statusNow, statusErr := reader.GetElectionStatus(electionID)
	displayStatus := statusNow
	if statusErr != nil {
		log.Printf("trail: election %q GetElectionStatus: %v", electionID, statusErr)
		displayStatus = "unknown"
	}

	tallyHex, tallyErr := reader.GetTally(electionID)
	if tallyErr != nil {
		log.Printf("trail: election %q GetTally: %v", electionID, tallyErr)
	}
	tallied := tallyErr == nil && tallyHex != ""

	if !tallied && !operator {
		return trailResponse{Sealed: true, Status: displayStatus, Election: electionID}, nil
	}

	events, err := readTrailEvents(runDir)
	if err != nil {
		return trailResponse{}, err
	}

	var partial bool
	var partialReason string

	page, err := reader.ListNullifiers(electionID, nullifierListPageSize, "")
	if err != nil {
		log.Printf("trail: election %q ListNullifiers: %v", electionID, err)
		partial, partialReason = true, "nullifier count unavailable"
	}
	height, tip, err := led.ChainInfo()
	if err != nil {
		log.Printf("trail: election %q ChainInfo: %v", electionID, err)
		if !partial {
			partial, partialReason = true, "chain height/tip unavailable"
		}
	}

	// Decode the human-readable results alongside the raw tally_hex evidence.
	// Only attempted when a tally actually exists (tallied); a decode failure
	// never fails the response — it just leaves Results nil and adds a
	// partial reason, same as the other best-effort live reads above.
	var results map[string]map[string]uint64
	if tallied {
		paramsHex, paramsErr := reader.GetElection(electionID)
		if paramsErr != nil {
			log.Printf("trail: election %q GetElection: %v", electionID, paramsErr)
			if !partial {
				partial, partialReason = true, "tally decode failed"
			}
		} else if decoded, decErr := decodeTally(tallyHex, paramsHex); decErr != nil {
			log.Printf("trail: election %q decodeTally: %v", electionID, decErr)
			if !partial {
				partial, partialReason = true, "tally decode failed"
			}
		} else {
			results = decoded
		}
	}

	return trailResponse{
		Sealed:   false,
		Status:   displayStatus,
		Election: electionID,
		Events:   events,
		Live: &liveProof{
			StatusNow:     displayStatus,
			NullifierRows: len(page.Nullifiers),
			TallyHex:      tallyHex,
			ChainHeight:   height,
			TipHash:       hex.EncodeToString(tip),
			Partial:       partial,
			PartialReason: partialReason,
		},
		Results: results,
	}, nil
}

// decodeTally decodes a hex-encoded saksi.protocol.v1.TallyResult against its
// hex-encoded saksi.protocol.v1.ElectionParameters and returns the
// human-readable results: contest id -> candidate label -> vote count.
//
// Contest ids are position-qualified as "<position>/cand<N>" (one contest per
// candidate per position — see saksi-auditor's fixture generator), so each
// entry in TallyResult.totals is a single candidate's vote count; this
// splits that flat, index-aligned pair of slices back into the nested shape.
// A contest id with no "/" (not the demo generator's convention, but not
// invalid wire data either) is kept as its own section under the synthetic
// label "cand0" rather than treated as an error.
func decodeTally(tallyHex, paramsHex string) (map[string]map[string]uint64, error) {
	rawTally, err := hex.DecodeString(tallyHex)
	if err != nil {
		return nil, fmt.Errorf("tally is not valid hex: %w", err)
	}
	var tally pb.TallyResult
	if err := proto.Unmarshal(rawTally, &tally); err != nil {
		return nil, fmt.Errorf("decode tally: %w", err)
	}

	rawParams, err := hex.DecodeString(paramsHex)
	if err != nil {
		return nil, fmt.Errorf("election params are not valid hex: %w", err)
	}
	var params pb.ElectionParameters
	if err := proto.Unmarshal(rawParams, &params); err != nil {
		return nil, fmt.Errorf("decode election params: %w", err)
	}

	totals := tally.GetTotals()
	contestIDs := params.GetContestIds()
	if len(totals) != len(contestIDs) {
		return nil, fmt.Errorf("tally has %d totals, election has %d contests", len(totals), len(contestIDs))
	}

	results := make(map[string]map[string]uint64)
	for i, contestID := range contestIDs {
		position, candidate := splitContestID(contestID)
		if results[position] == nil {
			results[position] = make(map[string]uint64)
		}
		results[position][candidate] = totals[i]
	}
	return results, nil
}

// splitContestID splits a "<position>/cand<N>" contest id into its position
// and candidate label. A contest id with no "/" is its own position with the
// synthetic candidate label "cand0" (the only value that contest carries).
func splitContestID(contestID string) (position, candidate string) {
	if idx := strings.LastIndex(contestID, "/"); idx >= 0 {
		return contestID[:idx], contestID[idx+1:]
	}
	return contestID, "cand0"
}

// readTrailEvents reads trail.json from the run folder. A missing file is not
// an error — it just means no on-chain events have been recorded yet.
func readTrailEvents(runDir string) ([]TrailEvent, error) {
	data, err := os.ReadFile(filepath.Join(runDir, trailJSONFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read trail.json: %w", err)
	}
	var events []TrailEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("decode trail.json: %w", err)
	}
	return events, nil
}
