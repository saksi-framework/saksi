package campaign

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// The trustee console's view of a ceremony: the roster, plus the context a
// trustee needs to know WHAT they are about to help decrypt, plus a timeline.
//
// It embeds CeremonyState rather than restating it, so every field the wizard
// already reads stays at the same JSON path and web/wizard.html keeps working
// unchanged.

// CeremonyEvent is one line of the ceremony's audit log.
type CeremonyEvent struct {
	At    *time.Time `json:"at,omitempty"`
	Kind  string     `json:"kind"` // setup | trustee | published | chain
	Who   string     `json:"who,omitempty"`
	Text  string     `json:"text"`
	TxID  string     `json:"tx_id,omitempty"`
	Block uint64     `json:"block,omitempty"`
}

// CeremonyView is the GET /api/ceremony/<run> body.
type CeremonyView struct {
	CeremonyState
	ElectionID    string          `json:"election_id"`
	Name          string          `json:"name"`
	Mode          string          `json:"mode"`
	Positions     int             `json:"positions"`
	PositionIDs   []string        `json:"position_ids,omitempty"`
	Contests      int             `json:"contests"`
	BallotRecords int             `json:"ballot_records"`
	BallotsSHA256 string          `json:"ballots_sha256,omitempty"`
	DKGSHA256     string          `json:"dkg_sha256,omitempty"`
	Events        []CeremonyEvent `json:"events"`
}

// buildCeremonyView wraps the roster with the "what is being decrypted" context
// and the audit-log timeline. Best-effort throughout: a run whose bundle has
// not been generated yet still returns a usable roster.
func (s *Server) buildCeremonyView(rec RunRecord, dir string, state CeremonyState) CeremonyView {
	v := CeremonyView{
		CeremonyState: state,
		ElectionID:    rec.RunID,
		Name:          rec.Config.Name,
		Mode:          rec.Config.Mode,
		Positions:     rec.Config.Positions,
	}

	var h boardHeader
	if readJSON(filepath.Join(dir, "header.json"), &h) == nil {
		v.BallotRecords = h.N
		v.Contests, v.PositionIDs = contestShape(h.Params)
	}
	v.DKGSHA256, _, v.BallotsSHA256 = runDigests(dir)
	if v.Contests == 0 {
		v.Contests = rec.Config.Positions * rec.Config.Candidates
	}
	v.Events = ceremonyEvents(dir, state)
	return v
}

// contestShape decodes the election parameters for the contest count and the
// distinct position ids, so the console can say "President · Vice President ·
// Senator" from the wire data rather than from a hardcoded list.
func contestShape(paramsHex string) (int, []string) {
	if paramsHex == "" {
		return 0, nil
	}
	raw, err := hex.DecodeString(paramsHex)
	if err != nil {
		return 0, nil
	}
	var params saksiprotocolv1.ElectionParameters
	if err := proto.Unmarshal(raw, &params); err != nil {
		return 0, nil
	}
	ids := params.GetContestIds()
	seen := map[string]bool{}
	var positions []string
	for _, id := range ids {
		p, _ := splitContestID(id)
		if !seen[p] {
			seen[p] = true
			positions = append(positions, p)
		}
	}
	return len(ids), positions
}

// ceremonyEvents merges what the console recorded (ceremony.json timestamps)
// with what the ledger recorded (trail.json receipts), newest last.
//
// Offline there are no receipts, which is exactly why the timestamps were added
// to ceremony.json: without them an offline ceremony has no timeline at all.
func ceremonyEvents(dir string, state CeremonyState) []CeremonyEvent {
	events := make([]CeremonyEvent, 0, 8)

	if state.StartedAt != nil {
		events = append(events, CeremonyEvent{
			At: state.StartedAt, Kind: "setup",
			Text: "Ceremony opened — the election was set up and closed to new ballots",
		})
	}
	for _, t := range state.Trustees {
		if !t.Submitted {
			continue
		}
		text := fmt.Sprintf("contributed %d partial decryption(s)", t.Contests)
		if t.Contests == 0 {
			text = "contributed their partial decryptions"
		}
		events = append(events, CeremonyEvent{
			At: t.SubmittedAt, Kind: "trustee", Who: t.Name, Text: text,
		})
	}
	if state.Published {
		events = append(events, CeremonyEvent{
			At: state.PublishedAt, Kind: "published",
			Text: fmt.Sprintf("Threshold met (%d of %d) — tally published",
				state.Submitted, state.Threshold),
		})
	}

	// Ledger receipts. Ballot submissions are omitted: one line per ballot would
	// bury the ceremony in a log that is not about the ceremony.
	if trail, err := readTrailEvents(dir); err == nil {
		for _, ev := range trail {
			if ev.Event == "SubmitBallot" {
				continue
			}
			e := CeremonyEvent{
				Kind:  "chain",
				Text:  ev.Event + " committed on-chain",
				TxID:  ev.Receipt.TxID,
				Block: ev.Receipt.BlockNumber,
			}
			if ev.Ref != "" {
				e.Text = ev.Event + " (" + ev.Ref + ") committed on-chain"
			}
			if !ev.Receipt.Timestamp.IsZero() {
				t := ev.Receipt.Timestamp
				e.At = &t
			}
			events = append(events, e)
		}
	}

	// Stable order: timed entries chronologically, undated ones kept in the
	// order they were produced rather than sorted to the front as zero times.
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].At == nil || events[j].At == nil {
			return false
		}
		return events[i].At.Before(*events[j].At)
	})
	return events
}
