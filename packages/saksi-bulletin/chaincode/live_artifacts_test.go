package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// liveFixture is saksi-protocol/test-vectors/live-v1/election.json: one live
// election (5 trustees, threshold 3, 3 voters x 2 positions x 3 candidates)
// whose every artifact was produced by the `saksi-demo live` CLI as separate
// processes. Regenerate with
//
//	SAKSI_LIVE_FIXTURE_OUT=$PWD/packages/saksi-protocol/test-vectors/live-v1/election.json \
//	  cargo test -p saksi-demo --test live_cli full_pipeline_through_the_cli
type liveFixture struct {
	ElectionID           string   `json:"election_id"`
	Params               string   `json:"params"`
	DKG                  string   `json:"dkg"`
	Ballots              []string `json:"ballots"`
	Partials             []string `json:"partials"`
	Totals               []uint64 `json:"totals"`
	TallyThreeSignatures string   `json:"tally_three_signatures"`
	TallyTwoSignatures   string   `json:"tally_two_signatures"`
}

func loadLiveFixture(t *testing.T) liveFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "saksi-protocol", "test-vectors", "live-v1", "election.json"))
	if err != nil {
		t.Fatalf("read live fixture: %v", err)
	}
	var f liveFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse live fixture: %v", err)
	}
	if len(f.Ballots) != 6 || len(f.Partials) != 18 {
		t.Fatalf("live fixture has %d ballots and %d partials, want 6 and 18", len(f.Ballots), len(f.Partials))
	}
	return f
}

// TestLiveArtifactsPassTheChaincode runs a CLI-produced live election through
// the real contract, unchanged: every lifecycle call is accepted, and the
// three refusals the demo shows (a spent nullifier, a changed byte, a tally
// two trustees signed) are refused by the gate that should refuse them.
func TestLiveArtifactsPassTheChaincode(t *testing.T) {
	f := loadLiveFixture(t)
	sc, ctx := &SmartContract{}, newContext()

	if err := sc.CreateElection(ctx, f.Params); err != nil {
		t.Fatalf("CreateElection: %v", err)
	}
	if err := sc.PublishDKGTranscript(ctx, f.DKG); err != nil {
		t.Fatalf("PublishDKGTranscript: %v", err)
	}

	// One changed byte in a CDS response, before the genuine ballot spends
	// its nullifier: refused by the CDS gate.
	tampered := editBallotHex(t, f.Ballots[0], func(b *saksiprotocolv1.Ballot) {
		b.WellFormednessProofs[0].Branches[0].Response[0] ^= 0x01
	})
	if gate := gateIDOf(sc.SubmitBallot(ctx, tampered)); gate != "cds" {
		t.Fatalf("ballot with one changed byte: gate %q, want cds", gate)
	}

	for i, b := range f.Ballots {
		if err := sc.SubmitBallot(ctx, b); err != nil {
			t.Fatalf("SubmitBallot[%d]: %v", i, err)
		}
	}
	if gate := gateIDOf(sc.SubmitBallot(ctx, f.Ballots[0])); gate != "nullifier" {
		t.Fatalf("resubmitted ballot: gate %q, want nullifier", gate)
	}

	if err := sc.CloseElection(ctx, f.ElectionID); err != nil {
		t.Fatalf("CloseElection: %v", err)
	}
	for i, p := range f.Partials {
		if err := sc.SubmitPartialDecryption(ctx, f.ElectionID, p); err != nil {
			t.Fatalf("SubmitPartialDecryption[%d]: %v", i, err)
		}
	}

	err := sc.PublishTally(ctx, f.TallyTwoSignatures)
	if err == nil || !strings.Contains(err.Error(), "threshold is 3") {
		t.Fatalf("tally with 2 signatures: %v, want a threshold refusal", err)
	}
	if err := sc.PublishTally(ctx, f.TallyThreeSignatures); err != nil {
		t.Fatalf("PublishTally with 3 signatures: %v", err)
	}

	got, err := sc.GetTally(ctx, f.ElectionID)
	if err != nil {
		t.Fatalf("GetTally: %v", err)
	}
	raw, _ := hex.DecodeString(got)
	var tally saksiprotocolv1.TallyResult
	if err := proto.Unmarshal(raw, &tally); err != nil {
		t.Fatalf("decode stored tally: %v", err)
	}
	if len(tally.GetTotals()) != len(f.Totals) {
		t.Fatalf("stored tally has %d totals, want %d", len(tally.GetTotals()), len(f.Totals))
	}
	for i, want := range f.Totals {
		if tally.GetTotals()[i] != want {
			t.Fatalf("stored total %d = %d, want %d", i, tally.GetTotals()[i], want)
		}
	}
}
