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

// wasmFixture is a live election in which some ballots were built by the
// phone's WebAssembly (@saksi/wasm, run under node by tools/live/test-wasm.sh)
// and the rest, the DKG, the partials and the tally by the `saksi-demo live`
// CLI. test-wasm.sh writes a fresh one on every run and points
// SAKSI_WASM_FIXTURE at it; without that variable the committed copy
// saksi-protocol/test-vectors/live-v1/wasm-election.json is read.
const (
	wasmFixtureSchema = "saksi-live-wasm-fixture-v1"
	regenerateWasm    = "regenerate it with tools/live/test-wasm.sh --write-fixture"
)

type wasmFixture struct {
	Schema               string   `json:"schema"`
	ElectionID           string   `json:"election_id"`
	Params               string   `json:"params"`
	DKG                  string   `json:"dkg"`
	Ballots              []string `json:"ballots"`
	WasmBallots          []int    `json:"wasm_ballots"`
	ChallengedBallot     string   `json:"challenged_ballot"`
	Partials             []string `json:"partials"`
	Totals               []uint64 `json:"totals"`
	TallyThreeSignatures string   `json:"tally_three_signatures"`
	TallyTwoSignatures   string   `json:"tally_two_signatures"`
}

func loadWasmFixture(t *testing.T) wasmFixture {
	t.Helper()
	path := os.Getenv("SAKSI_WASM_FIXTURE")
	if path == "" {
		path = filepath.Join("..", "..", "saksi-protocol", "test-vectors", "live-v1", "wasm-election.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read wasm fixture %s: %v", path, err)
	}
	var f wasmFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse wasm fixture: %v", err)
	}
	if f.Schema != wasmFixtureSchema {
		t.Fatalf("wasm fixture schema %q, want %q: %s", f.Schema, wasmFixtureSchema, regenerateWasm)
	}
	if len(f.WasmBallots) == 0 || len(f.Ballots) != 6 || f.ChallengedBallot == "" {
		t.Fatalf("wasm fixture has %d ballots (%d from wasm) and challenged=%t: %s",
			len(f.Ballots), len(f.WasmBallots), f.ChallengedBallot != "", regenerateWasm)
	}
	return f
}

// TestWasmBuiltBallotsPassTheChaincode submits ballots the phone's
// WebAssembly built to the real contract, unchanged, first and on their own,
// then completes the election with the CLI-built ballots. A ballot the voter
// challenged (Benaloh) carries the same nullifier as the one the voter cast,
// so once the cast one is recorded the challenged one is refused at the
// nullifier gate.
func TestWasmBuiltBallotsPassTheChaincode(t *testing.T) {
	f := loadWasmFixture(t)
	sc, ctx := &SmartContract{}, newContext()

	if err := sc.CreateElection(ctx, f.Params); err != nil {
		t.Fatalf("CreateElection: %v", err)
	}
	if err := sc.PublishDKGTranscript(ctx, f.DKG); err != nil {
		t.Fatalf("PublishDKGTranscript: %v", err)
	}

	// A wasm-built ballot with one changed CDS byte, while its nullifier is
	// still unspent: refused by the CDS gate.
	tampered := editBallotHex(t, f.ChallengedBallot, func(b *saksiprotocolv1.Ballot) {
		b.WellFormednessProofs[0].Branches[0].Response[0] ^= 0x01
	})
	if gate := gateIDOf(sc.SubmitBallot(ctx, tampered)); gate != "cds" {
		t.Fatalf("wasm ballot with one changed byte: gate %q, want cds", gate)
	}

	isWasm := map[int]bool{}
	for _, i := range f.WasmBallots {
		isWasm[i] = true
		if err := sc.SubmitBallot(ctx, f.Ballots[i]); err != nil {
			t.Fatalf("SubmitBallot of wasm-built ballot %d: %v (if the live wire format changed, %s)", i, err, regenerateWasm)
		}
	}
	for i, b := range f.Ballots {
		if isWasm[i] {
			continue
		}
		if err := sc.SubmitBallot(ctx, b); err != nil {
			t.Fatalf("SubmitBallot[%d]: %v (%s)", i, err, regenerateWasm)
		}
	}

	if gate := gateIDOf(sc.SubmitBallot(ctx, f.ChallengedBallot)); gate != "nullifier" {
		t.Fatalf("challenged ballot after the cast one: gate %q, want nullifier", gate)
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
