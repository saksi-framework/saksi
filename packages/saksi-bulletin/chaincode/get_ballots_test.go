package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// seedBallots writes n ballots for electionID straight into state, under the
// same composite key SubmitBallot uses, and returns their nullifiers in the
// order they were written. The CDS/credential machinery SubmitBallot runs is
// not what GetBallots is being tested on, so it is skipped here; GetBallot's
// own round-trip test covers the key shape.
func seedBallots(t *testing.T, ctx *fakeContext, electionID string, n int) []string {
	t.Helper()
	nullifiers := make([]string, 0, n)
	for i := 0; i < n; i++ {
		nullifier := fmt.Sprintf("%064x", i+1)
		key, err := ctx.stub.CreateCompositeKey(ballotIndex, []string{electionID, nullifier})
		if err != nil {
			t.Fatalf("build ballot key: %v", err)
		}
		if err := ctx.stub.PutState(key, []byte{byte(i + 1), 0xAA}); err != nil {
			t.Fatalf("seed ballot: %v", err)
		}
		nullifiers = append(nullifiers, nullifier)
	}
	ctx.stub.puts = 0 // seeding does not count against the evaluate-only check
	return nullifiers
}

// getBallots calls the contract and decodes its JSON array.
func getBallots(t *testing.T, sc *SmartContract, ctx *fakeContext, electionID string, nullifiers []string) []string {
	t.Helper()
	arg, err := json.Marshal(nullifiers)
	if err != nil {
		t.Fatal(err)
	}
	out, err := sc.GetBallots(ctx, electionID, string(arg))
	if err != nil {
		t.Fatalf("GetBallots: %v", err)
	}
	var ballots []string
	if err := json.Unmarshal([]byte(out), &ballots); err != nil {
		t.Fatalf("decode ballot page %q: %v", out, err)
	}
	return ballots
}

// TestGetBallotsPreservesRequestOrder is the contract the ledger dump depends
// on: entry i of the response is the ballot for nullifier i of the request,
// whatever order the keys sort in.
func TestGetBallotsPreservesRequestOrder(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	nullifiers := seedBallots(t, ctx, "election-2026", 5)

	// Ask in reverse: a response that came back in key order would fail here.
	asked := []string{nullifiers[4], nullifiers[0], nullifiers[3], nullifiers[1], nullifiers[2]}
	got := getBallots(t, sc, ctx, "election-2026", asked)
	if len(got) != len(asked) {
		t.Fatalf("got %d ballots, want %d", len(got), len(asked))
	}
	for i, nullifier := range asked {
		want, err := sc.GetBallot(ctx, "election-2026", nullifier)
		if err != nil {
			t.Fatalf("GetBallot %s: %v", nullifier, err)
		}
		if got[i] != want {
			t.Fatalf("ballot %d = %s, want %s (order not preserved)", i, got[i], want)
		}
	}
}

// TestGetBallotsAgreesWithGetBallot pins the batched read to the single read:
// the same bytes, hex-encoded the same way.
func TestGetBallotsAgreesWithGetBallot(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	nullifiers := seedBallots(t, ctx, "election-2026", 3)

	batched := getBallots(t, sc, ctx, "election-2026", nullifiers)
	for i, nullifier := range nullifiers {
		one, err := sc.GetBallot(ctx, "election-2026", nullifier)
		if err != nil {
			t.Fatalf("GetBallot %s: %v", nullifier, err)
		}
		if batched[i] != one {
			t.Fatalf("batched %q != single %q", batched[i], one)
		}
		if _, err := hex.DecodeString(batched[i]); err != nil {
			t.Fatalf("batched ballot %d is not hex: %v", i, err)
		}
	}
}

// TestGetBallotsReportsUnknownNullifierAsEmpty documents the absence contract:
// a nullifier the chain holds nothing for yields an empty entry at its
// position, and does not fail the page.
func TestGetBallotsReportsUnknownNullifierAsEmpty(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	nullifiers := seedBallots(t, ctx, "election-2026", 2)

	got := getBallots(t, sc, ctx, "election-2026",
		[]string{nullifiers[0], "deadbeef", nullifiers[1]})
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3 (an absent ballot still occupies its slot)", len(got))
	}
	if got[1] != "" {
		t.Fatalf("unknown nullifier returned %q, want an empty entry", got[1])
	}
	if got[0] == "" || got[2] == "" {
		t.Fatalf("a present ballot came back empty: %v", got)
	}

	// A nullifier from another election is absent too — the key is scoped.
	other := getBallots(t, sc, ctx, "election-other", nullifiers)
	for i, b := range other {
		if b != "" {
			t.Fatalf("entry %d leaked across elections: %q", i, b)
		}
	}
}

// TestGetBallotsEnforcesThePageCap is the reason the function is paged at all:
// one call can never be asked to pull an unbounded slice of the population.
func TestGetBallotsEnforcesThePageCap(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()

	atCap := make([]string, maxBallotBatchSize)
	for i := range atCap {
		atCap[i] = fmt.Sprintf("%064x", i+1)
	}
	if _, err := sc.GetBallots(ctx, "election-2026", mustJSON(t, atCap)); err != nil {
		t.Fatalf("a page exactly at the cap must be accepted: %v", err)
	}

	overCap := append(atCap, fmt.Sprintf("%064x", maxBallotBatchSize+1))
	_, err := sc.GetBallots(ctx, "election-2026", mustJSON(t, overCap))
	if err == nil {
		t.Fatalf("a page of %d must be rejected (cap is %d)", len(overCap), maxBallotBatchSize)
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("the cap error should say so: %v", err)
	}
}

// TestGetBallotsWritesNoState is the evaluate-only guarantee: a read that put
// anything on the ledger would have to be ordered, and would turn every dump
// page into a block.
func TestGetBallotsWritesNoState(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	nullifiers := seedBallots(t, ctx, "election-2026", 4)

	getBallots(t, sc, ctx, "election-2026", append(nullifiers, "deadbeef"))
	if ctx.stub.puts != 0 {
		t.Fatalf("GetBallots made %d state writes, want 0", ctx.stub.puts)
	}
}

// TestGetBallotsRejectsMalformedInput keeps the argument a JSON array; an empty
// page is legal and comes back as an empty array, not null.
func TestGetBallotsRejectsMalformedInput(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()

	if _, err := sc.GetBallots(ctx, "election-2026", "not json"); err == nil {
		t.Fatal("a non-JSON nullifier list should be rejected")
	}
	out, err := sc.GetBallots(ctx, "election-2026", "[]")
	if err != nil {
		t.Fatalf("an empty page is legal: %v", err)
	}
	if out != "[]" {
		t.Fatalf("an empty page marshalled as %q, want []", out)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
