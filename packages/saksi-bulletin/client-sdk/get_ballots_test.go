package clientsdk

import (
	"errors"
	"testing"
)

func TestGetBallotsMarshalsTheNullifierListAndDecodesThePage(t *testing.T) {
	fc := &fakeContract{evalReturn: []byte(`["aa","","cc"]`)}
	client := NewBulletinClient(fc)

	got, err := client.GetBallots("election-2026", []string{"n0", "n1", "n2"})
	if err != nil {
		t.Fatalf("GetBallots: %v", err)
	}
	if fc.submitName != "GetBallots" {
		t.Fatalf("transaction name = %q, want GetBallots", fc.submitName)
	}
	want := []string{"election-2026", `["n0","n1","n2"]`}
	if len(fc.submitArgs) != 2 || fc.submitArgs[0] != want[0] || fc.submitArgs[1] != want[1] {
		t.Fatalf("args = %v, want %v", fc.submitArgs, want)
	}
	// The absent ballot keeps its slot, so entry i still answers nullifier i.
	if len(got) != 3 || got[0] != "aa" || got[1] != "" || got[2] != "cc" {
		t.Fatalf("ballots = %v, want [aa  cc]", got)
	}
}

// TestGetBallotsRejectsAShortPage guards the positional contract: a response
// that does not line up with the request would silently mis-attribute ballots
// to nullifiers.
func TestGetBallotsRejectsAShortPage(t *testing.T) {
	fc := &fakeContract{evalReturn: []byte(`["aa"]`)}
	client := NewBulletinClient(fc)

	if _, err := client.GetBallots("election-2026", []string{"n0", "n1"}); err == nil {
		t.Fatal("a page with fewer entries than nullifiers must be rejected")
	}
}

// TestUnknownChaincodeFunction is what lets the ledger dump fall back to
// per-ballot reads against a deployment that predates GetBallots, instead of
// failing a whole run over a chaincode version.
func TestUnknownChaincodeFunction(t *testing.T) {
	unknown := []error{
		errors.New("Function GetBallots not found in contract SmartContract"),
		errors.New("chaincode response 500, function not found"),
	}
	for _, err := range unknown {
		if !UnknownChaincodeFunction(err) {
			t.Fatalf("should be recognised as an unknown function: %v", err)
		}
	}
	known := []error{nil, errors.New("no ballot found for election \"e\" nullifier \"n\""), errors.New("peer unavailable")}
	for _, err := range known {
		if UnknownChaincodeFunction(err) {
			t.Fatalf("should NOT be read as an unknown function: %v", err)
		}
	}
}
