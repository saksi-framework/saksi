package clientsdk

import (
	"errors"
	"testing"
)

type fakeContract struct {
	submitName string
	submitArgs []string
	evalReturn []byte
	evalErr    error
	submitErr  error
}

func (f *fakeContract) SubmitTransaction(name string, args ...string) ([]byte, error) {
	f.submitName = name
	f.submitArgs = args
	return nil, f.submitErr
}

func (f *fakeContract) EvaluateTransaction(name string, args ...string) ([]byte, error) {
	f.submitName = name
	f.submitArgs = args
	return f.evalReturn, f.evalErr
}

func TestSubmitBallotInvokesSubmitTransaction(t *testing.T) {
	fc := &fakeContract{}
	client := NewBulletinClient(fc)

	if err := client.SubmitBallot("0a0b0c"); err != nil {
		t.Fatalf("SubmitBallot: %v", err)
	}
	if fc.submitName != "SubmitBallot" {
		t.Fatalf("transaction name = %q, want SubmitBallot", fc.submitName)
	}
	if len(fc.submitArgs) != 1 || fc.submitArgs[0] != "0a0b0c" {
		t.Fatalf("args = %v, want [0a0b0c]", fc.submitArgs)
	}
}

func TestSubmitBallotRejectsEmpty(t *testing.T) {
	if err := NewBulletinClient(&fakeContract{}).SubmitBallot(""); err == nil {
		t.Fatal("SubmitBallot should reject empty input")
	}
}

func TestSubmitBallotWrapsError(t *testing.T) {
	fc := &fakeContract{submitErr: errors.New("endorsement failed")}
	err := NewBulletinClient(fc).SubmitBallot("0a")
	if err == nil || !errors.Is(err, fc.submitErr) {
		t.Fatalf("expected wrapped endorsement error, got: %v", err)
	}
}

func TestGetBallotReturnsPayloadAsString(t *testing.T) {
	fc := &fakeContract{evalReturn: []byte("deadbeef")}
	got, err := NewBulletinClient(fc).GetBallot("election-2026", "0d0d")
	if err != nil {
		t.Fatalf("GetBallot: %v", err)
	}
	if got != "deadbeef" {
		t.Fatalf("payload = %q, want deadbeef", got)
	}
	if fc.submitName != "GetBallot" {
		t.Fatalf("transaction name = %q, want GetBallot", fc.submitName)
	}
	if len(fc.submitArgs) != 2 || fc.submitArgs[0] != "election-2026" || fc.submitArgs[1] != "0d0d" {
		t.Fatalf("args = %v, want [election-2026 0d0d]", fc.submitArgs)
	}
}
