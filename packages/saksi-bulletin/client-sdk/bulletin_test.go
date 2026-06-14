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

func TestCreateElectionInvokesSubmitTransaction(t *testing.T) {
	fc := &fakeContract{}
	if err := NewBulletinClient(fc).CreateElection("0a0b0c"); err != nil {
		t.Fatalf("CreateElection: %v", err)
	}
	if fc.submitName != "CreateElection" {
		t.Fatalf("transaction name = %q, want CreateElection", fc.submitName)
	}
	if len(fc.submitArgs) != 1 || fc.submitArgs[0] != "0a0b0c" {
		t.Fatalf("args = %v, want [0a0b0c]", fc.submitArgs)
	}
}

func TestCreateElectionRejectsEmpty(t *testing.T) {
	if err := NewBulletinClient(&fakeContract{}).CreateElection(""); err == nil {
		t.Fatal("CreateElection should reject empty input")
	}
}

func TestGetElectionReturnsPayloadAsString(t *testing.T) {
	fc := &fakeContract{evalReturn: []byte("cafe")}
	got, err := NewBulletinClient(fc).GetElection("election-2026")
	if err != nil {
		t.Fatalf("GetElection: %v", err)
	}
	if got != "cafe" {
		t.Fatalf("payload = %q, want cafe", got)
	}
	if fc.submitName != "GetElection" {
		t.Fatalf("transaction name = %q, want GetElection", fc.submitName)
	}
	if len(fc.submitArgs) != 1 || fc.submitArgs[0] != "election-2026" {
		t.Fatalf("args = %v, want [election-2026]", fc.submitArgs)
	}
}

func TestPublishDKGTranscriptInvokesSubmitTransaction(t *testing.T) {
	fc := &fakeContract{}
	if err := NewBulletinClient(fc).PublishDKGTranscript("0a0b0c"); err != nil {
		t.Fatalf("PublishDKGTranscript: %v", err)
	}
	if fc.submitName != "PublishDKGTranscript" {
		t.Fatalf("transaction name = %q, want PublishDKGTranscript", fc.submitName)
	}
	if len(fc.submitArgs) != 1 || fc.submitArgs[0] != "0a0b0c" {
		t.Fatalf("args = %v, want [0a0b0c]", fc.submitArgs)
	}
}

func TestPublishDKGTranscriptRejectsEmpty(t *testing.T) {
	if err := NewBulletinClient(&fakeContract{}).PublishDKGTranscript(""); err == nil {
		t.Fatal("PublishDKGTranscript should reject empty input")
	}
}

func TestGetDKGTranscriptReturnsPayloadAsString(t *testing.T) {
	fc := &fakeContract{evalReturn: []byte("beef")}
	got, err := NewBulletinClient(fc).GetDKGTranscript("election-2026")
	if err != nil {
		t.Fatalf("GetDKGTranscript: %v", err)
	}
	if got != "beef" {
		t.Fatalf("payload = %q, want beef", got)
	}
	if fc.submitName != "GetDKGTranscript" {
		t.Fatalf("transaction name = %q, want GetDKGTranscript", fc.submitName)
	}
}

func TestCloseElectionInvokesSubmitTransaction(t *testing.T) {
	fc := &fakeContract{}
	if err := NewBulletinClient(fc).CloseElection("election-2026"); err != nil {
		t.Fatalf("CloseElection: %v", err)
	}
	if fc.submitName != "CloseElection" {
		t.Fatalf("transaction name = %q, want CloseElection", fc.submitName)
	}
	if len(fc.submitArgs) != 1 || fc.submitArgs[0] != "election-2026" {
		t.Fatalf("args = %v, want [election-2026]", fc.submitArgs)
	}
}

func TestGetElectionStatusReturnsPayloadAsString(t *testing.T) {
	fc := &fakeContract{evalReturn: []byte("open")}
	got, err := NewBulletinClient(fc).GetElectionStatus("election-2026")
	if err != nil {
		t.Fatalf("GetElectionStatus: %v", err)
	}
	if got != "open" {
		t.Fatalf("payload = %q, want open", got)
	}
	if fc.submitName != "GetElectionStatus" {
		t.Fatalf("transaction name = %q, want GetElectionStatus", fc.submitName)
	}
}

func TestSubmitPartialDecryptionInvokesSubmitTransaction(t *testing.T) {
	fc := &fakeContract{}
	if err := NewBulletinClient(fc).SubmitPartialDecryption("election-2026", "0a0b"); err != nil {
		t.Fatalf("SubmitPartialDecryption: %v", err)
	}
	if fc.submitName != "SubmitPartialDecryption" {
		t.Fatalf("transaction name = %q, want SubmitPartialDecryption", fc.submitName)
	}
	if len(fc.submitArgs) != 2 || fc.submitArgs[0] != "election-2026" || fc.submitArgs[1] != "0a0b" {
		t.Fatalf("args = %v, want [election-2026 0a0b]", fc.submitArgs)
	}
}

func TestSubmitPartialDecryptionRejectsEmpty(t *testing.T) {
	c := NewBulletinClient(&fakeContract{})
	if err := c.SubmitPartialDecryption("", "0a"); err == nil {
		t.Fatal("SubmitPartialDecryption should reject empty election id")
	}
	if err := c.SubmitPartialDecryption("election-2026", ""); err == nil {
		t.Fatal("SubmitPartialDecryption should reject empty partial hex")
	}
}

func TestGetPartialDecryptionReturnsPayloadAsString(t *testing.T) {
	fc := &fakeContract{evalReturn: []byte("feed")}
	got, err := NewBulletinClient(fc).GetPartialDecryption("election-2026", "contest-1", "trustee-1")
	if err != nil {
		t.Fatalf("GetPartialDecryption: %v", err)
	}
	if got != "feed" {
		t.Fatalf("payload = %q, want feed", got)
	}
	if fc.submitName != "GetPartialDecryption" {
		t.Fatalf("transaction name = %q, want GetPartialDecryption", fc.submitName)
	}
	if len(fc.submitArgs) != 3 || fc.submitArgs[0] != "election-2026" || fc.submitArgs[1] != "contest-1" || fc.submitArgs[2] != "trustee-1" {
		t.Fatalf("args = %v, want [election-2026 contest-1 trustee-1]", fc.submitArgs)
	}
}

func TestPublishTallyInvokesSubmitTransaction(t *testing.T) {
	fc := &fakeContract{}
	if err := NewBulletinClient(fc).PublishTally("0a0b0c"); err != nil {
		t.Fatalf("PublishTally: %v", err)
	}
	if fc.submitName != "PublishTally" {
		t.Fatalf("transaction name = %q, want PublishTally", fc.submitName)
	}
	if len(fc.submitArgs) != 1 || fc.submitArgs[0] != "0a0b0c" {
		t.Fatalf("args = %v, want [0a0b0c]", fc.submitArgs)
	}
}

func TestPublishTallyRejectsEmpty(t *testing.T) {
	if err := NewBulletinClient(&fakeContract{}).PublishTally(""); err == nil {
		t.Fatal("PublishTally should reject empty input")
	}
}

func TestGetTallyReturnsPayloadAsString(t *testing.T) {
	fc := &fakeContract{evalReturn: []byte("d00d")}
	got, err := NewBulletinClient(fc).GetTally("election-2026")
	if err != nil {
		t.Fatalf("GetTally: %v", err)
	}
	if got != "d00d" {
		t.Fatalf("payload = %q, want d00d", got)
	}
	if fc.submitName != "GetTally" {
		t.Fatalf("transaction name = %q, want GetTally", fc.submitName)
	}
}
