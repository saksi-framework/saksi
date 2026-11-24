package campaign

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

// argsLedger records the arguments of every SubmitWithReceipt.
type argsLedger struct {
	*fakeLedger
	args map[string][]string
}

func (a *argsLedger) SubmitWithReceipt(fn string, args ...string) ([]byte, clientsdk.Receipt, error) {
	a.mu.Lock()
	if a.args == nil {
		a.args = map[string][]string{}
	}
	a.args[fn] = append([]string(nil), args...)
	a.mu.Unlock()
	return a.fakeLedger.SubmitWithReceipt(fn, args...)
}

// The console registers the ledger's machine certificate for the election it
// just created, and records the registration as a lifecycle event whose ref
// is the fingerprint.
func TestSubmitOnChainRegistersTheMachine(t *testing.T) {
	dir := t.TempDir()
	led := &argsLedger{fakeLedger: &fakeLedger{}}
	e := newTestExecutor(t, dir)
	if err := e.submitOnChain(context.Background(), "run-1", ElectionConfig{}, led, writeTestBundle(t, filepath.Join(dir, "run-1"))); err != nil {
		t.Fatal(err)
	}
	b, err := loadBundle(filepath.Join(dir, "run-1", "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := led.args["RegisterPrecinctMachine"]
	if len(got) != 2 || got[0] != b.ElectionID || got[1] != fakeMachineFP {
		t.Fatalf("RegisterPrecinctMachine args = %v, want [%s %s]", got, b.ElectionID, fakeMachineFP)
	}
	trail, err := os.ReadFile(filepath.Join(dir, "run-1", "trail.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(trail), `"event":"RegisterPrecinctMachine","ref":"`+fakeMachineFP+`"`) {
		t.Fatalf("trail.ndjson has no registration naming the machine:\n%s", trail)
	}
}

// A refused registration stops the lifecycle before any ballot is sent.
func TestSubmitOnChainStopsWhenRegistrationIsRefused(t *testing.T) {
	dir := t.TempDir()
	led := &fakeLedger{failOn: "RegisterPrecinctMachine", failText: "gate=admin: RegisterPrecinctMachine needs an administrator"}
	e := newTestExecutor(t, dir)
	err := e.submitOnChain(context.Background(), "run-1", ElectionConfig{}, led, writeTestBundle(t, filepath.Join(dir, "run-1")))
	if err == nil || !strings.Contains(err.Error(), "RegisterPrecinctMachine") {
		t.Fatalf("err = %v, want a RegisterPrecinctMachine failure", err)
	}
	for _, fn := range led.callNames() {
		if fn == "SubmitBallot" || fn == "PublishDKGTranscript" {
			t.Fatalf("%s sent after a refused registration (calls %v)", fn, led.callNames())
		}
	}
}
