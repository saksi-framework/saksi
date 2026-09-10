package campaign

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A run whose mode is not "onchain" must never touch Fabric in ANY phase.
//
// It used to: Submit honoured the mode and no-opped, but CeremonyStart gated on
// e.fabric.Enabled() alone, so on a Fabric-wired console an OFFLINE run put its
// whole lifecycle on the chain — CreateElection, the DKG transcript, every
// ballot, CloseElection, the partials and the tally. The WSL run offline-mp-10k
// carries mode "offline" in run.json and 30,000 SubmitBallot rows in
// receipts.csv, and every validation-ladder tier (LadderConfig sets Mode
// "offline") ran the same way.

// reachableLookingFabric is a FabricConfig that Enabled() accepts and Connect()
// rejects instantly: the TLS cert path does not exist, so newGRPCConnection
// fails on its first os.ReadFile without dialling anything.
//
// That makes it an exact ledger-call counter for these tests. Every route to
// the chain in this package runs through FabricConfig.Connect, so "the phase
// returned nil" is the same statement as "it made zero ledger calls" — and a
// phase that reached for the chain fails loudly, naming the TLS cert, instead
// of quietly committing.
func reachableLookingFabric(t *testing.T) FabricConfig {
	t.Helper()
	return FabricConfig{
		PeerEndpoint: "127.0.0.1:1", // never dialled: the cert read fails first
		GatewayPeer:  "peer0.org1.example.com",
		TLSCert:      filepath.Join(t.TempDir(), "no-such-tls-cert.pem"),
		MSPID:        "Org1MSP",
		Cert:         filepath.Join(t.TempDir(), "no-such-cert.pem"),
		Key:          filepath.Join(t.TempDir(), "no-such-key.pem"),
		Channel:      "mychannel",
		Chaincode:    "saksi",
	}
}

// assertNoLedgerEvidence fails when a run folder holds the artifacts only a
// committed ledger call can produce.
func assertNoLedgerEvidence(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{"receipts.csv", trailNDJSONFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s exists: the run reached the ledger", name)
		}
	}
}

// Every ceremony entry point, on a Fabric-wired console, for a run that is not
// on-chain: all of them must complete locally and none of them may connect.
func TestOfflineCeremonyNeverTouchesFabric(t *testing.T) {
	for _, mode := range []string{"offline", ModeGroundTruth} {
		t.Run(mode, func(t *testing.T) {
			store := NewRunStore(t.TempDir())
			hub := NewHub()
			e := NewExecutor(store, hub, "saksi-demo", "", reachableLookingFabric(t))
			c := good()
			c.Mode = mode
			c.Trustees = mk(3)
			c.Threshold = 2
			runID, dir, err := store.Create(c, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			writeBundle(t, dir, runID, 2, 3)
			ctx := context.Background()

			if err := e.CeremonyStart(ctx, runID, c); err != nil {
				t.Fatalf("CeremonyStart went to the chain: %v", err)
			}
			for _, id := range []string{"1", "2"} {
				if err := e.CeremonySubmit(ctx, runID, c, id); err != nil {
					t.Fatalf("CeremonySubmit(%s) went to the chain: %v", id, err)
				}
			}
			st, err := e.CeremonyStatus(runID, c)
			if err != nil {
				t.Fatalf("CeremonyStatus went to the chain: %v", err)
			}
			if st.OnChain {
				t.Error("an offline run reports on_chain: the page would claim a ledger it never used")
			}
			if err := e.CeremonyPublish(ctx, runID, c); err != nil {
				t.Fatalf("CeremonyPublish went to the chain: %v", err)
			}
			assertNoLedgerEvidence(t, dir)
		})
	}
}

// The same thing through the console's own HTTP handlers, which is the path the
// --repeat driver and the wizard both take.
func TestOfflineCeremonyEndpointsNeverTouchFabric(t *testing.T) {
	store := NewRunStore(t.TempDir())
	hub := NewHub()
	fc := reachableLookingFabric(t)
	e := NewExecutor(store, hub, "saksi-demo", "", fc)
	e.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, nil }
	s := NewServer(store, e, hub, fc, nil, time.Minute)

	c := good()
	c.Trustees = mk(3)
	c.Threshold = 2
	runID, dir, err := store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeBundle(t, dir, runID, 2, 3)

	post := func(path string, body any) {
		t.Helper()
		w := httptest.NewRecorder()
		s.ServeHTTP(w, postJSON(path, body))
		if w.Code >= 300 {
			t.Fatalf("POST %s: %d %s", path, w.Code, strings.TrimSpace(w.Body.String()))
		}
		// The handlers dispatch in a goroutine; wait for the run to go idle.
		for i := 0; i < 400; i++ {
			st := httptest.NewRecorder()
			s.ServeHTTP(st, httptest.NewRequest("GET", "/api/runs/"+runID+"/status", nil))
			if !strings.Contains(st.Body.String(), `"busy":true`) {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("POST %s never finished", path)
	}

	post("/ceremony/start", map[string]string{"run_id": runID})
	post("/ceremony/submit", map[string]string{"run_id": runID, "trustee_id": "1"})
	post("/ceremony/submit", map[string]string{"run_id": runID, "trustee_id": "2"})
	post("/ceremony/publish", map[string]string{"run_id": runID})
	assertNoLedgerEvidence(t, dir)
}

// The validation ladder is the gate every large tier depends on, and every tier
// it runs is offline (LadderConfig). Driven through a REAL console wired to
// Fabric, the whole phase sequence — generate, check, submit, ceremony, verify —
// must complete without one ledger call. On-chain it was 100x slower than
// designed and measured the orderer's BatchTimeout instead of the build.
func TestLadderTiersNeverTouchFabric(t *testing.T) {
	demo := findDemo(t)
	store := NewRunStore(t.TempDir())
	hub := NewHub()
	fc := reachableLookingFabric(t)
	s := NewServer(store, NewExecutor(store, hub, demo, "", fc), hub, fc, nil, time.Minute)
	console := httptest.NewServer(s)
	defer console.Close()

	d, err := newRepeatDriver(RepeatOpts{
		BaseURL: console.URL, Log: io.Discard, Poll: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := LadderConfig(LadderTiers[0])
	if c.Mode == "onchain" {
		t.Fatalf("LadderConfig mode is %q: the ladder is an offline gate", c.Mode)
	}
	r, err := d.once(context.Background(), c, RepTag{Index: 1, Kind: "ladder"})
	if err != nil {
		t.Fatalf("ladder tier: %v", err)
	}
	if r.Failed {
		t.Fatalf("ladder tier failed: %s", r.Reason)
	}
	dir, err := store.Dir(r.RunID)
	if err != nil {
		t.Fatal(err)
	}
	assertNoLedgerEvidence(t, dir)
	// Zero ledger calls is only half of it: the tier's ceremony has to have
	// actually happened, locally. A ceremony that died reaching for the chain
	// also writes no receipts.
	var st CeremonyState
	if err := readJSON(filepath.Join(dir, CeremonyFile), &st); err != nil {
		t.Fatalf("the tier's local ceremony never ran: %v", err)
	}
	if !st.Published {
		t.Errorf("the tier's ceremony never published its tally: %+v", st)
	}
	if st.OnChain {
		t.Error("an offline tier's ceremony claims to be on-chain")
	}
}

// pathRecorder wraps a fakeConsole and records the request paths the --repeat
// driver actually posts, so a phase the driver must NOT run is provable.
type pathRecorder struct {
	http.Handler
	mu    sync.Mutex
	paths []string
}

func (p *pathRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.paths = append(p.paths, r.URL.Path)
	p.mu.Unlock()
	p.Handler.ServeHTTP(w, r)
}

func (p *pathRecorder) hit(path string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, got := range p.paths {
		if got == path {
			return true
		}
	}
	return false
}

// The parked duplicate-transaction question, settled.
//
// On an on-chain run the driver posted /submit — which drives the WHOLE
// lifecycle through submitOnChain, tally included — and then ran the ceremony,
// whose CeremonyStart calls setupOnChain again: a second CreateElection for an
// election that already exists. The chaincode refuses it ("election %q already
// exists", saksi-bulletin/chaincode/contract.go), which is why today's SP-1K
// runs show exactly 1,000 SubmitBallot receipts and not 2,000 — the ceremony
// died on its first call, before any ballot could be re-submitted. No ballot
// was ever duplicated; the duplicate CreateElection is now not issued at all.
//
// Offline the ceremony is still the run's local bookkeeping, so it must keep
// running.
func TestRepeatSkipsTheCeremonyOnChainAndKeepsItOffline(t *testing.T) {
	for _, tc := range []struct {
		mode        string
		wantCeremny bool
	}{
		{"onchain", false},
		{"offline", true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			fake := newFakeConsole()
			fake.perf = func(string, RepTag) map[string]string { return map[string]string{} }
			fake.end = func(string, RepTag) map[string]any { return map[string]any{} }
			rec := &pathRecorder{Handler: fake}
			srv := httptest.NewServer(rec)
			defer srv.Close()

			d, err := newRepeatDriver(RepeatOpts{
				BaseURL: srv.URL, Log: io.Discard, Poll: time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			c := good()
			c.Mode = tc.mode
			if _, err := d.once(context.Background(), c, RepTag{Index: 1, Kind: "measured"}); err != nil {
				t.Fatal(err)
			}
			if !rec.hit("/submit") {
				t.Fatal("the driver skipped /submit")
			}
			if got := rec.hit("/ceremony/start"); got != tc.wantCeremny {
				t.Errorf("%s run: ceremony ran = %v, want %v", tc.mode, got, tc.wantCeremny)
			}
		})
	}
}
