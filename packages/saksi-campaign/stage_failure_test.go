package campaign

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

// unreachableFabric is a network the console believes is configured whose
// connection fails at once: its TLS certificate does not exist.
func unreachableFabric(t *testing.T) FabricConfig {
	missing := filepath.Join(t.TempDir(), "missing.pem")
	return FabricConfig{
		PeerEndpoint: "127.0.0.1:1", GatewayPeer: "peer0.org1.example.com", TLSCert: missing,
		MSPID: "Org1MSP", Cert: missing, Key: missing, Channel: "saksi", Chaincode: "saksi-bulletin",
	}
}

// withLedger makes e's ballot-carrying stages drive led instead of a network.
func withLedger(e *Executor, led clientsdk.Ledger) {
	e.dialLedger = func() (clientsdk.Ledger, func(), error) { return led, func() {}, nil }
}

// Every way an on-chain Submit or CeremonyStart can fail, before, during or
// after the ballot window, ends the run failed with the stage's own reason in
// run.end and perf.csv — even though Verify, a separate phase, audits the
// local ballots cleanly afterwards.
func TestFailedBallotStageFailsTheRun(t *testing.T) {
	c := ElectionConfig{Mode: "onchain", Voters: 20, Positions: 1, Candidates: 2, Concurrency: 4}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, e *Executor, runDir string) error
		want  string
	}{
		{"bundle error: nothing generated", func(t *testing.T, e *Executor, _ string) error {
			withLedger(e, &fakeLedger{})
			return e.Submit(context.Background(), "run-1", c)
		}, "stage_error: submit: bundle: this run has no generated election"},
		{"connect failure", func(t *testing.T, e *Executor, runDir string) error {
			writeBallotStream(t, runDir, 20)
			e.fabric = unreachableFabric(t)
			return e.Submit(context.Background(), "run-1", c)
		}, "stage_error: submit: connect to Fabric:"},
		{"lifecycle step before the window", func(t *testing.T, e *Executor, runDir string) error {
			writeBallotStream(t, runDir, 20)
			withLedger(e, &fakeLedger{failOn: "CreateElection"})
			return e.Submit(context.Background(), "run-1", c)
		}, "stage_error: submit: CreateElection: boom"},
		{"ballot stream unreadable at the window", func(t *testing.T, e *Executor, runDir string) error {
			writeBallotStream(t, runDir, 20)
			writeBallotLinesFile(t, runDir, 19) // the bundle still says 20
			withLedger(e, &fakeLedger{})
			return e.Submit(context.Background(), "run-1", c)
		}, "stage_error: submit: bundle ballot_count is 20"},
		{"lifecycle step after the window", func(t *testing.T, e *Executor, runDir string) error {
			writeBallotStream(t, runDir, 20)
			withLedger(e, &fakeLedger{failOn: "PublishTally"})
			return e.Submit(context.Background(), "run-1", c)
		}, "stage_error: submit: PublishTally: boom"},
		{"ceremony start connect failure", func(t *testing.T, e *Executor, runDir string) error {
			writeBallotStream(t, runDir, 20)
			e.fabric = unreachableFabric(t)
			return e.CeremonyStart(context.Background(), "run-1", c)
		}, "stage_error: ceremony: connect to Fabric:"},
		{"ceremony start with no network", func(t *testing.T, e *Executor, runDir string) error {
			writeBallotStream(t, runDir, 20)
			return e.CeremonyStart(context.Background(), "run-1", c)
		}, "stage_error: ceremony: on-chain mode needs a Fabric network"},
		{"ceremony start bundle error", func(t *testing.T, e *Executor, _ string) error {
			return e.CeremonyStart(context.Background(), "run-1", c)
		}, "stage_error: ceremony: bundle: this run has no generated election"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			runDir := filepath.Join(dir, "run-1")
			e := newTestExecutor(t, dir)
			if err := tc.setup(t, e, runDir); err == nil {
				t.Fatal("the stage must fail")
			}
			cells := verifyPerfCells(t, e, "run-1", runDir, c)
			if cells["failed"] != "true" || !strings.HasPrefix(cells["fail_reason"], tc.want) {
				t.Fatalf("perf.csv failed/fail_reason = %q/%q, want true/%q…", cells["failed"], cells["fail_reason"], tc.want)
			}
			end := journalEventsOfType(t, runDir, "run.end")
			if len(end) != 1 || !jbool(end[0], "failed") || !strings.HasPrefix(jstring(end[0], "reason"), tc.want) {
				t.Fatalf("run.end = %v, want failed with %q…", end, tc.want)
			}
		})
	}
}

// The zero-progress predicate: an on-chain run that never put a ballot on the
// chain is failed even when no stage recorded an error — here, no stage ran at
// all. An offline run legitimately submits nothing and is not.
func TestNothingSubmittedFailsOnlyOnChainRuns(t *testing.T) {
	for mode, want := range map[string]string{"onchain": "nothing_submitted", "offline": ""} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			runDir := filepath.Join(dir, "run-1")
			e := newTestExecutor(t, dir)
			writeBallotStream(t, runDir, 20)
			c := ElectionConfig{Mode: mode, Voters: 20, Positions: 1, Candidates: 2, Concurrency: 4}
			if mode == "offline" { // on-chain: no stage runs at all, so none records an error
				if err := e.Submit(context.Background(), "run-1", c); err != nil {
					t.Fatalf("offline Submit: %v", err)
				}
			}
			cells := verifyPerfCells(t, e, "run-1", runDir, c)
			if got := cells["fail_reason"]; got != want || (cells["failed"] == "true") != (want != "") {
				t.Fatalf("%s: failed/fail_reason = %q/%q, want reason %q", mode, cells["failed"], got, want)
			}
		})
	}
}

// A window that dispatched nothing is nothing_submitted too, even when it
// reconciles (a bounded window owes only what it dispatched).
func TestEmptyBoundedWindowIsNothingSubmitted(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run-1")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(runDir, submitMetricsFile), submitMetrics{Expected: 20, Bounded: true, Stopped: true}); err != nil {
		t.Fatal(err)
	}
	in := finaliseInput(runDir, ElectionConfig{Mode: "onchain", Voters: 20, Positions: 1}, StreamAudit{}, nil, nil)
	if fin := Finalise(nil, in); !fin.Failed || fin.Reason != "nothing_submitted" {
		t.Fatalf("verdict = %v %q, want failed nothing_submitted", fin.Failed, fin.Reason)
	}
}

// A failed ballot stage is superseded by what finished its job: a later
// successful start, or a resume that closed the election. Anything else leaves
// it standing.
func TestBallotStageErrKeepsTheLastWord(t *testing.T) {
	fail := `{"event":"stage.ceremony.end","ok":false,"error":"connect to Fabric: refused"}`
	for _, tc := range []struct {
		name  string
		lines []string
		want  string
	}{
		{"no stage", nil, ""},
		{"a failure", []string{fail}, "ceremony: connect to Fabric: refused"},
		{"a legacy end with no ok", []string{`{"event":"stage.ceremony.end"}`}, ""},
		{"retried successfully", []string{fail, `{"event":"stage.ceremony.end","ok":true}`}, ""},
		{"resumed and closed", []string{fail, `{"event":"resume.close","ok":true}`}, ""},
		{"resume that did not close", []string{fail, `{"event":"resume.close","ok":false}`}, "ceremony: connect to Fabric: refused"},
		{"a later failure wins", []string{`{"event":"stage.ceremony.end","ok":true}`,
			`{"event":"stage.submit.end","ok":false,"error":"PublishTally: boom"}`}, "submit: PublishTally: boom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, JournalFile), []byte(strings.Join(tc.lines, "\n")+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			got := ""
			if err := ballotStageErr(dir); err != nil {
				got = err.Error()
			}
			if got != tc.want {
				t.Fatalf("ballotStageErr = %q, want %q", got, tc.want)
			}
		})
	}
}

// End to end against the real saksi-demo: an on-chain campaign whose Fabric
// connection fails records the repetition failed, and summary.csv counts it.
// Before, the rep was failed:false with an empty TPS and runs_failed 0.
func TestCampaignCountsAConnectFailureAsAFailedRep(t *testing.T) {
	demo := findDemo(t)
	fakeHostProbes(t, "", nil) // the preflight's TCP probe answers; the real connect does not
	store := NewRunStore(t.TempDir())
	hub := NewHub()
	fabric := unreachableFabric(t)
	s := NewServer(store, NewExecutor(store, hub, demo, "", fabric), hub, fabric, nil, 5*time.Minute)

	cfg := good()
	cfg.Mode = "onchain"
	rec, id := startCampaign(t, s, map[string]any{"config": cfg, "reps": 1}, "")
	if rec.Code != http.StatusAccepted || id == "" {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	if v := waitJob(t, s, id, 5*time.Minute); v.Status != jobDone {
		t.Fatalf("campaign job = %s %s; log:\n%s", v.Status, v.Error, strings.Join(v.Log, "\n"))
	}

	got := httptest.NewRecorder()
	s.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/api/campaigns/"+id, nil))
	var body struct {
		Reps    []campaignRep       `json:"reps"`
		Summary []map[string]string `json:"summary"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil || len(body.Reps) != 1 {
		t.Fatalf("GET campaign: %d %s (%v)", got.Code, got.Body, err)
	}
	r := body.Reps[0]
	if !r.Failed || r.Status != jobFailed || !strings.Contains(r.FailReason, "connect to Fabric") {
		t.Fatalf("rep = %+v, want failed with the connect error", r)
	}
	for _, row := range body.Summary {
		if row["metric"] == "runs_failed" {
			if row["median"] != "1" || !strings.Contains(row["failed_reasons"], "connect to Fabric") {
				t.Fatalf("summary runs_failed = %v, want 1 naming the connect error", row)
			}
			return
		}
	}
	t.Fatalf("summary has no runs_failed row: %v", body.Summary)
}
