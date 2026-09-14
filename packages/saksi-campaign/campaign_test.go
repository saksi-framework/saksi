package campaign

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// --- helpers -----------------------------------------------------------------

// enableTestAuth turns auth on for s with the auth tests' three fixture users.
func enableTestAuth(t *testing.T, s *Server) {
	t.Helper()
	users := []User{
		{Username: "admin", Role: RoleAdmin, PasswordBcrypt: fixtureHashes()["admin-pw"]},
		{Username: "t1", Role: RoleTrustee, TrusteeID: "1", PasswordBcrypt: fixtureHashes()["t1-pw"]},
	}
	data, _ := json.Marshal(users)
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableAuth(path); err != nil {
		t.Fatalf("EnableAuth: %v", err)
	}
}

// fakeHostProbes replaces the load-average reader and the Fabric dial for one test.
func fakeHostProbes(t *testing.T, loadavg string, dialErr error) {
	t.Helper()
	oldLoad, oldDial := readLoadAvg, dialFabric
	t.Cleanup(func() { readLoadAvg, dialFabric = oldLoad, oldDial })
	readLoadAvg = func() ([]byte, error) {
		if loadavg == "" {
			return nil, os.ErrNotExist
		}
		return []byte(loadavg), nil
	}
	dialFabric = func(string, time.Duration) error { return dialErr }
}

func codes(ws []PreflightWarning) map[string]string {
	m := map[string]string{}
	for _, w := range ws {
		m[w.Code] = w.Severity
	}
	return m
}

// waitJob polls a job until it leaves queued/running.
func waitJob(t *testing.T, s *Server, id string, limit time.Duration) jobView {
	t.Helper()
	deadline := time.Now().Add(limit)
	for {
		v, ok := s.jobs.view(id)
		if !ok {
			t.Fatalf("job %s unknown", id)
		}
		if v.Status != jobQueued && v.Status != jobRunning {
			return v
		}
		if time.Now().After(deadline) {
			t.Fatalf("job %s still %s after %s; log:\n%s", id, v.Status, limit, strings.Join(v.Log, "\n"))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func getCampaign(t *testing.T, s *Server, id string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/campaigns/"+id, nil))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func startCampaign(t *testing.T, s *Server, body any, sessionUser string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	req := signIn(t, s, sessionUser, postJSON("/api/campaigns", body))
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	var out struct {
		Campaign string `json:"campaign"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out.Campaign
}

// --- internal transport --------------------------------------------------------

// No header, query, cookie or address an outside caller controls can make a
// request internal: the marker is a context value only this package can set.
func TestInternalCallerCannotBeForged(t *testing.T) {
	s, _ := authServer(t)
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/preflight?internal=1&internal_call=true", nil)
	for _, h := range []string{"X-Internal", "X-Internal-Call", "X-Saksi-Internal", "Internal-Call-Key"} {
		req.Header.Set(h, "true")
	}
	req.AddCookie(&http.Cookie{Name: "internal", Value: "1"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged internal call over the network: want 401, got %d", resp.StatusCode)
	}

	local := httptest.NewRequest(http.MethodGet, "/api/preflight", nil)
	local.Header.Set("X-Internal", "true")
	local.RemoteAddr = "127.0.0.1:1"
	if internalCall(local) {
		t.Fatal("a header marked a request internal")
	}
}

// The in-process client reaches admin routes, and the trustee-only share route,
// with auth on and with auth off, through guard()'s Host check.
func TestInternalTransportWorksWithAuthOnAndOff(t *testing.T) {
	for _, authOn := range []bool{false, true} {
		t.Run(fmt.Sprintf("auth=%v", authOn), func(t *testing.T) {
			s, _, _ := testServer(t, []string{"127.0.0.1:8090", "localhost:8090"})
			if authOn {
				enableTestAuth(t, s)
				anon := httptest.NewRecorder()
				anonReq := postJSON("/generate", good())
				anonReq.Host = "127.0.0.1:8090"
				s.ServeHTTP(anon, anonReq)
				if anon.Code != http.StatusUnauthorized {
					t.Fatalf("auth is not on: anonymous /generate got %d", anon.Code)
				}
			}
			client, base := s.internalClient(nil)

			resp, err := client.Get(base + "/api/preflight?mode=offline")
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("GET /api/preflight in-process: %v %v", err, resp)
			}
			resp.Body.Close()

			b, _ := json.Marshal(good())
			resp, err = client.Post(base+"/generate", "application/json", bytes.NewReader(b))
			if err != nil || resp.StatusCode != http.StatusAccepted {
				t.Fatalf("POST /generate in-process: %v %v", err, resp)
			}
			var gen struct {
				RunID string `json:"run_id"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&gen)
			resp.Body.Close()

			sb, _ := json.Marshal(map[string]string{"run_id": gen.RunID, "trustee_id": "2"})
			resp, err = client.Post(base+"/ceremony/submit", "application/json", bytes.NewReader(sb))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				t.Fatalf("the driver's trustee-share call was refused by auth: %d", resp.StatusCode)
			}
		})
	}
}

// --- preflight -----------------------------------------------------------------

func TestPreflightFabricReachability(t *testing.T) {
	s, _ := gateServer(t, liveFabric(), "abc", 1<<62)

	fakeHostProbes(t, "", errors.New("connection refused"))
	rep := s.preflight(PreflightInput{Mode: "onchain"})
	if rep.Fabric.Reachable == nil || *rep.Fabric.Reachable {
		t.Fatalf("reachable = %v, want false", rep.Fabric.Reachable)
	}
	if codes(rep.Warnings)["fabric_unreachable"] != severityBlock || !rep.Blocked() {
		t.Fatalf("an unreachable peer must block an on-chain run: %+v", rep.Warnings)
	}
	if _, ok := codes(s.preflight(PreflightInput{Mode: "offline"}).Warnings)["fabric_unreachable"]; ok {
		t.Fatal("an offline run needs no peer")
	}

	fakeHostProbes(t, "", nil)
	rep = s.preflight(PreflightInput{Mode: "onchain"})
	if rep.Fabric.Reachable == nil || !*rep.Fabric.Reachable || rep.Blocked() {
		t.Fatalf("reachable peer: reachable=%v warnings=%+v", rep.Fabric.Reachable, rep.Warnings)
	}

	off, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	if rep := off.preflight(PreflightInput{Mode: "onchain"}); rep.Fabric.Enabled || rep.Fabric.Reachable != nil {
		t.Fatalf("no Fabric configured: enabled=%v reachable=%v", rep.Fabric.Enabled, rep.Fabric.Reachable)
	}
}

func TestPreflightLadder(t *testing.T) {
	fakeHostProbes(t, "", nil)
	s, root := gateServer(t, FabricConfig{}, "abc123", 1<<62)
	big := PreflightInput{Mode: "offline", Voters: 2000, Positions: 3}

	rep := s.preflight(big)
	if codes(rep.Warnings)["ladder_missing"] != severityBlock || rep.Ladder.OK {
		t.Fatalf("no ladder.json above the ceiling must block: ok=%v %+v", rep.Ladder.OK, rep.Warnings)
	}
	if rep := s.preflight(PreflightInput{Mode: "offline", Voters: LadderVoterCeiling}); rep.Blocked() {
		t.Fatalf("a tier at the ceiling needs no ladder: %+v", rep.Warnings)
	}

	writeLadder(t, root, "deadbeef")
	rep = s.preflight(big)
	if rep.Ladder.OK || rep.Ladder.LadderCommit != "deadbeef" || rep.Ladder.ConsoleCommit != "abc123" || !rep.Blocked() {
		t.Fatalf("stale ladder: %+v %+v", rep.Ladder, rep.Warnings)
	}

	writeLadder(t, root, "abc123")
	if rep := s.preflight(big); !rep.Ladder.OK || rep.Blocked() {
		t.Fatalf("matching ladder: %+v %+v", rep.Ladder, rep.Warnings)
	}
}

func TestPreflightDisk(t *testing.T) {
	fakeHostProbes(t, "", nil)
	need := uint64(100 * 3 * LedgerBytesPerBallot)
	in := PreflightInput{Mode: "onchain", Voters: 100, Positions: 3}

	s, root := gateServer(t, FabricConfig{}, "abc", need-1)
	rep := s.preflight(in)
	if codes(rep.Warnings)["disk_short"] != severityBlock {
		t.Fatalf("projected ledger above free space must block: %+v", rep.Warnings)
	}
	if rep.Disk.ProjectedLedgerBytes == nil || *rep.Disk.ProjectedLedgerBytes != need ||
		rep.Disk.FreeBytes == nil || *rep.Disk.FreeBytes != need-1 || rep.Disk.Path != root {
		t.Fatalf("disk report = %+v", rep.Disk)
	}

	s2, _ := gateServer(t, FabricConfig{}, "abc", need)
	if rep := s2.preflight(in); rep.Blocked() {
		t.Fatalf("exactly enough is enough: %+v", rep.Warnings)
	}
	if rep := s2.preflight(PreflightInput{Mode: "onchain"}); rep.Disk.ProjectedLedgerBytes != nil {
		t.Fatal("no voters/positions: nothing to project")
	}
}

func TestPreflightHostLoad(t *testing.T) {
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	cpus := float64(runtime.NumCPU())

	fakeHostProbes(t, fmt.Sprintf("%.2f %.2f 1.00 2/300 12345\n", cpus*0.5, cpus*0.4), nil)
	rep := s.preflight(PreflightInput{Mode: "offline"})
	if rep.Host.Load1 == nil || rep.Host.Load5 == nil || rep.Host.CPUs != runtime.NumCPU() {
		t.Fatalf("host = %+v", rep.Host)
	}
	if codes(rep.Warnings)["host_load"] != severityWarn || rep.Blocked() {
		t.Fatalf("load at 50%% of CPUs must warn, not block: %+v", rep.Warnings)
	}

	fakeHostProbes(t, fmt.Sprintf("%.2f 0.00 0.00 1/300 1\n", cpus*0.1), nil)
	if _, ok := codes(s.preflight(PreflightInput{Mode: "offline"}).Warnings)["host_load"]; ok {
		t.Fatal("load at 10% of CPUs must not warn")
	}

	fakeHostProbes(t, "", nil) // no /proc/loadavg: Windows
	if rep := s.preflight(PreflightInput{Mode: "offline"}); rep.Host.Load1 != nil || rep.Host.Load5 != nil {
		t.Fatalf("no loadavg must report null, got %v", rep.Host.Load1)
	}
}

func TestPreflightConcurrencyAgainstMaxMessageCount(t *testing.T) {
	fakeHostProbes(t, "", nil)
	t.Setenv("SAKSI_CONFIGTX", "")
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfgDir := filepath.Join(repo, filepath.FromSlash(filepath.Dir(ordererConfigtxPath)))
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cfgDir, filepath.Base(ordererConfigtxPath),
		"Orderer:\n  BatchTimeout: 2s\n  BatchSize:\n    MaxMessageCount: 50\n")

	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	s.exec.demoBin = filepath.Join(repo, "target", "release", "saksi-demo")

	rep := s.preflight(PreflightInput{Mode: "onchain", Concurrency: 8})
	if rep.ConcurrencyMinAdvised == nil || *rep.ConcurrencyMinAdvised != 50 {
		t.Fatalf("concurrency_min_advised = %v, want 50 (orderer_batch %v)", rep.ConcurrencyMinAdvised, rep.OrdererBatch)
	}
	if codes(rep.Warnings)["concurrency_low"] != severityWarn {
		t.Fatalf("8 in flight under MaxMessageCount 50 must warn: %+v", rep.Warnings)
	}
	if _, ok := codes(s.preflight(PreflightInput{Mode: "onchain", Concurrency: 128}).Warnings)["concurrency_low"]; ok {
		t.Fatal("128 in flight must not warn")
	}

	unknown, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	if rep := unknown.preflight(PreflightInput{Mode: "onchain", Concurrency: 8}); rep.ConcurrencyMinAdvised != nil {
		t.Fatal("no declared orderer config: min advised must be null")
	}
}

func TestPreflightVerifyThreads(t *testing.T) {
	fakeHostProbes(t, "", nil)
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)

	t.Setenv("SAKSI_AUDIT_THREADS", "1")
	rep := s.preflight(PreflightInput{Mode: "offline"})
	if rep.VerifyThreadsDefault != 1 || codes(rep.Warnings)["verify_threads"] != severityWarn {
		t.Fatalf("one verify thread must warn: %d %+v", rep.VerifyThreadsDefault, rep.Warnings)
	}

	t.Setenv("SAKSI_AUDIT_THREADS", "")
	t.Setenv("RAYON_NUM_THREADS", "")
	if got := s.preflight(PreflightInput{Mode: "offline"}).VerifyThreadsDefault; got != runtime.NumCPU() {
		t.Fatalf("default verify threads = %d, want every core (%d)", got, runtime.NumCPU())
	}
}

func TestPreflightRouteRejectsBadNumbers(t *testing.T) {
	fakeHostProbes(t, "", nil)
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	for _, q := range []string{"voters=abc", "positions=-1"} {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/preflight?"+q, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("?%s: want 400, got %d", q, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/preflight?voters=10&positions=3&concurrency=128", nil))
	var rep PreflightReport
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rep) != nil || rep.Run.Mode != "onchain" || rep.Run.Voters != 10 {
		t.Fatalf("GET /api/preflight = %d %s", rec.Code, rec.Body)
	}
}

// --- campaigns and jobs ---------------------------------------------------------

// A blocking-preflight campaign is refused with the findings unless forced.
func TestCampaignRefusedOnBlockUnlessForced(t *testing.T) {
	fakeHostProbes(t, "", nil)
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	c := good()
	c.Voters = 2000 // above the ladder ceiling, no ladder.json

	rec, _ := startCampaign(t, s, map[string]any{"config": c, "reps": 1}, "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "ladder_missing") {
		t.Fatalf("want 409 with the ladder finding, got %d %s", rec.Code, rec.Body)
	}
	if entries, _ := os.ReadDir(filepath.Join(s.store.Root(), campaignsDir)); len(entries) != 0 {
		t.Fatal("a refused campaign must leave nothing on disk")
	}

	rec, id := startCampaign(t, s, map[string]any{"config": c, "reps": 1, "force": true}, "")
	if rec.Code != http.StatusAccepted || id == "" {
		t.Fatalf("forced: want 202, got %d %s", rec.Code, rec.Body)
	}
	waitJob(t, s, id, time.Minute)
	_, body := getCampaign(t, s, id)
	pre, _ := body["preflight"].(map[string]any)
	if ws, _ := pre["warnings"].([]any); len(ws) == 0 {
		t.Fatalf("the forced campaign must keep its preflight snapshot: %v", body["preflight"])
	}
}

// One job console-wide; cancel stops after the current repetition; no attacks.
func TestCampaignExclusivityAndCancel(t *testing.T) {
	fakeHostProbes(t, "", nil)
	s, _, exec := testServer(t, nil)
	release := make(chan struct{})
	exec.run = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, errors.New("fake saksi-demo")
	}

	rec, id := startCampaign(t, s, map[string]any{"config": good(), "warmups": 1, "reps": 3}, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}

	// Wait for the first repetition to exist, so cancel lands mid-repetition.
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, body := getCampaign(t, s, id)
		if reps, _ := body["reps"].([]any); len(reps) >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first repetition never appeared")
		}
		time.Sleep(20 * time.Millisecond)
	}

	ladder := httptest.NewRecorder()
	s.ServeHTTP(ladder, httptest.NewRequest(http.MethodPost, "/api/ladder", nil))
	if ladder.Code != http.StatusConflict || !strings.Contains(ladder.Body.String(), id) {
		t.Fatalf("ladder while a campaign runs: want 409 naming %s, got %d %s", id, ladder.Code, ladder.Body)
	}
	if second, _ := startCampaign(t, s, map[string]any{"config": good(), "reps": 1}, ""); second.Code != http.StatusConflict ||
		!strings.Contains(second.Body.String(), id) {
		t.Fatalf("second campaign: want 409 naming %s, got %d %s", id, second.Code, second.Body)
	}

	cancel := httptest.NewRecorder()
	s.ServeHTTP(cancel, httptest.NewRequest(http.MethodPost, "/api/campaigns/"+id+"/cancel", nil))
	if cancel.Code != http.StatusAccepted {
		t.Fatalf("cancel: %d %s", cancel.Code, cancel.Body)
	}
	close(release)

	if v := waitJob(t, s, id, time.Minute); v.Status != jobCancelled || v.Kind != "campaign" || len(v.Log) == 0 {
		t.Fatalf("job = %+v", v)
	}
	code, body := getCampaign(t, s, id)
	reps, _ := body["reps"].([]any)
	if code != http.StatusOK || body["status"] != jobCancelled || len(reps) != 1 {
		t.Fatalf("cancelled campaign: %d status=%v reps=%d", code, body["status"], len(reps))
	}
	if cfg, _ := body["config"].(map[string]any); cfg["skip_attacks"] != true {
		t.Fatalf("a campaign must force skip_attacks: %v", cfg)
	}
	runID, _ := reps[0].(map[string]any)["run_id"].(string)
	if run, err := s.record(runID); err != nil || !run.Config.SkipAttacks || run.Config.Rep == nil || run.Config.Rep.Kind != "warmup" {
		t.Fatalf("repetition run.json: %+v %v", run.Config, err)
	}

	after := httptest.NewRecorder()
	s.ServeHTTP(after, httptest.NewRequest(http.MethodPost, "/api/campaigns/"+id+"/cancel", nil))
	if after.Code != http.StatusConflict {
		t.Fatalf("cancel of a finished campaign: want 409, got %d", after.Code)
	}
	if _, err := os.Stat(filepath.Join(s.store.Root(), campaignsDir, id, campaignLog)); err != nil {
		t.Fatalf("log.txt: %v", err)
	}
}

// A campaign whose file says running, read by a console that is not running
// it, was interrupted by a restart.
func TestCampaignMarkedInterruptedAfterRestart(t *testing.T) {
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	dir := filepath.Join(s.store.Root(), campaignsDir, "campaign-20260914-120000-1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := &campaignRecord{ID: filepath.Base(dir), Status: jobRunning, CreatedAt: time.Now().UTC(), Config: good()}
	if err := saveCampaign(dir, rec); err != nil {
		t.Fatal(err)
	}

	code, body := getCampaign(t, s, rec.ID)
	if code != http.StatusOK || body["status"] != jobInterrupted {
		t.Fatalf("want interrupted, got %d %v", code, body["status"])
	}
	var onDisk campaignRecord
	if err := readJSON(filepath.Join(dir, campaignFile), &onDisk); err != nil || onDisk.Status != jobInterrupted {
		t.Fatalf("interrupted must be persisted: %v %v", onDisk.Status, err)
	}

	list := httptest.NewRecorder()
	s.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/campaigns", nil))
	if !strings.Contains(list.Body.String(), `"status":"interrupted"`) {
		t.Fatalf("list: %s", list.Body)
	}
}

// The bundle holds each run's thesis files under <run-id>/, journal line 1,
// and the campaign's summary, record and preflight.
func TestCampaignExportBundle(t *testing.T) {
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	var reps []campaignRep
	for i, kind := range []string{"warmup", "measured"} {
		runID, dir, err := s.store.Create(good(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, PerfCSV, "run_id,committed_tps\n"+runID+",12.5\n")
		writeFile(t, dir, CorrectnessFile, "contest,E\n")
		writeFile(t, dir, JournalFile, `{"event":"env","go_os":"linux"}`+"\n"+`{"event":"run.end","failed":false}`+"\n")
		if i == 1 {
			writeFile(t, dir, NegativeTestsFile, "scenario,verdict\n")
		}
		reps = append(reps, campaignRep{Index: 1, Kind: kind, RunID: runID})
	}
	id := "campaign-20260914-130000-1"
	cdir := filepath.Join(s.store.Root(), campaignsDir, id)
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cdir, SummaryCSV, "metric,min\ncommitted_tps,12.5\n")
	if err := saveCampaign(cdir, &campaignRecord{ID: id, Status: jobDone, Config: good(), Reps: reps,
		Preflight: PreflightReport{Run: PreflightInput{Mode: "offline", Voters: 10}}}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/campaigns/"+id+"/export", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("export: %d %s", rec.Code, rec.Header())
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = string(data)
	}
	var names []string
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	want := []string{campaignFile, preflightBundleFile, SummaryCSV}
	for i, r := range reps {
		want = append(want, r.RunID+"/"+RunFile, r.RunID+"/"+PerfCSV, r.RunID+"/"+CorrectnessFile, r.RunID+"/"+journalLine1File)
		if i == 1 {
			want = append(want, r.RunID+"/"+NegativeTestsFile)
		}
	}
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Fatalf("zip entries:\n got %v\nwant %v", names, want)
	}
	if got := files[reps[0].RunID+"/"+journalLine1File]; got != `{"event":"env","go_os":"linux"}` {
		t.Fatalf("journal-line1.json = %q", got)
	}
	if !strings.Contains(files[campaignFile], `"committed_tps": 12.5`) {
		t.Fatalf("campaign.json in the bundle must carry the refreshed rows: %s", files[campaignFile])
	}
	if !strings.Contains(files[preflightBundleFile], `"voters": 10`) {
		t.Fatalf("preflight.json: %s", files[preflightBundleFile])
	}
}

// The ladder runs as a job; a failing tier fails the job with its reason.
func TestLadderJobReportsFailure(t *testing.T) {
	s, _, exec := testServer(t, nil)
	exec.run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("fake saksi-demo") }

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/ladder", nil))
	var body struct {
		Job string `json:"job"`
	}
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Job == "" {
		t.Fatalf("POST /api/ladder: %d %s", rec.Code, rec.Body)
	}
	v := waitJob(t, s, body.Job, time.Minute)
	if v.Kind != "ladder" || v.Status != jobFailed || !strings.Contains(v.Error, "ladder tier 1 voters") || v.Result != nil {
		t.Fatalf("ladder job = %+v", v)
	}
	got := httptest.NewRecorder()
	s.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/api/jobs/"+body.Job, nil))
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"status":"failed"`) {
		t.Fatalf("GET /api/jobs: %d %s", got.Code, got.Body)
	}
	if _, err := os.Stat(filepath.Join(s.store.Root(), LadderFile)); err == nil {
		t.Fatal("a failed ladder must not write ladder.json")
	}
}

// End to end against the real saksi-demo, with auth ON: the campaign drives the
// console in-process (no credential), and yields per-repetition rows, a summary
// and an export bundle.
func TestCampaignAgainstRealDemo(t *testing.T) {
	demo := findDemo(t)
	store := NewRunStore(t.TempDir())
	hub := NewHub()
	exec := NewExecutor(store, hub, demo, "", FabricConfig{})
	s := NewServer(store, exec, hub, FabricConfig{}, []string{"127.0.0.1:8090"}, 5*time.Minute)
	enableTestAuth(t, s)

	req := signIn(t, s, "admin", postJSON("/api/campaigns", map[string]any{"config": good(), "warmups": 1, "reps": 2}))
	req.Host = "127.0.0.1:8090"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	var started struct {
		Campaign string `json:"campaign"`
	}
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &started) != nil {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	if v := waitJob(t, s, started.Campaign, 10*time.Minute); v.Status != jobDone {
		t.Fatalf("campaign job = %s %s; log:\n%s", v.Status, v.Error, strings.Join(v.Log, "\n"))
	}

	get := signIn(t, s, "admin", httptest.NewRequest(http.MethodGet, "/api/campaigns/"+started.Campaign, nil))
	get.Host = "127.0.0.1:8090"
	got := httptest.NewRecorder()
	s.ServeHTTP(got, get)
	var body struct {
		Status  string              `json:"status"`
		Reps    []campaignRep       `json:"reps"`
		Summary []map[string]string `json:"summary"`
	}
	if got.Code != http.StatusOK || json.Unmarshal(got.Body.Bytes(), &body) != nil {
		t.Fatalf("GET campaign: %d %s", got.Code, got.Body)
	}
	if body.Status != jobDone || len(body.Reps) != 3 {
		t.Fatalf("campaign = %s with %d reps: %s", body.Status, len(body.Reps), got.Body)
	}
	for i, want := range []RepTag{{1, "warmup"}, {1, "measured"}, {2, "measured"}} {
		r := body.Reps[i]
		if r.Index != want.Index || r.Kind != want.Kind || r.Status != jobDone || r.Failed {
			t.Errorf("rep %d = %+v, want %+v done", i, r, want)
		}
	}
	summary := map[string]map[string]string{}
	for _, row := range body.Summary {
		summary[row["metric"]] = row
	}
	if summary["runs_measured"]["median"] != "2" || summary["runs_failed"]["median"] != "0" {
		t.Fatalf("summary = %v", body.Summary)
	}

	exp := signIn(t, s, "admin", httptest.NewRequest(http.MethodGet, "/api/campaigns/"+started.Campaign+"/export", nil))
	exp.Host = "127.0.0.1:8090"
	zipRec := httptest.NewRecorder()
	s.ServeHTTP(zipRec, exp)
	zr, err := zip.NewReader(bytes.NewReader(zipRec.Body.Bytes()), int64(zipRec.Body.Len()))
	if err != nil {
		t.Fatalf("export is not a zip: %v (%d)", err, zipRec.Code)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	for _, r := range body.Reps {
		for _, f := range []string{RunFile, PerfCSV, PerfSchemaFile, CorrectnessFile, journalLine1File} {
			if !names[r.RunID+"/"+f] {
				t.Errorf("bundle is missing %s/%s", r.RunID, f)
			}
		}
	}
	if !names[SummaryCSV] || !names[campaignFile] || !names[preflightBundleFile] {
		t.Errorf("bundle is missing campaign files: %v", names)
	}
}

// The ladder job against the real saksi-demo: every tier passes, ladder.json is
// written for the console's commit, and the job's result is that file.
func TestLadderJobAgainstRealDemo(t *testing.T) {
	demo := findDemo(t)
	if testing.Short() {
		t.Skip("runs the 1,000-voter ladder tier")
	}
	store := NewRunStore(t.TempDir())
	hub := NewHub()
	s := NewServer(store, NewExecutor(store, hub, demo, "", FabricConfig{}), hub, FabricConfig{}, nil, 10*time.Minute)
	s.gitHead = func() (string, bool) { return "abc123", true }
	enableTestAuth(t, s)

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, signIn(t, s, "admin", httptest.NewRequest(http.MethodPost, "/api/ladder", nil)))
	var body struct {
		Job string `json:"job"`
	}
	if rec.Code != http.StatusAccepted || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
		t.Fatalf("POST /api/ladder: %d %s", rec.Code, rec.Body)
	}
	v := waitJob(t, s, body.Job, 20*time.Minute)
	if v.Status != jobDone {
		t.Fatalf("ladder job = %s %s; log:\n%s", v.Status, v.Error, strings.Join(v.Log, "\n"))
	}
	var lr ladderRecord
	if err := json.Unmarshal(v.Result, &lr); err != nil || lr.Commit != "abc123" || len(lr.Runs) != len(LadderTiers) {
		t.Fatalf("result = %s (%v)", v.Result, err)
	}
	if rep := s.preflight(PreflightInput{Mode: "offline", Voters: 2000}); !rep.Ladder.OK || rep.Blocked() {
		t.Fatalf("after the ladder, preflight: %+v %+v", rep.Ladder, rep.Warnings)
	}
}

// Every study route is admin-only with auth on. The admin probes are chosen so
// none of them starts a job.
func TestStudyRoutesAreAdminOnly(t *testing.T) {
	s, h := authServer(t)
	for _, p := range []struct{ method, path string }{
		{http.MethodGet, "/api/preflight"}, {http.MethodGet, "/api/ladder"},
		{http.MethodGet, "/api/jobs/ladder-1"}, {http.MethodGet, "/api/campaigns"},
		{http.MethodPost, "/api/campaigns"}, {http.MethodGet, "/api/campaigns/c1"},
		{http.MethodPost, "/api/campaigns/c1/cancel"}, {http.MethodGet, "/api/campaigns/c1/export"},
	} {
		for user, want := range map[string]int{"": http.StatusUnauthorized, "t1": http.StatusForbidden, "admin": 0} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, signIn(t, s, user, httptest.NewRequest(p.method, p.path, nil)))
			denied := rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden
			if (want == 0 && denied) || (want != 0 && rec.Code != want) {
				t.Errorf("%s %s as %q: want %d (0 = allowed), got %d %s", p.method, p.path, user, want, rec.Code, rec.Body)
			}
		}
	}
	if s.jobs.running() != nil {
		t.Fatal("a probe started a job")
	}
}
