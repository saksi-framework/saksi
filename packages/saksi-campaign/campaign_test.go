package campaign

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- helpers -----------------------------------------------------------------

// enableTestAuth turns auth on for s with an admin and one trustee.
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

// fakeHostProbes replaces the load-average reader and the Fabric dial for one
// test, and makes the host look like plain Linux (no WSL host CPU sample).
func fakeHostProbes(t *testing.T, loadavg string, dialErr error) {
	t.Helper()
	oldLoad, oldDial, oldRel, oldCmd := readLoadAvg, dialFabric, readOSRelease, hostCPUCommand
	t.Cleanup(func() { readLoadAvg, dialFabric, readOSRelease, hostCPUCommand = oldLoad, oldDial, oldRel, oldCmd })
	readLoadAvg = func() ([]byte, error) {
		if loadavg == "" {
			return nil, os.ErrNotExist
		}
		return []byte(loadavg), nil
	}
	dialFabric = func(string, time.Duration) error { return dialErr }
	readOSRelease = func() ([]byte, error) { return []byte("6.8.0-45-generic\n"), nil }
	hostCPUCommand = func(context.Context) ([]byte, error) { return nil, errors.New("not WSL") }
}

// fakeWSLHost makes the host look like WSL2 whose Windows CPU sample prints out
// (or fails with err). Returns the number of times the command ran.
func fakeWSLHost(t *testing.T, out string, err error) *int {
	t.Helper()
	oldRel, oldCmd := readOSRelease, hostCPUCommand
	t.Cleanup(func() { readOSRelease, hostCPUCommand = oldRel, oldCmd })
	calls := new(int)
	readOSRelease = func() ([]byte, error) { return []byte("5.15.167.4-microsoft-standard-WSL2\n"), nil }
	hostCPUCommand = func(context.Context) ([]byte, error) {
		*calls++
		return []byte(out), err
	}
	return calls
}

func findings(ws []PreflightWarning) map[string]PreflightWarning {
	m := map[string]PreflightWarning{}
	for _, w := range ws {
		m[w.Code] = w
	}
	return m
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

// noCampaignStarted fails when a refused start left a folder or a job behind.
func noCampaignStarted(t *testing.T, s *Server) {
	t.Helper()
	if entries, _ := os.ReadDir(filepath.Join(s.store.Root(), campaignsDir)); len(entries) != 0 {
		t.Fatal("a refused campaign must leave nothing on disk")
	}
	if s.jobs.running() != nil {
		t.Fatal("a refused campaign must not start a job")
	}
}

// --- internal transport --------------------------------------------------------

// No header, query, cookie or address an outside caller controls can make a
// request internal: the marker is a context value only this package can set.
func TestInternalCallerCannotBeForged(t *testing.T) {
	s, _ := authServer(t)
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/generate?internal=1&internal_call=true", strings.NewReader("{}"))
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

// The in-process client reaches the driver's routes, the trustee-only share
// route included, with auth on and off, through guard()'s Host check, and
// nothing else.
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
			do := func(method, path string, body any) *http.Response {
				t.Helper()
				var rd io.Reader
				if body != nil {
					b, _ := json.Marshal(body)
					rd = bytes.NewReader(b)
				}
				req, _ := http.NewRequest(method, base+path, rd)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("%s %s in-process: %v", method, path, err)
				}
				t.Cleanup(func() { resp.Body.Close() })
				return resp
			}

			resp := do(http.MethodPost, "/generate", good())
			if resp.StatusCode != http.StatusAccepted {
				t.Fatalf("POST /generate in-process: %d", resp.StatusCode)
			}
			var gen struct {
				RunID string `json:"run_id"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&gen)

			if resp := do(http.MethodGet, "/api/runs/"+gen.RunID+"/status", nil); resp.StatusCode != http.StatusOK {
				t.Fatalf("GET status in-process: %d", resp.StatusCode)
			}
			if resp := do(http.MethodPost, "/ceremony/submit", map[string]string{"run_id": gen.RunID, "trustee_id": "2"}); resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				t.Fatalf("the driver's trustee-share call was refused: %d", resp.StatusCode)
			}
			for _, p := range []struct{ method, path string }{
				{http.MethodGet, "/api/preflight"}, {http.MethodPost, "/api/ladder"},
				{http.MethodGet, "/api/campaigns"}, {http.MethodPost, "/api/runs/" + gen.RunID + "/resume"},
				{http.MethodPost, "/api/runs/" + gen.RunID + "/verify-only"}, {http.MethodGet, "/wizard"},
				{http.MethodPost, "/attack"}, {http.MethodGet, "/generate"}, {http.MethodPost, "/export/" + gen.RunID + "/run.json"},
			} {
				if resp := do(p.method, p.path, nil); resp.StatusCode != http.StatusForbidden {
					t.Errorf("internal %s %s: want 403, got %d", p.method, p.path, resp.StatusCode)
				}
			}
		})
	}
}

// recordingTransport records every request before forwarding it.
type recordingTransport struct {
	mu    sync.Mutex
	calls [][2]string // method, path
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.calls = append(rt.calls, [2]string{r.Method, r.URL.Path})
	rt.mu.Unlock()
	return http.DefaultTransport.RoundTrip(r)
}

// Every request Repeat (warm-ups, measured reps, a sweep, a burst, local and
// on-chain) and RunLadder make must resolve to an allowed internal route, and
// every allowed route must be one they make. A driver call added to repeat.go
// without an allowlist entry fails here instead of as a 403 mid-campaign.
//
// The fake answers every call successfully, so this covers the driver's
// success-path calls. TestInternalRoutesCoverTheDriverOnErrors covers the
// calls it makes after a step fails.
func TestInternalRoutesCoverTheDriver(t *testing.T) {
	fake := newFakeConsole()
	fake.perf = func(string, RepTag) map[string]string {
		return map[string]string{"mode": "offline", "dropped": "0", "committed_tps": "5.000", "latency_p99_ms": "100.000"}
	}
	fake.end = func(string, RepTag) map[string]any { return map[string]any{"failed": false} }
	base := fake.start(t)
	rt := &recordingTransport{}
	client := &http.Client{Transport: rt}

	for _, mode := range []string{"offline", "onchain"} {
		o := testRepeatOpts(t, base)
		o.Client, o.Config.Mode = client, mode
		o.Warmups, o.Reps, o.Burst, o.Sweep, o.Window = 1, 1, 3, 2, time.Second
		if err := Repeat(context.Background(), o); err != nil {
			t.Fatalf("Repeat %s: %v", mode, err)
		}
	}
	if err := RunLadder(context.Background(), LadderOpts{
		BaseURL: base, Client: client, DataDir: t.TempDir(), Log: io.Discard, Poll: time.Millisecond,
		Head: func() (string, bool) { return "abc", true },
	}); err != nil {
		t.Fatalf("RunLadder: %v", err)
	}

	pattern := consolePatterns(t)
	used := map[string]bool{}
	for _, c := range rt.calls {
		p := pattern(c[0], c[1])
		if internalRoutes[p] != c[0] {
			t.Errorf("the driver calls %s %s (route %q), which internalRoutes does not allow", c[0], c[1], p)
		}
		used[p] = true
	}
	for p := range internalRoutes {
		if !used[p] {
			t.Errorf("internalRoutes allows %q, which the driver never calls", p)
		}
	}
}

// consolePatterns resolves a request to the console route it reaches, from the
// routes NewServer really registers.
func consolePatterns(t *testing.T) func(method, path string) string {
	t.Helper()
	s, _, _ := testServer(t, nil)
	mux := http.NewServeMux()
	for _, p := range s.routes {
		mux.HandleFunc(p, func(http.ResponseWriter, *http.Request) {})
	}
	return func(method, path string) string {
		_, pattern := mux.Handler(httptest.NewRequest(method, path, nil))
		return pattern
	}
}

// failOnce answers the first request to one console route with a 500 and
// hands every other request to the fake console.
type failOnce struct {
	pattern func(method, path string) string
	target  string
	next    http.Handler
	mu      sync.Mutex
	done    bool
}

func (f *failOnce) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	hit := !f.done && f.pattern(r.Method, r.URL.Path) == f.target
	f.done = f.done || hit
	f.mu.Unlock()
	if hit {
		http.Error(w, "injected failure", http.StatusInternalServerError)
		return
	}
	f.next.ServeHTTP(w, r)
}

// The driver's error branches: each allowed route fails once, in turn, and
// every call the driver makes afterwards must still be an allowed route.
func TestInternalRoutesCoverTheDriverOnErrors(t *testing.T) {
	fake := newFakeConsole()
	fake.perf = func(string, RepTag) map[string]string {
		return map[string]string{"mode": "offline", "dropped": "0", "committed_tps": "5.000", "latency_p99_ms": "100.000"}
	}
	fake.end = func(string, RepTag) map[string]any { return map[string]any{"failed": false} }
	pattern := consolePatterns(t)
	for _, target := range slices.Sorted(maps.Keys(internalRoutes)) {
		for _, mode := range []string{"offline", "onchain"} {
			srv := httptest.NewServer(&failOnce{pattern: pattern, target: target, next: fake})
			rt := &recordingTransport{}
			o := testRepeatOpts(t, srv.URL)
			o.Client, o.Config.Mode = &http.Client{Transport: rt}, mode
			o.Warmups, o.Reps = 1, 1
			_ = Repeat(context.Background(), o) // a failed step may end the campaign: that is the branch under test
			srv.Close()
			for _, c := range rt.calls {
				if p := pattern(c[0], c[1]); internalRoutes[p] != c[0] {
					t.Errorf("%s failing once (%s): the driver then calls %s %s (route %q), which internalRoutes does not allow",
						target, mode, c[0], c[1], p)
				}
			}
		}
	}
}

// An internal request reaches its handler as a served one would: a non-nil
// body and a loopback client address.
func TestInternalTransportRequestLooksServed(t *testing.T) {
	s, _, _ := testServer(t, nil)
	var body io.ReadCloser
	var remote string
	s.handler = http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { body, remote = r.Body, r.RemoteAddr })
	client, base := s.internalClient(nil)
	resp, err := client.Get(base + "/api/runs/x/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if body != http.NoBody || !isLoopback(remote) {
		t.Fatalf("handler saw body %v, remote %q; want http.NoBody and a loopback address", body, remote)
	}
}

// A handler panic reached through the internal transport is an error for the
// job that hit it, not a crashed console.
func TestInternalTransportRecoversHandlerPanic(t *testing.T) {
	s, _, _ := testServer(t, nil)
	s.handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })
	client, base := s.internalClient(nil)
	if _, err := client.Get(base + "/api/runs/x/status"); err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("want a handler-panicked error, got %v", err)
	}
}

// --- preflight -----------------------------------------------------------------

func TestPreflightFabric(t *testing.T) {
	s, _ := gateServer(t, liveFabric(), "abc", 1<<62)

	fakeHostProbes(t, "", errors.New("connection refused"))
	rep := s.preflight(PreflightInput{Mode: "onchain"})
	if rep.Fabric.Reachable == nil || *rep.Fabric.Reachable {
		t.Fatalf("reachable = %v, want false", rep.Fabric.Reachable)
	}
	f := findings(rep.Warnings)["fabric_unreachable"]
	if f.Severity != severityBlock || !f.Forceable {
		t.Fatalf("an unreachable peer must be a forceable block for an on-chain run: %+v", rep.Warnings)
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
	rep = off.preflight(PreflightInput{Mode: "onchain"})
	if rep.Fabric.Enabled || rep.Fabric.Reachable != nil {
		t.Fatalf("no Fabric configured: enabled=%v reachable=%v", rep.Fabric.Enabled, rep.Fabric.Reachable)
	}
	if f := findings(rep.Warnings)["fabric_not_configured"]; f.Severity != severityBlock || f.Forceable {
		t.Fatalf("on-chain with no Fabric must be an unforceable block: %+v", rep.Warnings)
	}
	if off.preflight(PreflightInput{Mode: "offline"}).Blocked() {
		t.Fatal("an offline run needs no Fabric")
	}
}

func TestPreflightLadder(t *testing.T) {
	fakeHostProbes(t, "", nil)
	s, root := gateServer(t, FabricConfig{}, "abc123", 1<<62)
	big := PreflightInput{Mode: "offline", Voters: 2000, Positions: 3}

	rep := s.preflight(big)
	if f := findings(rep.Warnings)["ladder_missing"]; f.Severity != severityBlock || f.Forceable || rep.Ladder.OK {
		t.Fatalf("no ladder.json above the ceiling must be an unforceable block: ok=%v %+v", rep.Ladder.OK, rep.Warnings)
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

	s, root := gateServer(t, liveFabric(), "abc", need-1)
	rep := s.preflight(in)
	if f := findings(rep.Warnings)["disk_short"]; f.Severity != severityBlock || f.Forceable {
		t.Fatalf("projected ledger above free space must be an unforceable block: %+v", rep.Warnings)
	}
	if rep.Disk.ProjectedLedgerBytes == nil || *rep.Disk.ProjectedLedgerBytes != need ||
		rep.Disk.FreeBytes == nil || *rep.Disk.FreeBytes != need-1 || rep.Disk.Path != root {
		t.Fatalf("disk report = %+v", rep.Disk)
	}

	s2, _ := gateServer(t, liveFabric(), "abc", need)
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
	if rep.Host.GuestLoad1 == nil || rep.Host.GuestLoad5 == nil || rep.Host.CPUs != runtime.NumCPU() || rep.Host.HostCPUPct != nil {
		t.Fatalf("host = %+v", rep.Host)
	}
	if codes(rep.Warnings)["host_load"] != severityWarn || rep.Blocked() {
		t.Fatalf("load at 50%% of CPUs must warn, not block: %+v", rep.Warnings)
	}

	fakeHostProbes(t, fmt.Sprintf("%.2f 0.00 0.00 1/300 1\n", cpus*0.1), nil)
	s.hostCache.reset()
	if _, ok := codes(s.preflight(PreflightInput{Mode: "offline"}).Warnings)["host_load"]; ok {
		t.Fatal("load at 10% of CPUs must not warn")
	}

	fakeHostProbes(t, "", nil) // no /proc/loadavg: Windows
	s.hostCache.reset()
	if rep := s.preflight(PreflightInput{Mode: "offline"}); rep.Host.GuestLoad1 != nil || rep.Host.GuestLoad5 != nil {
		t.Fatalf("no loadavg must report null, got %v", rep.Host.GuestLoad1)
	}
}

// reset drops the cached sample, so a test can change its fakes between calls.
func (c *hostSampleCache) reset() {
	c.mu.Lock()
	c.at = time.Time{}
	c.mu.Unlock()
}

// Inside WSL2 the guest's loadavg cannot see a Windows program eating cores;
// the Windows host's CPU is sampled through interop and warned on separately.
// The fake output is the Get-Counter form's: an invariant-culture average.
func TestPreflightHostCPUOnWSL(t *testing.T) {
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	fakeHostProbes(t, "0.50 0.40 0.30 1/100 1", nil)

	calls := fakeWSLHost(t, "29.430375364287\r\n", nil)
	rep := s.preflight(PreflightInput{Mode: "offline"})
	if rep.Host.HostCPUPct == nil || *rep.Host.HostCPUPct != 29.430375364287 || rep.Host.GuestLoad1 == nil || *rep.Host.GuestLoad1 != 0.5 || *calls != 1 {
		t.Fatalf("host = %+v (calls %d)", rep.Host, *calls)
	}
	if f := findings(rep.Warnings)["host_cpu"]; f.Severity != severityWarn {
		t.Fatalf("host CPU at 29.4%% must warn: %+v", rep.Warnings)
	}

	fakeWSLHost(t, "12,5", nil) // a comma-decimal culture, should one ever print
	s.hostCache.reset()
	rep = s.preflight(PreflightInput{Mode: "offline"})
	if rep.Host.HostCPUPct == nil || *rep.Host.HostCPUPct != 12.5 {
		t.Fatalf("comma decimal: %v", rep.Host.HostCPUPct)
	}
	if _, ok := codes(rep.Warnings)["host_cpu"]; ok {
		t.Fatal("host CPU at 12.5% must not warn")
	}

	fakeWSLHost(t, "", errors.New("powershell.exe: not found"))
	s.hostCache.reset()
	if rep := s.preflight(PreflightInput{Mode: "offline"}); rep.Host.HostCPUPct != nil {
		t.Fatalf("a failed sample must be null, got %v", *rep.Host.HostCPUPct)
	}

	calls = fakeWSLHost(t, "90", nil)
	readOSRelease = func() ([]byte, error) { return []byte("6.8.0-45-generic\n"), nil }
	s.hostCache.reset()
	if rep := s.preflight(PreflightInput{Mode: "offline"}); rep.Host.HostCPUPct != nil || *calls != 0 {
		t.Fatalf("outside WSL there is no host sample: %v (calls %d)", rep.Host.HostCPUPct, *calls)
	}
}

// Preflight reuses its host sample for preflightHostTTL, and concurrent
// callers share one sample in flight: a page looping GET /api/preflight
// cannot spawn a powershell.exe per request. Repetition samples stay live.
func TestPreflightHostSampleCached(t *testing.T) {
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	fakeHostProbes(t, "", nil)
	var mu sync.Mutex
	calls := 0
	readOSRelease = func() ([]byte, error) { return []byte("5.15.167.4-microsoft-standard-WSL2\n"), nil }
	hostCPUCommand = func(context.Context) ([]byte, error) {
		time.Sleep(100 * time.Millisecond) // long enough for the callers to overlap
		mu.Lock()
		calls++
		mu.Unlock()
		return []byte("20"), nil
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}

	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rep := s.preflight(PreflightInput{Mode: "offline"}); rep.Host.HostCPUPct == nil || *rep.Host.HostCPUPct != 20 {
				t.Errorf("a waiting caller must get the shared sample: %+v", rep.Host)
			}
		}()
	}
	wg.Wait()
	if n := count(); n != 1 {
		t.Fatalf("5 concurrent preflights spawned %d samples, want 1", n)
	}
	s.preflight(PreflightInput{Mode: "offline"})
	if n := count(); n != 1 {
		t.Fatalf("a preflight within %s must reuse the sample; %d samples", preflightHostTTL, n)
	}

	s.hostCache.mu.Lock()
	s.hostCache.at = time.Now().Add(-preflightHostTTL - time.Second)
	s.hostCache.mu.Unlock()
	s.preflight(PreflightInput{Mode: "offline"})
	if n := count(); n != 2 {
		t.Fatalf("an expired sample must be taken again; %d samples", n)
	}

	sampleHost() // a repetition's sample: never cached
	if n := count(); n != 3 {
		t.Fatalf("sampleHost must sample live; %d samples", n)
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

// SAKSI_AUDIT_THREADS is parsed as the auditor parses it: set to anything but a
// positive integer (empty included) and the auditor refuses to run.
func TestPreflightVerifyThreads(t *testing.T) {
	fakeHostProbes(t, "", nil)
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)

	for _, bad := range []string{"", "0", "-2", "four", "2.5", "++8"} {
		t.Setenv(auditThreadsEnv, bad)
		rep := s.preflight(PreflightInput{Mode: "offline"})
		if f := findings(rep.Warnings)["verify_threads_invalid"]; f.Severity != severityBlock || f.Forceable {
			t.Errorf("%s=%q must be an unforceable block: %+v", auditThreadsEnv, bad, rep.Warnings)
		}
	}
	t.Setenv(auditThreadsEnv, "+8")
	if rep := s.preflight(PreflightInput{Mode: "offline"}); rep.VerifyThreadsDefault != 8 || rep.Blocked() {
		t.Fatalf("+8: %d %+v", rep.VerifyThreadsDefault, rep.Warnings)
	}
	t.Setenv(auditThreadsEnv, " 1 ")
	rep := s.preflight(PreflightInput{Mode: "offline"})
	if rep.VerifyThreadsDefault != 1 || codes(rep.Warnings)["verify_threads"] != severityWarn || rep.Blocked() {
		t.Fatalf("one verify thread must warn: %d %+v", rep.VerifyThreadsDefault, rep.Warnings)
	}

	os.Unsetenv(auditThreadsEnv) // t.Setenv above restores it after the test
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

func TestCampaignBodyValidation(t *testing.T) {
	fakeHostProbes(t, "", nil)
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	for _, tc := range []struct {
		name string
		body map[string]any
		want string
	}{
		{"misspelled reps", map[string]any{"config": good(), "rep": 3}, "unknown field"},
		{"warm-ups only", map[string]any{"config": good(), "warmups": 2}, "reps must be >= 1"},
		{"nothing", map[string]any{"config": good()}, "reps must be >= 1"},
		{"sweep of 1", map[string]any{"config": good(), "reps": 1, "sweep": 1}, "sweep must be"},
		{"negative burst", map[string]any{"config": good(), "reps": 1, "burst": -1}, ">= 0"},
		{"burst over the offline bound", map[string]any{"config": good(), "reps": 1, "burst": OfflineRecordCeiling + 1},
			fmt.Sprintf("burst of %d voters", OfflineRecordCeiling+1)},
	} {
		rec, _ := startCampaign(t, s, tc.body, "")
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: want 400 %q, got %d %s", tc.name, tc.want, rec.Code, rec.Body)
		}
	}
	noCampaignStarted(t, s)
}

// The burst is its own election at `burst` voters, after the measured reps: its
// ladder and disk refusals must come at start, not hours in at its /generate.
func TestBurstEscapesPreflight(t *testing.T) {
	fakeHostProbes(t, "", nil)
	s, _ := gateServer(t, FabricConfig{}, "abc123", 1<<62)
	for _, force := range []bool{false, true} {
		rec, _ := startCampaign(t, s, map[string]any{"config": good(), "reps": 2, "burst": 2000, "force": force}, "")
		body := rec.Body.String()
		if rec.Code != http.StatusConflict || !strings.Contains(body, "ladder_missing") ||
			!strings.Contains(body, "burst of 2000 voters") || !strings.Contains(body, "cannot override") {
			t.Fatalf("force=%v: want 409 naming the burst's ladder block, got %d %s", force, rec.Code, body)
		}
	}
	noCampaignStarted(t, s)

	// On-chain: the measured reps fit the disk, the burst does not.
	oc := good()
	oc.Mode = "onchain"
	s2, root := gateServer(t, liveFabric(), "abc123", uint64(2*oc.Voters*oc.Positions*LedgerBytesPerBallot))
	writeLadder(t, root, "abc123")
	rec, _ := startCampaign(t, s2, map[string]any{"config": oc, "reps": 2, "burst": 2000}, "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "disk_short") ||
		!strings.Contains(rec.Body.String(), "a 2000-voter burst") {
		t.Fatalf("want 409 naming the burst's disk block, got %d %s", rec.Code, rec.Body)
	}
	noCampaignStarted(t, s2)
}

// Every run of a campaign lands on the same ledger: warm-ups, measured reps,
// every sweep step the sweep can run, and the burst. A campaign whose runs each
// fit but together do not is refused, and force cannot override it.
func TestCampaignDiskProjectsEveryRun(t *testing.T) {
	fakeHostProbes(t, "", nil)
	oc := good() // 10 voters x 1 position
	oc.Mode = "onchain"
	perRun := uint64(oc.Voters * oc.Positions * LedgerBytesPerBallot)
	o := CampaignOptions{Warmups: 1, Reps: 2, Sweep: 2, Burst: 5}
	want := 3*perRun + maxSweepSteps*perRun + 5*uint64(oc.Positions)*LedgerBytesPerBallot
	if got, _ := campaignDiskBytes(oc, o); got != want {
		t.Fatalf("campaignDiskBytes = %d, want %d", got, want)
	}
	if got, _ := campaignDiskBytes(oc, CampaignOptions{Reps: 4}); got != 4*perRun {
		t.Fatalf("no sweep, no burst: %d, want %d", got, 4*perRun)
	}

	s, _ := gateServer(t, liveFabric(), "abc", want-1)
	if rep := s.preflight(PreflightInput{Mode: "onchain", Voters: oc.Voters, Positions: oc.Positions}); rep.Blocked() {
		t.Fatalf("one run fits, so the one-run preflight must not block: %+v", rep.Warnings)
	}
	for _, force := range []bool{false, true} {
		rec, _ := startCampaign(t, s, map[string]any{"config": oc, "warmups": 1, "reps": 2, "sweep": 2, "burst": 5, "force": force}, "")
		body := rec.Body.String()
		for _, part := range []string{
			"disk_short", "cannot override", fmt.Sprintf("projects %d bytes", want), fmt.Sprintf("only %d bytes are free", want-1),
			"3 warm-up and measured runs", fmt.Sprintf("up to %d sweep steps", maxSweepSteps), "a 5-voter burst",
		} {
			if rec.Code != http.StatusConflict || !strings.Contains(body, part) {
				t.Fatalf("force=%v: want 409 naming %q, got %d %s", force, part, rec.Code, body)
			}
		}
	}
	noCampaignStarted(t, s)
}

// force overrides a peer that did not answer the probe, and nothing else.
func TestCampaignForceOverridesOnlyFabricUnreachable(t *testing.T) {
	fakeHostProbes(t, "", nil)
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	big := good()
	big.Voters = 2000 // above the ladder ceiling, no ladder.json
	rec, _ := startCampaign(t, s, map[string]any{"config": big, "reps": 1, "force": true}, "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "ladder_missing") ||
		!strings.Contains(rec.Body.String(), "cannot override ladder_missing") {
		t.Fatalf("a forced ladder block: want 409 that says it cannot be forced, got %d %s", rec.Code, rec.Body)
	}
	noCampaignStarted(t, s)

	fakeHostProbes(t, "", errors.New("connection refused"))
	s2, _ := gateServer(t, liveFabric(), "abc", 1<<62)
	oc := good()
	oc.Mode = "onchain"
	rec, _ = startCampaign(t, s2, map[string]any{"config": oc, "reps": 1}, "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "fabric_unreachable") {
		t.Fatalf("unreachable peer without force: want 409, got %d %s", rec.Code, rec.Body)
	}
	noCampaignStarted(t, s2)
	rec, id := startCampaign(t, s2, map[string]any{"config": oc, "reps": 1, "force": true}, "")
	if rec.Code != http.StatusAccepted || id == "" {
		t.Fatalf("forced: want 202, got %d %s", rec.Code, rec.Body)
	}
	waitJob(t, s2, id, time.Minute)
	var onDisk campaignRecord
	if err := readJSON(filepath.Join(s2.store.Root(), campaignsDir, id, campaignFile), &onDisk); err != nil {
		t.Fatal(err)
	}
	if f := findings(onDisk.Preflight.Warnings)["fabric_unreachable"]; !f.Forceable {
		t.Fatalf("the forced campaign must keep its preflight snapshot: %+v", onDisk.Preflight.Warnings)
	}
}

// One job console-wide; cancel stops after the current repetition; no attacks;
// every repetition carries its host samples.
func TestCampaignExclusivityAndCancel(t *testing.T) {
	fakeHostProbes(t, "1.00 0.50 0.25 1/100 1", nil)
	fakeWSLHost(t, "42", nil)
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
	var onDisk campaignRecord
	if err := readJSON(filepath.Join(s.store.Root(), campaignsDir, id, campaignFile), &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.Status != jobCancelled || len(onDisk.Reps) != 1 {
		t.Fatalf("cancelled campaign on disk: status=%s reps=%d", onDisk.Status, len(onDisk.Reps))
	}
	row := onDisk.Reps[0]
	if row.Status != jobFailed || row.HostStart == nil || row.HostEnd == nil ||
		row.HostStart.HostCPUPct == nil || *row.HostStart.HostCPUPct != 42 ||
		row.HostEnd.GuestLoad1 == nil || *row.HostEnd.GuestLoad1 != 1 {
		t.Fatalf("repetition row = %+v (start %+v end %+v)", row, row.HostStart, row.HostEnd)
	}
	if !onDisk.Config.SkipAttacks {
		t.Fatal("a campaign must force skip_attacks")
	}
	if run, err := s.record(row.RunID); err != nil || !run.Config.SkipAttacks || run.Config.Rep == nil || run.Config.Rep.Kind != "warmup" {
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
// it, was interrupted by a restart: its rows are settled from their run
// folders first, and once settled they are cached, not re-read.
func TestCampaignMarkedInterruptedAfterRestart(t *testing.T) {
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	runID, runDir, err := s.store.Create(good(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, runDir, PerfCSV, "run_id,committed_tps,latency_p99_ms\n"+runID+",12.5,80\n")
	writeFile(t, runDir, JournalFile, `{"event":"env"}`+"\n"+`{"event":"run.end","failed":false}`+"\n")

	dir := filepath.Join(s.store.Root(), campaignsDir, "campaign-20260914-120000-1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := &campaignRecord{ID: filepath.Base(dir), Status: jobRunning, CreatedAt: time.Now().UTC(), Config: good(),
		Reps: []campaignRep{{Index: 1, Kind: "measured", RunID: runID, Status: jobRunning}}}
	if err := saveCampaign(dir, rec); err != nil {
		t.Fatal(err)
	}

	code, body := getCampaign(t, s, rec.ID)
	reps, _ := body["reps"].([]any)
	if code != http.StatusOK || body["status"] != jobInterrupted || len(reps) != 1 {
		t.Fatalf("want interrupted with 1 row, got %d %v", code, body)
	}
	if row := reps[0].(map[string]any); row["status"] != jobDone || row["committed_tps"] != 12.5 {
		t.Fatalf("row must be settled from its run folder: %v", row)
	}
	var onDisk campaignRecord
	if err := readJSON(filepath.Join(dir, campaignFile), &onDisk); err != nil || onDisk.Status != jobInterrupted ||
		onDisk.Reps[0].Status != jobDone || *onDisk.Reps[0].CommittedTPS != 12.5 {
		t.Fatalf("interrupted state and settled rows must be persisted: %+v %v", onDisk, err)
	}

	writeFile(t, runDir, PerfCSV, "run_id,committed_tps,latency_p99_ms\n"+runID+",99,80\n")
	list := httptest.NewRecorder()
	s.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/campaigns", nil))
	if !strings.Contains(list.Body.String(), `"status":"interrupted"`) || !strings.Contains(list.Body.String(), `"committed_tps":12.5`) {
		t.Fatalf("list must show the settled, cached row: %s", list.Body)
	}
}

// The bundle holds each run's thesis files under <run-id>/, journal line 1,
// the campaign's summary, record and preflight, and a manifest of what is there.
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
	want := []string{campaignFile, preflightBundleFile, SummaryCSV, manifestFile}
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
	manifest := files[manifestFile]
	for _, line := range []string{
		reps[0].RunID + " (warmup 1, done)",
		"included: run.json, perf.csv, correctness.csv, journal-line1.json",
		"missing:  perf-schema.md, negative-tests.csv, ground-truth-check.json, timings.json",
		"missing:  perf-schema.md, ground-truth-check.json, timings.json",
		"included: summary.csv, campaign.json, preflight.json",
	} {
		if !strings.Contains(manifest, line) {
			t.Errorf("MANIFEST.txt lacks %q:\n%s", line, manifest)
		}
	}
}

// A file that exists but cannot be read aborts the response rather than
// finishing a valid-looking zip without it.
func TestCampaignExportAbortsOnReadError(t *testing.T) {
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	runID, dir, err := s.store.Create(good(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, TimingsFile), 0o755); err != nil { // opens, cannot be read
		t.Fatal(err)
	}
	id := "campaign-20260914-140000-1"
	cdir := filepath.Join(s.store.Root(), campaignsDir, id)
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := saveCampaign(cdir, &campaignRecord{ID: id, Status: jobDone, Reps: []campaignRep{{RunID: runID, Status: jobDone}}}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if p := recover(); p != http.ErrAbortHandler {
			t.Fatalf("want panic(http.ErrAbortHandler), got %v", p)
		}
	}()
	s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/campaigns/"+id+"/export", nil))
	t.Fatal("the export completed despite an unreadable file")
}

// A campaign.json that cannot be written is logged and kept as save_error.
func TestPersistCampaignRecordsSaveError(t *testing.T) {
	rec := &campaignRecord{ID: "campaign-x"}
	persistCampaign(filepath.Join(t.TempDir(), "no-such-dir"), rec)
	if rec.SaveError == "" {
		t.Fatal("a failed save must set save_error")
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
		if r.Index != want.Index || r.Kind != want.Kind || r.Status != jobDone || r.Failed || r.HostStart == nil || r.HostEnd == nil {
			t.Errorf("rep %d = %+v, want %+v done with host samples", i, r, want)
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
	if !names[SummaryCSV] || !names[campaignFile] || !names[preflightBundleFile] || !names[manifestFile] {
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

// A campaign posted with an attack plan (a single election's config reused)
// starts with the plan dropped: no repetition runs attacks, and none is refused
// by the plan-with-skip_attacks rule.
func TestCampaignDropsAttackPlan(t *testing.T) {
	fakeHostProbes(t, "", nil)
	s, _, exec := testServer(t, nil)
	exec.run = func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("fake saksi-demo") }
	c := good()
	c.AttackPlan = &AttackPlan{Stages: []string{StageBallots, StageClose}}
	if err := c.Validate(); err != nil {
		t.Fatalf("the plan must be one a single election accepts: %v", err)
	}

	rec, id := startCampaign(t, s, map[string]any{"config": c, "warmups": 1, "reps": 1, "burst": 3}, "")
	if rec.Code != http.StatusAccepted || id == "" {
		t.Fatalf("a campaign with an attack plan: want 202, got %d %s", rec.Code, rec.Body)
	}
	waitJob(t, s, id, time.Minute)
	var onDisk campaignRecord
	if err := readJSON(filepath.Join(s.store.Root(), campaignsDir, id, campaignFile), &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.Config.AttackPlan != nil || len(onDisk.Reps) != 3 {
		t.Fatalf("campaign.json: plan %+v, %d reps (want none, 3)", onDisk.Config.AttackPlan, len(onDisk.Reps))
	}
	for _, r := range onDisk.Reps {
		data, err := os.ReadFile(filepath.Join(s.store.Root(), r.RunID, RunFile))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "attack_plan") {
			t.Errorf("%s (%s) run.json carries an attack plan: %s", r.RunID, r.Kind, data)
		}
	}
}

// A campaign must not share the network with a single-election run that is
// running a phase or paused at an attack stage.
func TestPreflightBlocksWhileARunIsBusy(t *testing.T) {
	fakeHostProbes(t, "", nil)
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	if why := s.claim("security-run-1", func() {}); why != "" {
		t.Fatal(why)
	}
	s.exec.setPause("security-run-1", &stagePause{view: PauseView{Paused: true, Stage: StageBallots}})

	rep := s.preflight(PreflightInput{Mode: "offline"})
	f := findings(rep.Warnings)["run_busy"]
	if f.Severity != severityBlock || f.Forceable || !strings.Contains(f.Message, "security-run-1 (paused at the ballots attack stage)") {
		t.Fatalf("a busy run must be an unforceable block naming it and its pause: %+v", rep.Warnings)
	}
	rec, _ := startCampaign(t, s, map[string]any{"config": good(), "reps": 1, "force": true}, "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "run_busy") {
		t.Fatalf("a campaign while a run is busy: want 409 run_busy, got %d %s", rec.Code, rec.Body)
	}
	noCampaignStarted(t, s)

	s.exec.setPause("security-run-1", nil)
	s.finish("security-run-1")
	if rep := s.preflight(PreflightInput{Mode: "offline"}); rep.Blocked() {
		t.Fatalf("no run busy: %+v", rep.Warnings)
	}
}

// Preflight runs seconds before the job slot is claimed. A run that starts in
// between must still refuse the campaign: the busy check is repeated together
// with the claim.
func TestCampaignRefusesARunThatStartedDuringPreflight(t *testing.T) {
	fakeHostProbes(t, "", nil)
	s, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.freeSpace = func(string) (uint64, error) {
		once.Do(func() { close(entered); <-release })
		return 1 << 62, nil
	}
	done := make(chan *httptest.ResponseRecorder)
	go func() {
		rec, _ := startCampaign(t, s, map[string]any{"config": good(), "reps": 1}, "")
		done <- rec
	}()
	<-entered
	if why := s.claim("fault-run", func() {}); why != "" {
		t.Fatal(why)
	}
	close(release)
	rec := <-done
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "fault-run") {
		t.Fatalf("a run started during preflight: want 409 naming it, got %d %s", rec.Code, rec.Body)
	}
	noCampaignStarted(t, s)
	s.finish("fault-run")
}
