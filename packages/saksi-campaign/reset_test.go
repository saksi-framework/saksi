package campaign

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// enabledFabric passes FabricConfig.Enabled without pointing at anything real.
func enabledFabric() FabricConfig {
	return FabricConfig{PeerEndpoint: "127.0.0.1:1", GatewayPeer: "peer0.org1.example.com", TLSCert: "tls.crt",
		MSPID: "Org1MSP", Cert: "cert.pem", Key: "key.pem", Channel: "saksi", Chaincode: "saksi-bulletin"}
}

// scriptCall is one command a fake scriptRunner was asked to run.
type scriptCall struct {
	dir, name string
	args      []string
}

// resetServer is an on-chain console whose tier.sh is found at a fake repo
// root and whose script runner records its calls and runs run instead.
func resetServer(t *testing.T, run func(ctx context.Context, out io.Writer) (int, error)) (*Server, *[]scriptCall) {
	t.Helper()
	s, _ := gateServer(t, enabledFabric(), "abc", 1<<62)
	s.tierScript = func() (string, error) { return filepath.Join("/repo", "tools", "tier.sh"), nil }
	calls := &[]scriptCall{}
	var mu sync.Mutex
	s.runScript = func(ctx context.Context, dir string, out io.Writer, name string, args ...string) (int, error) {
		mu.Lock()
		*calls = append(*calls, scriptCall{dir, name, args})
		mu.Unlock()
		return run(ctx, out)
	}
	return s, calls
}

func postReset(t *testing.T, s *Server, body any, remote, user string) *httptest.ResponseRecorder {
	t.Helper()
	req := signIn(t, s, user, postJSON("/api/network/reset", body))
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

var goodReset = map[string]any{"voters": 1000, "positions": 1, "confirm": "RESET"}

const loopback = "127.0.0.1:50000"

func TestResetRefusals(t *testing.T) {
	never := func(context.Context, io.Writer) (int, error) {
		t.Fatal("tools/tier.sh ran on a refused reset")
		return 0, nil
	}
	s, calls := resetServer(t, never)
	cases := []struct {
		name   string
		body   any
		remote string
		want   int
		says   string
	}{
		{"non-loopback", goodReset, "192.0.2.7:4000", http.StatusForbidden, "loopback"},
		{"ipv6 non-loopback", goodReset, "[2001:db8::1]:4000", http.StatusForbidden, "loopback"},
		{"missing confirm", map[string]any{"voters": 1000, "positions": 1}, loopback, http.StatusBadRequest, "exactly \\\"RESET\\\""},
		{"lowercase confirm", map[string]any{"voters": 1000, "positions": 1, "confirm": "reset"}, loopback, http.StatusBadRequest, "exactly \\\"RESET\\\""},
		{"padded confirm", map[string]any{"voters": 1000, "positions": 1, "confirm": "RESET "}, loopback, http.StatusBadRequest, "exactly \\\"RESET\\\""},
		{"no voters", map[string]any{"positions": 1, "confirm": "RESET"}, loopback, http.StatusBadRequest, "voters"},
		{"unknown field", map[string]any{"voters": 1, "positions": 1, "confirm": "RESET", "force": true}, loopback, http.StatusBadRequest, "force"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postReset(t, s, tc.body, tc.remote, "")
			if rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.says) {
				t.Fatalf("want %d naming %s, got %d %s", tc.want, tc.says, rec.Code, rec.Body)
			}
		})
	}
	get := httptest.NewRequest(http.MethodGet, "/api/network/reset", nil)
	get.RemoteAddr = loopback
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, get)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: want 405, got %d", rec.Code)
	}

	off, _ := gateServer(t, FabricConfig{}, "abc", 1<<62)
	if rec := postReset(t, off, goodReset, loopback, ""); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Fabric") {
		t.Fatalf("no Fabric: want 400, got %d %s", rec.Code, rec.Body)
	}

	for _, host := range []struct {
		name, goos string
		bash       bool
		root       string
		says       string
	}{
		{"windows", "windows", true, t.TempDir(), "Windows"},
		{"no bash", "linux", false, t.TempDir(), "bash is not on"},
		{"no script", "linux", true, t.TempDir(), "tier.sh"},
	} {
		t.Run(host.name, func(t *testing.T) {
			s.tierScript = func() (string, error) {
				return locateTierScript(host.goos, func(string) (string, error) {
					if !host.bash {
						return "", errors.New("not found")
					}
					return "/bin/bash", nil
				}, host.root, true)
			}
			rec := postReset(t, s, goodReset, loopback, "")
			if rec.Code != http.StatusNotImplemented || !strings.Contains(rec.Body.String(), host.says) {
				t.Fatalf("want 501 naming %q, got %d %s", host.says, rec.Code, rec.Body)
			}
		})
	}
	if len(*calls) != 0 || s.jobs.running() != nil {
		t.Fatalf("a refused reset ran %v or holds the job slot", *calls)
	}
}

// Admin-only in the route table, and loopback-only even for an admin.
func TestResetNeedsAdminAndLoopbackWithAuthOn(t *testing.T) {
	s, calls := resetServer(t, func(context.Context, io.Writer) (int, error) { return 0, nil })
	enableTestAuth(t, s)
	for _, tc := range []struct {
		user, remote string
		want         int
	}{
		{"", loopback, http.StatusUnauthorized},
		{"t1", loopback, http.StatusForbidden},
		{"admin", "192.0.2.7:4000", http.StatusForbidden},
		{"admin", "10.0.0.2:4000", http.StatusForbidden},
	} {
		if rec := postReset(t, s, goodReset, tc.remote, tc.user); rec.Code != tc.want {
			t.Errorf("%q from %s: want %d, got %d %s", tc.user, tc.remote, tc.want, rec.Code, rec.Body)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("tools/tier.sh ran for a refused caller: %v", *calls)
	}
	rec := postReset(t, s, goodReset, "[::1]:4000", "admin")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("admin on loopback: want 202, got %d %s", rec.Code, rec.Body)
	}
	var out struct{ Job string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	waitJob(t, s, out.Job, time.Minute)
}

// The console never resets its own network or arms a fault from a job.
func TestInfraRoutesAreNotInternal(t *testing.T) {
	s, calls := resetServer(t, func(context.Context, io.Writer) (int, error) { return 0, nil })
	runID, _, err := s.store.Create(onchainConfig(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client, base := s.internalClient(nil)
	for _, p := range []struct{ path, body string }{
		{"/api/network/reset", `{"voters":1,"positions":1,"confirm":"RESET"}`},
		{"/api/runs/" + runID + "/fault", `{"kind":"peer-restart","at":0.5,"down_s":20,"confirm":"RESTART"}`},
	} {
		resp, err := client.Post(base+p.path, "application/json", strings.NewReader(p.body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("internal POST %s: want 403, got %d", p.path, resp.StatusCode)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("an internal call ran tools/tier.sh: %v", *calls)
	}
}

func TestResetRefusedWhileAnythingIsBusy(t *testing.T) {
	s, calls := resetServer(t, func(context.Context, io.Writer) (int, error) { return 0, nil })

	if why := s.claim("run-a", func() {}); why != "" {
		t.Fatal(why)
	}
	if rec := postReset(t, s, goodReset, loopback, ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "run-a") {
		t.Fatalf("a running phase: want 409 naming run-a, got %d %s", rec.Code, rec.Body)
	}
	s.exec.setPause("run-a", &stagePause{view: PauseView{Paused: true, Stage: StageBallots}})
	if rec := postReset(t, s, goodReset, loopback, ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "paused at the ballots") {
		t.Fatalf("a paused run: want 409 naming the pause, got %d %s", rec.Code, rec.Body)
	}
	s.exec.setPause("run-a", nil)
	s.finish("run-a")

	for _, kind := range []string{"campaign", "ladder", jobKindReset} {
		j, running := s.jobs.start(kind)
		if running != nil {
			t.Fatalf("slot held by %s", running.ID)
		}
		if rec := postReset(t, s, goodReset, loopback, ""); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), j.ID) {
			t.Fatalf("a running %s: want 409 naming %s, got %d %s", kind, j.ID, rec.Code, rec.Body)
		}
		s.jobs.run(j, func() (json.RawMessage, error) { return nil, nil }, nil)
	}
	if len(*calls) != 0 {
		t.Fatalf("tools/tier.sh ran while busy: %v", *calls)
	}
}

// While a reset runs, no phase, ladder or campaign starts; while a phase runs,
// the ladder does not start.
func TestResetExcludesPhasesLadderAndCampaigns(t *testing.T) {
	fakeHostProbes(t, "", nil)
	release := make(chan struct{})
	s, _ := resetServer(t, func(ctx context.Context, out io.Writer) (int, error) {
		<-release
		return 0, nil
	})
	rec := postReset(t, s, goodReset, loopback, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	var out struct{ Job string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	if why := s.claim("any-run", func() {}); !strings.Contains(why, "being reset") {
		t.Fatalf("a phase during a reset: claim = %q", why)
	}
	gen := httptest.NewRecorder()
	s.ServeHTTP(gen, postJSON("/generate", good()))
	if gen.Code != http.StatusConflict || !strings.Contains(gen.Body.String(), "being reset") {
		t.Fatalf("/generate during a reset: want 409, got %d %s", gen.Code, gen.Body)
	}
	lad := httptest.NewRecorder()
	s.ServeHTTP(lad, httptest.NewRequest(http.MethodPost, "/api/ladder", nil))
	if lad.Code != http.StatusConflict || !strings.Contains(lad.Body.String(), out.Job) {
		t.Fatalf("ladder during a reset: want 409, got %d %s", lad.Code, lad.Body)
	}
	if rec, _ := startCampaign(t, s, map[string]any{"config": good(), "reps": 1}, ""); rec.Code != http.StatusConflict {
		t.Fatalf("campaign during a reset: want 409, got %d %s", rec.Code, rec.Body)
	}
	close(release)
	if v := waitJob(t, s, out.Job, time.Minute); v.Status != jobDone {
		t.Fatalf("reset job: %+v", v)
	}

	if why := s.claim("fault-run", func() {}); why != "" {
		t.Fatal(why)
	}
	lad = httptest.NewRecorder()
	s.ServeHTTP(lad, httptest.NewRequest(http.MethodPost, "/api/ladder", nil))
	if lad.Code != http.StatusConflict || !strings.Contains(lad.Body.String(), "fault-run") {
		t.Fatalf("ladder beside a running phase: want 409 naming it, got %d %s", lad.Code, lad.Body)
	}
	s.finish("fault-run")
}

func TestResetJobRecordsOutputAndExitCode(t *testing.T) {
	for _, tc := range []struct {
		code   int
		status string
	}{{0, jobDone}, {3, jobFailed}} {
		t.Run(fmt.Sprint("exit ", tc.code), func(t *testing.T) {
			s, calls := resetServer(t, func(_ context.Context, out io.Writer) (int, error) {
				fmt.Fprintln(out, "tier: 1000 voters x 1 positions")
				fmt.Fprintln(out, "network down")
				return tc.code, nil
			})
			runDir := filepath.Join(s.store.Root(), "kept-run")
			if err := os.MkdirAll(runDir, 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, runDir, "run.json", `{"run_id":"kept-run"}`)

			rec := postReset(t, s, goodReset, loopback, "")
			var out struct{ Job string }
			_ = json.Unmarshal(rec.Body.Bytes(), &out)
			v := waitJob(t, s, out.Job, time.Minute)
			if v.Status != tc.status || v.Kind != jobKindReset {
				t.Fatalf("job = %+v, want %s", v, tc.status)
			}
			if strings.Join(v.Log, "|") != "tier: 1000 voters x 1 positions|network down" {
				t.Fatalf("job log = %q", v.Log)
			}
			var res map[string]any
			if err := json.Unmarshal(v.Result, &res); err != nil || res["exit_code"] != float64(tc.code) || res["timed_out"] != false {
				t.Fatalf("result = %s (%v)", v.Result, err)
			}
			if tc.code != 0 && !strings.Contains(v.Error, "exited with code 3") {
				t.Fatalf("error = %q", v.Error)
			}
			want := scriptCall{filepath.Dir(filepath.Join("/repo", "tools")), "bash", []string{filepath.Join("/repo", "tools", "tier.sh"), "1000", "1"}}
			if len(*calls) != 1 || fmt.Sprint((*calls)[0]) != fmt.Sprint(want) {
				t.Fatalf("ran %v, want %v", *calls, want)
			}
			logText, err := os.ReadFile(filepath.Join(s.store.Root(), networkResetLog))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{out.Job + " start: 1000 voters x 1 positions", "network down", fmt.Sprintf("end: exit %d", tc.code)} {
				if !strings.Contains(string(logText), want) {
					t.Fatalf("console log lacks %q:\n%s", want, logText)
				}
			}
			if data, err := os.ReadFile(filepath.Join(runDir, "run.json")); err != nil || string(data) != `{"run_id":"kept-run"}` {
				t.Fatalf("a reset touched a run folder: %q %v", data, err)
			}
		})
	}
}

// TestResetScriptHelper is not a test: runStreaming's tests run the test binary
// as the script, choosing its behaviour by environment.
func TestResetScriptHelper(t *testing.T) {
	switch os.Getenv("SAKSI_RESET_HELPER") {
	case "exit3":
		fmt.Println("helper: stdout")
		fmt.Fprintln(os.Stderr, "helper: stderr")
		os.Exit(3)
	case "hang":
		fmt.Println("helper: up")
		time.Sleep(2 * time.Minute)
		os.Exit(0)
	}
}

func TestRunStreamingCapturesOutputExitCodeAndKillsOnTimeout(t *testing.T) {
	helper := []string{"-test.run=^TestResetScriptHelper$"}

	t.Setenv("SAKSI_RESET_HELPER", "exit3")
	var out bytes.Buffer
	code, err := runStreaming(context.Background(), "", &out, os.Args[0], helper...)
	if err != nil || code != 3 {
		t.Fatalf("exit3: code %d err %v", code, err)
	}
	if !strings.Contains(out.String(), "helper: stdout\n") || !strings.Contains(out.String(), "helper: stderr\n") {
		t.Fatalf("both streams must reach the log, got %q", out.String())
	}

	t.Setenv("SAKSI_RESET_HELPER", "hang")
	out.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	code, err = runStreaming(ctx, "", &out, os.Args[0], helper...)
	if !errors.Is(err, context.DeadlineExceeded) || code != -1 {
		t.Fatalf("hang: code %d err %v, want the deadline", code, err)
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Fatalf("the timed-out process was not killed: returned after %s", took)
	}
	if !strings.Contains(out.String(), "helper: up") {
		t.Fatalf("output before the kill must be kept, got %q", out.String())
	}
}

func TestLocateTierScript(t *testing.T) {
	bash := func(string) (string, error) { return "/bin/bash", nil }
	root := t.TempDir()
	if _, err := locateTierScript("linux", bash, root, false); err == nil || !strings.Contains(err.Error(), "git checkout") {
		t.Fatalf("no repo root: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "tools"), "tier.sh", "#!/usr/bin/env bash\n")
	got, err := locateTierScript("linux", bash, root, true)
	if err != nil || got != filepath.Join(root, "tools", "tier.sh") {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := locateTierScript("windows", bash, root, true); err == nil || !strings.Contains(err.Error(), "WSL") {
		t.Fatalf("windows: %v", err)
	}
}

// writeIdentity writes a fresh self-signed identity (certificate, PKCS #8 key,
// and the certificate again as the TLS CA) under dir, and returns the
// certificate PEM.
func writeIdentity(t *testing.T, dir, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	writeFile(t, dir, "cert.pem", string(cert))
	writeFile(t, dir, "ca.crt", string(cert))
	writeFile(t, dir, "key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk8})))
	return cert
}

// cryptogen regenerates the network's MSP and TLS material under the same
// paths. A reset must leave the console using the new material without a
// restart: FabricConfig.Connect re-reads the files on every call, and the one
// connection the console caches (for /api/trail) is dropped by the reset.
func TestResetReloadsTheFabricIdentity(t *testing.T) {
	msp := t.TempDir()
	certA := writeIdentity(t, msp, "User1 before")
	fab := enabledFabric()
	fab.TLSCert, fab.Cert, fab.Key = filepath.Join(msp, "ca.crt"), filepath.Join(msp, "cert.pem"), filepath.Join(msp, "key.pem")

	store := NewRunStore(t.TempDir())
	hub := NewHub()
	s := NewServer(store, NewExecutor(store, hub, "saksi-demo", "", fab), hub, fab, nil, time.Minute)
	var certB []byte
	s.tierScript = func() (string, error) { return "/repo/tools/tier.sh", nil }
	s.runScript = func(context.Context, string, io.Writer, string, ...string) (int, error) {
		certB = writeIdentity(t, msp, "User1 after") // what network.sh up does
		return 0, nil
	}
	credentials := func() []byte {
		t.Helper()
		if _, _, err := s.dial(); err != nil {
			t.Fatalf("connect: %v", err)
		}
		return s.chainConn.Gateway().Identity().Credentials()
	}
	if got := credentials(); !bytes.Equal(got, certA) {
		t.Fatal("the first connection does not carry the starting identity")
	}

	rec := postReset(t, s, goodReset, loopback, "")
	var out struct{ Job string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if v := waitJob(t, s, out.Job, time.Minute); v.Status != jobDone {
		t.Fatalf("reset: %+v", v)
	}
	got := credentials()
	if bytes.Equal(got, certA) || !bytes.Equal(got, certB) {
		t.Fatal("after the reset the console still connects with the old identity")
	}
	// The fault's readiness probe and every executor phase connect afresh too.
	conn, err := fab.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !bytes.Equal(conn.Gateway().Identity().Credentials(), certB) {
		t.Fatal("FabricConfig.Connect did not read the regenerated identity")
	}
}
