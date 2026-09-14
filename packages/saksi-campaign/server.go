package campaign

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
)

//go:embed web/index.html web/trail.html web/wizard.html
var webFS embed.FS

// exportOrder is the downloadable run artifacts, in display order. exportAllowlist
// is derived from it — no arbitrary path is ever served via /export.
var exportOrder = []string{
	// Study data — proper CSVs, shown first.
	ElectionCSV,
	BallotsCSV,
	CorrectnessFile,
	NegativeTestsFile,
	GroundTruthBallotsCSV,
	GroundTruthSummaryCSV,
	PerfCSV,
	LatenciesCSV,
	// Raw artifacts — kept for re-audit / provenance.
	PerfSchemaFile,
	"header.json",
	BallotsFile,
	JournalFile,
	TimingsFile,
	GenTimingsFile,
	submitMetricsFile,
	RunFile,
	"receipts.csv",
	CheckFile,
	trailNDJSONFile, // new runs (Task 2+)
	trailJSONFile,   // legacy runs recorded before trail.ndjson
	// The chain's own copy of the run, so a reader can re-audit the LEDGER
	// dump rather than only the console's record of it. A subdirectory is
	// addressable because handleExport cuts the run id off the FIRST slash
	// and matches the whole remainder against this allowlist — nothing here
	// widens what may be served.
	LedgerDir + "/" + headerFile,
	LedgerDir + "/" + BallotsFile,
}

var exportAllowlist = func() map[string]bool {
	m := make(map[string]bool, len(exportOrder))
	for _, a := range exportOrder {
		m[a] = true
	}
	return m
}()

// Server owns the HTTP surface. All business logic lives in the executor/store;
// handlers only decode, validate, dispatch, and enforce the single-run lock +
// origin guard.
type Server struct {
	store      *RunStore
	exec       *Executor
	hub        *Hub
	fabric     FabricConfig
	timeout    time.Duration
	allowHosts map[string]bool
	handler    http.Handler

	mu   sync.Mutex
	busy map[string]context.CancelFunc // run id -> cancel of its running phase

	chainMu   sync.Mutex
	chainConn *clientsdk.Connection // lazily opened, cached across /api/trail requests

	// gitHead resolves the console binary's own commit, for the validation
	// ladder gate. Cached: it shells git, and the answer cannot change while
	// this process is running. Tests override it.
	gitHead  func() (string, bool)
	headOnce sync.Once
	head     string
	headOK   bool

	// freeSpace reports the bytes available on the volume holding path.
	// Overridden by tests, which must not depend on the disk they run on.
	freeSpace func(path string) (uint64, error)

	// dial resolves the chain reader + ledger for /api/trail. Defaults to
	// dialChain (lazy-connect via fabric); tests override it to inject fakes.
	dial func() (chainReader, clientsdk.Ledger, error)

	// auth is nil unless EnableAuth was called; nil means every route is open.
	auth *authState
	// routes is every pattern registered on the mux, for the role-table test.
	routes []string

	// jobs is the console-wide ladder/campaign job slot (jobs.go).
	jobs jobBoard
	// hostCache is the preflight's host sample, reused briefly (preflight.go).
	hostCache hostSampleCache

	// tierScript locates tools/tier.sh or says why this host cannot run it, and
	// runScript runs it (reset.go). Tests override both.
	tierScript func() (string, error)
	runScript  scriptRunner
}

// NewServer returns the console HTTP handler. fabric configures the live
// Fabric network /api/trail reads from (zero-value = every trail request 502s
// as unreachable). allowHosts is the set of Host header values accepted
// (DNS-rebinding defense); timeout bounds each phase.
func NewServer(store *RunStore, exec *Executor, hub *Hub, fabric FabricConfig, allowHosts []string, timeout time.Duration) *Server {
	s := &Server{
		store:      store,
		exec:       exec,
		hub:        hub,
		fabric:     fabric,
		timeout:    timeout,
		allowHosts: make(map[string]bool),
		busy:       make(map[string]context.CancelFunc),
	}
	s.dial = s.dialChain
	s.gitHead = s.consoleHead
	s.freeSpace = freeSpaceOn
	s.tierScript = consoleTierScript
	s.runScript = runStreaming
	// A fault never fires while anything else uses the network: stopping the
	// peer under it would wreck those runs.
	exec.faultGate = s.faultGate
	exec.phaseTimeout = timeout
	for _, h := range allowHosts {
		s.allowHosts[h] = true
	}
	mux := &routeMux{mux: http.NewServeMux()}
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/generate", s.handleGenerate)
	mux.HandleFunc("/submit", s.handleSubmit)
	mux.HandleFunc("/verify", s.handleVerify)
	mux.HandleFunc("/scenarios", s.handleScenarios)
	mux.HandleFunc("/run-all", s.handleRunAll)
	mux.HandleFunc("/cancel", s.handleCancel)
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/runs", s.handleRuns)
	mux.HandleFunc("/export/", s.handleExport)
	mux.HandleFunc("/api/trail/", s.handleTrailAPI)
	mux.HandleFunc("/trail/", s.handleTrailPage)
	mux.HandleFunc("/wizard", s.handleWizard)
	mux.HandleFunc("/ceremony/start", s.handleCeremonyStart)
	mux.HandleFunc("/ceremony/submit", s.handleCeremonySubmit)
	mux.HandleFunc("/ceremony/publish", s.handleCeremonyPublish)
	mux.HandleFunc("/api/ceremony/", s.handleCeremonyStatus)
	mux.HandleFunc("/api/check/", s.handleCheck)
	mux.HandleFunc("/api/scenarios/", s.handleScenarioList)
	mux.HandleFunc("/api/runs/", s.handleRunAction)
	mux.HandleFunc("/api/capabilities", s.handleCapabilities)
	mux.HandleFunc("/api/trail", s.handleTrailIndex)
	mux.HandleFunc("/attack", s.handleStagedAttack)
	mux.HandleFunc("/api/board/", s.handleBoard)
	mux.HandleFunc("/api/verify-code/", s.handleVerifyCode)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/me", s.handleMe)
	mux.HandleFunc("/api/preflight", s.handlePreflight)
	mux.HandleFunc("/api/ladder", s.handleLadder)
	mux.HandleFunc("/api/jobs/", s.handleJob)
	mux.HandleFunc("/api/campaigns", s.handleCampaigns)
	mux.HandleFunc("/api/campaigns/", s.handleCampaign)
	mux.HandleFunc("/api/network/reset", s.handleNetworkReset)
	// Browsers ask for a favicon on every page; without this route the request
	// falls through to "/" and, with auth on, logs a 401 on the public board.
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mountWebDir(mux, os.Getenv("SAKSI_WEB_DIR"))
	s.routes = mux.patterns
	s.handler = s.guard(s.authorize(mux))
	return s
}

// mountWebDir serves the browser apps the console can host: the public
// bulletin board at /board/, the trustee console at /trustee/ and the admin
// console at /admin/, read from <dir>/board, <dir>/trustee and <dir>/admin.
// Same origin as the API, so guard()'s cross-origin POST defense keeps
// protecting the ceremony endpoints, and the session cookie reaches the API.
//
// The apps select their election with a query parameter rather than a route,
// so http.FileServer's own index.html handling is the whole router and no SPA
// fallback is needed. An empty dir registers nothing and the console behaves
// exactly as it did before.
func mountWebDir(mux *routeMux, dir string) {
	if strings.TrimSpace(dir) == "" {
		return
	}
	for _, app := range []string{"board", "trustee", "admin"} {
		prefix := "/" + app + "/"
		mux.Handle(prefix, http.StripPrefix(prefix,
			http.FileServer(http.Dir(filepath.Join(dir, app)))))
		// Without this the bare path falls through to handleIndex's 404.
		mux.HandleFunc("/"+app, func(w http.ResponseWriter, r *http.Request) {
			target := r.URL.Path + "/"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
	}
}

// ServeHTTP makes *Server itself the http.Handler main.go passes to
// ListenAndServe, while keeping the concrete type available to tests (and to
// buildTrail's connection caching) that NewServer's former http.Handler return
// type hid.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// guard enforces the DNS-rebinding + cross-origin-POST defenses. A bare
// loopback bind does NOT stop a malicious web page from POSTing to
// 127.0.0.1:<port>, so we check Host against an allowlist and require any
// browser Origin to be same-origin.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.allowHosts) > 0 && !s.allowHosts[r.Host] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			if o := r.Header.Get("Origin"); o != "" {
				u, err := url.Parse(o)
				if err != nil || u.Host != r.Host {
					http.Error(w, "cross-origin request rejected", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// claim takes the single-run lock for runID and stores its cancel func, or
// returns why it cannot: a phase is already running on that run, a fault has
// the peer stopped or recovering, or the network is being reset (startExclusiveJob checks the other direction under the same
// lock, so the two cannot interleave).
func (s *Server) claim(runID string, cancel context.CancelFunc) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, running := s.busy[runID]; running {
		return "a phase is already running on this run"
	}
	if j := s.jobs.running(); j != nil && j.Kind == jobKindReset {
		return fmt.Sprintf("the network is being reset (job %s): wait for it to finish", j.ID)
	}
	if fr := s.exec.faultingRun(); fr != "" {
		return fmt.Sprintf("run %s's peer-restart fault has the Fabric peer stopped or recovering: wait for its fault.peer_ready", fr)
	}
	s.busy[runID] = cancel
	return ""
}

// busyRunsLocked names every run with a phase running other than the one named
// except, noting the stage a paused lifecycle holds at. Caller holds s.mu.
func (s *Server) busyRunsLocked(except string) []string {
	var names []string
	for _, id := range slices.Sorted(maps.Keys(s.busy)) {
		if id == except {
			continue
		}
		if pv := s.exec.PauseStatus(id); pv.Paused {
			id += " (paused at the " + pv.Stage + " attack stage)"
		}
		names = append(names, id)
	}
	return names
}

func (s *Server) finish(runID string) {
	s.mu.Lock()
	delete(s.busy, runID)
	s.mu.Unlock()
}

// dispatch runs fn as the run's single active phase under a timeout context,
// releasing the lock when done. Returns 409 if the run is already busy.
func (s *Server) dispatch(w http.ResponseWriter, runID string, fn func(context.Context)) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	if why := s.claim(runID, cancel); why != "" {
		cancel()
		http.Error(w, why, http.StatusConflict)
		return
	}
	go func() {
		defer cancel()
		defer s.finish(runID)
		fn(ctx)
	}()
	writeJSONResp(w, http.StatusAccepted, map[string]string{"run_id": runID})
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	c, ok := decodeConfig(w, r)
	if !ok {
		return
	}
	// Refuse an on-chain run with no network here, at step 1, rather than
	// letting it get as far as the ceremony and quietly execute locally.
	if c.Mode == "onchain" && !s.fabric.Enabled() {
		http.Error(w, errNoFabric().Error(), http.StatusBadRequest)
		return
	}
	if !s.admit(w, c) {
		return
	}
	runID, _, err := s.store.Create(c, time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.dispatch(w, runID, func(ctx context.Context) { _ = s.exec.Generate(ctx, runID, c) })
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	runID, ok := s.runIDFromBody(w, r)
	if !ok {
		return
	}
	if !s.ballotPhaseAllowed(w, runID, "verify") {
		return
	}
	rec, err := s.record(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.dispatch(w, runID, func(ctx context.Context) { _, _ = s.exec.Verify(ctx, runID, rec.Config) })
}

// ballotPhaseAllowed rejects phases that need encrypted ballots when the run
// was generated in ground-truth mode, which produces none. Refusing here — with
// the reason — beats letting the phase fail deep inside on a missing
// ballots.ndjson.
func (s *Server) ballotPhaseAllowed(w http.ResponseWriter, runID, phase string) bool {
	rec, err := s.record(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return false
	}
	if groundTruthOnly(rec.Config) {
		http.Error(w, fmt.Sprintf(
			"%s needs encrypted ballots; this run was generated in %q mode, which produces plaintext ground truth only",
			phase, ModeGroundTruth), http.StatusConflict)
		return false
	}
	return true
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	runID, ok := s.runIDFromBody(w, r)
	if !ok {
		return
	}
	rec, err := s.record(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.dispatch(w, runID, func(ctx context.Context) { _ = s.exec.Submit(ctx, runID, rec.Config) })
}

func (s *Server) handleRunAll(w http.ResponseWriter, r *http.Request) {
	c, ok := decodeConfig(w, r)
	if !ok {
		return
	}
	if c.Mode == "onchain" && !s.fabric.Enabled() {
		http.Error(w, errNoFabric().Error(), http.StatusBadRequest)
		return
	}
	// Offline, run-all never reaches a pause (Submit is a no-op and the
	// ceremony is not on this path), so the plan would be silently ignored on a
	// run still marked security_run. On-chain run-all pauses in submitOnChain.
	if c.AttackPlan != nil && c.Mode == "offline" {
		http.Error(w, "attack_plan is not run by an offline /run-all: use the step-by-step "+
			"ceremony (/generate, /ceremony/start, /ceremony/submit, /ceremony/publish), which pauses at each stage",
			http.StatusBadRequest)
		return
	}
	if !s.admit(w, c) {
		return
	}
	runID, _, err := s.store.Create(c, time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.dispatch(w, runID, func(ctx context.Context) {
		if err := s.exec.Generate(ctx, runID, c); err != nil {
			return
		}
		// Ground-truth runs stop after Generate: Submit and Verify both need
		// encrypted ballots, which this mode never produces.
		if groundTruthOnly(c) {
			return
		}
		if err := s.exec.Submit(ctx, runID, c); err != nil {
			return
		}
		_, _ = s.exec.Verify(ctx, runID, c)
	})
}

func (s *Server) handleScenarios(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RunID string   `json:"run_id"`
		List  []string `json:"list"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	runID, err := validRun(s, body.RunID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !s.ballotPhaseAllowed(w, runID, "scenarios") {
		return
	}
	s.dispatch(w, runID, func(ctx context.Context) {
		_ = s.exec.RunScenarios(ctx, runID, body.List)
	})
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	runID, ok := s.runIDFromBody(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	cancel := s.busy[runID]
	s.mu.Unlock()
	if cancel == nil {
		http.Error(w, "no phase running on this run", http.StatusConflict)
		return
	}
	cancel()
	s.hub.Publish(runID, Event{Phase: "cancel", Level: "info", Msg: "cancellation requested"})
	writeJSONResp(w, http.StatusOK, map[string]string{"run_id": runID})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	run := r.URL.Query().Get("run")
	if run == "" {
		http.Error(w, "missing run", http.StatusBadRequest)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, cancel := s.hub.Subscribe(run)
	defer cancel()
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case e, open := <-ch:
			if !open {
				return
			}
			data, _ := json.Marshal(e)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// runView is a run record enriched with the downloadable artifacts that
// currently exist for it, so the History UI can offer per-run CSV downloads
// (correctness / negative-tests) and mark which rows have results to load.
type runView struct {
	RunRecord
	Artifacts []string `json:"artifacts"`
	// Where the run stands, for the wizard's runs list. Status is "new" (no
	// journal yet), "open", "ended", "failed", "interrupted" (a ballot window
	// the resume route would accept) or "close-pending" (a resume landed every
	// ballot but the close failed; the resume route retries the close). Busy is a phase holding the run,
	// PausedStage the attack stage it waits at. Reason is run.end's raw failure
	// text, which can name internal addresses: handleRuns sends it only to an
	// admin session, or to everyone when auth is off.
	Busy           bool   `json:"busy"`
	PausedStage    string `json:"paused_stage,omitempty"`
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	BallotsStarted bool   `json:"ballots_started"`
	Resumable      bool   `json:"resumable"`
	// The T3 trail: a ballot window was interrupted at some point, the latest
	// resume's exact pending count (segment.start), and a verify-only
	// reconciliation on record.
	WasInterrupted bool `json:"was_interrupted"`
	ResumePending  *int `json:"resume_pending,omitempty"`
	Reconciled     bool `json:"reconciled"`
}

// fillState reads where the run in dir stands into v.
func (s *Server) fillState(v *runView, dir string) {
	s.mu.Lock()
	_, v.Busy = s.busy[v.RunID]
	s.mu.Unlock()
	if pv := s.exec.PauseStatus(v.RunID); v.Busy && pv.Paused {
		v.PausedStage = pv.Stage
	}
	events, err := readJournalEvents(dir)
	if err != nil {
		v.Status = "new"
		return
	}
	v.Status = "open"
	for _, ev := range events {
		switch jstring(ev, "event") {
		case "stage.ballots.start":
			v.BallotsStarted = true
		case "stage.ballots.interrupted":
			v.WasInterrupted = true
		case "segment.start":
			if p, ok := ev["pending"].(float64); ok {
				n := int(p)
				v.ResumePending = &n
			}
		case "verify_only.reconcile":
			v.Reconciled = true
		case "run.end":
			v.Status, v.Reason = "ended", ""
			if jbool(ev, "failed") {
				v.Status, v.Reason = "failed", jstring(ev, "reason")
			}
		}
	}
	// The resume route's own check, so the page offers Resume exactly when the
	// route would take it. ponytail: re-reads the journal of on-chain runs; fold
	// into the scan above if /runs gets slow on a large run store.
	if plan, err := planResume(dir, v.Config); err == nil {
		v.Status, v.Resumable = "interrupted", true
		if plan.CloseOnly {
			v.Status = "close-pending" // every ballot landed; only CloseElection is left to retry
		}
	}
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	recs, err := s.store.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// /runs is public; the failure reason is operator detail.
	showReason := s.auth == nil
	if sess := sessionFrom(r); sess != nil && sess.Role == RoleAdmin {
		showReason = true
	}
	views := make([]runView, 0, len(recs))
	for _, rec := range recs {
		dir, err := s.store.Dir(rec.RunID)
		if err != nil {
			continue
		}
		var arts []string
		for _, name := range exportOrder { // exportOrder = stable display order
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				arts = append(arts, name)
			}
		}
		v := runView{RunRecord: rec, Artifacts: arts}
		s.fillState(&v, dir)
		if !showReason {
			v.Reason = ""
		}
		views = append(views, v)
	}
	writeJSONResp(w, http.StatusOK, views)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/export/")
	id, artifact, found := strings.Cut(rest, "/")
	if !found || !exportAllowlist[artifact] {
		http.Error(w, "unknown artifact", http.StatusBadRequest)
		return
	}
	dir, err := s.store.Dir(id)
	if err != nil {
		http.Error(w, "invalid run id", http.StatusBadRequest)
		return
	}
	http.ServeFile(w, r, path.Join(dir, artifact))
}

// handleTrailAPI serves the on-chain audit trail for an election (== run id).
// Sealed until the tally is published (buildTrail's gate), unless the caller
// passes ?operator=1 from a loopback address and, when auth is on, holds an
// admin session.
func (s *Server) handleTrailAPI(w http.ResponseWriter, r *http.Request) {
	electionID := strings.TrimPrefix(r.URL.Path, "/api/trail/")
	if electionID == "" {
		http.Error(w, "missing election id", http.StatusBadRequest)
		return
	}
	dir, err := s.store.Dir(electionID)
	if err != nil {
		http.Error(w, "invalid election id", http.StatusBadRequest)
		return
	}
	operator := r.URL.Query().Get("operator") == "1" && isLoopback(r.RemoteAddr)
	// With auth on, loopback alone is not enough: every SSH-tunnel user and any
	// local process arrives as loopback. The unsealed view needs an admin
	// session; anyone else falls back to the sealed view without an error, as a
	// non-loopback caller always has.
	if s.auth != nil {
		sess := sessionFrom(r)
		operator = operator && sess != nil && sess.Role == RoleAdmin
	}

	reader, led, err := s.dial()
	if err != nil {
		http.Error(w, "chain unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	resp, err := buildTrail(reader, led, dir, electionID, operator)
	if err != nil {
		writeJSONResp(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSONResp(w, http.StatusOK, resp)
}

// handleTrailPage serves the public trail view (self-contained HTML; it
// fetches /api/trail/<id> client-side using the URL path itself).
func (s *Server) handleTrailPage(w http.ResponseWriter, r *http.Request) {
	data, err := webFS.ReadFile("web/trail.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// dialChain lazily opens ONE Fabric connection and caches it for reuse across
// requests. A connect failure is never cached — the next request retries.
func (s *Server) dialChain() (chainReader, clientsdk.Ledger, error) {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	if s.chainConn != nil {
		return s.chainConn.Bulletin, s.chainConn.Ledger(), nil
	}
	conn, err := s.fabric.Connect()
	if err != nil {
		return nil, nil, err
	}
	s.chainConn = conn
	return conn.Bulletin, conn.Ledger(), nil
}

// isLoopback reports whether remoteAddr (an http.Request.RemoteAddr, "host:port")
// resolves to a loopback address. Operator mode is honored only for loopback
// callers — the --allow-host guard can widen the Host allowlist for LAN
// outsiders, but that must never grant the operator (unsealed) view.
func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// --- helpers ---------------------------------------------------------------

func (s *Server) record(runID string) (RunRecord, error) {
	id, err := validRun(s, runID)
	if err != nil {
		return RunRecord{}, err
	}
	dir, _ := s.store.Dir(id)
	var rec RunRecord
	if err := readJSON(path.Join(dir, RunFile), &rec); err != nil {
		return RunRecord{}, fmt.Errorf("unknown run %q", runID)
	}
	return rec, nil
}

func (s *Server) runIDFromBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	var body struct {
		RunID string `json:"run_id"`
	}
	if !decodeJSON(w, r, &body) {
		return "", false
	}
	id, err := validRun(s, body.RunID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return "", false
	}
	return id, true
}

func validRun(s *Server, runID string) (string, error) {
	if _, err := s.store.Dir(runID); err != nil {
		return "", err
	}
	return runID, nil
}

func decodeConfig(w http.ResponseWriter, r *http.Request) (ElectionConfig, bool) {
	var c ElectionConfig
	if !decodeJSON(w, r, &c) {
		return c, false
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return c, false
	}
	return c, true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSONResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleWizard(w http.ResponseWriter, r *http.Request) {
	data, err := webFS.ReadFile("web/wizard.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// ceremonyRun resolves the run named in the body and refuses ground-truth runs,
// which have no ciphertexts to decrypt.
func (s *Server) ceremonyRun(w http.ResponseWriter, r *http.Request) (RunRecord, bool) {
	runID, ok := s.runIDFromBody(w, r)
	if !ok {
		return RunRecord{}, false
	}
	if !s.ballotPhaseAllowed(w, runID, "the trustee ceremony") {
		return RunRecord{}, false
	}
	rec, err := s.record(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return RunRecord{}, false
	}
	return rec, true
}

func (s *Server) handleCeremonyStart(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.ceremonyRun(w, r)
	if !ok {
		return
	}
	s.dispatch(w, rec.RunID, func(ctx context.Context) {
		_ = s.exec.CeremonyStart(ctx, rec.RunID, rec.Config)
	})
}

func (s *Server) handleCeremonySubmit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RunID   string `json:"run_id"`
		Trustee string `json:"trustee_id"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	// With auth on, authorize() admitted only a trustee session; the shares
	// submitted must be that trustee's own. The one role check that needs the
	// parsed body, so it cannot live in the route table.
	if sess := sessionFrom(r); sess != nil && sess.TrusteeID != body.Trustee {
		writeJSONResp(w, http.StatusForbidden, map[string]string{"error": fmt.Sprintf(
			"signed in as trustee %q: a trustee may submit only their own shares", sess.TrusteeID)})
		return
	}
	runID, err := validRun(s, body.RunID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !s.ballotPhaseAllowed(w, runID, "the trustee ceremony") {
		return
	}
	rec, err := s.record(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if strings.TrimSpace(body.Trustee) == "" {
		http.Error(w, "trustee_id is required", http.StatusBadRequest)
		return
	}
	s.dispatch(w, runID, func(ctx context.Context) {
		_ = s.exec.CeremonySubmit(ctx, runID, rec.Config, body.Trustee)
	})
}

// handleCeremonyPublish enforces the threshold BEFORE dispatching, so a
// below-quorum attempt is rejected outright rather than failing asynchronously
// where the UI would only learn about it from the log.
func (s *Server) handleCeremonyPublish(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.ceremonyRun(w, r)
	if !ok {
		return
	}
	state, err := s.exec.CeremonyStatus(rec.RunID, rec.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// A trustee may publish only an election they are a trustee of. (Auth off,
	// or an admin: no session trustee to check.)
	if sess := sessionFrom(r); sess != nil && sess.Role == RoleTrustee &&
		!slices.ContainsFunc(state.Trustees, func(t CeremonyTrustee) bool { return t.ID == sess.TrusteeID }) {
		writeJSONResp(w, http.StatusForbidden, map[string]string{"error": fmt.Sprintf(
			"trustee %q is not a trustee of this election", sess.TrusteeID)})
		return
	}
	if !state.Unlocked {
		http.Error(w, fmt.Sprintf(
			"the tally needs %d of %d trustees; %d have contributed so far",
			state.Threshold, len(state.Trustees), state.Submitted), http.StatusConflict)
		return
	}
	s.dispatch(w, rec.RunID, func(ctx context.Context) {
		_ = s.exec.CeremonyPublish(ctx, rec.RunID, rec.Config)
	})
}

func (s *Server) handleCeremonyStatus(w http.ResponseWriter, r *http.Request) {
	runID, err := validRun(s, strings.TrimPrefix(r.URL.Path, "/api/ceremony/"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rec, err := s.record(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	state, err := s.exec.CeremonyStatus(runID, rec.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dir, err := s.store.Dir(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// CeremonyView embeds CeremonyState, so every field the wizard already
	// reads stays at the same JSON path; the trustee console gets its context
	// on the same poll instead of a second request.
	writeJSONResp(w, http.StatusOK, s.buildCeremonyView(rec, dir, state))
}

// handleStagedAttack mounts one attack at its lifecycle stage — really against
// the ledger when the run is on-chain and a network is configured, simulated
// against a copy otherwise.
func (s *Server) handleStagedAttack(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RunID    string `json:"run_id"`
		Scenario string `json:"scenario"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	runID, err := validRun(s, body.RunID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !s.ballotPhaseAllowed(w, runID, "attack") {
		return
	}
	rec, err := s.record(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.dispatch(w, runID, func(ctx context.Context) {
		_ = s.exec.RunStagedAttack(ctx, runID, rec.Config, body.Scenario)
	})
}

// handleCapabilities tells the UI what this console can actually do, so the
// page never offers a mode the server cannot honour. Without it the wizard
// hardcoded all three modes and an on-chain selection silently ran offline.
func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSONResp(w, http.StatusOK, struct {
		Fabric  bool   `json:"fabric"`
		Peer    string `json:"peer,omitempty"`
		Channel string `json:"channel,omitempty"`
	}{
		Fabric:  s.fabric.Enabled(),
		Peer:    s.fabric.PeerEndpoint,
		Channel: s.fabric.Channel,
	})
}

// handleTrailIndex lists every election this console has recorded, each checked
// against the ledger. The chaincode has no ListElections — only per-election
// getters — so this is the run store cross-referenced with the chain rather
// than an enumeration of the ledger itself.
func (s *Server) handleTrailIndex(w http.ResponseWriter, r *http.Request) {
	rows, chain := s.trailIndex()
	writeJSONResp(w, http.StatusOK, struct {
		Chain bool            `json:"chain"`
		Rows  []trailIndexRow `json:"rows"`
	}{Chain: chain, Rows: rows})
}

// handleScenarioList serves the attack catalog for a run: every registered
// scenario's briefing plus its verdict, if it has been run. The wizard renders
// one step per entry, so the briefing shown to the audience is the same text
// the mutation code carries.
func (s *Server) handleScenarioList(w http.ResponseWriter, r *http.Request) {
	runID, err := validRun(s, strings.TrimPrefix(r.URL.Path, "/api/scenarios/"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	dir, err := s.store.Dir(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	list, err := ScenarioListings(dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResp(w, http.StatusOK, list)
}

// handleCheck runs the data-validation gate over a run's ground-truth tables —
// the "all records valid?" decision the methodology places between generation
// and the encrypted demonstration.
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	runID, err := validRun(s, strings.TrimPrefix(r.URL.Path, "/api/check/"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rec, err := s.record(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	rep, err := s.exec.RunCheck(runID, rec.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResp(w, http.StatusOK, rep)
}

// handleRunAction routes /api/runs/{id}/{action}: `status` (GET) reports
// whether a phase is running, `resume`, `verify-only` and `fault` (POST) act on
// the run.
func (s *Server) handleRunAction(w http.ResponseWriter, r *http.Request) {
	id, action, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/api/runs/"), "/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch action {
	case "status":
		s.handleRunStatus(w, r, id)
	case "resume":
		s.handleResume(w, r, id)
	case "verify-only":
		s.handleVerifyOnly(w, r, id)
	case "pause":
		s.handlePause(w, r, id)
	case "fault":
		s.handleFault(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

// handleRunStatus answers whether a phase is currently running on the run. The
// per-run lock is claimed before a dispatch answers 202, so a driver that saw
// the 202 and then polls this gets an exact answer rather than a race.
func (s *Server) handleRunStatus(w http.ResponseWriter, r *http.Request, id string) {
	runID, err := validRun(s, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	_, busy := s.busy[runID]
	s.mu.Unlock()
	writeJSONResp(w, http.StatusOK, map[string]any{"run_id": runID, "busy": busy})
}

// handleVerifyOnly serves POST /api/runs/{id}/verify-only: after an
// interruption (T3 — the peer was stopped mid-window), reconcile what the
// chain holds against this run's committed set and walk the chain, WITHOUT
// submitting anything more. It marks the run interrupted, which is what makes
// the difference visible instead of quietly resuming over it.
func (s *Server) handleVerifyOnly(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	runID, err := validRun(s, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rec, err := s.record(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if rec.Config.Mode != "onchain" {
		http.Error(w, fmt.Sprintf(
			"run mode is %q: only an on-chain run has a chain to reconcile against", rec.Config.Mode),
			http.StatusConflict)
		return
	}
	if !s.fabric.Enabled() {
		http.Error(w, errNoFabric().Error(), http.StatusBadRequest)
		return
	}
	s.dispatch(w, runID, func(ctx context.Context) { _ = s.exec.VerifyOnly(ctx, runID, rec.Config) })
}

// handleResume serves POST /api/runs/{id}/resume: restart an interrupted
// ballot window over the ballots the chain does not already hold, then close the
// election so the ceremony can run (resumeAndClose).
//
// The refusal is decided BEFORE anything is dispatched (planResume reads the
// run's journal, no network), so a run that cannot be resumed gets a 409 with
// the reason instead of a second window quietly opening on top of the first.
//
// The 202 body's `remaining` is the JOURNAL'S ESTIMATE (planResume: the
// interrupted window's ballots minus those it committed when it stamped its
// end, or minus its last progress checkpoint after a hard kill, which can
// undercount the ballots that were in flight), because the exact figure needs
// a paged ListNullifiers walk intersected with the population and this request
// must not block for it. The exact count is stamped as
// `segment.start {pending}` once the resume has taken its snapshot, and
// published on the run's event stream.
func (s *Server) handleResume(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	runID, err := validRun(s, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rec, err := s.record(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	dir, err := s.store.Dir(runID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	plan, err := planResume(dir, rec.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	// Refused here, with the words Resume would fail with, rather than a 202
	// for a phase that can only fail.
	if !s.fabric.Enabled() {
		http.Error(w, errNoFabric().Error(), http.StatusBadRequest)
		return
	}
	bundlePath, err := s.exec.bundlePath(runID)
	if err == nil {
		_, err = loadBundle(bundlePath)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	if why := s.claim(runID, cancel); why != "" {
		cancel()
		http.Error(w, why, http.StatusConflict)
		return
	}
	go func() {
		defer cancel()
		defer s.finish(runID)
		_ = s.exec.Resume(ctx, runID, rec.Config)
	}()
	writeJSONResp(w, http.StatusAccepted, plan)
}

// --- admission gates --------------------------------------------------------
//
// Two things can waste a whole tier's worth of wall clock: running a large tier
// on a build whose small tiers were never shown to be correct, and starting an
// on-chain tier the disk cannot hold. Both are refused here, at run creation,
// where the cost is an error message.

// LadderFile is the validation ladder's record, written beside the run folders.
const LadderFile = "ladder.json"

// LadderVoterCeiling is the largest tier that may run without the validation
// ladder having been run for this build.
const LadderVoterCeiling = 1000

// errLadderNotRun is the exact refusal text: one string, so a caller can match
// on it rather than on a message that varies with the tier.
const errLadderNotRun = "validation ladder has not been run for this build; run tools/ladder.sh first"

// LedgerBytesPerBallot is the ledger footprint budgeted for one ballot record
// (one voter x one position), used by the disk guard's projection.
const LedgerBytesPerBallot = 12000

// OfflineRunBytesPerRecord + OfflineRunBytesPerCandidate x candidates is the
// run folder an offline run leaves per ballot record (one voter x one
// position): ballots.ndjson (hex protobuf) and ballots.csv (the same ballot as
// JSON) are ~97 % of it, header.json's voter id and ground-truth-ballots.csv
// the rest. Measured from whole console runs (generate, check, the ceremony,
// verify) at 500 and 1,000 voters x 3 positions: the per-record slope was
// 4,652, 7,456 and 13,064 bytes at 2, 4 and 8 candidates, which is exactly
// 1,848 + 1,402 x candidates. The run id is inside every ballot, so a long
// election name adds a few bytes per record; the 80 % warning absorbs that.
const (
	OfflineRunBytesPerRecord    = 1848
	OfflineRunBytesPerCandidate = 1402
)

// AuditorBaseBytes + AuditorBytesPerRecord x records is the auditor's peak
// resident memory over a run: the whole-stream nullifier map
// (HashMap<[u8; 32], usize>) and header.json's voter_ids (one string per
// record, read with the header), everything else being per chunk. Measured as
// audit-stream's peak private bytes: 37.5 MiB at 50,000 records and 58.8 MiB at
// 200,000 (4 candidates), a 149-byte slope over a ~30 MiB base.
const (
	AuditorBaseBytes      = 32 << 20
	AuditorBytesPerRecord = 150
)

// resourceWarnFraction: preflight warns when a projection passes this share of
// the resource it is checked against (the gates block only above all of it).
const resourceWarnFraction = 0.8

// ladderRecord is <runs-root>/ladder.json: which build the ladder passed on,
// when, and the runs that prove it.
type ladderRecord struct {
	Commit string    `json:"commit"`
	RanAt  time.Time `json:"ran_at"`
	Runs   []string  `json:"runs"`
}

// admit applies the gates to a config before any run folder is created — a
// tier that cannot produce a trustworthy measurement should cost nothing but
// the error message. Every path that creates a run goes through here, so a
// second entry point cannot quietly skip them.
func (s *Server) admit(w http.ResponseWriter, c ElectionConfig) bool {
	for _, gate := range []func(ElectionConfig) error{s.ladderGate, s.diskGate, s.memoryGate} {
		if err := gate(c); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return false
		}
	}
	return true
}

// consoleHead is the console binary's own git commit, cached for the process.
func (s *Server) consoleHead() (string, bool) {
	s.headOnce.Do(func() { s.head, s.headOK = consoleGitHead() })
	return s.head, s.headOK
}

// ladderGate refuses a large offline/on-chain tier unless the validation ladder
// has been run for exactly this build. Ground-truth is exempt: it runs no
// cryptography and no chain, so there is nothing for the ladder to validate.
//
// A console that cannot resolve its own commit refuses too. The gate exists to
// prove a correspondence between a build and a passing ladder, and "I cannot
// tell which build I am" is not that proof.
func (s *Server) ladderGate(c ElectionConfig) error {
	if c.Mode == ModeGroundTruth || c.Voters <= LadderVoterCeiling {
		return nil
	}
	var rec ladderRecord
	if err := readJSON(filepath.Join(s.store.Root(), LadderFile), &rec); err != nil {
		return errors.New(errLadderNotRun)
	}
	head, ok := s.gitHead()
	if !ok || rec.Commit == "" || rec.Commit != head {
		return errors.New(errLadderNotRun)
	}
	return nil
}

// diskProjection is the disk a run will fill and what it is: an on-chain run's
// ledger on the peer volume, or an offline run's folder on the runs volume.
// Zero when the mode writes nothing that scales (ground truth) or the config
// does not say how much.
func diskProjection(c ElectionConfig) (uint64, string) {
	records := uint64(c.Voters) * uint64(c.Positions)
	switch c.Mode {
	case "onchain":
		return records * LedgerBytesPerBallot, fmt.Sprintf(
			"ledger (%d voters x %d positions x %d bytes per ballot)", c.Voters, c.Positions, LedgerBytesPerBallot)
	case "offline":
		if c.Candidates < 1 {
			return 0, ""
		}
		per := uint64(OfflineRunBytesPerRecord + OfflineRunBytesPerCandidate*c.Candidates)
		return records * per, fmt.Sprintf(
			"run folder (%d voters x %d positions x %d bytes per ballot record at %d candidates)",
			c.Voters, c.Positions, per, c.Candidates)
	}
	return 0, ""
}

// diskPath is the volume diskProjection's bytes land on.
func (s *Server) diskPath(mode string) string {
	if mode == "onchain" && s.fabric.PeerVolume != "" {
		return s.fabric.PeerVolume
	}
	return s.store.Root()
}

// diskGate refuses a tier whose projected ledger (on-chain) or run folder
// (offline) will not fit. The message carries the numbers, because "not enough
// disk" without them tells an operator nothing about which knob to turn.
//
// A probe that fails does NOT refuse: an unreadable volume is an
// instrumentation loss, and instrumentation must never be the thing that
// blocks a run.
func (s *Server) diskGate(c ElectionConfig) error {
	need, what := diskProjection(c)
	if need == 0 {
		return nil
	}
	path := s.diskPath(c.Mode)
	free, err := s.freeSpace(path)
	if err != nil || need <= free {
		return nil
	}
	return fmt.Errorf("this run projects %d bytes of %s but only %d bytes are free on %s: free space or run a smaller tier",
		need, what, free, path)
}

// auditMemory is the auditor's projected peak memory for c, or 0 for a mode
// that never runs it.
func auditMemory(c ElectionConfig) uint64 {
	if c.Mode != "offline" && c.Mode != "onchain" {
		return 0
	}
	records := uint64(c.Voters) * uint64(c.Positions)
	if records == 0 {
		return 0
	}
	return AuditorBaseBytes + records*AuditorBytesPerRecord
}

// memoryGate refuses a tier whose audit would not fit in the memory available
// now. Like diskGate, a host that cannot report it (Windows: no
// /proc/meminfo) is not refused.
func (s *Server) memoryGate(c ElectionConfig) error {
	need := auditMemory(c)
	avail, ok := memAvailable()
	if need == 0 || !ok || need <= avail {
		return nil
	}
	return fmt.Errorf("this run's audit projects %d bytes of memory (%d MiB + %d voters x %d positions x %d bytes per record) "+
		"but only %d bytes are available: close other programs or run a smaller tier",
		need, AuditorBaseBytes>>20, c.Voters, c.Positions, AuditorBytesPerRecord, avail)
}
