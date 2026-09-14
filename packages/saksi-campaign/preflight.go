package campaign

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Preflight: the conditions that silently spoil a measurement, checked before
// one starts. A game using seven of sixteen cores halved MP-10K throughput
// during validation and nothing said so; this report is what says so.
//
// A "block" is a run that cannot produce a valid result (it would fail, or be
// refused part-way); a "warn" is a run that would produce a number worth less
// than it looks. Campaigns refuse on a block, record the report either way, and
// let force override only the blocks in forceableBlocks.

const (
	// fabricProbeTimeout bounds the TCP dial to the gateway peer.
	fabricProbeTimeout = 2 * time.Second
	// hostCPUProbeTimeout bounds the Windows host CPU sample taken from WSL.
	hostCPUProbeTimeout = 5 * time.Second
	// hostLoadWarnFraction: warn when the guest's 1-minute load average, or the
	// Windows host's CPU use, exceeds this share of the machine — something
	// else is already using it.
	hostLoadWarnFraction = 0.25
	// singleVerifyThread is the verifier thread count that makes verify timings
	// incomparable with the reported rows (all run on every core).
	singleVerifyThread = 1
	// auditThreadsEnv is saksi-auditor's AUDIT_THREADS_ENV.
	auditThreadsEnv = "SAKSI_AUDIT_THREADS"

	severityBlock = "block"
	severityWarn  = "warn"
)

// forceableBlocks are the blocks a campaign's force may override: a peer that
// did not answer the probe may be up by the first ledger call. Every other
// block fails the first /generate or every run, so forcing it only wastes the
// campaign.
var forceableBlocks = map[string]bool{"fabric_unreachable": true}

// Per-record phase costs for the phase-timeout estimate: the desktop refit of
// the cost model over rows 2-4 on the parallel auditor (balotachain
// docs/desktop-runs/cost-model.md): generation, the on-chain ballot window,
// the auditor, and the on-chain ledger dump that verify runs before it.
const (
	genMsPerRecord        = 0.18
	submitMsPerRecord     = 1.24
	auditMsPerRecord      = 0.16
	ledgerDumpMsPerRecord = 0.67
	// phaseTimeoutWarnFraction: preflight warns when the estimate passes this
	// share of the phase timeout, and suggests a timeout it would not pass.
	phaseTimeoutWarnFraction = 0.75
)

// longestPhase estimates the longest single phase c runs. Each HTTP phase
// (/generate, /submit or /ceremony/start, /verify) gets the whole phase
// timeout; /run-all is the exception and runs all three under one. Ground
// truth runs no cryptography and gets no estimate.
func longestPhase(c ElectionConfig) (string, time.Duration) {
	type phase struct {
		name string
		ms   float64
	}
	var phases []phase
	switch c.Mode {
	case "onchain":
		phases = []phase{{"generate", genMsPerRecord}, {"ballot submission", submitMsPerRecord},
			{"verify", auditMsPerRecord + ledgerDumpMsPerRecord}}
	case "offline":
		phases = []phase{{"generate", genMsPerRecord}, {"verify", auditMsPerRecord}}
	}
	records := float64(c.Voters) * float64(c.Positions)
	var name string
	var longest time.Duration
	for _, p := range phases {
		if d := time.Duration(records * p.ms * float64(time.Millisecond)); d > longest {
			name, longest = p.name, d
		}
	}
	return name, longest
}

// readLoadAvg reads /proc/loadavg. Absent (Windows, macOS) means no load figure.
var readLoadAvg = func() ([]byte, error) { return os.ReadFile("/proc/loadavg") }

// readMeminfo reads /proc/meminfo. Absent (Windows, macOS) means no memory figure.
var readMeminfo = func() ([]byte, error) { return os.ReadFile("/proc/meminfo") }

// memAvailable is /proc/meminfo's MemAvailable in bytes: what the kernel says a
// new process can have without swapping.
func memAvailable() (uint64, bool) {
	data, err := readMeminfo()
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "MemAvailable:" {
			kb, err := strconv.ParseUint(f[1], 10, 64)
			return kb * 1024, err == nil
		}
	}
	return 0, false
}

// readOSRelease reads the kernel release; WSL2's contains "microsoft".
var readOSRelease = func() ([]byte, error) { return os.ReadFile("/proc/sys/kernel/osrelease") }

// hostCPUCommand samples the Windows host's CPU through WSL interop. Inside
// WSL2 /proc/loadavg sees only the guest VM, so a Windows program eating half
// the cores is invisible without it.
//
// Three one-second % Processor Time samples, averaging the last two: the first
// covers PowerShell's own startup, which inflated a single-shot reading
// (Win32_Processor LoadPercentage read 43 cold and 34 warm against a true
// 11-13). The value prints in the invariant culture; about 3.7 s in all.
var hostCPUCommand = func(ctx context.Context) ([]byte, error) {
	return cmdRunner(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		`$v = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3).CounterSamples.CookedValue; `+
			`(($v[1] + $v[2]) / 2).ToString([cultureinfo]::InvariantCulture)`)
}

// preflightHostTTL is how long a preflight reuses its host sample. Under WSL
// every sample spawns powershell.exe for seconds, and with auth off any page in
// the operator's browser can loop GET /api/preflight.
const preflightHostTTL = 10 * time.Second

// hostSampleCache holds the preflight's last host sample, with at most one
// sample in flight: concurrent callers wait for it instead of each spawning
// their own. Repetition samples (campaign rows) never go through it.
type hostSampleCache struct {
	mu      sync.Mutex
	at      time.Time
	sample  HostSample
	pending chan struct{} // closed when the in-flight sample lands
}

func (c *hostSampleCache) get() HostSample {
	c.mu.Lock()
	for {
		if !c.at.IsZero() && time.Since(c.at) < preflightHostTTL {
			s := c.sample
			c.mu.Unlock()
			return s
		}
		if c.pending == nil {
			break
		}
		p := c.pending
		c.mu.Unlock()
		<-p
		c.mu.Lock()
	}
	p := make(chan struct{})
	c.pending = p
	c.mu.Unlock()

	s := sampleHost()

	c.mu.Lock()
	c.sample, c.at, c.pending = s, time.Now(), nil
	c.mu.Unlock()
	close(p)
	return s
}

// dialFabric is the cheap reachability probe: a TCP connect, nothing more.
var dialFabric = func(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		_ = conn.Close()
	}
	return err
}

// HostSample is the machine's load at one instant: the guest's (this OS's)
// load averages and, under WSL, the Windows host's CPU use. A figure that could
// not be read is null.
type HostSample struct {
	At         time.Time `json:"at"`
	GuestLoad1 *float64  `json:"guest_load1"`
	GuestLoad5 *float64  `json:"guest_load5"`
	HostCPUPct *float64  `json:"host_cpu_pct"`
}

func sampleHost() HostSample {
	hs := HostSample{At: time.Now().UTC()}
	if data, err := readLoadAvg(); err == nil {
		if f := strings.Fields(string(data)); len(f) >= 2 {
			hs.GuestLoad1 = parseFloatPtr(f[0])
			hs.GuestLoad5 = parseFloatPtr(f[1])
		}
	}
	if rel, err := readOSRelease(); err == nil && strings.Contains(strings.ToLower(string(rel)), "microsoft") {
		ctx, cancel := context.WithTimeout(context.Background(), hostCPUProbeTimeout)
		defer cancel()
		if out, err := hostCPUCommand(ctx); err == nil {
			// A comma-decimal locale prints "12,5".
			if v := parseFloatPtr(strings.ReplaceAll(strings.TrimSpace(string(out)), ",", ".")); v != nil && *v >= 0 && *v <= 100 {
				hs.HostCPUPct = v
			}
		}
	}
	return hs
}

func parseFloatPtr(s string) *float64 {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &v
}

// PreflightInput is the run the report is checked against.
type PreflightInput struct {
	Mode        string `json:"mode"`
	Voters      int    `json:"voters,omitempty"`
	Positions   int    `json:"positions,omitempty"`
	Candidates  int    `json:"candidates,omitempty"`
	Concurrency int    `json:"concurrency,omitempty"`
}

// PreflightWarning is one finding. Code is stable for the UI and tests;
// Forceable says whether a campaign's force overrides this block.
type PreflightWarning struct {
	Severity  string `json:"severity"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Forceable bool   `json:"forceable"`
}

// PreflightReport is GET /api/preflight's body and every campaign's snapshot.
type PreflightReport struct {
	At     time.Time      `json:"at"`
	Run    PreflightInput `json:"run"`
	Fabric struct {
		Enabled   bool   `json:"enabled"`
		Reachable *bool  `json:"reachable"`
		Peer      string `json:"peer"`
		Channel   string `json:"channel"`
		Error     string `json:"error,omitempty"`
	} `json:"fabric"`
	OrdererBatch map[string]any `json:"orderer_batch"`
	Ladder       struct {
		OK            bool   `json:"ok"`
		LadderCommit  string `json:"ladder_commit"`
		ConsoleCommit string `json:"console_commit"`
	} `json:"ladder"`
	Disk struct {
		Path      string  `json:"path"`
		FreeBytes *uint64 `json:"free_bytes"`
		// ProjectedLedgerBytes is an on-chain run's ledger, ProjectedRunBytes an
		// offline run's folder; the other is null.
		ProjectedLedgerBytes *uint64 `json:"projected_ledger_bytes"`
		ProjectedRunBytes    *uint64 `json:"projected_run_bytes"`
	} `json:"disk"`
	// Memory is the auditor's projected peak against MemAvailable, which is null
	// where /proc/meminfo does not exist (Windows).
	Memory struct {
		AvailableBytes      *uint64 `json:"available_bytes"`
		ProjectedAuditBytes *uint64 `json:"projected_audit_bytes"`
	} `json:"memory"`
	Host struct {
		HostSample
		CPUs int `json:"cpus"`
	} `json:"host"`
	// PhaseTimeout is the console's --phase-timeout and the longest phase this
	// run is estimated to need under it.
	PhaseTimeout struct {
		Seconds      float64  `json:"seconds"`
		LongestPhase string   `json:"longest_phase,omitempty"`
		EstimatedS   *float64 `json:"estimated_s"`
	} `json:"phase_timeout"`
	VerifyThreadsDefault  int                `json:"verify_threads_default"`
	ConcurrencyMinAdvised *int               `json:"concurrency_min_advised"`
	Warnings              []PreflightWarning `json:"warnings"`
}

func (p *PreflightReport) add(severity, code, format string, args ...any) {
	p.Warnings = append(p.Warnings, PreflightWarning{
		Severity: severity, Code: code, Message: fmt.Sprintf(format, args...),
		Forceable: severity == severityBlock && forceableBlocks[code],
	})
}

// Blocked reports whether any finding is a block.
func (p PreflightReport) Blocked() bool {
	for _, w := range p.Warnings {
		if w.Severity == severityBlock {
			return true
		}
	}
	return false
}

// unforceable lists the codes of the blocks force cannot override.
func (p PreflightReport) unforceable() []string {
	var out []string
	for _, w := range p.Warnings {
		if w.Severity == severityBlock && !w.Forceable {
			out = append(out, w.Code)
		}
	}
	return out
}

// preflight checks the console and host against the run in.
func (s *Server) preflight(in PreflightInput) PreflightReport {
	rep := PreflightReport{At: time.Now().UTC(), Run: in, Warnings: []PreflightWarning{}}
	onchain := in.Mode == "onchain"
	c := ElectionConfig{Mode: in.Mode, Voters: in.Voters, Positions: in.Positions, Candidates: in.Candidates}

	rep.Fabric.Enabled = s.fabric.Enabled()
	rep.Fabric.Peer, rep.Fabric.Channel = s.fabric.PeerEndpoint, s.fabric.Channel
	if onchain && !rep.Fabric.Enabled {
		rep.add(severityBlock, "fabric_not_configured",
			"an on-chain run needs a Fabric network, and this console was started without one (--fabric-* flags)")
	}
	if rep.Fabric.Enabled {
		err := dialFabric(s.fabric.PeerEndpoint, fabricProbeTimeout)
		ok := err == nil
		rep.Fabric.Reachable = &ok
		if err != nil {
			rep.Fabric.Error = err.Error()
			if onchain {
				rep.add(severityBlock, "fabric_unreachable",
					"the Fabric peer %s is not reachable (%v): an on-chain run would fail at its first ledger call",
					s.fabric.PeerEndpoint, err)
			}
		}
	}

	env := map[string]any{}
	probeOrdererBatch(s.exec.demoBin, env, func(string) {})
	if ob, ok := env["orderer_batch"].(map[string]any); ok {
		rep.OrdererBatch = ob
		if v, _ := ob["MaxMessageCount"].(string); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				rep.ConcurrencyMinAdvised = &n
			}
		}
	}

	// A phase holds its run's lock for as long as it runs, including while its
	// lifecycle is paused at an attack stage, so the busy map sees both.
	s.mu.Lock()
	busy := s.busyRunsLocked("")
	s.mu.Unlock()
	if len(busy) > 0 {
		rep.add(severityBlock, "run_busy",
			"a phase is running on %s: a campaign would share the network and the machine with it; let it finish or cancel it first",
			strings.Join(busy, ", "))
	}

	head, headOK := s.gitHead()
	rep.Ladder.ConsoleCommit = head
	var lr ladderRecord
	if readJSON(filepath.Join(s.store.Root(), LadderFile), &lr) == nil {
		rep.Ladder.LadderCommit = lr.Commit
	}
	rep.Ladder.OK = headOK && lr.Commit != "" && lr.Commit == head
	if err := s.ladderGate(c); err != nil {
		rep.add(severityBlock, "ladder_missing", "%d voters is above the %d-voter ceiling: %v",
			in.Voters, LadderVoterCeiling, err)
	}

	// The same volumes and formulas the admission gates use, so the report and
	// the refusal at /generate cannot disagree.
	rep.Disk.Path = s.diskPath(in.Mode)
	free, freeErr := s.freeSpace(rep.Disk.Path)
	if freeErr == nil {
		rep.Disk.FreeBytes = &free
	}
	if need, what := diskProjection(c); need > 0 {
		if onchain {
			rep.Disk.ProjectedLedgerBytes = &need
		} else {
			rep.Disk.ProjectedRunBytes = &need
		}
		if err := s.diskGate(c); err != nil {
			rep.add(severityBlock, "disk_short", "%v", err)
		} else if freeErr == nil && float64(need) > resourceWarnFraction*float64(free) {
			rep.add(severityWarn, "disk_tight", "this run projects %d bytes of %s, over %.0f%% of the %d bytes free on %s",
				need, what, resourceWarnFraction*100, free, rep.Disk.Path)
		}
	}
	avail, haveMem := memAvailable()
	if haveMem {
		rep.Memory.AvailableBytes = &avail
	}
	if need := auditMemory(c); need > 0 {
		rep.Memory.ProjectedAuditBytes = &need
		if err := s.memoryGate(c); err != nil {
			rep.add(severityBlock, "memory_short", "%v", err)
		} else if haveMem && float64(need) > resourceWarnFraction*float64(avail) {
			rep.add(severityWarn, "memory_tight", "this run's audit projects %d bytes of memory, over %.0f%% of the %d bytes available",
				need, resourceWarnFraction*100, avail)
		}
	}

	rep.Host.HostSample = s.hostCache.get()
	rep.Host.CPUs = runtime.NumCPU()
	if l := rep.Host.GuestLoad1; l != nil && *l > hostLoadWarnFraction*float64(rep.Host.CPUs) {
		rep.add(severityWarn, "host_load",
			"the 1-minute load average is %.2f, above %.0f%% of %d CPUs: something else is using this machine and will slow the run",
			*l, hostLoadWarnFraction*100, rep.Host.CPUs)
	}
	if p := rep.Host.HostCPUPct; p != nil && *p > hostLoadWarnFraction*100 {
		rep.add(severityWarn, "host_cpu",
			"the Windows host's CPU is at %.0f%%, above %.0f%%: a program outside WSL is using cores the run needs",
			*p, hostLoadWarnFraction*100)
	}

	if adv := rep.ConcurrencyMinAdvised; onchain && adv != nil && in.Concurrency > 0 && in.Concurrency < *adv {
		rep.add(severityWarn, "concurrency_low",
			"%d ballots in flight is below the orderer's MaxMessageCount %d: every block waits the batch timeout, so the run measures the timeout rather than the network",
			in.Concurrency, *adv)
	}

	rep.PhaseTimeout.Seconds = s.timeout.Seconds()
	if name, est := longestPhase(c); est > 0 && s.timeout > 0 {
		secs := est.Seconds()
		rep.PhaseTimeout.LongestPhase, rep.PhaseTimeout.EstimatedS = name, &secs
		records := c.Voters * c.Positions
		switch suggest := time.Duration(math.Ceil(est.Hours()/phaseTimeoutWarnFraction)) * time.Hour; {
		case est > s.timeout:
			rep.add(severityBlock, "phase_timeout_short",
				"the %s phase is estimated at %s for %d ballot records, over this console's %s phase timeout, so it would be cancelled part-way: restart the console with --phase-timeout %s (env SAKSI_PHASE_TIMEOUT)",
				name, est.Round(time.Second), records, s.timeout, suggest)
		case float64(est) > phaseTimeoutWarnFraction*float64(s.timeout):
			rep.add(severityWarn, "phase_timeout_tight",
				"the %s phase is estimated at %s for %d ballot records, over %.0f%% of this console's %s phase timeout: a slower run is cancelled part-way, so consider --phase-timeout %s (env SAKSI_PHASE_TIMEOUT)",
				name, est.Round(time.Second), records, phaseTimeoutWarnFraction*100, s.timeout, suggest)
		}
	}

	threads, err := auditThreadsDefault()
	rep.VerifyThreadsDefault = threads
	switch {
	case err != nil:
		rep.add(severityBlock, "verify_threads_invalid", "%v: the auditor refuses to start, so every run's verify would fail", err)
	case threads == singleVerifyThread:
		rep.add(severityWarn, "verify_threads",
			"the auditor will verify ballots on 1 thread (%s, RAYON_NUM_THREADS or a 1-CPU host): verify timings will not compare with runs on every core",
			auditThreadsEnv)
	}
	return rep
}

// auditThreadsDefault is the thread count saksi-demo's auditor would verify on
// when started from this console, with the auditor's own parse rules
// (saksi-auditor demo.rs parse_audit_threads): SAKSI_AUDIT_THREADS, when SET
// (even empty), must trim to a positive integer or the auditor errors; unset,
// rayon's pool applies (RAYON_NUM_THREADS, else every core).
func auditThreadsDefault() (int, error) {
	if raw, set := os.LookupEnv(auditThreadsEnv); set {
		// Rust's usize parse accepts one leading '+'; Go's does not.
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(raw), "+"), 10, strconv.IntSize)
		if err != nil || n < 1 {
			return 0, fmt.Errorf("%s=%q is not a positive integer thread count", auditThreadsEnv, raw)
		}
		return int(n), nil
	}
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RAYON_NUM_THREADS"))); err == nil && n >= 1 {
		return n, nil
	}
	return runtime.NumCPU(), nil
}

// handlePreflight serves GET /api/preflight[?mode=&voters=&positions=&candidates=&concurrency=].
// mode defaults to onchain: the study's measured runs are on-chain.
func (s *Server) handlePreflight(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	in := PreflightInput{Mode: q.Get("mode")}
	if in.Mode == "" {
		in.Mode = "onchain"
	}
	for name, dst := range map[string]*int{"voters": &in.Voters, "positions": &in.Positions, "candidates": &in.Candidates, "concurrency": &in.Concurrency} {
		raw := q.Get(name)
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			http.Error(w, name+" must be a non-negative integer", http.StatusBadRequest)
			return
		}
		*dst = n
	}
	writeJSONResp(w, http.StatusOK, s.preflight(in))
}
