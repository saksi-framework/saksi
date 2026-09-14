package campaign

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Preflight: the conditions that silently spoil a measurement, checked before
// one starts. A game using seven of sixteen cores halved MP-10K throughput
// during validation and nothing said so; this report is what says so.
//
// A "block" is a run that cannot produce a valid result (it would fail, or be
// refused part-way); a "warn" is a run that would produce a number worth less
// than it looks. Campaigns refuse on a block unless forced and record the
// report either way.

const (
	// fabricProbeTimeout bounds the TCP dial to the gateway peer.
	fabricProbeTimeout = 2 * time.Second
	// hostLoadWarnFraction: warn when the 1-minute load average exceeds this
	// share of the CPUs, i.e. something else is already using the machine.
	hostLoadWarnFraction = 0.25
	// singleVerifyThread is the verifier thread count that makes verify timings
	// incomparable with the reported rows (all run on every core).
	singleVerifyThread = 1

	severityBlock = "block"
	severityWarn  = "warn"
)

// readLoadAvg reads /proc/loadavg. Absent (Windows, macOS) means no load figure.
// Package variable so tests can fake it.
var readLoadAvg = func() ([]byte, error) { return os.ReadFile("/proc/loadavg") }

// dialFabric is the cheap reachability probe: a TCP connect, nothing more.
// Package variable so tests can fake it.
var dialFabric = func(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		_ = conn.Close()
	}
	return err
}

// PreflightInput is the run the report is checked against.
type PreflightInput struct {
	Mode        string `json:"mode"`
	Voters      int    `json:"voters,omitempty"`
	Positions   int    `json:"positions,omitempty"`
	Concurrency int    `json:"concurrency,omitempty"`
}

// PreflightWarning is one finding. Code is stable for the UI and tests.
type PreflightWarning struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
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
		Path                 string  `json:"path"`
		FreeBytes            *uint64 `json:"free_bytes"`
		ProjectedLedgerBytes *uint64 `json:"projected_ledger_bytes"`
	} `json:"disk"`
	Host struct {
		Load1 *float64 `json:"load1"`
		Load5 *float64 `json:"load5"`
		CPUs  int      `json:"cpus"`
	} `json:"host"`
	VerifyThreadsDefault  int                `json:"verify_threads_default"`
	ConcurrencyMinAdvised *int               `json:"concurrency_min_advised"`
	Warnings              []PreflightWarning `json:"warnings"`
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

// preflight checks the console and host against the run in.
func (s *Server) preflight(in PreflightInput) PreflightReport {
	rep := PreflightReport{At: time.Now().UTC(), Run: in, Warnings: []PreflightWarning{}}
	add := func(sev, code, format string, args ...any) {
		rep.Warnings = append(rep.Warnings, PreflightWarning{sev, code, fmt.Sprintf(format, args...)})
	}
	onchain := in.Mode == "onchain"
	c := ElectionConfig{Mode: in.Mode, Voters: in.Voters, Positions: in.Positions}

	rep.Fabric.Enabled = s.fabric.Enabled()
	rep.Fabric.Peer, rep.Fabric.Channel = s.fabric.PeerEndpoint, s.fabric.Channel
	if rep.Fabric.Enabled {
		err := dialFabric(s.fabric.PeerEndpoint, fabricProbeTimeout)
		ok := err == nil
		rep.Fabric.Reachable = &ok
		if err != nil {
			rep.Fabric.Error = err.Error()
			if onchain {
				add(severityBlock, "fabric_unreachable",
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

	head, headOK := s.gitHead()
	rep.Ladder.ConsoleCommit = head
	var lr ladderRecord
	if readJSON(filepath.Join(s.store.Root(), LadderFile), &lr) == nil {
		rep.Ladder.LadderCommit = lr.Commit
	}
	rep.Ladder.OK = headOK && lr.Commit != "" && lr.Commit == head
	if err := s.ladderGate(c); err != nil {
		add(severityBlock, "ladder_missing", "%d voters is above the %d-voter ceiling: %v",
			in.Voters, LadderVoterCeiling, err)
	}

	// The same volume and formula the disk gate uses, so the report and the
	// refusal at /generate cannot disagree.
	rep.Disk.Path = s.fabric.PeerVolume
	if rep.Disk.Path == "" {
		rep.Disk.Path = s.store.Root()
	}
	if free, err := s.freeSpace(rep.Disk.Path); err == nil {
		rep.Disk.FreeBytes = &free
	}
	if in.Voters > 0 && in.Positions > 0 {
		need := uint64(in.Voters) * uint64(in.Positions) * LedgerBytesPerBallot
		rep.Disk.ProjectedLedgerBytes = &need
	}
	if err := s.diskGate(c); err != nil {
		add(severityBlock, "disk_short", "%v", err)
	}

	rep.Host.CPUs = runtime.NumCPU()
	if data, err := readLoadAvg(); err == nil {
		if f := strings.Fields(string(data)); len(f) >= 2 {
			if l1, err := strconv.ParseFloat(f[0], 64); err == nil {
				rep.Host.Load1 = &l1
			}
			if l5, err := strconv.ParseFloat(f[1], 64); err == nil {
				rep.Host.Load5 = &l5
			}
		}
	}
	if l := rep.Host.Load1; l != nil && *l > hostLoadWarnFraction*float64(rep.Host.CPUs) {
		add(severityWarn, "host_load",
			"the 1-minute load average is %.2f, above %.0f%% of %d CPUs: something else is using this machine and will slow the run",
			*l, hostLoadWarnFraction*100, rep.Host.CPUs)
	}

	if adv := rep.ConcurrencyMinAdvised; onchain && adv != nil && in.Concurrency > 0 && in.Concurrency < *adv {
		add(severityWarn, "concurrency_low",
			"%d ballots in flight is below the orderer's MaxMessageCount %d: every block waits the batch timeout, so the run measures the timeout rather than the network",
			in.Concurrency, *adv)
	}

	rep.VerifyThreadsDefault = auditThreadsDefault()
	if rep.VerifyThreadsDefault == singleVerifyThread {
		add(severityWarn, "verify_threads",
			"the auditor will verify ballots on 1 thread (SAKSI_AUDIT_THREADS, RAYON_NUM_THREADS or a 1-CPU host): verify timings will not compare with runs on every core")
	}
	return rep
}

// auditThreadsDefault is the thread count saksi-demo's auditor would verify
// on when started from this console: SAKSI_AUDIT_THREADS, else rayon's
// RAYON_NUM_THREADS, else every core.
func auditThreadsDefault() int {
	for _, key := range []string{"SAKSI_AUDIT_THREADS", "RAYON_NUM_THREADS"} {
		if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key))); err == nil && n >= 1 {
			return n
		}
	}
	return runtime.NumCPU()
}

// handlePreflight serves GET /api/preflight[?mode=&voters=&positions=&concurrency=].
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
	for name, dst := range map[string]*int{"voters": &in.Voters, "positions": &in.Positions, "concurrency": &in.Concurrency} {
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
