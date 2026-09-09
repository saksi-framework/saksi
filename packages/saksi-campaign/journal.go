package campaign

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The run journal, environment snapshot, resource sampler, and finaliser.
//
// Today nothing records the environment a run executed in, nothing samples
// resources while it runs, and nothing defines when a run has failed. This
// file adds all four: journal.ndjson is an append-only, one-JSON-object-per-
// line event log per run folder (fsynced at checkpoint events so a crash
// loses at most the events since the last checkpoint, never a torn line);
// CollectEnv fingerprints the machine and binaries a run executed against;
// StartSampler polls `docker stats` for CPU/memory/IO while a run is live;
// Finalise decides pass/fail and the scaling-limit verdict at run.end.
//
// Later tasks wire this into the executor; this file only provides the API
// and tests it.

// JournalFile is the run-folder-relative name of the event journal.
const JournalFile = "journal.ndjson"

// journalFile is what Journal needs from its underlying file. *os.File
// satisfies it; tests inject a fake to exercise the Sync-error path without
// touching disk.
type journalFile interface {
	io.Writer
	Sync() error
	Close() error
}

// Journal is an append-only, one-JSON-object-per-line event log for a single
// run folder. Every Stamp call takes the mutex and issues exactly one Write;
// checkpoint events (run.start, stage.*, rep.*, ballots.progress, segment.*,
// run.end) additionally fsync.
type Journal struct {
	mu     sync.Mutex
	f      journalFile
	path   string
	opened time.Time
	failed error
}

// OpenJournal creates <runDir>/journal.ndjson and writes the environment
// snapshot as line 1: {"event":"env", ...env, "ts": RFC3339}, fsynced
// immediately.
func OpenJournal(runDir string, env map[string]any) (*Journal, error) {
	path := filepath.Join(runDir, JournalFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open journal: %w", err)
	}
	j := newJournal(f, time.Now())
	j.path = path

	line := make(map[string]any, len(env)+2)
	for k, v := range env {
		line[k] = v
	}
	line["event"] = "env"
	line["ts"] = time.Now().UTC().Format(time.RFC3339)
	if err := j.writeLine(line, true); err != nil {
		f.Close()
		return nil, err
	}
	return j, nil
}

// newJournal builds a Journal over an already-open journalFile. Unexported:
// production code always goes through OpenJournal; tests use this to inject
// a fake file and a fixed opened time.
func newJournal(f journalFile, opened time.Time) *Journal {
	return &Journal{f: f, opened: opened}
}

// Stamp appends {"event":event,"ts":...,"mono_ms":<since open>,...fields} and
// fsyncs if event is a checkpoint. A prior Sync error is returned on every
// later call, without writing.
func (j *Journal) Stamp(event string, fields map[string]any) error {
	line := make(map[string]any, len(fields)+3)
	for k, v := range fields {
		line[k] = v
	}
	line["event"] = event
	line["ts"] = time.Now().UTC().Format(time.RFC3339)
	line["mono_ms"] = time.Since(j.opened).Milliseconds()
	return j.writeLine(line, isCheckpoint(event))
}

func (j *Journal) writeLine(line map[string]any, checkpoint bool) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed != nil {
		return j.failed
	}
	b, err := json.Marshal(line)
	if err != nil {
		return fmt.Errorf("marshal journal line: %w", err)
	}
	b = append(b, '\n')
	if _, err := j.f.Write(b); err != nil {
		j.failed = fmt.Errorf("write journal line: %w", err)
		return j.failed
	}
	if checkpoint {
		if err := j.f.Sync(); err != nil {
			j.failed = fmt.Errorf("sync journal: %w", err)
			return j.failed
		}
	}
	return nil
}

// Close closes the underlying journal file.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.f.Close()
}

// isCheckpoint reports whether event is one of the checkpoint events that
// fsync: run.start, stage.*, rep.*, ballots.progress, segment.*, run.end.
func isCheckpoint(event string) bool {
	switch event {
	case "run.start", "run.end", "ballots.progress":
		return true
	}
	return strings.HasPrefix(event, "stage.") ||
		strings.HasPrefix(event, "rep.") ||
		strings.HasPrefix(event, "segment.")
}

// ---- Environment snapshot -------------------------------------------------

const envProbeTimeout = 10 * time.Second

// cmdRunner shells an external command and returns its output. Package
// variable so tests can replace it to make every probe fail (simulating a
// cleared PATH) without touching the real environment or requiring
// docker/git to be installed on the test machine.
var cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

func runProbe(name string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), envProbeTimeout)
	defer cancel()
	out, err := cmdRunner(ctx, name, args...)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// CollectEnv fingerprints the machine and binaries a run executes against.
// Every probe has a 10s timeout; a failed probe records null for its key and
// is listed in null_probes. CollectEnv never returns an error.
func CollectEnv(demoBin string) map[string]any {
	env := map[string]any{
		"go_os":      runtime.GOOS,
		"go_arch":    runtime.GOARCH,
		"go_version": runtime.Version(),
	}
	var nullProbes []string
	null := func(key string) {
		env[key] = nil
		nullProbes = append(nullProbes, key)
	}

	probeDemoVersion(demoBin, env, null)

	if head, ok := gitHeadFor(demoBin); ok {
		env["git_head_saksi"] = head
	} else {
		null("git_head_saksi")
	}

	if consolePath, err := os.Executable(); err == nil {
		if head, ok := gitHeadFor(consolePath); ok {
			env["git_head_console"] = head
		} else {
			null("git_head_console")
		}
	} else {
		null("git_head_console")
	}

	probeDockerVersion(env, null)
	probeDockerInfo(env, null)
	probeContainers(env, null)
	probeUname(env, null)
	probeCPUModel(env, null)

	if nullProbes == nil {
		nullProbes = []string{}
	}
	env["null_probes"] = nullProbes
	return env
}

func probeDemoVersion(demoBin string, env map[string]any, null func(string)) {
	if out, ok := runProbe(demoBin, "--version"); ok && out != "" {
		env["saksi_demo_version"] = out
		return
	}
	if sum := fileDigest(demoBin); sum != "" {
		env["saksi_demo_sha256"] = sum
		return
	}
	null("saksi_demo_version")
}

// gitHeadFor walks up from the directory containing bin until a .git is
// found, then runs `git rev-parse HEAD` there.
func gitHeadFor(bin string) (string, bool) {
	dir, ok := findGitRoot(filepath.Dir(bin))
	if !ok {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), envProbeTimeout)
	defer cancel()
	out, err := cmdRunner(ctx, "git", "-C", dir, "rev-parse", "HEAD")
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func findGitRoot(dir string) (string, bool) {
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

func probeDockerVersion(env map[string]any, null func(string)) {
	out, ok := runProbe("docker", "version", "--format", "{{json .}}")
	if !ok {
		null("docker_version")
		return
	}
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		null("docker_version")
		return
	}
	env["docker_version"] = v
}

type dockerInfoSubset struct {
	NCPU          int    `json:"NCPU"`
	MemTotal      int64  `json:"MemTotal"`
	ServerVersion string `json:"ServerVersion"`
	OSType        string `json:"OSType"`
}

func probeDockerInfo(env map[string]any, null func(string)) {
	out, ok := runProbe("docker", "info", "--format", "{{json .}}")
	if !ok {
		null("docker_info")
		return
	}
	var info dockerInfoSubset
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		null("docker_info")
		return
	}
	env["docker_info"] = info
}

// probeContainers inspects every container whose name starts with "peer" or
// "orderer".
func probeContainers(env map[string]any, null func(string)) {
	out, ok := runProbe("docker", "ps", "-a", "--format", "{{.Names}}")
	if !ok {
		null("containers")
		return
	}
	result := []map[string]any{}
	for _, name := range strings.Fields(out) {
		if !strings.HasPrefix(name, "peer") && !strings.HasPrefix(name, "orderer") {
			continue
		}
		if c, ok := inspectContainer(name); ok {
			result = append(result, c)
		}
	}
	env["containers"] = result
}

type containerInspect struct {
	Name       string `json:"Name"`
	HostConfig struct {
		NanoCpus int64 `json:"NanoCpus"`
		Memory   int64 `json:"Memory"`
	} `json:"HostConfig"`
}

func inspectContainer(name string) (map[string]any, bool) {
	out, ok := runProbe("docker", "inspect", name)
	if !ok {
		return nil, false
	}
	var arr []containerInspect
	if err := json.Unmarshal([]byte(out), &arr); err != nil || len(arr) == 0 {
		return nil, false
	}
	c := arr[0]
	return map[string]any{
		"Name":                c.Name,
		"HostConfig.NanoCpus": c.HostConfig.NanoCpus,
		"HostConfig.Memory":   c.HostConfig.Memory,
	}, true
}

func probeUname(env map[string]any, null func(string)) {
	name, args := "uname", []string{"-a"}
	if runtime.GOOS == "windows" {
		name, args = "cmd", []string{"/c", "ver"}
	}
	if out, ok := runProbe(name, args...); ok {
		env["uname"] = out
		return
	}
	null("uname")
}

func probeCPUModel(env map[string]any, null func(string)) {
	if v, ok := cpuModelFromProcCPUInfo(); ok {
		env["cpu_model"] = v
		return
	}
	if v, ok := runProbe("sysctl", "-n", "machdep.cpu.brand_string"); ok && v != "" {
		env["cpu_model"] = v
		return
	}
	if out, ok := runProbe("wmic", "cpu", "get", "name"); ok {
		if v := firstWmicValue(out); v != "" {
			env["cpu_model"] = v
			return
		}
	}
	null("cpu_model")
}

func cpuModelFromProcCPUInfo() (string, bool) {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "model name") {
			if i := strings.Index(line, ":"); i >= 0 {
				return strings.TrimSpace(line[i+1:]), true
			}
		}
	}
	return "", false
}

// firstWmicValue pulls the value line out of `wmic ... get name` output,
// which is a "Name" header, the value, then blank lines.
func firstWmicValue(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "Name" {
			continue
		}
		return line
	}
	return ""
}

// ---- Disk: ledger bytes ----------------------------------------------------

// LedgerBytes reports the on-disk size of the Fabric ledger under
// peerVolume: `du -sb` on the volume path, falling back to a rough sum of
// `docker system df -v`'s local-volume sizes if `du` is unavailable. On
// Windows (no du) it sums file sizes under peerVolume directly — the same
// result `Get-ChildItem -Recurse | Measure-Object Length -Sum` would give,
// without spawning PowerShell.
func LedgerBytes(peerVolume string) (int64, error) {
	if runtime.GOOS == "windows" {
		return ledgerBytesWalk(peerVolume)
	}
	ctx, cancel := context.WithTimeout(context.Background(), envProbeTimeout)
	defer cancel()
	if out, err := cmdRunner(ctx, "du", "-sb", peerVolume); err == nil {
		if n, ok := parseDuOutput(string(out)); ok {
			return n, nil
		}
	}
	return ledgerBytesFromDockerDF(peerVolume)
}

func parseDuOutput(out string) (int64, bool) {
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ledgerBytesFromDockerDF sums every local volume's SIZE column.
//
// ponytail: not scoped to peerVolume — it's a fallback for when du itself is
// missing, so a precise per-volume number isn't available anyway. Upgrade to
// `docker volume inspect --format '{{.Mountpoint}}'` matched against
// peerVolume if a tighter number is ever needed.
func ledgerBytesFromDockerDF(peerVolume string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), envProbeTimeout)
	defer cancel()
	out, err := cmdRunner(ctx, "docker", "system", "df", "-v")
	if err != nil {
		return 0, fmt.Errorf("ledger bytes for %s: du and docker system df both failed: %w", peerVolume, err)
	}
	var total int64
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if n, ok := parseByteSize(fields[len(fields)-1]); ok {
			total += n
		}
	}
	return total, nil
}

func ledgerBytesWalk(peerVolume string) (int64, error) {
	var total int64
	err := filepath.WalkDir(peerVolume, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("ledger bytes for %s: %w", peerVolume, err)
	}
	return total, nil
}

// ---- Finaliser --------------------------------------------------------------

// Segment is one sustained/ramp measurement window.
type Segment struct {
	Index            int
	Committed        int
	WindowMs         int64
	TPS              float64
	P50Ms            float64
	DriverCeilingTPS float64
}

// FinaliseInput is everything Finalise needs to decide pass/fail and the
// scaling-limit verdict.
type FinaliseInput struct {
	Voters, Positions int
	Segments          []Segment
	Dropped           int
	ReconcileOK       bool
	EByContest        map[string]int64
	StageErr          error
	Interrupted       bool
}

// FinaliseResult is the run.end verdict.
type FinaliseResult struct {
	Failed       bool
	Reason       string
	SustainedTPS *float64
	ArrivalTPS   float64
	ScalingLimit string // "true" | "false" | "inconclusive"
	Sustained    bool
}

// runFailed implements the failed-run predicate: stage error, or any ballot
// dropped, or a reconcile mismatch, or a nonzero E for any contest, or the
// run was interrupted. Reason is the first clause that fired, in that order.
func runFailed(f FinaliseInput) (bool, string) {
	if f.StageErr != nil {
		return true, "stage_error: " + f.StageErr.Error()
	}
	if f.Dropped > 0 {
		return true, fmt.Sprintf("dropped: %d", f.Dropped)
	}
	if !f.ReconcileOK {
		return true, "reconcile_mismatch"
	}
	contests := make([]string, 0, len(f.EByContest))
	for c := range f.EByContest {
		contests = append(contests, c)
	}
	sort.Strings(contests)
	for _, c := range contests {
		if e := f.EByContest[c]; e != 0 {
			return true, fmt.Sprintf("e_nonzero: %s=%d", c, e)
		}
	}
	if f.Interrupted {
		return true, "interrupted"
	}
	return false, ""
}

// Finalise decides the run.end verdict and stamps it.
func Finalise(j *Journal, f FinaliseInput) FinaliseResult {
	failed, reason := runFailed(f)
	res := FinaliseResult{
		Failed:     failed,
		Reason:     reason,
		ArrivalTPS: float64(f.Voters) / 36000,
		Sustained:  len(f.Segments) == 1 && !f.Interrupted,
	}

	res.ScalingLimit = "inconclusive"
	if res.Sustained {
		seg := f.Segments[0]
		if seg.WindowMs != 0 { // zero window: TPS stays nil, never divide by zero
			tps := seg.TPS
			res.SustainedTPS = &tps
			switch {
			case seg.TPS >= 0.8*seg.DriverCeilingTPS: // driver was the ceiling
				res.ScalingLimit = "inconclusive"
			case seg.TPS < res.ArrivalTPS:
				res.ScalingLimit = "true"
			default:
				res.ScalingLimit = "false"
			}
		}
	}

	if j != nil {
		var sustainedTPS any
		if res.SustainedTPS != nil {
			sustainedTPS = *res.SustainedTPS
		}
		_ = j.Stamp("run.end", map[string]any{
			"failed":        res.Failed,
			"reason":        res.Reason,
			"sustained_tps": sustainedTPS,
			"arrival_tps":   res.ArrivalTPS,
			"scaling_limit": res.ScalingLimit,
			"sustained":     res.Sustained,
		})
	}
	return res
}
