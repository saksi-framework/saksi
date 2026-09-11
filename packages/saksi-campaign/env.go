package campaign

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// The environment snapshot: CollectEnv fingerprints the machine and binaries
// a run executes against, for the journal's line-1 env event (see
// journal.go's OpenJournal). Split out of journal.go to keep that file to
// the journal/LedgerBytes/finaliser API.

const envProbeTimeout = 10 * time.Second

// cmdRunner shells an external command and returns its output. Package
// variable so tests can replace it to make every probe fail (simulating a
// cleared PATH) without touching the real environment or requiring
// docker/git to be installed on the test machine. Also used by LedgerBytes
// (journal.go) and the sampler (sampler.go).
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

	probeOrdererBatch(demoBin, env, null)
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

// ordererConfigtxPath is the declared orderer configuration network.sh
// installs into fabric-samples before it creates the channel.
const ordererConfigtxPath = "packages/saksi-bulletin/network/configtx.yaml"

// ordererBatchKeys are the configtx.yaml keys that set the orderer's batching
// behaviour, which is the part of the environment that moves throughput and
// latency most (see configtx.yaml's header for the measurements).
var ordererBatchKeys = []string{
	"BatchTimeout",
	"MaxMessageCount",
	"AbsoluteMaxBytes",
	"PreferredMaxBytes",
	"SnapshotIntervalSize",
}

// probeOrdererBatch records the orderer batching parameters this run's channel
// was created under, as `orderer_batch`. It reads the DECLARED file committed
// in the repository rather than fetching the live channel config, so it is
// accurate exactly when the network was brought up through network.sh — which
// is every path this console is used from (tools/up.sh, tools/tier.sh). With
// SAKSI_CONFIGTX=default the operator opted out of the declared file for an
// A/B run and the stock test-network values apply; the mode is recorded and
// the values are not, since they then live in fabric-samples rather than here.
func probeOrdererBatch(demoBin string, env map[string]any, null func(string)) {
	mode := os.Getenv("SAKSI_CONFIGTX")
	if mode == "" {
		mode = "saksi"
	}
	out := map[string]any{"saksi_configtx": mode}
	if mode != "saksi" {
		env["orderer_batch"] = out
		return
	}

	root, ok := findGitRoot(filepath.Dir(demoBin))
	if !ok {
		null("orderer_batch")
		return
	}
	values, err := parseOrdererBatch(filepath.Join(root, ordererConfigtxPath))
	if err != nil {
		null("orderer_batch")
		return
	}
	for k, v := range values {
		out[k] = v
	}
	env["orderer_batch"] = out
}

// parseOrdererBatch pulls the ordererBatchKeys out of a configtx.yaml by
// scanning for "Key: value" lines. Each key appears exactly once in the file
// and only under the Orderer section, so this needs no YAML parser; comment
// lines (the header's own table of these values included) are skipped.
func parseOrdererBatch(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	found := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, key := range ordererBatchKeys {
			if _, seen := found[key]; seen {
				continue
			}
			rest, ok := strings.CutPrefix(line, key+":")
			if !ok {
				continue
			}
			if i := strings.Index(rest, "#"); i >= 0 {
				rest = rest[:i]
			}
			found[key] = strings.TrimSpace(rest)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return found, nil
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
