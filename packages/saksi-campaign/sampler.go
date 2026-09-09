package campaign

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// The docker-stats resource sampler. Split out of journal.go to keep that
// file under ~500 lines; see journal.go for the journal/env/finaliser API
// this feeds.

// ContainerStats is one container's aggregated CPU/memory over a sampler run.
type ContainerStats struct {
	PeakCPU, MeanCPU float64
	PeakMem, MeanMem int64
}

// Samples is the sampler's summary, returned by the stop func StartSampler
// hands back.
type Samples struct {
	PerContainer map[string]ContainerStats
	Malformed    int
}

const defaultSampleInterval = 5 * time.Second

// StartSampler polls `docker stats` every interval (default 5s) and stamps
// one "sample" journal event per kept container line, plus one for the
// console's own process (name "client"). If docker isn't on PATH it stamps a
// single {"docker": null} "sampler" event and returns immediately. stop()
// halts sampling and returns the aggregated peak/mean per container.
func StartSampler(ctx context.Context, j *Journal, containers []string, interval time.Duration) func() Samples {
	if interval <= 0 {
		interval = defaultSampleInterval
	}
	if _, err := exec.LookPath("docker"); err != nil {
		_ = j.Stamp("sampler", map[string]any{"docker": nil})
		return func() Samples { return Samples{PerContainer: map[string]ContainerStats{}} }
	}

	sctx, cancel := context.WithCancel(ctx)
	agg := newSampleAgg()
	done := make(chan struct{})

	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-t.C:
				sampleOnce(sctx, j, containers, agg)
			}
		}
	}()

	return func() Samples {
		cancel()
		<-done
		return agg.result()
	}
}

func sampleOnce(ctx context.Context, j *Journal, containers []string, agg *sampleAgg) {
	sctx, cancel := context.WithTimeout(ctx, envProbeTimeout)
	defer cancel()
	if out, err := cmdRunner(sctx, "docker", "stats", "--no-stream", "--format", "{{json .}}"); err == nil {
		lines, malformed := parseDockerStatsLines(out, containers)
		agg.malformed += malformed
		for _, l := range lines {
			agg.add(l.Name, l.CPUPct, l.HasCPU, l.MemBytes)
			var cpu any
			if l.HasCPU {
				cpu = l.CPUPct
			}
			_ = j.Stamp("sample", map[string]any{
				"container":       l.Name,
				"cpu_pct":         cpu,
				"mem_bytes":       l.MemBytes,
				"net_in_bytes":    l.NetInBytes,
				"net_out_bytes":   l.NetOutBytes,
				"block_in_bytes":  l.BlockInBytes,
				"block_out_bytes": l.BlockOutBytes,
			})
		}
	}
	sampleClient(j, agg)
}

// cpuSecondsFn returns the process's accumulated CPU time in seconds, via a
// platform syscall (procstat_unix.go / procstat_windows.go). Package variable
// so tests can inject a fake sequence of readings.
var cpuSecondsFn = processCPUSeconds

// sampleClient samples the console's own process: heap+runtime memory via
// runtime.ReadMemStats(Sys), and CPU% as 100 * (delta CPU seconds / delta
// wall seconds) between this call and the previous one. The first sample has
// no prior reading to delta against, so it reports cpu_pct: null; so does any
// sample where the syscall itself fails.
func sampleClient(j *Journal, agg *sampleAgg) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	sys := int64(m.Sys)

	pct, hasCPU := agg.clientCPUPct(time.Now(), cpuSecondsFn)

	agg.add("client", pct, hasCPU, sys)
	var cpu any
	if hasCPU {
		cpu = pct
	}
	_ = j.Stamp("sample", map[string]any{
		"container": "client",
		"cpu_pct":   cpu,
		"mem_bytes": sys,
	})
}

// ---- aggregation ------------------------------------------------------------

type containerAcc struct {
	n               int
	cpuSum, peakCPU float64
	memSum          float64
	peakMem         int64
}

type sampleAgg struct {
	malformed int
	acc       map[string]*containerAcc

	// client CPU-time delta tracking, for clientCPUPct.
	haveLastClientCPU bool
	lastClientCPU     float64
	lastClientCPUTime time.Time
}

func newSampleAgg() *sampleAgg { return &sampleAgg{acc: map[string]*containerAcc{}} }

// clientCPUPct returns 100 * (delta CPU seconds / delta wall seconds) since
// the previous call, using cpuSeconds to read the current accumulated CPU
// time. The first call (or a failed read) has nothing to delta against and
// returns (0, false).
func (a *sampleAgg) clientCPUPct(now time.Time, cpuSeconds func() (float64, bool)) (float64, bool) {
	cur, ok := cpuSeconds()
	if !ok {
		return 0, false
	}
	defer func() { a.lastClientCPU, a.lastClientCPUTime, a.haveLastClientCPU = cur, now, true }()

	if !a.haveLastClientCPU {
		return 0, false
	}
	dWall := now.Sub(a.lastClientCPUTime).Seconds()
	if dWall <= 0 {
		return 0, false
	}
	return 100 * (cur - a.lastClientCPU) / dWall, true
}

func (a *sampleAgg) add(name string, cpuPct float64, hasCPU bool, memBytes int64) {
	c, ok := a.acc[name]
	if !ok {
		c = &containerAcc{}
		a.acc[name] = c
	}
	c.n++
	c.memSum += float64(memBytes)
	if memBytes > c.peakMem {
		c.peakMem = memBytes
	}
	if hasCPU {
		c.cpuSum += cpuPct
		if cpuPct > c.peakCPU {
			c.peakCPU = cpuPct
		}
	}
}

func (a *sampleAgg) result() Samples {
	out := make(map[string]ContainerStats, len(a.acc))
	for name, c := range a.acc {
		var meanCPU float64
		var meanMem int64
		if c.n > 0 {
			meanCPU = c.cpuSum / float64(c.n)
			meanMem = int64(c.memSum / float64(c.n))
		}
		out[name] = ContainerStats{PeakCPU: c.peakCPU, MeanCPU: meanCPU, PeakMem: c.peakMem, MeanMem: meanMem}
	}
	return Samples{PerContainer: out, Malformed: a.malformed}
}

// ---- docker-stats line parsing ----------------------------------------------

// statLine is one parsed, kept docker-stats sample.
type statLine struct {
	Name                                                           string
	CPUPct                                                         float64
	HasCPU                                                         bool
	MemBytes, NetInBytes, NetOutBytes, BlockInBytes, BlockOutBytes int64
}

// dockerStatsJSON mirrors the fields `docker stats --format '{{json .}}'`
// emits that this sampler needs.
type dockerStatsJSON struct {
	Name     string `json:"Name"`
	CPUPerc  string `json:"CPUPerc"`
	MemUsage string `json:"MemUsage"`
	NetIO    string `json:"NetIO"`
	BlockIO  string `json:"BlockIO"`
}

// parseDockerStatsLines parses one JSON object per line, keeping only
// containers named in keep. A line that isn't valid JSON, or whose fields
// don't parse, is skipped and counted as malformed.
func parseDockerStatsLines(out []byte, keep []string) ([]statLine, int) {
	wanted := make(map[string]bool, len(keep))
	for _, k := range keep {
		wanted[k] = true
	}
	var lines []statLine
	malformed := 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var d dockerStatsJSON
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			malformed++
			continue
		}
		if !wanted[d.Name] {
			continue
		}
		sl, ok := parseStatLine(d)
		if !ok {
			malformed++
			continue
		}
		lines = append(lines, sl)
	}
	return lines, malformed
}

func parseStatLine(d dockerStatsJSON) (statLine, bool) {
	sl := statLine{Name: d.Name}

	if cpu := strings.TrimSuffix(strings.TrimSpace(d.CPUPerc), "%"); cpu != "" {
		if v, err := strconv.ParseFloat(cpu, 64); err == nil {
			sl.CPUPct, sl.HasCPU = v, true
		}
	}

	memLeft, _, ok := splitSlash(d.MemUsage)
	if !ok {
		return statLine{}, false
	}
	mem, ok := parseByteSize(memLeft)
	if !ok {
		return statLine{}, false
	}
	sl.MemBytes = mem

	netIn, netOut, ok := splitSlash(d.NetIO)
	if !ok {
		return statLine{}, false
	}
	if sl.NetInBytes, ok = parseByteSize(netIn); !ok {
		return statLine{}, false
	}
	if sl.NetOutBytes, ok = parseByteSize(netOut); !ok {
		return statLine{}, false
	}

	blkIn, blkOut, ok := splitSlash(d.BlockIO)
	if !ok {
		return statLine{}, false
	}
	if sl.BlockInBytes, ok = parseByteSize(blkIn); !ok {
		return statLine{}, false
	}
	if sl.BlockOutBytes, ok = parseByteSize(blkOut); !ok {
		return statLine{}, false
	}
	return sl, true
}

func splitSlash(s string) (left, right string, ok bool) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

// parseByteSize parses docker's "123.4MiB"-style sizes (decimal or binary
// units) into bytes.
func parseByteSize(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	i := 0
	for i < len(s) && (s[i] == '.' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	if i == 0 {
		return 0, false
	}
	val, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0, false
	}
	mult, ok := byteUnitMultiplier(strings.TrimSpace(s[i:]))
	if !ok {
		return 0, false
	}
	return int64(val * mult), true
}

func byteUnitMultiplier(unit string) (float64, bool) {
	const (
		kb = 1000
		mb = kb * 1000
		gb = mb * 1000
		tb = gb * 1000

		kib = 1024
		mib = kib * 1024
		gib = mib * 1024
		tib = gib * 1024
	)
	switch unit {
	case "B", "":
		return 1, true
	case "kB", "KB":
		return kb, true
	case "KiB":
		return kib, true
	case "MB":
		return mb, true
	case "MiB":
		return mib, true
	case "GB":
		return gb, true
	case "GiB":
		return gib, true
	case "TB":
		return tb, true
	case "TiB":
		return tib, true
	}
	return 0, false
}
