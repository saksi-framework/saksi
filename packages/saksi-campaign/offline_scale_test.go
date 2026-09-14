package campaign

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeMeminfo makes memAvailable report avail bytes, or nothing when avail is 0.
func fakeMeminfo(t *testing.T, avail uint64) {
	t.Helper()
	old := readMeminfo
	t.Cleanup(func() { readMeminfo = old })
	readMeminfo = func() ([]byte, error) {
		if avail == 0 {
			return nil, errors.New("no /proc/meminfo")
		}
		return []byte(fmt.Sprintf("MemTotal:       99999999 kB\nMemAvailable:   %d kB\n", avail/1024)), nil
	}
}

// Row 8 (MP-3.5M offline) as preflight sees it: the run folder is projected on
// the runs volume and the audit against MemAvailable, each blocking above its
// resource and warning above 80 % of it.
func TestPreflightOfflineDiskAndMemory(t *testing.T) {
	fakeHostProbes(t, "", nil)
	in := PreflightInput{Mode: "offline", Voters: 3_524_078, Positions: 3, Candidates: 4}
	records := uint64(in.Voters * in.Positions)
	disk := records * (OfflineRunBytesPerRecord + OfflineRunBytesPerCandidate*4)
	mem := AuditorBaseBytes + records*AuditorBytesPerRecord
	if disk != 78_826_576_704 || mem != 1_619_389_532 {
		t.Fatalf("row 8 projects %d bytes of disk and %d of memory: the constants moved", disk, mem)
	}

	for _, tc := range []struct {
		name        string
		free, avail uint64
		want        map[string]string // code -> severity; absent = must not fire
	}{
		{"both fit", 2 * disk, 2 * mem, map[string]string{}},
		{"disk short", disk - 1, 2 * mem, map[string]string{"disk_short": severityBlock}},
		{"disk tight", disk + disk/10, 2 * mem, map[string]string{"disk_tight": severityWarn}},
		{"memory short", 2 * disk, mem - 1, map[string]string{"memory_short": severityBlock}},
		{"memory tight", 2 * disk, mem + mem/10, map[string]string{"memory_tight": severityWarn}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, root := gateServer(t, FabricConfig{}, "abc", tc.free)
			writeLadder(t, root, "abc")
			fakeMeminfo(t, tc.avail)
			rep := s.preflight(in)
			got := findings(rep.Warnings)
			for _, code := range []string{"disk_short", "disk_tight", "memory_short", "memory_tight"} {
				if want, fires := tc.want[code]; fires != (got[code].Code != "") || got[code].Severity != want {
					t.Errorf("%s: want %q, got %+v (all %+v)", code, want, got[code], rep.Warnings)
				}
			}
			if got["disk_short"].Forceable || got["memory_short"].Forceable {
				t.Error("a resource block must not be forceable")
			}
			if rep.Disk.Path != root || rep.Disk.ProjectedRunBytes == nil || *rep.Disk.ProjectedRunBytes != disk ||
				rep.Disk.ProjectedLedgerBytes != nil {
				t.Errorf("disk report = %+v, want %d run bytes on %s and no ledger", rep.Disk, disk, root)
			}
			if rep.Memory.ProjectedAuditBytes == nil || *rep.Memory.ProjectedAuditBytes != mem ||
				rep.Memory.AvailableBytes == nil || *rep.Memory.AvailableBytes != tc.avail/1024*1024 {
				t.Errorf("memory report = %+v", rep.Memory)
			}
		})
	}

	// No /proc/meminfo (Windows): null, and nothing to block or warn on.
	s, root := gateServer(t, FabricConfig{}, "abc", 2*disk)
	writeLadder(t, root, "abc")
	fakeMeminfo(t, 0)
	rep := s.preflight(in)
	if rep.Memory.AvailableBytes != nil || findings(rep.Warnings)["memory_short"].Code != "" {
		t.Fatalf("no meminfo: memory = %+v, warnings %+v", rep.Memory, rep.Warnings)
	}
	// Ground truth writes and audits nothing that scales.
	if rep := s.preflight(PreflightInput{Mode: ModeGroundTruth, Voters: 3_524_078, Positions: 3, Candidates: 4}); rep.Disk.ProjectedRunBytes != nil || rep.Memory.ProjectedAuditBytes != nil {
		t.Fatalf("ground truth projected %+v / %+v", rep.Disk, rep.Memory)
	}
}

// /generate refuses what preflight blocks, before a run folder exists.
func TestGenerateRefusesAnOfflineTierThatWillNotFit(t *testing.T) {
	c := good()
	c.Voters, c.Positions, c.Candidates = 3_524_078, 3, 4
	for name, setup := range map[string]func(*Server){
		"disk": func(s *Server) {
			s.freeSpace = func(string) (uint64, error) { return 1 << 30, nil }
			fakeMeminfo(t, 1<<40)
		},
		"memory": func(s *Server) { fakeMeminfo(t, 1<<30) },
	} {
		t.Run(name, func(t *testing.T) {
			s, root := gateServer(t, FabricConfig{}, "abc", 1<<50)
			writeLadder(t, root, "abc")
			setup(s)
			rec := postConfig(t, s, c)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "this run") {
				t.Fatalf("want 400 naming the projection, got %d %s", rec.Code, rec.Body)
			}
			if runs, _ := s.store.List(); len(runs) != 0 {
				t.Fatalf("a refused tier left %d run folders", len(runs))
			}
		})
	}
}

// Above the old 10,000-voter cap, a real offline run through the console's own
// API completes: generate, check, the ceremony and verify, E = 0.
func TestOfflineRunAboveTheOldCapCompletes(t *testing.T) {
	demo := findDemo(t)
	store := NewRunStore(t.TempDir())
	hub := NewHub()
	s := NewServer(store, NewExecutor(store, hub, demo, "", FabricConfig{}), hub, FabricConfig{}, nil, 5*time.Minute)
	s.gitHead = func() (string, bool) { return "abc", true }
	writeLadder(t, store.Root(), "abc")
	console := httptest.NewServer(s)
	defer console.Close()

	d, err := newRepeatDriver(RepeatOpts{BaseURL: console.URL, Log: io.Discard, Poll: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	c := good()
	c.Voters = 20_000
	r, err := d.once(context.Background(), c, RepTag{Index: 1, Kind: "measured"})
	if err != nil {
		t.Fatalf("offline 20,000-voter run: %v", err)
	}
	if !r.GatePass || r.Failed {
		t.Fatalf("offline 20,000-voter run: gate %v, failed %v (%s)", r.GatePass, r.Failed, r.Reason)
	}
	cells := perfCells(t, mustDir(t, store, r.RunID))
	if cells["voters"] != "20000" || cells["proof_verify_inproc_ms"] == "" {
		t.Fatalf("perf row = %v, want a verified 20,000-voter run", cells)
	}
}

func mustDir(t *testing.T, store *RunStore, runID string) string {
	t.Helper()
	dir, err := store.Dir(runID)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
