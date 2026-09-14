package campaign

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Measurement campaigns from the console: Repeat, run as a job against the
// console's own API (internal.go), persisted under <runs>/campaigns/<id>/:
//
//	campaign.json  config, options, preflight snapshot, status, a row per repetition
//	summary.csv    the file Repeat writes (absent until the campaign completes)
//	log.txt        the driver's progress lines
//
// A campaign never runs attacks: skip_attacks is forced on every repetition.

const (
	campaignsDir = "campaigns"
	campaignFile = "campaign.json"
	campaignLog  = "log.txt"
)

// CampaignOptions are POST /api/campaigns' repetition options (RepeatOpts).
type CampaignOptions struct {
	Warmups int     `json:"warmups"`
	Reps    int     `json:"reps"`
	Sweep   float64 `json:"sweep,omitempty"`
	WindowS float64 `json:"window_s,omitempty"`
	Burst   int     `json:"burst,omitempty"`
	Force   bool    `json:"force,omitempty"`
}

// campaignRep is one repetition as its run folder reports it.
type campaignRep struct {
	Index        int      `json:"index"`
	Kind         string   `json:"kind"`
	RunID        string   `json:"run_id"`
	Status       string   `json:"status"` // running | done | failed
	CommittedTPS *float64 `json:"committed_tps"`
	LatencyP99Ms *float64 `json:"latency_p99_ms"`
	Failed       bool     `json:"failed"`
	FailReason   string   `json:"fail_reason,omitempty"`
}

// campaignRecord is campaign.json.
type campaignRecord struct {
	ID         string          `json:"id"`
	Status     string          `json:"status"`
	Error      string          `json:"error,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	Config     ElectionConfig  `json:"config"`
	Options    CampaignOptions `json:"options"`
	Preflight  PreflightReport `json:"preflight"`
	Reps       []campaignRep   `json:"reps"`
}

func (s *Server) campaignDir(id string) (string, error) {
	if !runIDPattern.MatchString(id) {
		return "", fmt.Errorf("invalid campaign id %q", id)
	}
	return filepath.Join(s.store.Root(), campaignsDir, id), nil
}

// saveCampaign writes campaign.json atomically (temp file + rename), so a crash
// mid-write never leaves a campaign unreadable. Caller holds s.jobs.mu.
func saveCampaign(dir string, rec *campaignRecord) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, campaignFile+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, campaignFile))
}

// loadCampaign reads campaign.json. A campaign whose file says running but
// that is not this process's active job was running when the console stopped:
// it is marked interrupted, on disk, rather than left claiming to run.
func (s *Server) loadCampaign(id string) (campaignRecord, bool, error) {
	dir, err := s.campaignDir(id)
	if err != nil {
		return campaignRecord{}, false, err
	}
	s.jobs.mu.Lock()
	defer s.jobs.mu.Unlock()
	var rec campaignRecord
	if err := readJSON(filepath.Join(dir, campaignFile), &rec); err != nil {
		return campaignRecord{}, false, fmt.Errorf("unknown campaign %q", id)
	}
	active := s.jobs.active != nil && s.jobs.active.ID == id
	if rec.Status == jobRunning && !active {
		rec.Status = jobInterrupted
		rec.Error = "the console stopped while this campaign was running"
		_ = saveCampaign(dir, &rec)
	}
	return rec, active, nil
}

// refreshReps fills each repetition from its run folder: perf.csv's row and
// run.end's verdict, the same two sources Repeat's collect reads. Only the
// newest repetition of a live campaign can still be running.
func (s *Server) refreshReps(rec *campaignRecord, active bool) {
	for i := range rec.Reps {
		rep := &rec.Reps[i]
		rep.CommittedTPS, rep.LatencyP99Ms, rep.Failed, rep.FailReason = nil, nil, false, ""
		dir, err := s.store.Dir(rep.RunID)
		if err != nil {
			rep.Status, rep.Failed, rep.FailReason = jobFailed, true, err.Error()
			continue
		}
		var perf map[string]string
		if data, err := os.ReadFile(filepath.Join(dir, PerfCSV)); err == nil {
			perf, _ = perfRowCells(data, rep.RunID)
		}
		journal, _ := os.ReadFile(filepath.Join(dir, JournalFile))
		end, ended := runEndEvent(journal)
		if active && i == len(rec.Reps)-1 && (!ended || perf == nil) {
			rep.Status = jobRunning
			continue
		}
		r := repResult{Perf: perf}
		if v, ok := r.num("committed_tps"); ok {
			rep.CommittedTPS = &v
		}
		if v, ok := r.num("latency_p99_ms"); ok {
			rep.LatencyP99Ms = &v
		}
		switch {
		case ended && jbool(end, "failed"):
			rep.Failed, rep.FailReason = true, jstring(end, "reason")
			if rep.FailReason == "" {
				rep.FailReason = "failed"
			}
		case perf == nil:
			rep.Failed, rep.FailReason = true, "no perf.csv"
		case !ended:
			rep.Failed, rep.FailReason = true, "run never reached run.end"
		}
		rep.Status = jobDone
		if rep.Failed {
			rep.Status = jobFailed
		}
	}
}

func jbool(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// handleCampaigns serves GET (list, newest first) and POST (start) on /api/campaigns.
func (s *Server) handleCampaigns(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.listCampaigns(w)
		return
	}
	var req struct {
		Config ElectionConfig `json:"config"`
		CampaignOptions
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	c := req.Config
	c.applyDefaults()
	c.SkipAttacks = true // measured repetitions never run attacks
	if err := c.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	o := req.CampaignOptions
	switch {
	case o.Warmups < 0 || o.Reps < 0 || o.Burst < 0 || o.WindowS < 0:
		http.Error(w, "warmups, reps, burst and window_s must be >= 0", http.StatusBadRequest)
		return
	case o.Sweep != 0 && o.Sweep <= 1:
		http.Error(w, "sweep must be > 1 (the per-step rate multiplier) or 0", http.StatusBadRequest)
		return
	case o.Warmups+o.Reps+o.Burst == 0 && o.Sweep == 0:
		http.Error(w, "nothing to run: set reps, warmups, burst or sweep", http.StatusBadRequest)
		return
	}
	if running := s.jobs.running(); running != nil {
		busyResponse(w, running)
		return
	}
	pre := s.preflight(PreflightInput{Mode: c.Mode, Voters: c.Voters, Positions: c.Positions, Concurrency: c.Concurrency})
	if pre.Blocked() && !o.Force {
		writeJSONResp(w, http.StatusConflict, map[string]any{
			"error":    "preflight blocks this campaign; fix the blocking findings or pass force: true",
			"warnings": pre.Warnings,
		})
		return
	}
	j, running := s.jobs.start("campaign")
	if running != nil {
		busyResponse(w, running)
		return
	}
	rec := &campaignRecord{
		ID: j.ID, Status: jobRunning, CreatedAt: j.StartedAt,
		Config: c, Options: o, Preflight: pre, Reps: []campaignRep{},
	}
	dir, logFile, err := s.createCampaign(rec)
	if err != nil {
		s.jobs.run(j, func() (json.RawMessage, error) { return nil, err }, func(status, errText string) {
			if dir != "" { // campaign.json exists: do not leave it claiming to run
				rec.Status, rec.Error = status, errText
				_ = saveCampaign(dir, rec)
			}
		})
		http.Error(w, "cannot create the campaign folder: "+err.Error(), http.StatusInternalServerError)
		return
	}
	j.onRun = func(runID string) { s.recordRep(dir, rec, runID) }
	client, base := s.internalClient(j)
	go s.jobs.run(j, func() (json.RawMessage, error) {
		defer logFile.Close()
		err := Repeat(context.Background(), RepeatOpts{
			BaseURL: base, Client: client, Config: c,
			Warmups: o.Warmups, Reps: o.Reps, Sweep: o.Sweep, Burst: o.Burst,
			Window: time.Duration(o.WindowS * float64(time.Second)),
			Out:    filepath.Join(dir, SummaryCSV),
			Log:    io.MultiWriter(jobLog{&s.jobs, j}, logFile),
		})
		result, _ := json.Marshal(map[string]string{"campaign": rec.ID})
		return result, err
	}, func(status, errText string) {
		now := time.Now().UTC()
		rec.Status, rec.Error, rec.FinishedAt = status, errText, &now
		s.refreshReps(rec, false)
		_ = saveCampaign(dir, rec)
	})
	writeJSONResp(w, http.StatusAccepted, map[string]string{"campaign": rec.ID})
}

// createCampaign makes the campaign folder, its first campaign.json and log.txt.
// dir is returned non-empty once campaign.json has been written.
func (s *Server) createCampaign(rec *campaignRecord) (string, *os.File, error) {
	dir, err := s.campaignDir(rec.ID)
	if err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, err
	}
	s.jobs.mu.Lock()
	err = saveCampaign(dir, rec)
	s.jobs.mu.Unlock()
	if err != nil {
		return "", nil, err
	}
	f, err := os.Create(filepath.Join(dir, campaignLog))
	return dir, f, err
}

// recordRep appends the repetition a /generate just created. The run's own
// run.json carries its rep tag, so the row is read from the run, not guessed.
func (s *Server) recordRep(dir string, rec *campaignRecord, runID string) {
	row := campaignRep{RunID: runID, Status: jobRunning}
	if run, err := s.record(runID); err == nil && run.Config.Rep != nil {
		row.Index, row.Kind = run.Config.Rep.Index, run.Config.Rep.Kind
	}
	s.jobs.mu.Lock()
	defer s.jobs.mu.Unlock()
	rec.Reps = append(rec.Reps, row)
	_ = saveCampaign(dir, rec)
}

func (s *Server) listCampaigns(w http.ResponseWriter) {
	entries, err := os.ReadDir(filepath.Join(s.store.Root(), campaignsDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := []campaignRecord{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if rec, _, err := s.loadCampaign(e.Name()); err == nil {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	writeJSONResp(w, http.StatusOK, out)
}

// handleCampaign routes /api/campaigns/<id>, /<id>/cancel and /<id>/export.
func (s *Server) handleCampaign(w http.ResponseWriter, r *http.Request) {
	id, action, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/api/campaigns/"), "/")
	want := http.MethodGet
	if action == "cancel" {
		want = http.MethodPost
	}
	if r.Method != want {
		http.Error(w, want+" required", http.StatusMethodNotAllowed)
		return
	}
	rec, active, err := s.loadCampaign(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	switch action {
	case "":
		s.refreshReps(&rec, active)
		dir, _ := s.campaignDir(id)
		resp := struct {
			campaignRecord
			Summary []map[string]string `json:"summary"`
		}{campaignRecord: rec}
		if data, err := os.ReadFile(filepath.Join(dir, SummaryCSV)); err == nil {
			resp.Summary = parseCSVRows(data)
		}
		writeJSONResp(w, http.StatusOK, resp)
	case "cancel":
		if !s.jobs.requestCancel(id) {
			http.Error(w, fmt.Sprintf("campaign %s is not running", id), http.StatusConflict)
			return
		}
		writeJSONResp(w, http.StatusAccepted, map[string]string{
			"campaign": id, "status": "cancelling after the current repetition",
		})
	case "export":
		s.refreshReps(&rec, active)
		s.streamCampaignBundle(w, rec)
	default:
		http.NotFound(w, r)
	}
}

// parseCSVRows reads a CSV with a header row into one header -> cell map per row.
func parseCSVRows(data []byte) []map[string]string {
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil || len(rows) == 0 {
		return nil
	}
	out := make([]map[string]string, 0, len(rows)-1)
	for _, row := range rows[1:] {
		m := make(map[string]string, len(rows[0]))
		for i, h := range rows[0] {
			if i < len(row) {
				m[h] = row[i]
			}
		}
		out = append(out, m)
	}
	return out
}
