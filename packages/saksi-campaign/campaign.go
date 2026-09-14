package campaign

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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

// campaignRep is one repetition as its run folder reports it. Once its status
// is done or failed the values are final and cached in campaign.json; only an
// in-progress repetition is read from its run folder.
type campaignRep struct {
	Index        int      `json:"index"`
	Kind         string   `json:"kind"`
	RunID        string   `json:"run_id"`
	Status       string   `json:"status"` // running | done | failed
	CommittedTPS *float64 `json:"committed_tps"`
	LatencyP99Ms *float64 `json:"latency_p99_ms"`
	Failed       bool     `json:"failed"`
	FailReason   string   `json:"fail_reason,omitempty"`
	// HostStart is sampled before the repetition's /generate, HostEnd after its
	// verify phase: a repetition that shared the machine shows it afterwards.
	HostStart *HostSample `json:"host_start,omitempty"`
	HostEnd   *HostSample `json:"host_end,omitempty"`
}

// campaignRecord is campaign.json.
type campaignRecord struct {
	ID         string          `json:"id"`
	Status     string          `json:"status"`
	Error      string          `json:"error,omitempty"`
	SaveError  string          `json:"save_error,omitempty"`
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
// mid-write never leaves a campaign unreadable.
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

// persistCampaign saves rec, and on failure logs it and keeps the reason in
// save_error, which the next save that succeeds writes out and GET shows while
// the campaign runs. Caller holds s.jobs.mu.
func persistCampaign(dir string, rec *campaignRecord) {
	if err := saveCampaign(dir, rec); err != nil {
		log.Printf("campaign %s: campaign.json not saved: %v", rec.ID, err)
		rec.SaveError = fmt.Sprintf("%s: %v", time.Now().UTC().Format(time.RFC3339), err)
	}
}

// loadCampaign returns a campaign: the live record when it is this process's
// running job, campaign.json otherwise. A file that says running but that no
// job here owns was running when the console stopped: its rows are settled
// from their run folders and it is marked interrupted, on disk.
func (s *Server) loadCampaign(id string) (campaignRecord, bool, error) {
	dir, err := s.campaignDir(id)
	if err != nil {
		return campaignRecord{}, false, err
	}
	s.jobs.mu.Lock()
	defer s.jobs.mu.Unlock()
	if a := s.jobs.active; a != nil && a.ID == id && a.campaign != nil {
		cp := *a.campaign
		cp.Reps = append([]campaignRep{}, a.campaign.Reps...)
		return cp, true, nil
	}
	var rec campaignRecord
	if err := readJSON(filepath.Join(dir, campaignFile), &rec); err != nil {
		return campaignRecord{}, false, fmt.Errorf("unknown campaign %q", id)
	}
	if rec.Status == jobRunning {
		s.refreshReps(&rec, false)
		rec.Status = jobInterrupted
		rec.Error = "the console stopped while this campaign was running"
		persistCampaign(dir, &rec)
	}
	return rec, false, nil
}

// refreshReps fills every repetition that is not yet final from its run folder:
// perf.csv's row and run.end's verdict, the same two sources Repeat's collect
// reads. With active set, the newest repetition may still be running and is
// left so; every other one is settled.
func (s *Server) refreshReps(rec *campaignRecord, active bool) {
	for i := range rec.Reps {
		rep := &rec.Reps[i]
		if rep.Status == jobDone || rep.Status == jobFailed {
			continue // final, cached
		}
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
		rep.CommittedTPS, rep.LatencyP99Ms, rep.Failed, rep.FailReason = nil, nil, false, ""
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
	switch r.Method {
	case http.MethodGet:
		s.listCampaigns(w)
		return
	case http.MethodPost:
	default:
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Config ElectionConfig `json:"config"`
		CampaignOptions
	}
	// Unknown fields are refused: a misspelled "rep" would otherwise run a
	// campaign with no measured repetitions.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid campaign body: "+err.Error(), http.StatusBadRequest)
		return
	}
	c := req.Config
	c.applyDefaults()
	c.SkipAttacks = true // measured repetitions never run attacks
	// A plan is dropped, not refused: it must go before Validate, which
	// rejects a plan alongside skip_attacks. The burst copy inherits the nil.
	c.AttackPlan = nil
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
	case o.Reps < 1 && o.Sweep == 0 && o.Burst == 0:
		http.Error(w, "reps must be >= 1 unless sweep or burst is set", http.StatusBadRequest)
		return
	}
	// The burst is its own election at o.Burst voters, run after the measured
	// repetitions: checked now, or it fails hours in at its own /generate.
	var burst *ElectionConfig
	if o.Burst > 0 {
		b := c
		b.Voters, b.SendRate, b.WindowS = o.Burst, 0, 0
		if err := b.Validate(); err != nil {
			http.Error(w, fmt.Sprintf("burst of %d voters: %v", o.Burst, err), http.StatusBadRequest)
			return
		}
		burst = &b
	}
	if running := s.jobs.running(); running != nil {
		busyResponse(w, running)
		return
	}
	pre := s.preflight(PreflightInput{Mode: c.Mode, Voters: c.Voters, Positions: c.Positions,
		Candidates: c.Candidates, Concurrency: c.Concurrency})
	if burst != nil {
		if err := s.ladderGate(*burst); err != nil {
			pre.add(severityBlock, "ladder_missing", "the burst of %d voters is above the %d-voter ceiling: %v",
				burst.Voters, LadderVoterCeiling, err)
		}
	}
	// Preflight projects one run; the campaign's runs all land on the same
	// ledger, since nothing resets the network between repetitions, and an
	// offline campaign keeps every run folder. A probe that failed does not
	// refuse, exactly as the disk gate does.
	if free := pre.Disk.FreeBytes; free != nil {
		if need, parts := campaignDiskBytes(c, o); need > *free {
			what, why := "ledger", "no network reset runs between repetitions"
			if c.Mode == "offline" {
				what, why = "run folders", "every repetition keeps its run folder"
			}
			pre.add(severityBlock, "disk_short",
				"this campaign projects %d bytes of %s (%s) but only %d bytes are free on %s: "+
					"%s, so free space or run fewer repetitions",
				need, what, parts, *free, pre.Disk.Path, why)
		}
	}
	if codes := pre.unforceable(); len(codes) > 0 {
		writeJSONResp(w, http.StatusConflict, map[string]any{
			"error": fmt.Sprintf("preflight blocks this campaign, and force cannot override %s: "+
				"each fails the first /generate or every run", strings.Join(codes, ", ")),
			"warnings": pre.Warnings,
		})
		return
	}
	if pre.Blocked() && !o.Force {
		writeJSONResp(w, http.StatusConflict, map[string]any{
			"error":    "preflight blocks this campaign; fix the blocking findings or pass force: true (only fabric_unreachable can be forced)",
			"warnings": pre.Warnings,
		})
		return
	}
	// Preflight ran seconds ago and a single run may have started since: the
	// busy check and the claim happen together here, under s.mu.
	j := s.startExclusiveJob(w, "campaign")
	if j == nil {
		return
	}
	rec := &campaignRecord{
		ID: j.ID, Status: jobRunning, CreatedAt: j.StartedAt,
		Config: c, Options: o, Preflight: pre, Reps: []campaignRep{},
	}
	dir, logFile, err := s.createCampaign(j, rec)
	if err != nil {
		s.jobs.run(j, func() (json.RawMessage, error) { return nil, err }, func(status, errText string) {
			if dir != "" { // campaign.json exists: do not leave it claiming to run
				rec.Status, rec.Error = status, errText
				persistCampaign(dir, rec)
			}
		})
		http.Error(w, "cannot create the campaign folder: "+err.Error(), http.StatusInternalServerError)
		return
	}
	j.onRun = func(runID string, start HostSample) { s.recordRep(dir, rec, runID, start) }
	j.onRepEnd = func(runID string) { s.endRep(dir, rec, runID) }
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
		persistCampaign(dir, rec)
	})
	writeJSONResp(w, http.StatusAccepted, map[string]string{"campaign": rec.ID})
}

// campaignDiskBytes projects the disk a whole campaign fills, with the disk
// gate's per-run projection (the ledger on-chain, the run folder offline):
// every warm-up and measured run, every sweep step the sweep can run
// (maxSweepSteps; each step offers at most the config's voters), and the
// burst. It returns the total and its breakdown, for the refusal message.
func campaignDiskBytes(c ElectionConfig, o CampaignOptions) (uint64, string) {
	perRun, _ := diskProjection(c)
	runs := uint64(o.Warmups + o.Reps)
	total := runs * perRun
	parts := []string{fmt.Sprintf("%d warm-up and measured runs x %d bytes", runs, perRun)}
	if o.Sweep > 1 {
		total += maxSweepSteps * perRun
		parts = append(parts, fmt.Sprintf("up to %d sweep steps x %d bytes", maxSweepSteps, perRun))
	}
	if o.Burst > 0 {
		burst := c
		burst.Voters = o.Burst
		b, _ := diskProjection(burst)
		total += b
		parts = append(parts, fmt.Sprintf("a %d-voter burst of %d bytes", o.Burst, b))
	}
	return total, strings.Join(parts, " + ")
}

// createCampaign makes the campaign folder, its first campaign.json and log.txt,
// and attaches rec to j as the live record. dir is returned non-empty once
// campaign.json has been written.
func (s *Server) createCampaign(j *job, rec *campaignRecord) (string, *os.File, error) {
	dir, err := s.campaignDir(rec.ID)
	if err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, err
	}
	s.jobs.mu.Lock()
	j.campaign = rec
	err = saveCampaign(dir, rec)
	s.jobs.mu.Unlock()
	if err != nil {
		return "", nil, err
	}
	f, err := os.Create(filepath.Join(dir, campaignLog))
	return dir, f, err
}

// recordRep appends the repetition a /generate just created, with the host
// sample taken before it. The run's own run.json carries its rep tag, so the
// row is read from the run, not guessed. Every earlier repetition is over by
// now, so their values are settled and cached first.
func (s *Server) recordRep(dir string, rec *campaignRecord, runID string, start HostSample) {
	row := campaignRep{RunID: runID, Status: jobRunning, HostStart: &start}
	if run, err := s.record(runID); err == nil && run.Config.Rep != nil {
		row.Index, row.Kind = run.Config.Rep.Index, run.Config.Rep.Kind
	}
	s.jobs.mu.Lock()
	defer s.jobs.mu.Unlock()
	s.refreshReps(rec, false)
	rec.Reps = append(rec.Reps, row)
	persistCampaign(dir, rec)
}

// endRep takes a finished repetition's closing host sample and settles its row.
func (s *Server) endRep(dir string, rec *campaignRecord, runID string) {
	s.jobs.mu.Lock()
	i := pendingRepIndex(rec.Reps, runID)
	s.jobs.mu.Unlock()
	if i < 0 {
		return
	}
	end := sampleHost() // outside the lock: under WSL it shells out
	s.jobs.mu.Lock()
	defer s.jobs.mu.Unlock()
	rec.Reps[i].HostEnd = &end
	s.refreshReps(rec, false)
	persistCampaign(dir, rec)
}

// pendingRepIndex is the index of the row for runID still waiting for its
// closing sample, or -1.
func pendingRepIndex(reps []campaignRep, runID string) int {
	for i, r := range reps {
		if r.RunID == runID && r.HostEnd == nil {
			return i
		}
	}
	return -1
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
		if rec, active, err := s.loadCampaign(e.Name()); err == nil {
			s.refreshReps(&rec, active)
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
