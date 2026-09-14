package campaign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Long-running console jobs: the validation ladder and measurement campaigns.
//
// The console runs ONE job at a time. Both kinds drive elections on the same
// network and host, and two at once would measure each other.

// Job statuses.
const (
	jobQueued      = "queued"
	jobRunning     = "running"
	jobDone        = "done"
	jobFailed      = "failed"
	jobCancelled   = "cancelled"
	jobInterrupted = "interrupted" // campaigns only: the console stopped mid-run
)

// jobLogLines is how many of a job's latest log lines GET /api/jobs/<id> returns.
const jobLogLines = 200

// job is one ladder or campaign run. Every field is guarded by jobBoard.mu,
// except the hooks, which are set before the job's goroutine starts and never
// again.
type job struct {
	ID         string
	Kind       string // "ladder" | "campaign"
	Status     string
	StartedAt  time.Time
	FinishedAt *time.Time
	Error      string
	Result     json.RawMessage
	log        []string
	cancel     bool
	campaign   *campaignRecord // campaigns: the live record, saved as campaign.json

	onRun    func(runID string, start HostSample) // campaigns: a repetition's run was created
	onRepEnd func(runID string)                   // campaigns: a repetition's run is over
}

// jobBoard is the console-wide job slot. The zero value is ready.
//
// ponytail: jobs live in memory, so a restart forgets them; campaigns persist
// themselves (campaign.go) and are marked interrupted on the next read.
type jobBoard struct {
	mu     sync.Mutex
	n      int
	active *job
	all    map[string]*job
}

// start claims the slot for a new job, or returns the job already holding it.
func (b *jobBoard) start(kind string) (*job, *job) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active != nil {
		return nil, b.active
	}
	if b.all == nil {
		b.all = make(map[string]*job)
	}
	b.n++
	now := time.Now().UTC()
	j := &job{
		ID:        fmt.Sprintf("%s-%s-%d", kind, now.Format("20060102-150405"), b.n),
		Kind:      kind,
		Status:    jobQueued,
		StartedAt: now,
	}
	b.all[j.ID] = j
	b.active = j
	return j, nil
}

// running returns the job holding the slot, or nil.
func (b *jobBoard) running() *job {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.active
}

func (b *jobBoard) cancelRequested(j *job) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return j.cancel
}

// requestCancel flags the running job with this id; false when it is not running.
func (b *jobBoard) requestCancel(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active == nil || b.active.ID != id {
		return false
	}
	b.active.cancel = true
	return true
}

// run executes fn as j. fn's error decides the status; persist, when set, runs
// under the board lock in the same critical section that frees the slot, so no
// reader can see the slot free while a campaign's file still says running.
func (b *jobBoard) run(j *job, fn func() (json.RawMessage, error), persist func(status, errText string)) {
	b.mu.Lock()
	j.Status = jobRunning
	b.mu.Unlock()

	result, err := fn()

	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now().UTC()
	j.FinishedAt, j.Result = &now, result
	switch {
	case err == nil:
		j.Status = jobDone
	case errors.Is(err, errJobCancelled):
		j.Status = jobCancelled
	default:
		j.Status, j.Error = jobFailed, err.Error()
	}
	if persist != nil {
		persist(j.Status, j.Error)
	}
	if b.active == j {
		b.active = nil
	}
}

// Write makes a job a log sink: each Write is one or more whole lines, which is
// how Repeat and RunLadder print.
type jobLog struct {
	b *jobBoard
	j *job
}

func (l jobLog) Write(p []byte) (int, error) {
	l.b.mu.Lock()
	defer l.b.mu.Unlock()
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		l.j.log = append(l.j.log, strings.TrimRight(line, "\r"))
	}
	if over := len(l.j.log) - jobLogLines; over > 0 {
		l.j.log = append([]string(nil), l.j.log[over:]...)
	}
	return len(p), nil
}

// jobView is GET /api/jobs/<id>'s body.
type jobView struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Status     string          `json:"status"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt *time.Time      `json:"finished_at"`
	Error      string          `json:"error,omitempty"`
	Log        []string        `json:"log"`
	Result     json.RawMessage `json:"result"`
}

func (b *jobBoard) view(id string) (jobView, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	j, ok := b.all[id]
	if !ok {
		return jobView{}, false
	}
	return jobView{
		ID: j.ID, Kind: j.Kind, Status: j.Status,
		StartedAt: j.StartedAt, FinishedAt: j.FinishedAt, Error: j.Error,
		Log: append([]string{}, j.log...), Result: j.Result,
	}, true
}

// busyResponse is the 409 for a second job start.
func busyResponse(w http.ResponseWriter, running *job) {
	writeJSONResp(w, http.StatusConflict, map[string]string{
		"error": fmt.Sprintf("the console runs one job at a time; %s %s is running", running.Kind, running.ID),
		"job":   running.ID,
	})
}

// handleLadder serves POST /api/ladder: the validation ladder as a job, driven
// in-process. Its result is the ladder.json it wrote.
func (s *Server) handleLadder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	// The ladder runs elections on this host too: not beside a running phase
	// (a fault run's included), and not during a reset (the slot).
	j := s.startExclusiveJob(w, "ladder")
	if j == nil {
		return
	}
	client, base := s.internalClient(j)
	go s.jobs.run(j, func() (json.RawMessage, error) {
		err := RunLadder(context.Background(), LadderOpts{
			BaseURL: base, Client: client, DataDir: s.store.Root(),
			Head: s.gitHead, Log: jobLog{&s.jobs, j},
		})
		if err != nil {
			return nil, err
		}
		return os.ReadFile(filepath.Join(s.store.Root(), LadderFile))
	}, nil)
	writeJSONResp(w, http.StatusAccepted, map[string]string{"job": j.ID})
}

// handleJob serves GET /api/jobs/<id>.
func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	v, ok := s.jobs.view(strings.TrimPrefix(r.URL.Path, "/api/jobs/"))
	if !ok {
		http.Error(w, "unknown job", http.StatusNotFound)
		return
	}
	writeJSONResp(w, http.StatusOK, v)
}
