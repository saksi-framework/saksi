package campaign

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// RunFile is the per-run metadata document written into each run folder.
const RunFile = "run.json"

// runIDPattern is the allowlist a run id must match before it is ever joined
// into a filesystem path — no slashes, no dots, no traversal.
var runIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// RunRecord is the persisted metadata for one run (its config + when it was
// created). Written as run.json by Create; read back by List.
type RunRecord struct {
	RunID     string         `json:"run_id"`
	Config    ElectionConfig `json:"config"`
	CreatedAt time.Time      `json:"created_at"`
}

// RunStore owns the run-folder tree under root. It hands out traversal-safe run
// ids and enumerates history. The store never calls time.Now itself — the
// caller passes the timestamp, so runs are deterministic in tests.
type RunStore struct {
	root    string
	mu      sync.Mutex
	counter int
}

// NewRunStore returns a store rooted at root (created on first Create).
func NewRunStore(root string) *RunStore {
	return &RunStore{root: root}
}

// Root returns the store's root directory.
func (s *RunStore) Root() string { return s.root }

// Create validates the config, mints a traversal-safe run id from the election
// name + timestamp + a monotonic counter, creates the run folder, and writes
// run.json. Returns the run id and its directory.
func (s *RunStore) Create(c ElectionConfig, ts time.Time) (string, string, error) {
	if err := c.Validate(); err != nil {
		return "", "", err
	}
	s.mu.Lock()
	s.counter++
	counter := s.counter
	s.mu.Unlock()

	runID := fmt.Sprintf("%s-%s-%d", slugify(c.Name), ts.UTC().Format("20060102-150405"), counter)
	dir, err := s.Dir(runID)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("create run dir: %w", err)
	}
	rec := RunRecord{RunID: runID, Config: c, CreatedAt: ts.UTC()}
	if err := writeJSON(filepath.Join(dir, RunFile), rec); err != nil {
		return "", "", err
	}
	return runID, dir, nil
}

// Dir resolves a run id to its directory, rejecting anything that is not a
// simple allowlisted slug (defense against path traversal). No user string is
// ever interpolated into a path without passing this gate.
func (s *RunStore) Dir(runID string) (string, error) {
	if !runIDPattern.MatchString(runID) {
		return "", fmt.Errorf("invalid run id %q", runID)
	}
	dir := filepath.Join(s.root, runID)
	// Belt and suspenders: the joined path must be exactly root/<runID>.
	if rel, err := filepath.Rel(s.root, dir); err != nil || rel != runID {
		return "", fmt.Errorf("invalid run id %q", runID)
	}
	return dir, nil
}

// List returns every run's record, newest first.
func (s *RunStore) List() ([]RunRecord, error) {
	entries, err := os.ReadDir(s.root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var recs []RunRecord
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var rec RunRecord
		if err := readJSON(filepath.Join(s.root, e.Name(), RunFile), &rec); err != nil {
			continue // not a run folder (or unreadable) — skip
		}
		recs = append(recs, rec)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].CreatedAt.After(recs[j].CreatedAt) })
	return recs, nil
}

// slugify lowercases s and collapses every non-[a-z0-9] run to a single dash,
// trimmed and length-capped, so the result is always a valid run-id prefix.
func slugify(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 32 {
		out = strings.Trim(out[:32], "-")
	}
	if out == "" {
		out = "run"
	}
	return out
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
