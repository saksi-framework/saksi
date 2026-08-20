package campaign

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateWritesRunJSON(t *testing.T) {
	root := t.TempDir()
	s := NewRunStore(root)
	ts := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	runID, dir, err := s.Create(good(), ts)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !runIDPattern.MatchString(runID) {
		t.Fatalf("run id %q is not a safe slug", runID)
	}
	if _, err := os.Stat(filepath.Join(dir, RunFile)); err != nil {
		t.Fatalf("run.json not written: %v", err)
	}

	// The record round-trips.
	var rec RunRecord
	if err := readJSON(filepath.Join(dir, RunFile), &rec); err != nil {
		t.Fatalf("read run.json: %v", err)
	}
	if rec.RunID != runID || rec.Config.Name != "midterm" {
		t.Fatalf("unexpected record: %+v", rec)
	}
}

func TestCreateRejectsInvalidConfig(t *testing.T) {
	s := NewRunStore(t.TempDir())
	bad := good()
	bad.Threshold = 99
	if _, _, err := s.Create(bad, time.Now()); err == nil {
		t.Fatal("Create must reject an invalid config")
	}
}

func TestDirRejectsTraversal(t *testing.T) {
	s := NewRunStore(t.TempDir())
	for _, bad := range []string{"../etc", "..", "a/b", "/abs", "foo/../bar", "UPPER", ".hidden"} {
		if _, err := s.Dir(bad); err == nil {
			t.Fatalf("Dir(%q) should be rejected", bad)
		}
	}
	// A well-formed id resolves under root.
	dir, err := s.Dir("midterm-20260819-120000-1")
	if err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	if filepath.Dir(dir) != s.Root() {
		t.Fatalf("resolved dir %q not under root %q", dir, s.Root())
	}
}

func TestListNewestFirst(t *testing.T) {
	s := NewRunStore(t.TempDir())
	base := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	_, _, _ = s.Create(good(), base)                  // oldest
	_, _, _ = s.Create(good(), base.Add(2*time.Hour)) // newest
	_, _, _ = s.Create(good(), base.Add(1*time.Hour)) // middle

	recs, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("expected 3 runs, got %d", len(recs))
	}
	if !recs[0].CreatedAt.After(recs[1].CreatedAt) || !recs[1].CreatedAt.After(recs[2].CreatedAt) {
		t.Fatalf("runs not newest-first: %v %v %v",
			recs[0].CreatedAt, recs[1].CreatedAt, recs[2].CreatedAt)
	}
}

func TestListEmptyStore(t *testing.T) {
	s := NewRunStore(filepath.Join(t.TempDir(), "does-not-exist-yet"))
	recs, err := s.List()
	if err != nil {
		t.Fatalf("List on empty store: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("expected no runs, got %d", len(recs))
	}
}
