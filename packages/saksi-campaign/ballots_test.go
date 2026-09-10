package campaign

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLines(t *testing.T, dir string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, BallotsFile),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestBallotReaderAbortsOnNonHexLine: At() must refuse the corrupt line by
// number rather than hand back something that would be submitted as a ballot.
func TestBallotReaderAbortsOnNonHexLine(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, dir, "aabb", "ccdd", "zz", "eeff")
	r, err := openBallotReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	for _, i := range []int{0, 1} {
		if _, err := r.At(i); err != nil {
			t.Fatalf("At(%d): %v", i, err)
		}
	}
	_, err = r.At(2)
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("At(2) must abort naming line 3, got: %v", err)
	}
}

// TestBallotReaderRejectsRereadingAnIndex: the reader scans forward once, so a
// second request for an index it already handed out is a bug in the caller,
// not a silently different ballot.
func TestBallotReaderRejectsRereadingAnIndex(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, dir, "aabb", "ccdd")
	r, err := openBallotReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if line, err := r.At(0); err != nil || line != "aabb" {
		t.Fatalf("At(0) = %q, %v", line, err)
	}
	if _, err := r.At(0); err == nil || !strings.Contains(err.Error(), "already read") {
		t.Fatalf("re-reading index 0 must be an error, got: %v", err)
	}
	// Out-of-order access still works: index 1 was never taken.
	if line, err := r.At(1); err != nil || line != "ccdd" {
		t.Fatalf("At(1) = %q, %v", line, err)
	}
	if _, err := r.At(2); !errors.Is(err, io.EOF) {
		t.Fatalf("past the end must be io.EOF, got: %v", err)
	}
}
