package campaign

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Streaming access to a run's ballots.ndjson.
//
// The population is never loaded whole — at 1M voters the file is gigabytes,
// and every consumer here (CSV export, digest, on-chain submission) reads one
// line at a time under a 4 MiB per-line cap, the same bufio pattern check.go
// uses for the ground-truth table.
//
// A truncated or non-hex line is fatal and names its line number. Skipping it
// would read downstream as a clean undercount, which is exactly the silent
// failure the reconcile gate exists to prevent.

// BallotsFile is the run-folder-relative ndjson stream of hex-encoded ballots.
const BallotsFile = "ballots.ndjson"

// maxBallotLine caps one ballot line, matching MAX_BALLOT_LINE_BYTES in
// saksi-auditor/src/stream.rs.
const maxBallotLine = 4 * 1024 * 1024

func newBallotScanner(f *os.File) *bufio.Scanner {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 256*1024), maxBallotLine)
	return sc
}

// scanBallotLines calls fn(index, line) for every line of <dir>/ballots.ndjson
// in order, holding one line in memory at a time. Index and line number agree
// (the generator writes exactly one ballot per line), so a scanner error is
// reported against the line it stopped on.
func scanBallotLines(dir string, fn func(i int, line string) error) error {
	f, err := os.Open(filepath.Join(dir, BallotsFile))
	if err != nil {
		return err
	}
	defer f.Close()

	sc := newBallotScanner(f)
	i := 0
	for ; sc.Scan(); i++ {
		if err := fn(i, strings.TrimSpace(sc.Text())); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s line %d: %w", BallotsFile, i+1, err)
	}
	return nil
}

// isHexLine reports whether s is a non-empty, even-length run of hex digits —
// the wire form every ballot line must have.
func isHexLine(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func errBadBallotLine(lineNo int) error {
	return fmt.Errorf("%s line %d: truncated or non-hex ballot", BallotsFile, lineNo)
}

// validateBallots scans the whole stream and returns how many ballots it
// holds, aborting on the first truncated or non-hex line by number. Run before
// any ballot is submitted, so a corrupt file fails the run instead of
// committing a prefix of it.
func validateBallots(dir string) (int, error) {
	n := 0
	err := scanBallotLines(dir, func(i int, line string) error {
		if !isHexLine(line) {
			return errBadBallotLine(i + 1)
		}
		n++
		return nil
	})
	return n, err
}

// ballotReader hands out ballot lines BY INDEX while scanning the file exactly
// once. bench.Run dispatches indices in order but its workers arrive here out
// of order, so lines scanned past a caller's index are parked in ahead — at
// most one per in-flight worker, never the whole population.
type ballotReader struct {
	mu   sync.Mutex
	f    *os.File
	sc   *bufio.Scanner
	next int // index the scanner will produce on its next Scan
	// wanted reports whether index i will ever be asked for. Lines it rejects
	// are dropped instead of parked in ahead — a resume skips every already
	// committed index, and parking those would hold the whole committed
	// population in memory. nil = every line may be asked for.
	wanted func(i int) bool
	ahead  map[int]string
}

func openBallotReader(dir string) (*ballotReader, error) {
	f, err := os.Open(filepath.Join(dir, BallotsFile))
	if err != nil {
		return nil, err
	}
	return &ballotReader{f: f, sc: newBallotScanner(f), ahead: make(map[int]string)}, nil
}

// At returns the hex ballot at index i, io.EOF past the end of the stream, or
// an error naming the line number of a truncated / non-hex line. Each index
// may be requested only once.
func (r *ballotReader) At(i int) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if line, ok := r.ahead[i]; ok {
		delete(r.ahead, i)
		return line, nil
	}
	if i < r.next {
		return "", fmt.Errorf("%s index %d was already read", BallotsFile, i)
	}
	for {
		if !r.sc.Scan() {
			if err := r.sc.Err(); err != nil {
				return "", fmt.Errorf("%s line %d: %w", BallotsFile, r.next+1, err)
			}
			return "", io.EOF
		}
		line := strings.TrimSpace(r.sc.Text())
		idx := r.next
		r.next++
		if !isHexLine(line) {
			return "", errBadBallotLine(idx + 1)
		}
		if idx == i {
			return line, nil
		}
		if r.wanted == nil || r.wanted(idx) {
			r.ahead[idx] = line
		}
	}
}

func (r *ballotReader) Close() error { return r.f.Close() }
