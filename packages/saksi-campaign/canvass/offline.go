package canvass

// Offline replay engine for the canvass attack console: one generated
// election with a faked chain read-back (the generated ballots in nullifier
// order), signed precinct returns released one at a time, the attack hooks of
// balotachain's tools/security/canvass/mutate_return.py, an audit-canvass pass
// after every arrival, and assert_outcome.py's verdict at the end. It is the
// Go port of that folder's selftest.sh, at the console's fixture size. No
// Fabric and no HTTP: the console routes drive it.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FixtureArgs are the exact `saksi-demo gen` arguments of the console fixture
// (after `gen --stream <dir>`).
var FixtureArgs = []string{
	"--precincts", "10", "--voters", "1000", "--positions", "3", "--candidates", "4",
	"--trustees", "5", "--threshold", "3", "--distribution", "realistic", "--election-id", "cv-ui",
}

// FixtureMarker is written last into a fixture whose baseline canvass passed
// 7/7; a fixture without it (or with other arguments) is rebuilt.
const FixtureMarker = "fixture.json"

// signedReturn is where a precinct's signed return waits in the fixture until
// the attempt releases it as return.json (selftest.sh's hiding step).
const signedReturn = ".signed-return.json"

// closeTip is selftest.sh's fake close tip hash: "11" x 32.
var closeTip = strings.Repeat("11", 32)

// ArrivalDelay is the pause between two arrivals; tests set it to 0.
var ArrivalDelay = 600 * time.Millisecond

// Tool scripts, in the --canvass-tools folder.
const (
	mutateScript = "mutate_return.py"
	assertScript = "assert_outcome.py"
	sortScript   = "_sort_nullifier.py"
)

type fixtureMarker struct {
	Args      []string `json:"args"`
	Built     string   `json:"built"`
	Precincts []string `json:"precincts"`
	Baseline  string   `json:"baseline"`
}

// FixtureValid reports whether dir holds a finished fixture built with
// FixtureArgs: the marker, the registry and every precinct's signed return.
func FixtureValid(dir string) bool {
	var m fixtureMarker
	if err := readJSON(filepath.Join(dir, FixtureMarker), &m); err != nil {
		return false
	}
	if strings.Join(m.Args, " ") != strings.Join(FixtureArgs, " ") || len(m.Precincts) == 0 {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "national", "registry.json")); err != nil {
		return false
	}
	for _, f := range m.Precincts {
		if _, err := os.Stat(filepath.Join(dir, f, signedReturn)); err != nil {
			return false
		}
	}
	return true
}

// CheckTools reports a missing tool script in toolsDir, or python3 missing.
func CheckTools(toolsDir string) error {
	if toolsDir == "" {
		return errors.New("no canvass tools folder (--canvass-tools or SAKSI_CANVASS_TOOLS)")
	}
	for _, s := range []string{mutateScript, assertScript, sortScript} {
		if _, err := os.Stat(filepath.Join(toolsDir, s)); err != nil {
			return fmt.Errorf("canvass tools: %w", err)
		}
	}
	if _, err := exec.LookPath("python3"); err != nil {
		return fmt.Errorf("canvass tools need python3: %w", err)
	}
	return nil
}

// BuildFixture builds the offline canvass fixture into dir, or reuses dir when
// FixtureValid. It generates the election, fakes each precinct's ledger
// read-back and close.json, signs every return, runs the baseline canvass
// over all ten returns and refuses the fixture unless all seven checks pass.
// The returns are then hidden as precinct-NN/.signed-return.json and
// national/returns/ removed, so an attempt releases them one at a time. The
// build happens in <dir>.building and is renamed into place at the end.
func BuildFixture(ctx context.Context, dir, demoBin, toolsDir string, log io.Writer) error {
	if log == nil {
		log = io.Discard
	}
	if FixtureValid(dir) {
		fmt.Fprintf(log, "fixture: reusing %s\n", dir)
		return nil
	}
	if err := CheckTools(toolsDir); err != nil {
		return err
	}
	if demoBin == "" {
		return errors.New("no saksi-demo binary")
	}
	tmp := dir + ".building"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(tmp), 0o755); err != nil {
		return err
	}
	t0 := time.Now()
	fmt.Fprintf(log, "fixture: saksi-demo gen %s\n", strings.Join(FixtureArgs, " "))
	if out, err := runChild(ctx, nil, demoBin, append([]string{"gen", "--stream", tmp}, FixtureArgs...)...); err != nil {
		return fmt.Errorf("gen: %w (%.300s)", err, out)
	}
	folders, err := Precincts(tmp)
	if err != nil {
		return err
	}
	if len(folders) == 0 {
		return fmt.Errorf("gen wrote no precinct folders into %s", tmp)
	}
	for _, f := range folders {
		pdir := filepath.Join(tmp, f)
		if err := os.MkdirAll(filepath.Join(pdir, "ledger"), 0o755); err != nil {
			return err
		}
		ledger := filepath.Join(pdir, "ledger", "ballots.ndjson")
		if out, err := runChild(ctx, nil, "python3", filepath.Join(toolsDir, sortScript),
			filepath.Join(pdir, "ballots.ndjson"), ledger); err != nil {
			return fmt.Errorf("%s: sort ledger: %w (%.300s)", f, err, out)
		}
		n, _ := strconv.Atoi(precinctDir.FindStringSubmatch(f)[1])
		blk := 100 + n
		// Same bytes as selftest.sh's printf.
		closeJSON := fmt.Sprintf("{\"close_block\": %d, \"close_tip_hash\": \"%s\"}\n", blk, closeTip)
		if err := os.WriteFile(filepath.Join(pdir, "close.json"), []byte(closeJSON), 0o644); err != nil {
			return err
		}
		if out, err := runChild(ctx, nil, demoBin, "sign-return", pdir, "--ledger", ledger,
			"--close-block", strconv.Itoa(blk), "--tip-hash", closeTip,
			"--key", filepath.Join(pdir, "authority.key"),
			"--out", filepath.Join(pdir, "return.json")); err != nil {
			return fmt.Errorf("%s: sign-return: %w (%.300s)", f, err, out)
		}
	}
	returns := filepath.Join(tmp, "national", "returns")
	if err := os.MkdirAll(returns, 0o755); err != nil {
		return err
	}
	for _, f := range folders {
		if err := copyFile(filepath.Join(tmp, f, "return.json"), filepath.Join(returns, precinctID(f)+".json")); err != nil {
			return err
		}
	}
	out, _ := runChild(ctx, nil, demoBin, "audit-canvass", tmp, "--json", "--out", filepath.Join(tmp, "baseline"))
	var doc canvassDoc
	if err := json.Unmarshal(out, &doc); err != nil || doc.Pass == nil {
		return fmt.Errorf("baseline audit-canvass produced no verdict (%.300s)", out)
	}
	passed := 0
	var failed []string
	for _, c := range doc.Checks {
		if c.Verdict == "pass" {
			passed++
		} else {
			failed = append(failed, c.Check+": "+c.Reason)
		}
	}
	if !*doc.Pass || passed != len(CanvassChecks) || len(doc.Checks) != len(CanvassChecks) {
		return fmt.Errorf("baseline canvass passed %d/%d checks; fixture refused: %s", passed, len(CanvassChecks), strings.Join(failed, "; "))
	}
	fmt.Fprintf(log, "fixture: baseline canvass 7/7 pass\n")
	if err := os.RemoveAll(returns); err != nil {
		return err
	}
	for _, f := range folders {
		if err := os.Rename(filepath.Join(tmp, f, "return.json"), filepath.Join(tmp, f, signedReturn)); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(tmp, FixtureMarker), fixtureMarker{
		Args: FixtureArgs, Built: time.Now().UTC().Format(time.RFC3339), Precincts: folders, Baseline: "7/7 pass",
	}); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.Rename(tmp, dir); err != nil {
		return err
	}
	fmt.Fprintf(log, "fixture: built %s in %d ms\n", dir, time.Since(t0).Milliseconds())
	return nil
}

// CanvassChecks are audit-canvass's seven check ids, in its order.
var CanvassChecks = []string{
	"canvass.registry",
	"canvass.completeness",
	"canvass.signature",
	"canvass.precinct_recompute",
	"canvass.national_sum",
	"canvass.accuracy",
	"canvass.nullifier_unique",
}

// Event types.
const (
	EventStart    = "start"    // attempt folder ready, every tile waiting
	EventArrival  = "arrival"  // one precinct's turn: released, hooked, canvassed
	EventNational = "national" // the national hook ran (before the final canvass)
	EventFinal    = "final"    // final canvass and verdict
	EventError    = "error"    // the attempt could not complete
)

// Event is one step of an attempt, JSON-serialisable for the SSE stream.
type Event struct {
	Type     string `json:"type"`
	Attempt  int    `json:"attempt"`
	Scenario string `json:"scenario"`
	// Seq is the arrival number (1..N) on arrival events.
	Seq int `json:"seq,omitempty"`
	// Precinct is the arriving precinct (pNN) on arrival events.
	Precinct string `json:"precinct,omitempty"`
	// Delivered is false when the return never reached national/returns (T13).
	Delivered *bool `json:"delivered,omitempty"`
	// Hook is the attack hook's output lines ([MOUNTED] / [skip]).
	Hook  []string `json:"hook,omitempty"`
	Tiles []Tile   `json:"tiles,omitempty"`
	// Checks are the canvass checks after this step (arrival and final).
	Checks    []CheckResult `json:"checks,omitempty"`
	Final     *Final        `json:"final,omitempty"`
	Error     string        `json:"error,omitempty"`
	ElapsedMs int64         `json:"elapsed_ms"`
}

// Final is the verdict of an attempt.
type Final struct {
	Checks   []CheckResult `json:"checks"`
	Pass     bool          `json:"pass"`
	Expected []string      `json:"expected"`
	Got      []string      `json:"got"`
	// Verdict is assert_outcome.py's PASS/FAIL (for clean: PASS when no
	// check failed, judged here since assert_outcome.py has no clean row).
	Verdict string `json:"verdict"`
	// Assert is assert_outcome.py's printed line.
	Assert string `json:"assert,omitempty"`
	// Mounted is false when an attack never printed [MOUNTED] (FAIL).
	Mounted bool `json:"mounted"`
}

// AttemptResult is what RunAttempt returns and writes as attempt.json.
type AttemptResult struct {
	N         int    `json:"n"`
	Scenario  string `json:"scenario"`
	Dir       string `json:"dir"`
	Started   string `json:"started"`
	ElapsedMs int64  `json:"elapsed_ms"`
	Tiles     []Tile `json:"tiles"`
	Final     *Final `json:"final,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Attempt folder files.
const (
	AttemptFile = "attempt.json"
	EventsFile  = "events.ndjson"
)

var attemptName = regexp.MustCompile(`^(\d+)-`)

// NextAttempt is one more than the highest <n>-<id> folder in attemptsDir.
func NextAttempt(attemptsDir string) (int, error) {
	entries, err := os.ReadDir(attemptsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	max := 0
	for _, e := range entries {
		if m := attemptName.FindStringSubmatch(e.Name()); m != nil && e.IsDir() {
			if n, _ := strconv.Atoi(m[1]); n > max {
				max = n
			}
		}
	}
	return max + 1, nil
}

// RunAttempt replays one scenario over a copy of the fixture in
// attemptsDir/<n>-<scenario>/ and calls emit (may be nil) for every event.
// Precincts are released in order: the signed return becomes return.json,
// the return hook runs (attack scenarios), the return is copied to
// national/returns/pNN.json unless the hook removed it, audit-canvass runs
// over what has arrived, and an arrival event carries the tiles. After the
// last precinct the national hook runs, the final canvass, and
// assert_outcome.py judges the failed-check set. Callers serialise attempts.
func RunAttempt(ctx context.Context, fixtureDir, attemptsDir, demoBin, toolsDir, scenario string, emit func(Event)) (*AttemptResult, error) {
	sc, ok := LookupScenario(scenario)
	if !ok {
		return nil, fmt.Errorf("unknown scenario %q", scenario)
	}
	if !sc.Live {
		return nil, fmt.Errorf("scenario %s needs Fabric and runs only on chain (%s)", sc.ID, RecordedNote)
	}
	if !FixtureValid(fixtureDir) {
		return nil, fmt.Errorf("no valid fixture in %s; build it first", fixtureDir)
	}
	if err := CheckTools(toolsDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(attemptsDir, 0o755); err != nil {
		return nil, err
	}
	n, err := NextAttempt(attemptsDir)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(attemptsDir, fmt.Sprintf("%d-%s", n, sc.ID))
	if err := os.Mkdir(dir, 0o755); err != nil {
		return nil, err
	}
	a := &attempt{sc: sc, n: n, dir: dir, demo: demoBin, tools: toolsDir, start: time.Now(), user: emit}
	res := &AttemptResult{N: n, Scenario: sc.ID, Dir: dir, Started: a.start.UTC().Format(time.RFC3339)}
	ev, err := a.events()
	if err == nil {
		defer ev.Close()
		a.log = ev
		err = a.run(ctx, fixtureDir, res)
	}
	if err != nil {
		res.Error = err.Error()
		a.emit(Event{Type: EventError, Error: err.Error()})
	}
	res.ElapsedMs = time.Since(a.start).Milliseconds()
	if werr := writeJSON(filepath.Join(dir, AttemptFile), res); werr != nil && err == nil {
		err = werr
	}
	return res, err
}

type attempt struct {
	sc        Scenario
	n         int
	dir, demo string
	tools     string
	start     time.Time
	user      func(Event)
	log       io.Writer
	mounted   bool
	precincts []string // pNN in arrival order
}

func (a *attempt) events() (*os.File, error) {
	return os.Create(filepath.Join(a.dir, EventsFile))
}

func (a *attempt) emit(e Event) {
	e.Attempt, e.Scenario = a.n, a.sc.ID
	e.ElapsedMs = time.Since(a.start).Milliseconds()
	if a.log != nil {
		if raw, err := json.Marshal(e); err == nil {
			a.log.Write(append(raw, '\n'))
		}
	}
	if a.user != nil {
		a.user(e)
	}
}

func (a *attempt) run(ctx context.Context, fixtureDir string, res *AttemptResult) error {
	if err := copyTree(fixtureDir, a.dir); err != nil {
		return fmt.Errorf("copy fixture: %w", err)
	}
	national := filepath.Join(a.dir, "national")
	returns := filepath.Join(national, "returns")
	if err := os.RemoveAll(returns); err != nil {
		return err
	}
	if err := os.MkdirAll(returns, 0o755); err != nil {
		return err
	}
	folders, err := Precincts(a.dir)
	if err != nil {
		return err
	}
	for _, f := range folders {
		a.precincts = append(a.precincts, precinctID(f))
	}
	waiting := make([]Tile, 0, len(a.precincts))
	for _, p := range a.precincts {
		waiting = append(waiting, Tile{Precinct: p, State: TileWaiting, Checks: []string{}, Reasons: []string{}})
	}
	res.Tiles = waiting
	a.emit(Event{Type: EventStart, Tiles: waiting})

	// Arrivals are ArrivalDelay apart, counted from the previous arrival's
	// start: the canvass after an arrival overlaps the wait, not adds to it.
	var last time.Time
	for i, f := range folders {
		if wait := ArrivalDelay - time.Since(last); i > 0 && wait > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		last = time.Now()
		pid := precinctID(f)
		pdir := filepath.Join(a.dir, f)
		ret := filepath.Join(pdir, "return.json")
		if err := os.Rename(filepath.Join(pdir, signedReturn), ret); err != nil {
			return fmt.Errorf("%s: release return: %w", f, err)
		}
		var hook []string
		if a.sc.attack != "" {
			hook, err = a.hook(ctx, "return", pdir, ret, national)
			if err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
		}
		delivered := false
		if _, err := os.Stat(ret); err == nil {
			if err := copyFile(ret, filepath.Join(returns, pid+".json")); err != nil {
				return err
			}
			delivered = true
		}
		doc, tiles, err := a.canvass(ctx, i+1)
		if err != nil {
			return fmt.Errorf("after %s: %w", pid, err)
		}
		res.Tiles = tiles
		d := delivered
		a.emit(Event{Type: EventArrival, Seq: i + 1, Precinct: pid, Delivered: &d, Hook: hook, Tiles: tiles, Checks: doc.Checks})
	}

	if a.sc.attack != "" {
		hook, err := a.hook(ctx, "national", national)
		if err != nil {
			return err
		}
		a.emit(Event{Type: EventNational, Hook: hook})
	}
	doc, tiles, err := a.canvass(ctx, len(folders))
	if err != nil {
		return fmt.Errorf("final canvass: %w", err)
	}
	res.Tiles = tiles
	final, err := a.verdict(ctx, doc)
	if err != nil {
		return err
	}
	res.Final = final
	a.emit(Event{Type: EventFinal, Tiles: tiles, Checks: doc.Checks, Final: final})
	return nil
}

// hook runs mutate_return.py the way canvass.go's script() runs an attack
// hook: SAKSI_HOOK and SAKSI_ATTACK in the environment, the documented
// positional arguments, plus --scenario (the script's own selector).
func (a *attempt) hook(ctx context.Context, name string, args ...string) ([]string, error) {
	env := []string{"SAKSI_HOOK=" + name, "SAKSI_ATTACK=" + a.sc.attack, "SAKSI_DEMO=" + a.demo}
	if a.sc.t14 != "" {
		env = append(env, "CANVASS_T14="+a.sc.t14)
	}
	argv := append([]string{filepath.Join(a.tools, mutateScript), "--scenario", a.sc.attack}, args...)
	out, err := runChild(ctx, env, "python3", argv...)
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" {
			continue
		}
		lines = append(lines, l)
		if strings.HasPrefix(l, "[MOUNTED] "+a.sc.attack+" ") {
			a.mounted = true
		}
	}
	if err != nil {
		return lines, fmt.Errorf("%s hook: %w", name, err)
	}
	return lines, nil
}

// canvass runs audit-canvass over the attempt folder and attributes the
// result. Precincts after the first `arrived` are still waiting.
func (a *attempt) canvass(ctx context.Context, arrived int) (canvassDoc, []Tile, error) {
	var doc canvassDoc
	out, runErr := runChild(ctx, nil, a.demo, "audit-canvass", a.dir, "--json", "--out", a.dir)
	if err := json.Unmarshal(out, &doc); err != nil || doc.Pass == nil {
		return doc, nil, fmt.Errorf("audit-canvass produced no verdict: %v (%.300s)", runErr, out)
	}
	entries, err := os.ReadDir(filepath.Join(a.dir, "national", "returns"))
	if err != nil {
		return doc, nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	tiles, err := Attribute(out, names)
	if err != nil {
		return doc, nil, err
	}
	pending := map[string]bool{}
	for _, p := range a.precincts[arrived:] {
		pending[p] = true
	}
	for i := range tiles {
		if pending[tiles[i].Precinct] && tiles[i].State == TileMissing {
			tiles[i].State = TileWaiting
		}
	}
	return doc, tiles, nil
}

var assertLine = regexp.MustCompile(`^(PASS|FAIL|ERROR) `)

// verdict judges the final canvass: assert_outcome.py for an attack (its own
// scenario id: T14a/T14b stay as they are), set equality here for clean.
func (a *attempt) verdict(ctx context.Context, doc canvassDoc) (*Final, error) {
	f := &Final{Checks: doc.Checks, Pass: *doc.Pass, Expected: a.sc.Expected, Got: []string{}, Mounted: a.mounted}
	for _, c := range doc.Checks {
		if c.Verdict != "pass" {
			f.Got = append(f.Got, c.Check)
		}
	}
	if a.sc.attack == "" {
		f.Mounted = true
		f.Verdict = "FAIL"
		if len(f.Got) == 0 && f.Pass {
			f.Verdict = "PASS"
		}
		f.Assert = fmt.Sprintf("%s clean: expected [] got [%s]", f.Verdict, strings.Join(f.Got, ","))
		return f, nil
	}
	out, err := runChild(ctx, nil, "python3", filepath.Join(a.tools, assertScript), a.sc.ID,
		filepath.Join(a.dir, "canvass-checks.csv"), "--out", filepath.Join(a.dir, "negative-tests-canvass.csv"))
	line := strings.TrimSpace(string(out))
	m := assertLine.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("assert_outcome.py gave no verdict: %v (%.300s)", err, line)
	}
	f.Assert, f.Verdict = line, m[1]
	if !a.mounted {
		f.Verdict = "FAIL"
		f.Assert += " (never mounted: only [skip] lines)"
	}
	return f, nil
}

// runChild runs a child with extra environment entries. Inherited CANVASS_*
// and SAKSI_HOOK/SAKSI_ATTACK variables are dropped so a target override in
// the console's own environment never changes a scenario. stdout is returned
// even on a non-zero exit; stderr is folded into the error.
func runChild(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	base := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "CANVASS_") || strings.HasPrefix(kv, "SAKSI_HOOK=") || strings.HasPrefix(kv, "SAKSI_ATTACK=") {
			continue
		}
		base = append(base, kv)
	}
	cmd.Env = append(base, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%s: %w: %s", filepath.Base(name), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// copyTree copies the fixture into dst, leaving out the build marker, the
// baseline canvass and any national/returns.
func copyTree(src, dst string) error {
	skip := map[string]bool{FixtureMarker: true, "baseline": true, filepath.Join("national", "returns"): true}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if skip[rel] {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, raw, 0o644)
}
