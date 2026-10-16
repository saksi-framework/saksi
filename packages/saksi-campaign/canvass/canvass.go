// Package canvass drives the precinct-to-national smoke demonstration: every
// precinct-NN folder of one `saksi-demo gen --stream <dir> --precincts N` pass
// runs the console's on-chain lifecycle in turn on one channel, signs a
// precinct return over its ledger read-back, transmits it to the national
// folder, and then the national canvass (`saksi-demo audit-canvass`) runs over
// all of them.
//
// Every network call goes through Chain and every child process through
// Runner, so the sequence, the folder layout and the exit-code logic are
// testable without Fabric or the Rust binary.
package canvass

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Chain is the per-precinct on-chain work. The production implementation is
// campaign.Executor's precinct seam (PrecinctLifecycle, PrecinctVerify,
// PrecinctChainInfo); folder is the precinct-NN folder name.
type Chain interface {
	// Lifecycle runs CreateElection through PublishTally, calling beforeClose
	// after the ballot window and before CloseElection.
	Lifecycle(ctx context.Context, folder string, beforeClose func(context.Context) error) error
	// Verify dumps the chain's record into <folder>/ledger/ and audits it,
	// returning the precinct's local audit verdict ("pass" or "fail").
	Verify(ctx context.Context, folder string) (string, error)
	// ChainInfo is the channel height (ChainInfo.Height) and tip block hash.
	ChainInfo(ctx context.Context) (uint64, []byte, error)
}

// Runner runs a child process with extra environment entries and returns its
// stdout. On a non-zero exit it returns stdout AND an error.
type Runner func(ctx context.Context, env []string, name string, args ...string) ([]byte, error)

// Options configures one driver run.
type Options struct {
	Dir     string // generator output: precinct-NN/ folders and national/
	Out     string // where canvass-run.json, canvass.json and canvass-checks.csv go
	DemoBin string // saksi-demo
	// Attack names the attack this run mounts (Task 5). Empty = clean run.
	Attack string
	// AttackScript runs after each return is built and before it is copied
	// to national/returns/, and once more after every precinct, before the
	// canvass. PreCloseScript runs inside each lifecycle after the ballots
	// and before CloseElection. Each is a command line split on spaces.
	AttackScript   string
	PreCloseScript string
	Chain          Chain
	Run            Runner
	Log            io.Writer
}

// Exit codes.
const (
	ExitPass  = 0 // canvass passed; or an attack run finished, whatever the verdict
	ExitFail  = 1 // clean run whose canvass failed a check
	ExitError = 2 // the run itself could not complete
)

// RunFile is the driver's own record of the run.
const RunFile = "canvass-run.json"

// PrecinctRow is one precinct's record in canvass-run.json.
type PrecinctRow struct {
	PrecinctID string `json:"precinct_id"`
	Folder     string `json:"folder"`
	ElectionID string `json:"election_id"`
	// Wall times, in milliseconds. PrecinctWindowMs spans the whole precinct
	// (lifecycle start to return transmitted). CloseToReturnMs starts when
	// CloseElection is dispatched and ends when sign-return has written the
	// return: close, partials, tally, ledger dump and audit, ChainInfo, sign.
	PrecinctWindowMs int64  `json:"precinct_window_ms"`
	LifecycleMs      int64  `json:"lifecycle_ms"`
	VerifyMs         int64  `json:"verify_ms"`
	SignMs           int64  `json:"sign_ms"`
	CloseToReturnMs  int64  `json:"close_to_return_ms"`
	Audit            string `json:"audit"`
	CloseBlock       uint64 `json:"close_block"`
	CloseTipHash     string `json:"close_tip_hash"`
	// Records and Verified are sign-return's own count of the ledger
	// read-back. sign-return exits 0 when some records fail verification, so
	// the gap is recorded here rather than inferred from its exit code.
	Records  int  `json:"records"`
	Verified int  `json:"verified"`
	Copied   bool `json:"copied_to_national"`
	// SubmitMetrics is the ballot window's submit-metrics.json verbatim
	// (window, committed TPS, latency percentiles), the same figures perf.csv
	// carries.
	SubmitMetrics json.RawMessage `json:"submit_metrics,omitempty"`
}

// RunRecord is canvass-run.json.
type RunRecord struct {
	Dir          string          `json:"dir"`
	Attack       string          `json:"attack,omitempty"`
	Started      string          `json:"started"`
	Precincts    []PrecinctRow   `json:"precincts"`
	CanvassMs    int64           `json:"canvass_ms"`
	TotalMs      int64           `json:"total_ms"`
	Canvass      json.RawMessage `json:"canvass,omitempty"` // canvass.json verbatim
	CanvassPass  *bool           `json:"canvass_pass,omitempty"`
	FailedChecks []string        `json:"failed_checks"`
	ExitCode     int             `json:"exit_code"`
	Error        string          `json:"error,omitempty"`
}

var precinctDir = regexp.MustCompile(`^precinct-(\d{2,})$`)

// Precincts lists the precinct-NN folders of dir in name order. Folders are
// matched by name only: national/ also holds a header.json and is not a run.
func Precincts(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && precinctDir.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// precinctID maps precinct-NN to pNN, the id in registry.json.
func precinctID(folder string) string { return "p" + precinctDir.FindStringSubmatch(folder)[1] }

// Run drives the whole demonstration and returns the process exit code. The
// error, when non-nil, is why the run could not complete (ExitError).
func Run(ctx context.Context, o Options) (int, error) {
	if o.Out == "" {
		o.Out = o.Dir
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	if err := os.MkdirAll(o.Out, 0o755); err != nil {
		return ExitError, err
	}
	start := time.Now()
	rec := RunRecord{Dir: o.Dir, Attack: o.Attack, Started: start.UTC().Format(time.RFC3339), FailedChecks: []string{}}
	code, err := run(ctx, o, &rec)
	if err != nil {
		code = ExitError
		rec.Error = err.Error()
	}
	rec.ExitCode = code
	rec.TotalMs = time.Since(start).Milliseconds()
	if werr := writeJSON(filepath.Join(o.Out, RunFile), rec); werr != nil && err == nil {
		return ExitError, werr
	}
	return code, err
}

func run(ctx context.Context, o Options, rec *RunRecord) (int, error) {
	national := filepath.Join(o.Dir, "national")
	// registry.json is the generator's last write: without it the pass did
	// not finish and the precinct folders cannot be trusted.
	if _, err := os.Stat(filepath.Join(national, "registry.json")); err != nil {
		return ExitError, fmt.Errorf("%s has no national/registry.json (unfinished generation?): %w", o.Dir, err)
	}
	returns := filepath.Join(national, "returns")
	if existing, _ := filepath.Glob(filepath.Join(returns, "*.json")); len(existing) > 0 {
		return ExitError, fmt.Errorf("%s already holds returns: this generation was already driven; regenerate it", returns)
	}
	if err := os.MkdirAll(returns, 0o755); err != nil {
		return ExitError, err
	}
	folders, err := Precincts(o.Dir)
	if err != nil {
		return ExitError, err
	}
	if len(folders) == 0 {
		return ExitError, fmt.Errorf("%s holds no precinct-NN folders", o.Dir)
	}
	for _, f := range folders {
		row, err := o.precinct(ctx, f, national)
		rec.Precincts = append(rec.Precincts, row)
		if err != nil {
			return ExitError, fmt.Errorf("%s: %w", f, err)
		}
	}
	if o.AttackScript != "" {
		if err := o.script(ctx, o.AttackScript, "national", national); err != nil {
			return ExitError, err
		}
	}

	fmt.Fprintf(o.Log, "national canvass over %d precincts…\n", len(folders))
	t := time.Now()
	out, runErr := o.Run(ctx, nil, o.DemoBin, "audit-canvass", o.Dir, "--json", "--out", o.Out)
	rec.CanvassMs = time.Since(t).Milliseconds()
	var doc struct {
		Pass   *bool `json:"pass"`
		Checks []struct {
			Check   string `json:"check"`
			Verdict string `json:"verdict"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(out, &doc); err != nil || doc.Pass == nil {
		return ExitError, fmt.Errorf("audit-canvass produced no verdict: %v (output: %.200s)", runErr, out)
	}
	rec.Canvass = json.RawMessage(out)
	rec.CanvassPass = doc.Pass
	for _, c := range doc.Checks {
		if c.Verdict != "pass" {
			rec.FailedChecks = append(rec.FailedChecks, c.Check)
		}
	}
	verdict := "PASS"
	if !*doc.Pass {
		verdict = "FAIL (" + strings.Join(rec.FailedChecks, ", ") + ")"
	}
	fmt.Fprintf(o.Log, "canvass %s in %d ms\n", verdict, rec.CanvassMs)
	switch {
	case o.Attack != "" && *doc.Pass:
		fmt.Fprintf(o.Log, "WARNING: attack %s was not detected by the canvass\n", o.Attack)
		return ExitPass, nil
	case o.Attack != "":
		return ExitPass, nil
	case !*doc.Pass:
		return ExitFail, nil
	}
	return ExitPass, nil
}

// precinct runs one precinct end to end and transmits its return.
func (o Options) precinct(ctx context.Context, folder, national string) (PrecinctRow, error) {
	pdir := filepath.Join(o.Dir, folder)
	row := PrecinctRow{PrecinctID: precinctID(folder), Folder: folder}
	var h struct {
		ElectionID string `json:"election_id"`
	}
	if err := readJSON(filepath.Join(pdir, "header.json"), &h); err != nil {
		return row, err
	}
	row.ElectionID = h.ElectionID
	fmt.Fprintf(o.Log, "%s (%s): lifecycle…\n", folder, h.ElectionID)

	t0 := time.Now()
	var closeAt time.Time
	beforeClose := func(ctx context.Context) error {
		if o.PreCloseScript != "" {
			if err := o.script(ctx, o.PreCloseScript, "pre-close", pdir, h.ElectionID); err != nil {
				return err
			}
		}
		closeAt = time.Now()
		return nil
	}
	if err := o.Chain.Lifecycle(ctx, folder, beforeClose); err != nil {
		return row, fmt.Errorf("lifecycle: %w", err)
	}
	row.LifecycleMs = time.Since(t0).Milliseconds()
	if raw, err := os.ReadFile(filepath.Join(pdir, "submit-metrics.json")); err == nil && json.Valid(raw) {
		row.SubmitMetrics = raw
	}

	t := time.Now()
	audit, err := o.Chain.Verify(ctx, folder)
	row.VerifyMs = time.Since(t).Milliseconds()
	row.Audit = audit
	if err != nil {
		return row, fmt.Errorf("verify: %w", err)
	}
	ledger := filepath.Join(pdir, "ledger", "ballots.ndjson")
	if _, err := os.Stat(ledger); err != nil {
		return row, fmt.Errorf("no ledger dump (the chain read-back failed; see journal.ndjson): %w", err)
	}

	height, tip, err := o.Chain.ChainInfo(ctx)
	if err != nil {
		return row, fmt.Errorf("chain info: %w", err)
	}
	row.CloseBlock, row.CloseTipHash = height, hex.EncodeToString(tip)
	if err := writeJSON(filepath.Join(pdir, "close.json"), map[string]any{
		"close_block": row.CloseBlock, "close_tip_hash": row.CloseTipHash,
	}); err != nil {
		return row, err
	}

	t = time.Now()
	retPath := filepath.Join(pdir, "return.json")
	out, err := o.Run(ctx, nil, o.DemoBin, "sign-return", pdir,
		"--ledger", ledger,
		"--close-block", strconv.FormatUint(height, 10),
		"--tip-hash", row.CloseTipHash,
		"--key", filepath.Join(pdir, "authority.key"),
		"--out", retPath)
	row.SignMs = time.Since(t).Milliseconds()
	if !closeAt.IsZero() {
		row.CloseToReturnMs = time.Since(closeAt).Milliseconds()
	}
	if err != nil {
		return row, fmt.Errorf("sign-return: %w", err)
	}
	row.Records, row.Verified = signedCounts(string(out))
	note := ""
	if row.Verified != row.Records {
		note = " — NOT every record verified"
	}
	fmt.Fprintf(o.Log, "%s: return built, %d records, %d verified%s\n", folder, row.Records, row.Verified, note)

	if o.AttackScript != "" {
		if err := o.script(ctx, o.AttackScript, "return", pdir, retPath, national); err != nil {
			return row, err
		}
	}
	// An attack script that removed the return dropped it on the path (T13).
	if raw, err := os.ReadFile(retPath); err == nil {
		dst := filepath.Join(national, "returns", row.PrecinctID+".json")
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			return row, err
		}
		row.Copied = true
	} else if errors.Is(err, os.ErrNotExist) && o.AttackScript != "" {
		fmt.Fprintf(o.Log, "%s: return removed by the attack script, not transmitted\n", folder)
	} else {
		return row, fmt.Errorf("read return: %w", err)
	}
	row.PrecinctWindowMs = time.Since(t0).Milliseconds()
	return row, nil
}

var signedLine = regexp.MustCompile(`: (\d+) records \((\d+) verified\)`)

// signedCounts reads sign-return's "N records (V verified)" summary; -1 when
// the line is missing.
func signedCounts(out string) (records, verified int) {
	m := signedLine.FindStringSubmatch(out)
	if m == nil {
		return -1, -1
	}
	records, _ = strconv.Atoi(m[1])
	verified, _ = strconv.Atoi(m[2])
	return records, verified
}

// script runs an attack hook. The hook name and the attack id travel in the
// environment (SAKSI_HOOK, SAKSI_ATTACK) so the positional arguments stay the
// documented ones. A hook that exits non-zero stops the run.
func (o Options) script(ctx context.Context, cmdline, hook string, args ...string) error {
	parts := strings.Fields(cmdline)
	env := []string{"SAKSI_HOOK=" + hook, "SAKSI_ATTACK=" + o.Attack}
	out, err := o.Run(ctx, env, parts[0], append(parts[1:], args...)...)
	if len(out) > 0 {
		fmt.Fprintf(o.Log, "[%s hook] %s\n", hook, strings.TrimSpace(string(out)))
	}
	if err != nil {
		return fmt.Errorf("%s hook: %w", hook, err)
	}
	return nil
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
