package canvass

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeWorld is the fake chain and the fake child processes in one, so the
// test can read the whole run as one ordered event log.
type fakeWorld struct {
	t        *testing.T
	dir      string
	mu       sync.Mutex
	events   []string
	height   uint64
	pass     bool // audit-canvass verdict
	failOn   string
	replayed bool // a pre-tally replay committed, so PublishTally is refused
	verified int  // what sign-return reports verified (3 records)
	// onScript, when set, runs for each attack-hook call (hook, args).
	onScript func(hook string, args []string)
}

func (w *fakeWorld) log(format string, a ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, fmt.Sprintf(format, a...))
}

func (w *fakeWorld) Lifecycle(ctx context.Context, folder string, h Hooks) (string, error) {
	w.log("lifecycle %s", folder)
	if w.failOn == "lifecycle" {
		return "", errors.New("peer gone")
	}
	if err := h.BeforeClose(ctx); err != nil {
		return "", err
	}
	w.log("close %s", folder)
	w.log("partials %s", folder)
	if h.BeforeTally != nil {
		if err := h.BeforeTally(ctx); err != nil {
			return "", err
		}
	}
	w.log("tally %s", folder)
	// A replayed tally committed first: the precinct's own one is refused.
	if w.replayed && h.BeforeTally != nil {
		if !h.TolerateTallyRefusal {
			return "", errors.New("PublishTally: tally already published")
		}
		return "refused: PublishTally: tally already published", nil
	}
	return "published", nil
}

func (w *fakeWorld) Verify(_ context.Context, folder string) (string, error) {
	w.log("verify %s", folder)
	if w.failOn == "dump" {
		return "pass", nil // the dump failed silently ("not run"): no ledger/ written
	}
	led := filepath.Join(w.dir, folder, "ledger")
	if err := os.MkdirAll(led, 0o755); err != nil {
		return "", err
	}
	return "pass", os.WriteFile(filepath.Join(led, "ballots.ndjson"), []byte("aa\nbb\ncc\n"), 0o644)
}

func (w *fakeWorld) ChainInfo(context.Context) (uint64, []byte, error) {
	w.mu.Lock()
	w.height++
	h := w.height
	w.mu.Unlock()
	w.log("chaininfo")
	return h, bytes.Repeat([]byte{byte(h)}, 32), nil
}

func (w *fakeWorld) run(_ context.Context, env []string, name string, args ...string) ([]byte, error) {
	if name != "saksi-demo" {
		hook := strings.TrimPrefix(env[0], "SAKSI_HOOK=")
		w.log("script %s %s [%s] %s", name, hook, env[1], strings.Join(args, " "))
		if w.onScript != nil {
			w.onScript(hook, args)
		}
		return nil, nil
	}
	switch args[0] {
	case "sign-return":
		pdir := args[1]
		w.log("sign-return %s", strings.Join(args[1:], " "))
		out := argAfter(args, "--out")
		ret := fmt.Sprintf(`{"precinct_id":"%s"}`, filepath.Base(pdir))
		if err := os.WriteFile(out, []byte(ret), 0o644); err != nil {
			return nil, err
		}
		return []byte(fmt.Sprintf("signed return e p: 3 records (%d verified), digest ab -> %s\n", w.verified, out)), nil
	case "audit-canvass":
		w.log("audit-canvass %s", strings.Join(args[1:], " "))
		if w.pass {
			return []byte(`{"pass":true,"checks":[{"check":"canvass.registry","verdict":"pass","reason":""}]}`), nil
		}
		return []byte(`{"pass":false,"checks":[{"check":"canvass.registry","verdict":"pass","reason":""},` +
			`{"check":"canvass.signature","verdict":"fail","reason":"p01"}]}`), errors.New("exit status 1")
	}
	return nil, fmt.Errorf("unexpected %v", args)
}

func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// genDir lays out what `saksi-demo gen --precincts 2` writes, plus two
// folders the driver must skip.
func genDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for k, p := range []string{"precinct-02", "precinct-01"} { // out of order on purpose
		pdir := filepath.Join(dir, p)
		if err := os.MkdirAll(pdir, 0o755); err != nil {
			t.Fatal(err)
		}
		h := fmt.Sprintf(`{"election_id":"base-p%02d"}`, 2-k)
		if err := os.WriteFile(filepath.Join(pdir, "header.json"), []byte(h), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"national", "precinct-xx", "notes"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// national/ has a header.json too: it must not be taken for a precinct.
	for _, f := range []string{"national/header.json", "national/registry.json", "national/aggregate.json"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func newWorld(t *testing.T) (*fakeWorld, Options) {
	dir := genDir(t)
	w := &fakeWorld{t: t, dir: dir, pass: true, verified: 3}
	out := filepath.Join(t.TempDir(), "run")
	return w, Options{Dir: dir, Out: out, DemoBin: "saksi-demo", Chain: w, Run: w.run}
}

func readRecord(t *testing.T, o Options) RunRecord {
	t.Helper()
	var rec RunRecord
	if err := readJSON(filepath.Join(o.Out, RunFile), &rec); err != nil {
		t.Fatalf("canvass-run.json: %v", err)
	}
	return rec
}

func TestCleanRunSequenceAndLayout(t *testing.T) {
	w, o := newWorld(t)
	code, err := Run(context.Background(), o)
	if err != nil || code != ExitPass {
		t.Fatalf("code %d, err %v", code, err)
	}
	p := func(f string) string { return filepath.Join(o.Dir, f) }
	want := []string{
		"lifecycle precinct-01", "close precinct-01", "partials precinct-01", "tally precinct-01", "verify precinct-01", "chaininfo",
		"sign-return " + p("precinct-01") + " --ledger " + p("precinct-01/ledger/ballots.ndjson") +
			" --close-block 1 --tip-hash " + strings.Repeat("01", 32) +
			" --key " + p("precinct-01/authority.key") + " --out " + p("precinct-01/return.json"),
		"lifecycle precinct-02", "close precinct-02", "partials precinct-02", "tally precinct-02", "verify precinct-02", "chaininfo",
		"sign-return " + p("precinct-02") + " --ledger " + p("precinct-02/ledger/ballots.ndjson") +
			" --close-block 2 --tip-hash " + strings.Repeat("02", 32) +
			" --key " + p("precinct-02/authority.key") + " --out " + p("precinct-02/return.json"),
		"audit-canvass " + o.Dir + " --json --out " + o.Out,
	}
	if strings.Join(w.events, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s\nwant:\n%s", strings.Join(w.events, "\n"), strings.Join(want, "\n"))
	}
	// close.json is ChainInfo as reported: Height as is, tip hash in hex.
	var cl struct {
		CloseBlock   uint64 `json:"close_block"`
		CloseTipHash string `json:"close_tip_hash"`
	}
	if err := readJSON(p("precinct-02/close.json"), &cl); err != nil || cl.CloseBlock != 2 || cl.CloseTipHash != strings.Repeat("02", 32) {
		t.Fatalf("close.json = %+v (%v)", cl, err)
	}
	// Each return is transmitted byte for byte under its precinct id.
	for _, k := range []string{"01", "02"} {
		src, _ := os.ReadFile(p("precinct-" + k + "/return.json"))
		dst, err := os.ReadFile(p("national/returns/p" + k + ".json"))
		if err != nil || !bytes.Equal(src, dst) {
			t.Fatalf("national/returns/p%s.json = %q (%v), want %q", k, dst, err, src)
		}
	}
	rec := readRecord(t, o)
	if len(rec.Precincts) != 2 || rec.Precincts[0].PrecinctID != "p01" || rec.Precincts[1].ElectionID != "base-p02" {
		t.Fatalf("precinct rows = %+v", rec.Precincts)
	}
	r := rec.Precincts[0]
	if r.Records != 3 || r.Verified != 3 || !r.Copied || r.Audit != "pass" || r.CloseBlock != 1 || r.Tally != "published" {
		t.Fatalf("row = %+v", r)
	}
	if rec.CanvassPass == nil || !*rec.CanvassPass || len(rec.FailedChecks) != 0 || rec.ExitCode != ExitPass {
		t.Fatalf("record = %+v", rec)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Canvass, &doc); err != nil || doc["pass"] != true {
		t.Fatalf("canvass.json not embedded: %s", rec.Canvass)
	}
}

func TestVerifiedGapIsRecorded(t *testing.T) {
	w, o := newWorld(t)
	w.verified = 2
	if code, err := Run(context.Background(), o); err != nil || code != ExitPass {
		t.Fatalf("code %d, err %v", code, err)
	}
	if r := readRecord(t, o).Precincts[0]; r.Records != 3 || r.Verified != 2 {
		t.Fatalf("row = %+v, want 3 records 2 verified", r)
	}
}

func TestCleanRunFailingCanvassExitsOne(t *testing.T) {
	w, o := newWorld(t)
	w.pass = false
	code, err := Run(context.Background(), o)
	if err != nil || code != ExitFail {
		t.Fatalf("code %d, err %v; want %d", code, err, ExitFail)
	}
	rec := readRecord(t, o)
	if strings.Join(rec.FailedChecks, ",") != "canvass.signature" || rec.ExitCode != ExitFail {
		t.Fatalf("record = %+v", rec)
	}
}

func TestAttackRunHooksInOrderAndExitsZeroOnDetection(t *testing.T) {
	w, o := newWorld(t)
	w.pass = false
	o.Attack = "T13"
	o.AttackScript = "python3 mutate.py"
	o.PreCloseScript = "raw.sh"
	o.PreTallyScript = "replay.sh"
	o.PreTallyTolerate = true
	w.replayed = true
	// T13: the hook drops precinct 01's return on the path.
	w.onScript = func(hook string, args []string) {
		n := len(args) // ... <precinct dir> <return path> <national dir>
		if hook == "return" && strings.HasSuffix(args[n-3], "precinct-01") {
			_ = os.Remove(args[n-2])
		}
	}
	code, err := Run(context.Background(), o)
	if err != nil || code != ExitPass {
		t.Fatalf("code %d, err %v", code, err)
	}
	p := func(f string) string { return filepath.Join(o.Dir, f) }
	nat := p("national")
	want := []string{
		"lifecycle precinct-01",
		"script raw.sh pre-close [SAKSI_ATTACK=T13] " + p("precinct-01") + " base-p01",
		"close precinct-01", "partials precinct-01",
		"script replay.sh pre-tally [SAKSI_ATTACK=T13] " + p("precinct-01") + " base-p01",
		"tally precinct-01", "verify precinct-01", "chaininfo", "sign-return",
		"script python3 return [SAKSI_ATTACK=T13] mutate.py " + p("precinct-01") + " " + p("precinct-01/return.json") + " " + nat,
		"lifecycle precinct-02",
		"script raw.sh pre-close [SAKSI_ATTACK=T13] " + p("precinct-02") + " base-p02",
		"close precinct-02", "partials precinct-02",
		"script replay.sh pre-tally [SAKSI_ATTACK=T13] " + p("precinct-02") + " base-p02",
		"tally precinct-02", "verify precinct-02", "chaininfo", "sign-return",
		"script python3 return [SAKSI_ATTACK=T13] mutate.py " + p("precinct-02") + " " + p("precinct-02/return.json") + " " + nat,
		"script python3 national [SAKSI_ATTACK=T13] mutate.py " + nat,
		"audit-canvass",
	}
	got := make([]string, len(w.events))
	for i, e := range w.events {
		got[i] = e
		if strings.HasPrefix(e, "sign-return") || strings.HasPrefix(e, "audit-canvass") {
			got[i] = strings.Fields(e)[0]
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if _, err := os.Stat(p("national/returns/p01.json")); !os.IsNotExist(err) {
		t.Fatal("a dropped return was transmitted")
	}
	rec := readRecord(t, o)
	if rec.Precincts[0].Tally != "refused: PublishTally: tally already published" {
		t.Fatalf("tolerated refusal not recorded: %q", rec.Precincts[0].Tally)
	}
	if rec.Precincts[0].Copied || !rec.Precincts[1].Copied || rec.Attack != "T13" ||
		strings.Join(rec.FailedChecks, ",") != "canvass.signature" {
		t.Fatalf("record = %+v", rec)
	}
}

func TestAttackRunUndetectedStillExitsZero(t *testing.T) {
	_, o := newWorld(t)
	o.Attack = "T19"
	if code, err := Run(context.Background(), o); err != nil || code != ExitPass {
		t.Fatalf("code %d, err %v", code, err)
	}
	if rec := readRecord(t, o); rec.CanvassPass == nil || !*rec.CanvassPass {
		t.Fatalf("record = %+v", rec)
	}
}

func TestRunErrors(t *testing.T) {
	cases := map[string]func(*fakeWorld, *Options){
		"lifecycle fails": func(w *fakeWorld, _ *Options) { w.failOn = "lifecycle" },
		"refused tally, not tolerated": func(w *fakeWorld, o *Options) {
			w.replayed, o.Attack, o.PreTallyScript = true, "T20", "replay.sh"
		},
		"no ledger dump": func(w *fakeWorld, _ *Options) { w.failOn = "dump" },
		"no registry": func(_ *fakeWorld, o *Options) {
			_ = os.Remove(filepath.Join(o.Dir, "national", "registry.json"))
		},
		"already driven": func(_ *fakeWorld, o *Options) {
			_ = os.MkdirAll(filepath.Join(o.Dir, "national", "returns"), 0o755)
			_ = os.WriteFile(filepath.Join(o.Dir, "national", "returns", "p01.json"), []byte(`{}`), 0o644)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w, o := newWorld(t)
			mutate(w, &o)
			code, err := Run(context.Background(), o)
			if err == nil || code != ExitError {
				t.Fatalf("code %d, err %v; want %d", code, err, ExitError)
			}
			if rec := readRecord(t, o); rec.Error == "" || rec.ExitCode != ExitError {
				t.Fatalf("record = %+v", rec)
			}
			for _, e := range w.events {
				if strings.HasPrefix(e, "audit-canvass") {
					t.Fatal("canvass ran after a failed precinct")
				}
			}
		})
	}
}

func TestPrecinctsSkipsNationalAndStrays(t *testing.T) {
	got, err := Precincts(genDir(t))
	if err != nil || strings.Join(got, ",") != "precinct-01,precinct-02" {
		t.Fatalf("Precincts = %v, %v", got, err)
	}
}

func TestMidRunFailureCarriesTheRecoveryAdvice(t *testing.T) {
	w, o := newWorld(t)
	w.failOn = "lifecycle"
	_, err := Run(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), PartialRunAdvice) {
		t.Fatalf("err = %v, want the partial-run advice", err)
	}
}

func TestDistributionIsRecorded(t *testing.T) {
	_, o := newWorld(t)
	o.Distribution = "realistic"
	if _, err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if rec := readRecord(t, o); rec.Distribution != "realistic" {
		t.Fatalf("distribution = %q", rec.Distribution)
	}
}
