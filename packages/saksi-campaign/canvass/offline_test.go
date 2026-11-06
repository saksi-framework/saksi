package canvass

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// toolsDir is the balotachain attack-tools folder: SAKSI_CANVASS_TOOLS, or
// the sibling checkout next to this saksi tree. "" when neither exists.
func toolsDir(t *testing.T) string {
	t.Helper()
	if d := os.Getenv("SAKSI_CANVASS_TOOLS"); d != "" {
		return d
	}
	d, _ := filepath.Abs(filepath.Join("..", "..", "..", "..", "balotachain", "tools", "security", "canvass"))
	if _, err := os.Stat(filepath.Join(d, assertScript)); err == nil {
		return d
	}
	return ""
}

// wantTiles is the attribution each recorded attack must produce over its
// 2026-10-18 canvass.json (testdata/evidence/<id>, copied verbatim from
// balotachain origin/feat/precinct-evidence:
// docs/desktop-runs/2026-10-18-precinct-canvass/attacks/<id>/).
var wantTiles = map[string]struct{ tampered, rejected, missing []string }{
	"T9":   {tampered: []string{"p03"}},
	"T10":  {tampered: []string{"p03"}, rejected: []string{"p03-dup"}},
	"T11":  {rejected: []string{"p99"}},
	"T12":  {tampered: []string{"p04"}},
	"T13":  {missing: []string{"p05"}},
	"T14a": {tampered: []string{"p03"}},
	"T14b": {tampered: []string{"p03"}},
	"T15":  {tampered: []string{"p06"}},
	"T16":  {tampered: []string{"p07"}},
	"T21":  {tampered: []string{"p03"}},
	"T24":  {tampered: []string{"p01"}},
	"T19":  {},
	"T20":  {},
}

func byState(tiles []Tile, state string) []string {
	var out []string
	for _, t := range tiles {
		if t.State == state {
			out = append(out, t.Precinct)
		}
	}
	sort.Strings(out)
	return out
}

func TestAttributeEvidence(t *testing.T) {
	for id, want := range wantTiles {
		t.Run(id, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "evidence", id, "canvass.json"))
			if err != nil {
				t.Fatal(err)
			}
			list, err := os.ReadFile(filepath.Join("testdata", "evidence", id, "national-returns.txt"))
			if err != nil {
				t.Fatal(err)
			}
			tiles, err := Attribute(raw, strings.Fields(string(list)))
			if err != nil {
				t.Fatal(err)
			}
			for state, w := range map[string][]string{TileTampered: want.tampered, TileRejected: want.rejected, TileMissing: want.missing} {
				if got := byState(tiles, state); !reflect.DeepEqual(got, w) && !(len(got) == 0 && len(w) == 0) {
					t.Errorf("%s tiles = %v, want %v", state, got, w)
				}
			}
			if got := len(byState(tiles, TileReceived)) + len(byState(tiles, TileTampered)) + len(byState(tiles, TileMissing)); got != 10 {
				t.Errorf("%d registered tiles, want 10", got)
			}
			sc, _ := LookupScenario(id)
			expected := map[string]bool{}
			for _, c := range sc.Expected {
				expected[c] = true
			}
			for _, tile := range tiles {
				for _, c := range tile.Checks {
					if !expected[c] {
						t.Errorf("%s flagged by %s, not in EXPECTED[%s] %v", tile.Precinct, c, id, sc.Expected)
					}
					if notAttributed[c] {
						t.Errorf("%s flagged by %s, which is never attributed", tile.Precinct, c)
					}
				}
				if tile.State == TileTampered && len(tile.Reasons) == 0 && len(tile.Checks) == 0 {
					t.Errorf("%s tampered with no check", tile.Precinct)
				}
			}
		})
	}
}

func TestAttributeTokenBoundaries(t *testing.T) {
	doc := `{"precincts":[
	  {"precinct_id":"p01","signature_ok":true,"recompute_ok":true},
	  {"precinct_id":"p03","signature_ok":true,"recompute_ok":true},
	  {"precinct_id":"p10","signature_ok":null,"recompute_ok":null}],
	 "checks":[
	  {"check":"canvass.registry","verdict":"fail","reason":"p03-dup.json: precinct \"p03-dup\" is not in the registry"},
	  {"check":"canvass.completeness","verdict":"fail","reason":"no accepted return from p01, p10"},
	  {"check":"canvass.national_sum","verdict":"fail","reason":"p01 differs"}],
	 "pass":false}`
	tiles, err := Attribute([]byte(doc), []string{"p01.json", "p03.json", "p03-dup.json", "notes.txt"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, tl := range tiles {
		got[tl.Precinct] = tl.State
	}
	want := map[string]string{"p01": TileReceived, "p03": TileReceived, "p10": TileMissing, "p03-dup": TileRejected}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tiles %v, want %v", got, want)
	}
	if r := tiles[3]; r.Precinct != "p03-dup" || !reflect.DeepEqual(r.Checks, []string{"canvass.registry"}) {
		t.Fatalf("rejected tile %+v", r)
	}
}

func TestAttributeRowFlags(t *testing.T) {
	doc := `{"precincts":[{"precinct_id":"p02","signature_ok":true,"recompute_ok":false}],"checks":[],"pass":false}`
	tiles, err := Attribute([]byte(doc), []string{"p02.json"})
	if err != nil {
		t.Fatal(err)
	}
	if tiles[0].State != TileTampered || !reflect.DeepEqual(tiles[0].Checks, []string{"canvass.precinct_recompute"}) {
		t.Fatalf("tile %+v", tiles[0])
	}
	if _, err := Attribute([]byte(`{"precincts":[]}`), nil); err == nil {
		t.Fatal("empty canvass.json accepted")
	}
}

func TestScenarioTableShape(t *testing.T) {
	var live, recorded []string
	for _, s := range Scenarios() {
		if s.Live {
			live = append(live, s.ID)
			if s.Recorded != nil {
				t.Errorf("%s is live and recorded", s.ID)
			}
		} else {
			recorded = append(recorded, s.ID)
			if s.Recorded == nil || s.Recorded.Note != "on-chain, needs Fabric — recorded 2026-10-18" || s.Where != "chain" {
				t.Errorf("%s: recorded chain scenario wrong: %+v", s.ID, s)
			}
		}
	}
	if want := []string{"clean", "T9", "T10", "T11", "T12", "T13", "T14a", "T14b", "T15", "T16", "T21", "T24"}; !reflect.DeepEqual(live, want) {
		t.Errorf("live %v, want %v", live, want)
	}
	if want := []string{"T19", "T20"}; !reflect.DeepEqual(recorded, want) {
		t.Errorf("recorded %v, want %v", recorded, want)
	}
	a, _ := LookupScenario("T14a")
	b, _ := LookupScenario("T14b")
	if a.attack != "T14" || a.t14 != "" || b.attack != "T14" || b.t14 != "close" {
		t.Errorf("T14 variants wired wrong: %+v %+v", a, b)
	}
}

// TestScenarioTableMatchesAssertOutcome parses EXPECTED and MOUNT out of
// balotachain's assert_outcome.py and fails on any difference from the Go
// table (ids, check order, mount text).
func TestScenarioTableMatchesAssertOutcome(t *testing.T) {
	dir := toolsDir(t)
	if dir == "" {
		t.Skip("balotachain tools/security/canvass not found (set SAKSI_CANVASS_TOOLS)")
	}
	raw, err := os.ReadFile(filepath.Join(dir, assertScript))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	block := func(name string) string {
		i := strings.Index(src, "\n"+name+" = {")
		if i < 0 {
			t.Fatalf("%s not found in assert_outcome.py", name)
		}
		j := strings.Index(src[i:], "\n}")
		return src[i : i+j]
	}
	expRE := regexp.MustCompile(`"(T\w+)":\s*\[([^\]]*)\]`)
	strRE := regexp.MustCompile(`"([^"]+)"`)
	py := map[string][]string{}
	for _, m := range expRE.FindAllStringSubmatch(block("EXPECTED"), -1) {
		checks := []string{}
		for _, c := range strRE.FindAllStringSubmatch(m[2], -1) {
			checks = append(checks, c[1])
		}
		py[m[1]] = checks
	}
	mountRE := regexp.MustCompile(`"(T\w+)":\s*"((?:[^"\\]|\\.)*)"`)
	pyMount := map[string]string{}
	for _, m := range mountRE.FindAllStringSubmatch(block("MOUNT"), -1) {
		pyMount[m[1]] = m[2]
	}
	if len(py) == 0 || len(pyMount) == 0 {
		t.Fatal("parsed nothing from assert_outcome.py")
	}
	goExp := map[string][]string{}
	goMount := map[string]string{}
	for _, s := range Scenarios() {
		if s.ID == "clean" {
			continue
		}
		goExp[s.ID] = s.Expected
		goMount[s.ID] = s.Mount
	}
	if !reflect.DeepEqual(goExp, py) {
		t.Errorf("EXPECTED drift:\n go %v\n py %v", goExp, py)
	}
	if !reflect.DeepEqual(goMount, pyMount) {
		t.Errorf("MOUNT drift:\n go %v\n py %v", goMount, pyMount)
	}
}

func TestNextAttempt(t *testing.T) {
	d := t.TempDir()
	if n, err := NextAttempt(filepath.Join(d, "none")); err != nil || n != 1 {
		t.Fatalf("missing dir: %d %v", n, err)
	}
	for _, n := range []string{"1-clean", "7-T9", "x-T10"} {
		os.Mkdir(filepath.Join(d, n), 0o755)
	}
	os.WriteFile(filepath.Join(d, "12-file"), nil, 0o644)
	if n, err := NextAttempt(d); err != nil || n != 8 {
		t.Fatalf("next = %d %v, want 8", n, err)
	}
}

func TestRunAttemptRefusals(t *testing.T) {
	d := t.TempDir()
	for id, want := range map[string]string{"T99": "unknown scenario", "T19": "needs Fabric", "clean": "no valid fixture"} {
		if _, err := RunAttempt(context.Background(), filepath.Join(d, "fixture"), filepath.Join(d, "attempts"), "saksi-demo", d, id, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err %v, want %q", id, err, want)
		}
	}
}
