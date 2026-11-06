package canvass

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Tile states.
const (
	TileWaiting  = "waiting"  // its return has not been released yet
	TileReceived = "received" // received and nothing names it
	TileTampered = "tampered" // see Attribute
	TileMissing  = "missing"  // its turn passed and no return arrived
	TileRejected = "rejected" // a national/returns file that is not a registered precinct
)

// Tile is one box on the canvass page: a registered precinct, or a rejected
// arrival (a national/returns file that names no registered precinct, such as
// T10's p03-dup.json or T11's p99.json).
type Tile struct {
	Precinct string   `json:"precinct"`
	State    string   `json:"state"`
	Checks   []string `json:"checks"`
	Reasons  []string `json:"reasons"`
}

// CheckResult is one canvass check as canvass.json carries it.
type CheckResult struct {
	Check   string `json:"check"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
}

// canvassDoc is the part of canvass.json the attribution reads.
type canvassDoc struct {
	Precincts []struct {
		PrecinctID  string `json:"precinct_id"`
		SignatureOK *bool  `json:"signature_ok"`
		RecomputeOK *bool  `json:"recompute_ok"`
	} `json:"precincts"`
	Checks []CheckResult `json:"checks"`
	Pass   *bool         `json:"pass"`
}

// notAttributed are the checks whose failure says nothing about one
// precinct's return mid-stream (every waiting precinct is "incomplete", and
// the national product differs until the last return lands). They appear in
// the final verdict only.
var notAttributed = map[string]bool{
	"canvass.completeness": true,
	"canvass.national_sum": true,
}

// Attribute maps one canvass.json and the file names in national/returns to
// tiles. The TAMPERED rule: a registered precinct is tampered if its
// canvass.json row has signature_ok == false or recompute_ok == false, or the
// reason of any failing check other than canvass.completeness and
// canvass.national_sum names its id (pNN as a whole token). A registered
// precinct with no pNN.json file is missing (the caller turns it into waiting
// while its turn has not come). Every *.json file whose stem is not a
// registered precinct id gets a rejected tile. Registered tiles come first,
// in canvass.json order, then rejected tiles in name order.
func Attribute(canvassJSON []byte, returns []string) ([]Tile, error) {
	var doc canvassDoc
	if err := json.Unmarshal(canvassJSON, &doc); err != nil {
		return nil, fmt.Errorf("canvass.json: %w", err)
	}
	if len(doc.Precincts) == 0 {
		return nil, fmt.Errorf("canvass.json lists no precincts")
	}
	files := map[string]bool{}
	for _, f := range returns {
		if strings.HasSuffix(f, ".json") {
			files[strings.TrimSuffix(f, ".json")] = true
		}
	}
	registered := map[string]bool{}
	tiles := make([]Tile, 0, len(doc.Precincts))
	for _, p := range doc.Precincts {
		registered[p.PrecinctID] = true
		t := Tile{Precinct: p.PrecinctID, State: TileMissing, Checks: []string{}, Reasons: []string{}}
		if files[p.PrecinctID] {
			t.State = TileReceived
		}
		attribute(&t, doc.Checks)
		if p.SignatureOK != nil && !*p.SignatureOK {
			t.addCheck("canvass.signature")
		}
		if p.RecomputeOK != nil && !*p.RecomputeOK {
			t.addCheck("canvass.precinct_recompute")
		}
		if len(t.Checks) > 0 {
			t.State = TileTampered
		}
		tiles = append(tiles, t)
	}
	var stray []string
	for stem := range files {
		if !registered[stem] {
			stray = append(stray, stem)
		}
	}
	sort.Strings(stray)
	for _, stem := range stray {
		t := Tile{Precinct: stem, State: TileRejected, Checks: []string{}, Reasons: []string{}}
		attribute(&t, doc.Checks)
		tiles = append(tiles, t)
	}
	return tiles, nil
}

// attribute adds every failing, attributable check whose reason names the
// tile, with the reason segments ("; "-separated problems) that name it.
func attribute(t *Tile, checks []CheckResult) {
	for _, c := range checks {
		if c.Verdict == "pass" || notAttributed[c.Check] {
			continue
		}
		var hit []string
		for _, seg := range strings.Split(c.Reason, "; ") {
			if namesToken(seg, t.Precinct) {
				hit = append(hit, seg)
			}
		}
		if len(hit) == 0 {
			continue
		}
		t.addCheck(c.Check)
		t.Reasons = append(t.Reasons, c.Check+": "+strings.Join(hit, "; "))
	}
}

func (t *Tile) addCheck(id string) {
	for _, c := range t.Checks {
		if c == id {
			return
		}
	}
	t.Checks = append(t.Checks, id)
}

// namesToken reports whether s names name as a whole token: not preceded by
// a letter or digit, and not followed by a letter, digit or '-' (so p03 does
// not match inside p03-dup.json, but does inside "cv-x-p03" or "p03.json").
// A plain scan, so no pattern is compiled per tile.
func namesToken(s, name string) bool {
	for from := 0; ; {
		i := strings.Index(s[from:], name)
		if i < 0 {
			return false
		}
		i += from
		j := i + len(name)
		before := i == 0 || !isAlnum(s[i-1])
		after := j == len(s) || !(isAlnum(s[j]) || s[j] == '-')
		if before && after {
			return true
		}
		from = i + 1
	}
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
