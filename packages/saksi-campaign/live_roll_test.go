package campaign

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Tests of the voter list file: parsing, sorting, numbering, validation and
// the fingerprint (docs/live/voter-list-api.md). Every name and date here is
// fictional.

var rollToday = time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC)

const rollHeader = "last_name,first_name,middle_name,date_of_birth\n"

func parseRoll(t *testing.T, text string) ParsedVoterList {
	t.Helper()
	return parseVoterList(text, "0001A", rollToday)
}

func errCodes(p ParsedVoterList) []string {
	var out []string
	for _, e := range p.Errors {
		out = append(out, fmt.Sprintf("%d:%s", e.Line, e.Code))
	}
	return out
}

func TestVoterListSortsAndNumbers(t *testing.T) {
	p := parseRoll(t, "# Fictional voters only.\n"+rollHeader+
		"Sampol,Tres,Pagsubok,1992-03-03\n"+
		"  Halimbawa ,  Dos  ,,1991-02-02\r\n"+
		"\n"+
		"halimbawa,Uno,Pagsubok,1990-01-01\n")
	if len(p.Errors) != 0 {
		t.Fatalf("errors: %v", p.Errors)
	}
	want := []VoterRow{
		{Seq: 1, Line: 4, LastName: "Halimbawa", FirstName: "Dos", DateOfBirth: "1991-02-02"},
		{Seq: 2, Line: 6, LastName: "halimbawa", FirstName: "Uno", MiddleName: "Pagsubok", DateOfBirth: "1990-01-01"},
		{Seq: 3, Line: 3, LastName: "Sampol", FirstName: "Tres", MiddleName: "Pagsubok", DateOfBirth: "1992-03-03"},
	}
	if len(p.Rows) != len(want) {
		t.Fatalf("rows: %+v", p.Rows)
	}
	for i := range want {
		if p.Rows[i] != want[i] {
			t.Errorf("row %d: %+v, want %+v", i, p.Rows[i], want[i])
		}
	}
	if !p.Valid() || len(p.Fingerprint) != 64 {
		t.Fatalf("valid %v fingerprint %q", p.Valid(), p.Fingerprint)
	}
}

// Every error kind, each in a file of its own, with the line it names.
func TestVoterListErrors(t *testing.T) {
	ok := "Halimbawa,Uno,,1990-01-01\n"
	var big strings.Builder
	big.WriteString(rollHeader)
	for i := 0; i < 201; i++ {
		fmt.Fprintf(&big, "Halimbawa,Uno%s%c,,1990-01-01\n", strings.Repeat("a", i%50+1), 'A'+i/50)
	}
	cases := []struct {
		name, text string
		want       []string
	}{
		{"missing last name", rollHeader + ok + " ,Dos,,1991-02-02\n", []string{"3:missing-last-name"}},
		{"missing first name", rollHeader + ok + "Halimbawa,,,1991-02-02\n", []string{"3:missing-first-name"}},
		{"punctuation only is missing", rollHeader + ok + "Halimbawa,-.,,1991-02-02\n", []string{"3:missing-first-name"}},
		{"bad characters", rollHeader + ok + "Halim<b>bawa,Dos,,1991-02-02\n", []string{"3:invalid-name"}},
		{"name too long", rollHeader + ok + strings.Repeat("A", 101) + ",Dos,,1991-02-02\n", []string{"3:invalid-name"}},
		{"bad middle name", rollHeader + ok + "Halimbawa,Dos,1,1991-02-02\n", []string{"3:invalid-name"}},
		{"date not a date", rollHeader + ok + "Halimbawa,Dos,,1991-02-30\n", []string{"3:invalid-date"}},
		{"date wrong form", rollHeader + ok + "Halimbawa,Dos,,02/02/1991\n", []string{"3:invalid-date"}},
		{"date one digit month", rollHeader + ok + "Halimbawa,Dos,,1991-2-02\n", []string{"3:invalid-date"}},
		{"date before 1900", rollHeader + ok + "Halimbawa,Dos,,1899-12-31\n", []string{"3:invalid-date"}},
		{"date in the future", rollHeader + ok + "Halimbawa,Dos,,2026-11-19\n", []string{"3:future-date"}},
		{"duplicate after normalising", rollHeader + ok + "HALIMBAWA ,  uno,Iba,1990-01-01\n", []string{"3:duplicate"}},
		{"duplicate with the tilde folded", rollHeader + "Peña,Uno,,1990-01-01\n" + "Pena,Uno,,1990-01-01\n", []string{"3:duplicate"}},
		{"duplicate with a hyphen", rollHeader + "Dela-Cruz,Uno,,1990-01-01\n" + "Dela  Cruz,Uno,,1990-01-01\n", []string{"3:duplicate"}},
		{"wrong field count", rollHeader + ok + "Halimbawa,Dos,1991-02-02\n", []string{"3:bad-row"}},
		{"header that does not match", "surname,given,middle,dob\n" + ok, []string{"1:bad-header"}},
		{"no header", "", []string{"0:empty"}},
		{"header only", rollHeader, []string{"0:empty"}},
		{"bad quoting", rollHeader + ok + "\"Halim\"bawa,Dos,,1991-02-02\n", []string{"3:bad-csv"}},
		{"more than 200 rows", big.String(), []string{"0:too-many-rows"}},
		{"too large", rollHeader + strings.Repeat("#"+strings.Repeat("x", 1000)+"\n", 70), []string{"0:too-large"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := parseRoll(t, tc.text)
			got := errCodes(p)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("errors %v, want %v", got, tc.want)
			}
			if p.Valid() || p.Fingerprint != "" {
				t.Fatalf("a list with errors is valid (%v) or has a fingerprint %q", p.Valid(), p.Fingerprint)
			}
			for _, e := range p.Errors {
				if e.Message == "" {
					t.Fatalf("error %s has no message", e.Code)
				}
				for _, d := range []string{"1991", "1990", "1899", "02/02", "2026-11-19"} {
					if strings.Contains(e.Message, d) {
						t.Fatalf("error message %q echoes a date", e.Message)
					}
				}
			}
		})
	}
}

// The canonical text and the worked example in docs/live/voter-list-api.md.
func TestVoterListFingerprintVector(t *testing.T) {
	text := "# Fictional voters for the documentation's worked example.\n" + rollHeader +
		"Sampol,Tres,,1992-03-03\n" +
		"Halimbawa,Uno,Pagsubok,1990-01-01\n" +
		"Peña,  Dos ,Santos-Reyes,1991-02-02\n"
	p := parseRoll(t, text)
	if !p.Valid() {
		t.Fatalf("errors: %v", p.Errors)
	}
	canon := "saksi-voter-list-v1\n" +
		"precinct\t0001A\n" +
		"count\t3\n" +
		"1\tHalimbawa\tUno\tPagsubok\t1990-01-01\n" +
		"2\tPeña\tDos\tSantos-Reyes\t1991-02-02\n" +
		"3\tSampol\tTres\t\t1992-03-03\n"
	if got := canonicalVoterList("0001A", p.Rows); got != canon {
		t.Fatalf("canonical text:\n%q\nwant\n%q", got, canon)
	}
	sum := sha256.Sum256([]byte(canon))
	if p.Fingerprint != hex.EncodeToString(sum[:]) {
		t.Fatalf("fingerprint %s is not the SHA-256 of the canonical text", p.Fingerprint)
	}
	// The value written in the contract document.
	const docVector = "cc0ad92dc0fce5cd088bde29bd4f6c03f3d66122e4fe06d4f44425851273dd75"
	if p.Fingerprint != docVector {
		t.Fatalf("fingerprint %s, the document says %s", p.Fingerprint, docVector)
	}
}

// The fingerprint depends on the rows and the precinct, not on file order,
// comments, blank lines, surrounding spaces or line endings; any changed
// character of a row changes it.
func TestVoterListFingerprintStability(t *testing.T) {
	a := parseRoll(t, rollHeader+"Sampol,Tres,,1992-03-03\nHalimbawa,Uno,Pagsubok,1990-01-01\n")
	b := parseRoll(t, "# a comment\r\n"+strings.ReplaceAll(rollHeader, "\n", "\r\n")+
		"\r\n Halimbawa , Uno ,  Pagsubok,1990-01-01\r\nSampol,Tres,,1992-03-03")
	if !a.Valid() || !b.Valid() || a.Fingerprint != b.Fingerprint {
		t.Fatalf("same rows, different fingerprints: %s %s (%v %v)", a.Fingerprint, b.Fingerprint, a.Errors, b.Errors)
	}
	// A UTF-8 byte order mark is ignored.
	if c := parseRoll(t, "\ufeff"+rollHeader+"Sampol,Tres,,1992-03-03\nHalimbawa,Uno,Pagsubok,1990-01-01\n"); c.Fingerprint != a.Fingerprint {
		t.Fatalf("a BOM changed the fingerprint: %v", c.Errors)
	}
	// Decomposed "n" + combining tilde is the same name as the composed "ñ".
	d1 := parseRoll(t, rollHeader+"Peña,Uno,,1990-01-01\n")
	d2 := parseRoll(t, rollHeader+"Peña,Uno,,1990-01-01\n")
	if !d1.Valid() || d1.Fingerprint != d2.Fingerprint {
		t.Fatalf("NFC: %s %s", d1.Fingerprint, d2.Fingerprint)
	}
	for name, text := range map[string]string{
		"case":   rollHeader + "SAMPOL,Tres,,1992-03-03\nHalimbawa,Uno,Pagsubok,1990-01-01\n",
		"middle": rollHeader + "Sampol,Tres,X,1992-03-03\nHalimbawa,Uno,Pagsubok,1990-01-01\n",
		"date":   rollHeader + "Sampol,Tres,,1992-03-04\nHalimbawa,Uno,Pagsubok,1990-01-01\n",
		"row":    rollHeader + "Sampol,Tres,,1992-03-03\n",
	} {
		if c := parseRoll(t, text); !c.Valid() || c.Fingerprint == a.Fingerprint {
			t.Errorf("%s: a changed list kept the fingerprint (%v)", name, c.Errors)
		}
	}
	if c := parseVoterList(rollHeader+"Sampol,Tres,,1992-03-03\nHalimbawa,Uno,Pagsubok,1990-01-01\n", "0002B", rollToday); c.Fingerprint == a.Fingerprint {
		t.Error("another precinct kept the fingerprint")
	}
	// The same input always gives the same value.
	for i := 0; i < 3; i++ {
		if c := parseRoll(t, rollHeader+"Sampol,Tres,,1992-03-03\nHalimbawa,Uno,Pagsubok,1990-01-01\n"); c.Fingerprint != a.Fingerprint {
			t.Fatal("the fingerprint is not stable")
		}
	}
}

func TestVoterNameKey(t *testing.T) {
	for in, want := range map[string]string{
		"  dela   Cruz ":  "DELA CRUZ",
		"Dela-Cruz":       "DELA CRUZ",
		"Dela‐Cruz":       "DELA CRUZ", // U+2010
		"PEÑA":            "PENA",
		"Peña":      "PENA",
		"José":            "JOSE",
		"Ma. Clara":       "MA CLARA",
		"O'Brien":         "OBRIEN",
		"O’Brien":         "OBRIEN",
		" Uno ": "UNO",
	} {
		if got := voterNameKey(in); got != want {
			t.Errorf("voterNameKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPrecinctValue(t *testing.T) {
	for _, ok := range []string{"0001A", "1234Z"} {
		if !ValidPrecinct(ok) {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{"", "001A", "0001a", "00001A", "0001AB", "ABCD1"} {
		if ValidPrecinct(bad) {
			t.Errorf("%s accepted", bad)
		}
	}
	if precinctLabel("0001A") != "Precinct 0001A (demonstration)" {
		t.Fatal(precinctLabel("0001A"))
	}
}
