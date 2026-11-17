package campaign

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// The voter list of a live election's one precinct (docs/live/voter-list-api.md).
//
// The presenter uploads a CSV at setup. One parsing rule, used by the preview
// and by POST /api/live/elections alike, sorts the rows, numbers them 1..N,
// reports every error per row, and computes the list's fingerprint. A list
// with any error, or with no row, cannot be locked.
//
// A date of birth is compared on the console only. No error message carries
// one, and nothing after the lock returns one.

const (
	// voterListHeader is the one header row a list file may have.
	voterListHeader = "last_name,first_name,middle_name,date_of_birth"
	// voterListMaxRows is a precinct's cap (RA 8189 Sec. 6).
	voterListMaxRows = 200
	// voterListMaxBytes caps the CSV text.
	voterListMaxBytes = 64 << 10
	// voterNameMaxBytes caps one name field, after normalising its spaces.
	voterNameMaxBytes = 100
	// voterListDomain is the first line of the fingerprint's canonical text.
	voterListDomain = "saksi-voter-list-v1"

	// DefaultLivePrecinct is --live-precinct's default.
	DefaultLivePrecinct = "0001A"
)

var precinctPattern = regexp.MustCompile(`^[0-9]{4}[A-Z]$`)

// ValidPrecinct reports whether p has a precinct number's shape: four digits
// and a capital letter (RA 8189 Sec. 26).
func ValidPrecinct(p string) bool { return precinctPattern.MatchString(p) }

// precinctLabel is how every screen names the precinct: the word
// "demonstration" is always attached.
func precinctLabel(p string) string { return "Precinct " + p + " (demonstration)" }

// VoterRow is one row of the list. Line is the CSV line it came from (1 is
// the first line of the file); Seq is its sequence number after sorting.
type VoterRow struct {
	Seq         int    `json:"seq"`
	Line        int    `json:"line"`
	LastName    string `json:"last_name"`
	FirstName   string `json:"first_name"`
	MiddleName  string `json:"middle_name"`
	DateOfBirth string `json:"date_of_birth"`
}

// VoterListError is one error in a list file. Line 0 is the whole file.
type VoterListError struct {
	Line    int    `json:"line"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ParsedVoterList is a list file parsed: its rows sorted and numbered, its
// errors, and the fingerprint (empty unless the list is valid).
type ParsedVoterList struct {
	Precinct    string
	Rows        []VoterRow
	Errors      []VoterListError
	Fingerprint string
	// dobOK[i] says whether Rows[i]'s date of birth is valid.
	dobOK []bool
}

// Valid reports whether the list can be locked: no error and at least one row.
func (p ParsedVoterList) Valid() bool { return len(p.Errors) == 0 && len(p.Rows) > 0 }

// voterDisplayName is a name as it is shown and fingerprinted: Unicode NFC,
// surrounding white space removed, every run of white space one space.
func voterDisplayName(s string) string {
	return strings.Join(strings.Fields(norm.NFC.String(s)), " ")
}

// voterNameKey is a name as it is matched and compared for duplicates:
// decomposed (NFKD) with every combining mark dropped (so "Ñ" is "N" and "É"
// is "E"), upper case, hyphens, dashes and periods read as a space,
// apostrophes dropped, and white space collapsed and trimmed.
func voterNameKey(s string) string {
	var b strings.Builder
	for _, r := range norm.NFKD.String(s) {
		switch {
		case unicode.Is(unicode.Mn, r):
		case r == '\'' || r == '‘' || r == '’':
		case r == '-' || r == '.' || unicode.Is(unicode.Pd, r):
			b.WriteRune(' ')
		default:
			b.WriteRune(unicode.ToUpper(r))
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// validNameChars reports whether a display name holds only letters, marks,
// spaces, hyphens, periods and apostrophes.
func validNameChars(s string) bool {
	for _, r := range s {
		switch {
		case unicode.IsLetter(r), unicode.Is(unicode.M, r), r == ' ', r == '.', r == '\'', r == '’',
			r == '-', unicode.Is(unicode.Pd, r):
		default:
			return false
		}
	}
	return true
}

// parseDOB reads a date of birth: exactly YYYY-MM-DD, a real calendar date,
// not before 1900-01-01. future reports a date after today anywhere on earth
// (now plus 14 hours, UTC).
func parseDOB(s string, now time.Time) (ok, future bool) {
	if len(s) != 10 {
		return false, false
	}
	d, err := time.Parse("2006-01-02", s)
	if err != nil || d.Format("2006-01-02") != s || d.Year() < 1900 {
		return false, false
	}
	latest := now.Add(14 * time.Hour).UTC()
	today := time.Date(latest.Year(), latest.Month(), latest.Day(), 0, 0, 0, 0, time.UTC)
	return true, d.After(today)
}

// canonicalVoterList is the text the fingerprint is the SHA-256 of: UTF-8,
// each line ending in LF, fields separated by one TAB (no name can hold a TAB):
//
//	saksi-voter-list-v1
//	precinct<TAB><precinct>
//	count<TAB><N>
//	<seq><TAB><last><TAB><first><TAB><middle><TAB><YYYY-MM-DD>   one per row, by seq
func canonicalVoterList(precinct string, rows []VoterRow) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\nprecinct\t%s\ncount\t%d\n", voterListDomain, precinct, len(rows))
	for _, r := range rows {
		fmt.Fprintf(&b, "%d\t%s\t%s\t%s\t%s\n", r.Seq, r.LastName, r.FirstName, r.MiddleName, r.DateOfBirth)
	}
	return b.String()
}

func voterListFingerprint(precinct string, rows []VoterRow) string {
	sum := sha256.Sum256([]byte(canonicalVoterList(precinct, rows)))
	return hex.EncodeToString(sum[:])
}

// fingerprintShort is the first 16 hex digits, as the pages show it.
func fingerprintShort(fp string) string {
	if len(fp) < 16 {
		return fp
	}
	return fp[:16]
}

// parseVoterList parses a list file for precinct. now decides which dates of
// birth are in the future.
func parseVoterList(text, precinct string, now time.Time) ParsedVoterList {
	p := ParsedVoterList{Precinct: precinct}
	fileErr := func(line int, code, msg string) { p.Errors = append(p.Errors, VoterListError{line, code, msg}) }
	if len(text) > voterListMaxBytes {
		fileErr(0, "too-large", fmt.Sprintf("the file is larger than %d KiB", voterListMaxBytes>>10))
		return p
	}
	if !utf8.ValidString(text) {
		fileErr(0, "bad-csv", "the file is not UTF-8 text")
		return p
	}
	text = strings.TrimPrefix(text, "\ufeff")
	r := csv.NewReader(strings.NewReader(text))
	r.Comment = '#'
	r.FieldsPerRecord = -1

	type rowAt struct {
		row   VoterRow
		dobOK bool
		bad   bool
		last  string
		first string
		mid   string
	}
	var rows []rowAt
	header := false
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			line := 0
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				line = pe.Line
			}
			fileErr(line, "bad-csv", "the file is not valid CSV here (check the quotes)")
			return p
		}
		line, _ := r.FieldPos(0)
		if !header {
			got := make([]string, len(rec))
			for i, f := range rec {
				got[i] = strings.TrimSpace(f)
			}
			if strings.Join(got, ",") != voterListHeader {
				fileErr(line, "bad-header", "the first row must be the header "+voterListHeader)
				return p
			}
			header = true
			continue
		}
		if len(rec) != 4 {
			fileErr(line, "bad-row", fmt.Sprintf("a row needs 4 fields (last_name, first_name, middle_name, date_of_birth); this one has %d", len(rec)))
			continue
		}
		ra := rowAt{row: VoterRow{Line: line,
			LastName: voterDisplayName(rec[0]), FirstName: voterDisplayName(rec[1]),
			MiddleName: voterDisplayName(rec[2]), DateOfBirth: strings.TrimSpace(rec[3])}}
		ra.last, ra.first, ra.mid = voterNameKey(ra.row.LastName), voterNameKey(ra.row.FirstName), voterNameKey(ra.row.MiddleName)
		for _, f := range []struct{ val, key, what, missing string }{
			{ra.row.LastName, ra.last, "last name", "missing-last-name"},
			{ra.row.FirstName, ra.first, "first name", "missing-first-name"},
			{ra.row.MiddleName, ra.mid, "middle name", ""},
		} {
			switch {
			case len(f.val) > voterNameMaxBytes || !validNameChars(f.val):
				fileErr(line, "invalid-name", fmt.Sprintf("the %s must be letters, spaces, hyphens, periods or apostrophes, at most %d bytes", f.what, voterNameMaxBytes))
				ra.bad = true
			case f.missing != "" && f.key == "":
				fileErr(line, f.missing, "the "+f.what+" is missing")
				ra.bad = true
			}
		}
		ok, future := parseDOB(ra.row.DateOfBirth, now)
		ra.dobOK = ok && !future
		switch {
		case !ok:
			fileErr(line, "invalid-date", "the date of birth is not a real date in the form YYYY-MM-DD (from 1900)")
		case future:
			fileErr(line, "future-date", "the date of birth is in the future")
		}
		rows = append(rows, ra)
	}
	if !header {
		fileErr(0, "empty", "the file has no header and no voters")
		return p
	}
	// Duplicates: same last name, first name and date of birth after
	// normalising, against every earlier row of the file.
	seen := map[string]int{}
	for _, ra := range rows {
		if ra.bad || !ra.dobOK {
			continue
		}
		k := ra.last + "\x00" + ra.first + "\x00" + ra.row.DateOfBirth
		if first, dup := seen[k]; dup {
			fileErr(ra.row.Line, "duplicate", fmt.Sprintf("the same voter as line %d (last name, first name and date of birth)", first))
			continue
		}
		seen[k] = ra.row.Line
	}
	if len(rows) == 0 && len(p.Errors) == 0 {
		fileErr(0, "empty", "the list has no voters")
	}
	if len(rows) > voterListMaxRows {
		fileErr(0, "too-many-rows", fmt.Sprintf("the list has %d rows; a precinct holds at most %d voters (RA 8189 Sec. 6)", len(rows), voterListMaxRows))
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		for _, c := range [][2]string{{a.last, b.last}, {a.first, b.first}, {a.mid, b.mid},
			{a.row.DateOfBirth, b.row.DateOfBirth}, {a.row.LastName, b.row.LastName},
			{a.row.FirstName, b.row.FirstName}, {a.row.MiddleName, b.row.MiddleName}} {
			if c[0] != c[1] {
				return c[0] < c[1]
			}
		}
		return a.row.Line < b.row.Line
	})
	for i := range rows {
		rows[i].row.Seq = i + 1
		p.Rows = append(p.Rows, rows[i].row)
		p.dobOK = append(p.dobOK, rows[i].dobOK)
	}
	sort.SliceStable(p.Errors, func(i, j int) bool { return p.Errors[i].Line < p.Errors[j].Line })
	if p.Valid() {
		p.Fingerprint = voterListFingerprint(precinct, p.Rows)
	}
	return p
}

// VoterListPreviewRow is one row of the preview: never the date itself.
type VoterListPreviewRow struct {
	Seq              int    `json:"seq"`
	Line             int    `json:"line"`
	LastName         string `json:"last_name"`
	FirstName        string `json:"first_name"`
	MiddleName       string `json:"middle_name"`
	DateOfBirthValid bool   `json:"date_of_birth_valid"`
}

// VoterListPreview is POST /api/live/voter-list/preview.
type VoterListPreview struct {
	Precinct         string                `json:"precinct"`
	PrecinctLabel    string                `json:"precinct_label"`
	Valid            bool                  `json:"valid"`
	Count            int                   `json:"count"`
	MaxRows          int                   `json:"max_rows"`
	Rows             []VoterListPreviewRow `json:"rows"`
	Errors           []VoterListError      `json:"errors"`
	Fingerprint      string                `json:"fingerprint"`
	FingerprintShort string                `json:"fingerprint_short"`
}

func previewOf(p ParsedVoterList) VoterListPreview {
	v := VoterListPreview{
		Precinct: p.Precinct, PrecinctLabel: precinctLabel(p.Precinct),
		Valid: p.Valid(), Count: len(p.Rows), MaxRows: voterListMaxRows,
		Rows: []VoterListPreviewRow{}, Errors: p.Errors,
		Fingerprint: p.Fingerprint, FingerprintShort: fingerprintShort(p.Fingerprint),
	}
	if v.Errors == nil {
		v.Errors = []VoterListError{}
	}
	for i, r := range p.Rows {
		v.Rows = append(v.Rows, VoterListPreviewRow{Seq: r.Seq, Line: r.Line,
			LastName: r.LastName, FirstName: r.FirstName, MiddleName: r.MiddleName,
			DateOfBirthValid: p.dobOK[i]})
	}
	return v
}

// voterRowKey is what the phone's find matches on.
type voterRowKey struct{ last, first, dob string }

func keyOfRow(r VoterRow) voterRowKey {
	return voterRowKey{voterNameKey(r.LastName), voterNameKey(r.FirstName), r.DateOfBirth}
}
