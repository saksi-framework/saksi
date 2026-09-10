package campaign

import (
	"encoding/csv"
	"strings"
	"testing"
)

// TestCSVEscapeQuotesFreeText: fail_reason is the only free-text column and it
// carries error strings, which contain commas and quotes. An unescaped one
// would shift every column after it.
func TestCSVEscapeQuotesFreeText(t *testing.T) {
	reason := `stage_error: reconcile: committed 4 != expected "5"`
	row := csvEscape([]string{"run-1", reason, "plain"})
	want := `"stage_error: reconcile: committed 4 != expected ""5"""`
	if row[1] != want {
		t.Fatalf("escaped cell = %s, want %s", row[1], want)
	}
	if row[0] != "run-1" || row[2] != "plain" {
		t.Fatalf("cells without a comma or quote must be left alone: %v", row)
	}
	// The escaped row still parses back to the original cells.
	got := parseCSVLine(t, strings.Join(row, ","))
	if len(got) != 3 || got[1] != reason {
		t.Fatalf("round trip = %q", got)
	}
}

// parseCSVLine reads one CSV record back, the way a spreadsheet would.
func parseCSVLine(t *testing.T, line string) []string {
	t.Helper()
	rec, err := csv.NewReader(strings.NewReader(line)).Read()
	if err != nil {
		t.Fatalf("escaped row does not parse as CSV: %v", err)
	}
	return rec
}
