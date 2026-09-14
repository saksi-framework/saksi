package campaign

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// The thesis export bundle: GET /api/campaigns/<id>/export streams a zip of
// the artifacts Chapter 4 cites for every run in the campaign (the file set the
// desktop-run notes copy by hand), plus the campaign's own summary, record and
// preflight snapshot. Streamed straight into the response; nothing touches disk.

// bundleRunFiles are copied from each run folder when present, as <run-id>/<file>.
var bundleRunFiles = []string{
	RunFile, PerfCSV, PerfSchemaFile, CorrectnessFile, NegativeTestsFile, CheckFile, TimingsFile,
}

// journalLine1File is the journal's first line (the env snapshot) in the bundle.
const journalLine1File = "journal-line1.json"

// preflightBundleFile is the campaign's preflight snapshot in the bundle.
const preflightBundleFile = "preflight.json"

func (s *Server) streamCampaignBundle(w http.ResponseWriter, rec campaignRecord) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+rec.ID+`.zip"`)
	zw := zip.NewWriter(w)
	defer zw.Close()

	// ponytail: a write error mid-stream just ends the zip; the client sees a
	// truncated archive, which is all an HTTP response can say once it started.
	seen := map[string]bool{}
	for _, rep := range rec.Reps {
		dir, err := s.store.Dir(rep.RunID)
		if err != nil || seen[rep.RunID] {
			continue
		}
		seen[rep.RunID] = true
		for _, name := range bundleRunFiles {
			if err := zipFile(zw, rep.RunID+"/"+name, filepath.Join(dir, name)); err != nil {
				return
			}
		}
		if line := journalLine1(filepath.Join(dir, JournalFile)); line != nil {
			if err := zipBytes(zw, rep.RunID+"/"+journalLine1File, line); err != nil {
				return
			}
		}
	}
	if cdir, err := s.campaignDir(rec.ID); err == nil {
		if err := zipFile(zw, SummaryCSV, filepath.Join(cdir, SummaryCSV)); err != nil {
			return
		}
	}
	for _, doc := range []struct {
		name string
		v    any
	}{{campaignFile, rec}, {preflightBundleFile, rec.Preflight}} {
		data, err := json.MarshalIndent(doc.v, "", "  ")
		if err != nil || zipBytes(zw, doc.name, data) != nil {
			return
		}
	}
}

// zipFile copies path into the zip as name; a missing file is skipped, not an error.
func zipFile(zw *zip.Writer, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	dst, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, f)
	return err
}

func zipBytes(zw *zip.Writer, name string, data []byte) error {
	dst, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = dst.Write(data)
	return err
}

// journalLine1 returns the journal's first line, or nil when there is none.
func journalLine1(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadBytes('\n')
	line = bytes.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil
	}
	return line
}
