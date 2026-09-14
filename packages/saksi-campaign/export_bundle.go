package campaign

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// The thesis export bundle: GET /api/campaigns/<id>/export streams a zip of
// the artifacts Chapter 4 cites for every run in the campaign (the file set the
// desktop-run notes copy by hand), plus the campaign's own summary, record and
// preflight snapshot, and a MANIFEST.txt saying what each run had and lacked.
// Streamed straight into the response; nothing touches disk.

// bundleRunFiles are copied from each run folder when present, as <run-id>/<file>.
var bundleRunFiles = []string{
	RunFile, PerfCSV, PerfSchemaFile, CorrectnessFile, NegativeTestsFile, CheckFile, TimingsFile,
}

const (
	// journalLine1File is the journal's first line (the env snapshot) in the bundle.
	journalLine1File = "journal-line1.json"
	// preflightBundleFile is the campaign's preflight snapshot in the bundle.
	preflightBundleFile = "preflight.json"
	// manifestFile lists, per run, the files included and the ones missing.
	manifestFile = "MANIFEST.txt"
)

// streamCampaignBundle writes the zip. A file that is absent is recorded as
// missing in the manifest; a file that cannot be READ aborts the response
// (http.ErrAbortHandler), so a client never receives a complete-looking zip
// with a hole in it.
func (s *Server) streamCampaignBundle(w http.ResponseWriter, rec campaignRecord) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+rec.ID+`.zip"`)
	zw := zip.NewWriter(w)
	must := func(err error) {
		if err != nil {
			panic(http.ErrAbortHandler)
		}
	}
	var manifest strings.Builder
	fmt.Fprintf(&manifest, "campaign %s (status %s)\n", rec.ID, rec.Status)
	list := func(title string, have, missing []string) {
		fmt.Fprintf(&manifest, "\n%s\n  included: %s\n  missing:  %s\n", title, strings.Join(have, ", "), strings.Join(missing, ", "))
	}
	tally := func(ok bool, name string, have, missing *[]string) {
		if ok {
			*have = append(*have, name)
		} else {
			*missing = append(*missing, name)
		}
	}

	seen := map[string]bool{}
	for _, rep := range rec.Reps {
		dir, err := s.store.Dir(rep.RunID)
		if err != nil || seen[rep.RunID] {
			continue
		}
		seen[rep.RunID] = true
		var have, missing []string
		for _, name := range bundleRunFiles {
			ok, err := zipFile(zw, rep.RunID+"/"+name, filepath.Join(dir, name))
			must(err)
			tally(ok, name, &have, &missing)
		}
		line, err := journalLine1(filepath.Join(dir, JournalFile))
		must(err)
		if line != nil {
			must(zipBytes(zw, rep.RunID+"/"+journalLine1File, line))
		}
		tally(line != nil, journalLine1File, &have, &missing)
		list(fmt.Sprintf("%s (%s %d, %s)", rep.RunID, rep.Kind, rep.Index, rep.Status), have, missing)
	}

	var have, missing []string
	if cdir, err := s.campaignDir(rec.ID); err == nil {
		ok, err := zipFile(zw, SummaryCSV, filepath.Join(cdir, SummaryCSV))
		must(err)
		tally(ok, SummaryCSV, &have, &missing)
	}
	for _, doc := range []struct {
		name string
		v    any
	}{{campaignFile, rec}, {preflightBundleFile, rec.Preflight}} {
		data, err := json.MarshalIndent(doc.v, "", "  ")
		must(err)
		must(zipBytes(zw, doc.name, data))
		have = append(have, doc.name)
	}
	list("campaign", have, missing)
	must(zipBytes(zw, manifestFile, []byte(manifest.String())))
	must(zw.Close())
}

// zipFile copies path into the zip as name. It reports false with no error
// when the file does not exist; any other open or read failure is an error.
func zipFile(zw *zip.Writer, name, path string) (bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	dst, err := zw.Create(name)
	if err != nil {
		return false, err
	}
	_, err = io.Copy(dst, f)
	return err == nil, err
}

func zipBytes(zw *zip.Writer, name string, data []byte) error {
	dst, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = dst.Write(data)
	return err
}

// journalLine1 returns the journal's first line; nil with no error when there
// is no journal or it is empty.
func journalLine1(path string) ([]byte, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	line, err := bufio.NewReader(f).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	line = bytes.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, nil
	}
	return line, nil
}
