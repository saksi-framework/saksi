package campaign

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIndexServesSelfContainedUI(t *testing.T) {
	_, h, _ := testServer(t, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`id="name"`, `id="trustees"`, `id="voters"`, `id="mode"`,
		"new EventSource", "/generate", "/run-all",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("UI is missing %q", want)
		}
	}
	// No external asset references (self-contained, CSP-friendly).
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
		t.Fatal("UI must not reference external assets")
	}
}

func TestTrailPageServesSelfContainedUI(t *testing.T) {
	_, h, _ := testServer(t, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/trail/some-run", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /trail/some-run want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`id="sealed-banner"`, `id="timeline"`, `id="results"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("trail UI is missing %q", want)
		}
	}
	// No external asset references (self-contained, CSP-friendly).
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
		t.Fatal("trail UI must not reference external assets")
	}
}

// The wizard is one self-contained file with no build step, so nothing type-
// checks its JavaScript. A function that is called but never defined is valid
// syntax and fails only at runtime, in the browser, silently killing whatever
// feature depended on it.
//
// This happened: a patch inserted the in-lifecycle attack panel's call sites
// but its definitions landed nowhere, so `renderStages` threw a ReferenceError
// and the whole live-attack UI was dead while the backend tested green.
func TestWizardDefinesEveryFunctionItCalls(t *testing.T) {
	page, err := webFS.ReadFile("web/wizard.html")
	if err != nil {
		t.Fatalf("read wizard.html: %v", err)
	}
	js := string(page)

	// Functions the page wires to events or calls across sections — the ones a
	// bad merge or a mis-anchored patch can silently drop.
	for _, fn := range []string{
		"renderStageResults", "watchPauses", "stopPauseWatch", "renderPause", "attackRow",
		"verdictChip", "gateLine", "attackPlan", "loadAttacks", "showAttack", "runAttack",
		"paintAttack", "renderBoard", "loadResults", "renderRail", "renderARail",
		"showIDChip", "startRun", "runCheck", "startSaksi", "startCeremony",
		"startVerify", "refreshCeremony", "renderTrail", "openStream", "closeStream",
		"showLoader", "hideLoader", "fileChips", "artifactsFor", "config",
	} {
		called := strings.Contains(js, fn+"(")
		defined := strings.Contains(js, "function "+fn+"(") ||
			strings.Contains(js, "const "+fn+" =") ||
			strings.Contains(js, "let "+fn+" =")
		if called && !defined {
			t.Errorf("wizard.html calls %s() but never defines it — "+
				"it will throw a ReferenceError and silently disable that feature", fn)
		}
	}

	// Module-level state the handlers close over. runID and friends are
	// declared in one combined let statement, so match the initialiser rather
	// than a "let <name>" prefix.
	for _, decl := range []string{
		"pauseTimer = null", "let attacks", "let caps", "runID = null",
	} {
		if !strings.Contains(js, decl) {
			t.Errorf("wizard.html is missing the declaration %q", decl)
		}
	}
}

// The wizard's defaults ARE the paper's configuration (3 of 5 trustees), and
// its download chips name real files. Both are plain string literals no
// compiler checks, and both have already drifted once: Task 2 renamed
// trail.json to trail.ndjson while the chip label kept pointing at the old
// name, offering a download that no longer exists.
func TestWizardDefaultsMatchThePaper(t *testing.T) {
	for _, f := range []string{"web/wizard.html", "web/index.html"} {
		page, err := webFS.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if strings.Contains(string(page), "trail.json") {
			t.Errorf("%s still offers trail.json — Task 2 replaced it with trail.ndjson", f)
		}
	}
	js, err := webFS.ReadFile("web/wizard.html")
	if err != nil {
		t.Fatalf("read wizard.html: %v", err)
	}
	for _, want := range []string{
		`"COMELEC", "Civil Society Watch", "University IT", "Academe Observer", "Bar Association"`,
		`id="threshold" type="number" min="1" value="3"`,
		"3 of 5 (paper configuration)",
	} {
		if !strings.Contains(string(js), want) {
			t.Errorf("wizard.html no longer carries the paper configuration %q", want)
		}
	}
}
