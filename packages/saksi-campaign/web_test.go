package campaign

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
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
		"checkAuth", "needSignIn", "showApp", "apiFetch", "errorBody", "renderErr", "setMode",
		"showSetup", "syncPlan", "schedulePreflight", "runPreflight", "renderPreflight", "syncStart",
		"watchJob", "watchLadder", "syncReset", "followReset", "startCampaign", "openCampaign",
		"refreshCampaign", "renderCampaign", "loadCampaigns", "loadRuns", "renderRuns", "runAction",
		"whenIdle", "renderFaultRuns", "syncFault", "applyPreset", "renderPresets", "onFormChange",
		"syncHints", "hostCell", "boot", "refreshStudy", "openRun", "syncSweepHint", "duration",
		"busy", "addRetry",
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

// A campaign row's "contended" chip must mean what preflight's host warning
// means: the page carries the threshold as a literal, pinned here to the Go one.
func TestWizardContendedThresholdMatchesPreflight(t *testing.T) {
	page, err := webFS.ReadFile("web/wizard.html")
	if err != nil {
		t.Fatalf("read wizard.html: %v", err)
	}
	want := fmt.Sprintf("const HOST_WARN_FRACTION = %v;", hostLoadWarnFraction)
	if !strings.Contains(string(page), want) {
		t.Errorf("wizard.html must declare %q to match preflight.go's hostLoadWarnFraction", want)
	}
}

// The wizard offers the peer-restart fault only on runs the fault route would
// arm (handleFault, fault.go in PR #46): on-chain, not a campaign repetition,
// no attack plan, no time-bounded window, ballot window not opened, idle and
// generated. The page's filter is JavaScript no Go test can run, so each clause
// is pinned here as text; dropping one would offer a run the route refuses.
func TestWizardFaultFilterMirrorsTheFaultRoute(t *testing.T) {
	page, err := webFS.ReadFile("web/wizard.html")
	if err != nil {
		t.Fatalf("read wizard.html: %v", err)
	}
	js := string(page)
	start := strings.Index(js, "const faultEligible = ")
	if start < 0 {
		t.Fatal("wizard.html no longer declares faultEligible")
	}
	end := strings.Index(js[start:], "\n};")
	if end < 0 {
		t.Fatal("faultEligible has no end")
	}
	body := js[start : start+end]
	for clause, rule := range map[string]string{
		`c.mode === "onchain"`: "run mode must be onchain",
		`!c.rep`:               "a campaign repetition never carries a fault",
		`!c.attack_plan`:       "a run with an attack plan is refused",
		`!c.fault_plan`:        "a run already armed",
		`!(c.window_s > 0)`:    "a time-bounded window is refused",
		`!r.busy`:              "the route claims the run's lock",
		`r.status !== "new"`:   "the run needs a journal (generated)",
		`!r.ballots_started`:   "armed only before stage.ballots.start",
	} {
		if !strings.Contains(body, clause) {
			t.Errorf("faultEligible lost %q (%s)", clause, rule)
		}
	}
}

// Every campaign option the route accepts can be sent from the wizard: a field
// renamed on one side and not the other would silently drop, say, the sweep
// from row 5, because the route only refuses unknown keys, not missing ones.
func TestWizardSendsEveryCampaignOption(t *testing.T) {
	page, err := webFS.ReadFile("web/wizard.html")
	if err != nil {
		t.Fatalf("read wizard.html: %v", err)
	}
	js := string(page)
	start := strings.Index(js, "async function startCampaign()")
	if start < 0 {
		t.Fatal("wizard.html no longer defines startCampaign")
	}
	body := js[start : start+strings.Index(js[start:], "\n}\n")]
	opts := reflect.TypeOf(CampaignOptions{})
	for i := 0; i < opts.NumField(); i++ {
		name := strings.Split(opts.Field(i).Tag.Get("json"), ",")[0]
		if !strings.Contains(body, name+":") && !strings.Contains(body, "body."+name+" =") {
			t.Errorf("startCampaign never sends the campaign option %q", name)
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

// Step 4 renders each trustee card from the server's ceremony state, not from
// the click: a submit in flight shows a disabled "Recording…", a failed one its
// error and "Try again", and while another trustee's shares are being recorded
// the rest wait. A 409 from the submit route re-polls rather than re-enabling
// "Submit share", which is what left the card stuck before.
func TestWizardCeremonyRendersSubmitState(t *testing.T) {
	page, err := webFS.ReadFile("web/wizard.html")
	if err != nil {
		t.Fatalf("read wizard.html: %v", err)
	}
	js := string(page)
	start := strings.Index(js, "async function refreshCeremony()")
	if start < 0 {
		t.Fatal("wizard.html no longer defines refreshCeremony")
	}
	body := js[start : start+strings.Index(js[start:], "\n}\n")]
	for clause, rule := range map[string]string{
		"tr.submitting":     "a submit in flight disables the card",
		`"Recording…"`:      "the in-flight label",
		"tr.submit_error":   "a failed submit shows its error",
		`"Try again"`:       "the retry label",
		"st.busy !== tr.id": "other trustees wait while one is recorded",
		"Another trustee's share is being recorded; this unlocks when it finishes.": "the wait text",
		"st.published || !!st.busy": "publish stays disabled while a submit runs",
		`e.status === 409) { $("err3").textContent = ""; refreshCeremony(); return; }`: "a 409 clears its refusal and re-polls instead of restoring the button",
	} {
		if !strings.Contains(body, clause) {
			t.Errorf("refreshCeremony lost %q (%s)", clause, rule)
		}
	}
	if strings.Contains(body, `b.textContent = "Submit share"`) {
		t.Error(`refreshCeremony's click handler restores "Submit share" on failure; it must keep the card's own label and re-poll on 409`)
	}
}

// webBlock returns the text of page from the first occurrence of start to the
// next line that closes a top-level block, so a check reads one handler.
func webBlock(t *testing.T, page, start string) string {
	t.Helper()
	i := strings.Index(page, start)
	if i < 0 {
		t.Fatalf("page no longer contains %q", start)
	}
	j := strings.Index(page[i:], "\n}")
	if j < 0 {
		t.Fatalf("%q has no end", start)
	}
	return page[i : i+j]
}

func readWeb(t *testing.T, name string) string {
	t.Helper()
	b, err := webFS.ReadFile("web/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// Destructive console actions ask first: the network reset and the T3 fault
// are gated on a typed word, cancelling a campaign or a classic-console run on
// a confirm(). DESIGN.md "Do's and Don'ts", saksi console bullet.
func TestConsoleDestructiveActionsConfirm(t *testing.T) {
	wiz := readWeb(t, "wizard.html")
	for block, want := range map[string]string{
		"function syncReset()":                `$("rsConfirm").value !== "RESET"`,
		"function syncFault()":                `$("ftConfirm").value !== "RESTART"`,
		`$("cvCancel").onclick = async () =>`: "if (!confirm(",
	} {
		if !strings.Contains(webBlock(t, wiz, block), want) {
			t.Errorf("wizard.html %s lost its confirmation %q", block, want)
		}
	}
	idx := readWeb(t, "index.html")
	if !strings.Contains(webBlock(t, idx, `$("btnCancel").onclick = () =>`), "confirm(") {
		t.Error("index.html's Cancel no longer asks before cancelling the run")
	}
}

// A disabled console control says why in its title, and a control whose
// request is in flight says what it is doing, so a greyed-out button is never
// a mystery.
func TestConsoleDisabledControlsSayWhy(t *testing.T) {
	wiz := readWeb(t, "wizard.html")
	for block, wants := range map[string][]string{
		"function syncReset()": {"type RESET in the box to enable", "set voters and positions", `"Resetting…"`},
		"function syncFault()": {"type RESTART in the box to enable", "no eligible run: generate an on-chain election first", `"Arming…"`},
		"function syncStart()": {"preflight blocks this run: ", "starting; wait for the console to answer"},
		"async function refreshCeremony()": {
			"needs ${t} of ${n} trustee shares", "the tally is already published", `"Publishing…"`,
			"a trustee's share is being recorded; this unlocks when it finishes", "publish the tally first",
		},
		"async function runAction(":           {`"Resuming…"`, `"Reconciling…"`},
		`$("cvCancel").onclick = async () =>`: {`"Cancelling…"`},
	} {
		body := webBlock(t, wiz, block)
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Errorf("wizard.html %s lost %q", block, want)
			}
		}
	}
	// The publish flag is released once the run is idle, so the button never
	// stays on "Publishing…" after a publish that failed on the server.
	if !strings.Contains(webBlock(t, wiz, `$("btnPublish").onclick = async () =>`), "whenIdle(id") {
		t.Error("the Publish handler no longer waits for the run to go idle before releasing its busy state")
	}
}

// Load failures show inline with a Retry, not a silent empty panel.
func TestConsoleErrorsOfferRetry(t *testing.T) {
	wiz := readWeb(t, "wizard.html")
	for _, want := range []string{
		`addRetry("err2b", runCheck)`, `addRetry("err2", startSaksi)`, `addRetry("err4", startVerify)`,
		`addRetry("rlLoadErr", loadRuns)`, `addRetry("cpErr", loadCampaigns)`, `addRetry("cvErr", refreshCampaign)`,
	} {
		if !strings.Contains(wiz, want) {
			t.Errorf("wizard.html lost the retry %q", want)
		}
	}
	if !strings.Contains(readWeb(t, "index.html"), `errRetry($("history")`) {
		t.Error("index.html's history no longer offers a retry when it fails to load")
	}
	if !strings.Contains(readWeb(t, "trail.html"), `$("btnRetry").onclick = load`) {
		t.Error("trail.html's error no longer offers a retry")
	}
}

// Below the threshold the wizard must show the system refusing, not a grey
// button: "Attempt decryption" stays clickable, the real request goes out, and
// the server's 409 text lands in a persistent refusal panel with the time and
// share count. The panel keys on the server's own prefix, so the two must agree.
func TestWizardCeremonyShowsSubthresholdRefusal(t *testing.T) {
	wiz := readWeb(t, "wizard.html")
	if !strings.Contains(wiz, `id="refusalBox"`) {
		t.Error("the ceremony step lost its refusal panel")
	}
	refresh := webBlock(t, wiz, "async function refreshCeremony()")
	for _, want := range []string{
		`$("btnPublish").disabled = st.published || !!st.busy || publishing;`,
		`"Attempt decryption"`, "renderRefusals(st)",
	} {
		if !strings.Contains(refresh, want) {
			t.Errorf("refreshCeremony lost %q", want)
		}
	}
	if strings.Contains(refresh, `disabled = !st.unlocked`) {
		t.Error("publish is disabled below the threshold again; the refusal demo needs it clickable")
	}
	panel := webBlock(t, wiz, "function renderRefusals(st)")
	for _, want := range []string{"Decryption refused below the threshold", "toLocaleTimeString()", "shares</b> (threshold", "r.msg"} {
		if !strings.Contains(panel, want) {
			t.Errorf("renderRefusals lost %q", want)
		}
	}
	click := webBlock(t, wiz, `$("btnPublish").onclick = async () =>`)
	for _, want := range []string{`post("/ceremony/publish"`, `e.status === 409 && /^Decryption refused:/.test(e.message)`, "msg: e.message"} {
		if !strings.Contains(click, want) {
			t.Errorf("the Publish handler lost %q", want)
		}
	}
	msg := belowThresholdRefusal(CeremonyState{Threshold: 3, Submitted: 2, Trustees: make([]CeremonyTrustee, 5)})
	if !strings.HasPrefix(msg, "Decryption refused:") {
		t.Errorf("server refusal %q no longer starts with the prefix the wizard matches", msg)
	}
}

// An on-chain run's correctness.csv carries a local and a ledger block of rows
// for the same contests. The wizard's results step once rendered both blocks as
// contests and fed both to the board, which doubled every count ("2,000 votes
// counted" for 1,000 voters) and showed false ties.
func TestWizardResultsCountEachContestOnce(t *testing.T) {
	body := webBlock(t, readWeb(t, "wizard.html"), "async function loadResults()")
	for clause, rule := range map[string]string{
		`header.indexOf("source")`:                     "the source column is located by name",
		`r[src] === "ledger"`:                          "ledger rows are told apart from local ones",
		`const rows = all.filter((r) => !isLedger(r))`: "the table and the board take one row per contest",
		"Ledger decoded":                               "the ledger shows as a second source of the same contest",
		"renderBoard(rows)":                            "the board reads the local rows only",
	} {
		if !strings.Contains(body, clause) {
			t.Errorf("loadResults lost %q (%s)", clause, rule)
		}
	}
}
