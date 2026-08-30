package campaign

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Selecting on-chain with no Fabric network used to fall through to the local
// path and report success, while the page said "committing to Fabric". A run
// that looks committed and is not is worse than one that fails, so each
// ceremony entry point must refuse.
func TestOnChainCeremonyRefusesWithoutFabric(t *testing.T) {
	store := NewRunStore(t.TempDir())
	c := good()
	c.Mode = "onchain"
	runID, _, err := store.Create(c, time.Now())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// FabricConfig zero value => Enabled() is false.
	e := NewExecutor(store, NewHub(), "saksi-demo", "", FabricConfig{})
	ctx := context.Background()

	if err := e.CeremonySubmit(ctx, runID, c, "1"); err == nil {
		t.Error("CeremonySubmit accepted an on-chain run with no Fabric network")
	}
	if err := e.CeremonyPublish(ctx, runID, c); err == nil {
		t.Error("CeremonyPublish accepted an on-chain run with no Fabric network")
	}
}

// The fallback is narrowed, not removed: modes that never involve a ledger must
// still run locally exactly as before.
func TestLocalModesStillRunWithoutFabric(t *testing.T) {
	for _, mode := range []string{"offline", ModeGroundTruth} {
		c := good()
		c.Mode = mode
		if !localCeremonyOK(c) {
			t.Errorf("%s mode should still be allowed to run without a ledger", mode)
		}
	}
	c := good()
	c.Mode = "onchain"
	if localCeremonyOK(c) {
		t.Error("onchain mode must not be treated as a local ceremony")
	}
}

// The console should refuse an impossible run at step 1 rather than letting it
// reach the ceremony.
func TestGenerateRejectsOnChainWithoutFabric(t *testing.T) {
	store := NewRunStore(t.TempDir())
	hub := NewHub()
	srv := NewServer(store, NewExecutor(store, hub, "saksi-demo", "", FabricConfig{}),
		hub, FabricConfig{}, nil, time.Minute)

	body := `{"name":"e","trustees":[{"name":"a"},{"name":"b"},{"name":"c"}],"threshold":2,
	          "positions":1,"candidates":2,"voters":10,"distribution":"uniform","mode":"onchain"}`
	req := httptest.NewRequest("POST", "/generate", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400 for on-chain with no Fabric", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "fabric") {
		t.Errorf("error should name the missing flags, got %q", rec.Body.String())
	}
}

// The index must degrade to "not on chain" rather than failing when no ledger
// is reachable — that is its normal state during an offline demonstration.
func TestTrailIndexWithoutChain(t *testing.T) {
	store := NewRunStore(t.TempDir())
	hub := NewHub()
	c := good()
	runID, _, err := store.Create(c, time.Now())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	srv := NewServer(store, NewExecutor(store, hub, "saksi-demo", "", FabricConfig{}),
		hub, FabricConfig{}, nil, time.Minute)

	rows, chain := srv.trailIndex()
	if chain {
		t.Error("reported a chain connection with no Fabric configured")
	}
	if len(rows) != 1 || rows[0].ElectionID != runID {
		t.Fatalf("rows = %+v, want the one created run", rows)
	}
	if rows[0].OnChain {
		t.Error("row claims to be on chain with no chain reachable")
	}
	if rows[0].Mode != c.Mode || rows[0].Voters != c.Voters {
		t.Errorf("row lost its config: %+v", rows[0])
	}
}

// Every attack must declare where in the election it belongs, or it silently
// disappears from the wizard instead of appearing at its stage.
func TestEveryScenarioDeclaresAStage(t *testing.T) {
	valid := map[string]bool{}
	for _, st := range StageOrder {
		valid[st] = true
	}
	for _, sc := range Registry() {
		if !valid[sc.Stage] {
			t.Errorf("%s has stage %q, not one of %v", sc.ID, sc.Stage, StageOrder)
		}
	}
}

// Every stage must have something to show, and the union must be the whole
// catalogue — an attack in no stage would never be offered.
func TestStagesPartitionTheCatalogue(t *testing.T) {
	seen := 0
	for _, st := range StageOrder {
		got := ScenariosForStage(st)
		if len(got) == 0 {
			t.Errorf("stage %q has no attacks; the panel would render empty", st)
		}
		seen += len(got)
	}
	if seen != len(Registry()) {
		t.Errorf("stages cover %d attacks, catalogue has %d", seen, len(Registry()))
	}
}

// close-stage attacks describe something missing or reordered across the whole
// ballot set, which no single submission can express. Claiming otherwise would
// send them down the live path and produce a misleading result.
func TestOnlySubmittableStagesAreLiveCapable(t *testing.T) {
	for _, sc := range Registry() {
		want := sc.Stage != StageClose
		if sc.LiveCapable() != want {
			t.Errorf("%s (stage %s): LiveCapable=%v, want %v", sc.ID, sc.Stage, sc.LiveCapable(), want)
		}
	}
}

// The listing carries the stage through, since the page groups by it.
func TestListingsCarryStageAndLiveFlags(t *testing.T) {
	list, err := ScenarioListings(t.TempDir())
	if err != nil {
		t.Fatalf("listings: %v", err)
	}
	for _, l := range list {
		if l.Stage == "" {
			t.Errorf("%s listing has no stage", l.ID)
		}
		if l.WasLive {
			t.Errorf("%s claims a live verdict before being run", l.ID)
		}
	}
}

// A run that asked to skip attacks must not be offered any. The panels are
// opt-in either way, but the flag is what makes a clean end-to-end run one
// click, so it needs to survive into the stored config.
func TestSkipAttacksIsRecordedOnTheRun(t *testing.T) {
	store := NewRunStore(t.TempDir())
	c := good()
	c.SkipAttacks = true
	runID, _, err := store.Create(c, time.Now())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	recs, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, r := range recs {
		if r.RunID == runID && !r.Config.SkipAttacks {
			t.Error("skip_attacks did not survive into the stored run config")
		}
	}
	if err := c.Validate(); err != nil {
		t.Errorf("a skip-attacks run should still validate: %v", err)
	}
}
