package campaign

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// writeBundle plants a run bundle whose partial decryptions carry real
// trustee_id fields, the way `saksi-demo gen` emits them: one per
// (contest, trustee), contest-major.
func writeBundle(t *testing.T, dir string, electionID string, contests, trustees int) {
	t.Helper()
	var partials []string
	for c := 0; c < contests; c++ {
		for tr := 1; tr <= trustees; tr++ {
			pd := &saksiprotocolv1.PartialDecryption{
				Version:   1,
				TrusteeId: strconv.Itoa(tr),
				ContestId: "president/cand" + strconv.Itoa(c),
			}
			raw, err := proto.Marshal(pd)
			if err != nil {
				t.Fatal(err)
			}
			partials = append(partials, hex.EncodeToString(raw))
		}
	}
	b := onChainBundle{ElectionID: electionID, PartialDecryptions: partials}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Each trustee must own exactly one share per contest, grouped by the
// trustee_id inside the protobuf rather than by position in the array.
func TestPartialsGroupByTrusteeID(t *testing.T) {
	dir := t.TempDir()
	writeBundle(t, dir, "e1", 6, 3)
	raw, _ := os.ReadFile(filepath.Join(dir, "bundle.json"))
	var b onChainBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	byTrustee, err := partialsByTrustee(&b)
	if err != nil {
		t.Fatal(err)
	}
	if len(byTrustee) != 3 {
		t.Fatalf("want 3 trustees, got %d", len(byTrustee))
	}
	for id, ps := range byTrustee {
		if len(ps) != 6 {
			t.Fatalf("trustee %s owns %d shares, want one per contest (6)", id, len(ps))
		}
	}
}

// The gate: below threshold nothing publishes, at threshold it does. This is
// the property the whole ceremony exists to demonstrate.
func TestPublishRefusedBelowThresholdAndAllowedAtIt(t *testing.T) {
	s, h, exec := testServer(t, nil)
	c := good()
	c.Trustees = mk(3)
	c.Threshold = 2
	runID, dir, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeBundle(t, dir, runID, 4, 3)

	publish := func() int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, postJSON("/ceremony/publish", map[string]string{"run_id": runID}))
		return w.Code
	}

	if got := publish(); got != http.StatusConflict {
		t.Fatalf("publish with 0 of 2 trustees: got %d, want %d", got, http.StatusConflict)
	}

	if err := exec.CeremonySubmit(context.Background(), runID, c, "1"); err != nil {
		t.Fatalf("first trustee: %v", err)
	}
	if got := publish(); got != http.StatusConflict {
		t.Fatalf("publish with 1 of 2 trustees must still refuse: got %d", got)
	}

	if err := exec.CeremonySubmit(context.Background(), runID, c, "2"); err != nil {
		t.Fatalf("second trustee: %v", err)
	}
	st, err := exec.CeremonyStatus(runID, c)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unlocked || st.Submitted != 2 {
		t.Fatalf("threshold should be met: submitted=%d unlocked=%v", st.Submitted, st.Unlocked)
	}
	if got := publish(); got != http.StatusAccepted {
		t.Fatalf("publish at threshold: got %d, want %d", got, http.StatusAccepted)
	}
	// /ceremony/publish dispatches asynchronously (202), so acceptance alone
	// proves nothing completed. Wait for the run to actually report published —
	// that is the assertion worth making, and it also stops the background
	// goroutine from writing into the temp dir during cleanup.
	waitPublished(t, exec, runID, c)
}

// waitPublished polls the ceremony until the tally is published, failing if it
// never lands.
func waitPublished(t *testing.T, exec *Executor, runID string, c ElectionConfig) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st, err := exec.CeremonyStatus(runID, c)
		if err == nil && st.Published {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("tally never reached published state after the threshold was met")
}

// A trustee that holds no shares in this election must be rejected, not
// silently counted toward the quorum.
func TestSubmitUnknownTrusteeRejected(t *testing.T) {
	s, _, exec := testServer(t, nil)
	c := good()
	c.Trustees = mk(3)
	runID, dir, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeBundle(t, dir, runID, 2, 3)
	if err := exec.CeremonySubmit(context.Background(), runID, c, "99"); err == nil {
		t.Fatal("a trustee with no shares must be rejected")
	}
}

// Roster names come from the config; progress comes from the record. Editing
// the config must never desync the cards from the wire trustee ids.
func TestStatusRosterTracksConfig(t *testing.T) {
	s, _, exec := testServer(t, nil)
	c := good()
	c.Trustees = []Trustee{{Name: "COMELEC"}, {Name: "Watchdog"}, {Name: "University"}}
	c.Threshold = 2
	runID, dir, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeBundle(t, dir, runID, 3, 3)

	st, err := exec.CeremonyStatus(runID, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Trustees) != 3 || st.Trustees[0].Name != "COMELEC" || st.Trustees[0].ID != "1" {
		t.Fatalf("roster should mirror the config: %+v", st.Trustees)
	}
	if st.Trustees[0].Contests != 3 {
		t.Fatalf("each trustee owns one share per contest, got %d", st.Trustees[0].Contests)
	}
	if st.Unlocked {
		t.Fatal("nothing submitted yet — must not be unlocked")
	}
}

// Ground-truth runs have no ciphertexts, so the ceremony must refuse them
// rather than failing on a missing bundle.
func TestCeremonyRefusesGroundTruthRuns(t *testing.T) {
	s, h, _ := testServer(t, nil)
	c := good()
	c.Mode = ModeGroundTruth
	runID, _, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/ceremony/start", "/ceremony/publish"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, postJSON(path, map[string]string{"run_id": runID}))
		if w.Code != http.StatusConflict {
			t.Fatalf("%s on a ground-truth run: got %d, want %d", path, w.Code, http.StatusConflict)
		}
	}
}
