package campaign

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
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

// hexSignedTally builds a TallyResult signed by trustees "1".."n" (the wire
// ids the generator emits) and hex-encodes it. Signature bytes are opaque
// here: the console only ever filters this list, it never verifies it — the
// chaincode and the auditor do that.
func hexSignedTally(t *testing.T, electionID string, trustees int) string {
	t.Helper()
	tr := &saksiprotocolv1.TallyResult{
		Version:    1,
		ElectionId: electionID,
		Totals:     []uint64{7, 3},
	}
	for i := 1; i <= trustees; i++ {
		tr.Signatures = append(tr.Signatures, &saksiprotocolv1.TrusteeSignature{
			TrusteeId: strconv.Itoa(i),
			Signature: bytes.Repeat([]byte{byte(i)}, 64),
		})
	}
	raw, err := proto.Marshal(tr)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

// signaturesIn returns the trustee ids signing a hex-encoded tally, in order.
func signaturesIn(t *testing.T, tallyHex string) []string {
	t.Helper()
	raw, err := hex.DecodeString(tallyHex)
	if err != nil {
		t.Fatal(err)
	}
	var tr saksiprotocolv1.TallyResult
	if err := proto.Unmarshal(raw, &tr); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, s := range tr.GetSignatures() {
		ids = append(ids, s.GetTrusteeId())
	}
	return ids
}

// The published tally must carry the signatures of the trustees who actually
// acted — not every signature the generator produced. Publishing the full list
// would make a 1-of-5 ceremony look like a 5-of-5 one on-chain.
func TestPublishedTallyCarriesOnlySubmittedSignatures(t *testing.T) {
	state := CeremonyState{
		Threshold: 2,
		Trustees: []CeremonyTrustee{
			{ID: "1", Submitted: true},
			{ID: "2"},
			{ID: "3", Submitted: true},
		},
	}
	got, err := tallyToPublish(hexSignedTally(t, "run-1", 3), state)
	if err != nil {
		t.Fatal(err)
	}
	if ids := signaturesIn(t, got); !reflect.DeepEqual(ids, []string{"1", "3"}) {
		t.Fatalf("published signatures = %v, want [1 3]", ids)
	}
}

// The rest of the tally must survive the re-encoding untouched.
func TestPublishedTallyPreservesTotalsAndElectionID(t *testing.T) {
	state := CeremonyState{Trustees: []CeremonyTrustee{{ID: "1", Submitted: true}}}
	got, err := tallyToPublish(hexSignedTally(t, "run-7", 3), state)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(got)
	if err != nil {
		t.Fatal(err)
	}
	var tr saksiprotocolv1.TallyResult
	if err := proto.Unmarshal(raw, &tr); err != nil {
		t.Fatal(err)
	}
	if tr.GetElectionId() != "run-7" || !reflect.DeepEqual(tr.GetTotals(), []uint64{7, 3}) {
		t.Fatalf("re-encoding changed the tally: %+v", &tr)
	}
}

// A bundle generated before tally signatures existed has none to filter. It is
// published verbatim — the chaincode is what refuses it, honestly, rather than
// this console silently rewriting an old artifact.
func TestPublishedTallyLeavesLegacyUnsignedTallyUnchanged(t *testing.T) {
	tallyHex := hexSignedTally(t, "run-1", 0)
	got, err := tallyToPublish(tallyHex, CeremonyState{Trustees: []CeremonyTrustee{{ID: "1", Submitted: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if got != tallyHex {
		t.Fatalf("legacy tally was rewritten: %q -> %q", tallyHex, got)
	}
}

func TestPublishedTallyRejectsUndecodableTally(t *testing.T) {
	if _, err := tallyToPublish("nothex", CeremonyState{}); err == nil {
		t.Fatal("a tally that is not hex must be an error, not a silent publish")
	}
}

// The wiring, end to end on the console side: real CeremonySubmit calls decide
// which signatures the tally carries.
func TestCeremonySubmitDecidesPublishedSignatures(t *testing.T) {
	s, _, exec := testServer(t, nil)
	c := good()
	c.Trustees = mk(3)
	c.Threshold = 2
	runID, dir, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeBundle(t, dir, runID, 2, 3)

	// Plant a signed tally in the bundle the way the generator now emits it.
	raw, err := os.ReadFile(filepath.Join(dir, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b onChainBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	b.Tally = hexSignedTally(t, runID, 3)
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"2", "3"} {
		if err := exec.CeremonySubmit(context.Background(), runID, c, id); err != nil {
			t.Fatalf("trustee %s: %v", id, err)
		}
	}
	state, err := exec.CeremonyStatus(runID, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tallyToPublish(b.Tally, state)
	if err != nil {
		t.Fatal(err)
	}
	if ids := signaturesIn(t, got); !reflect.DeepEqual(ids, []string{"2", "3"}) {
		t.Fatalf("published signatures = %v, want [2 3] (the trustees that submitted)", ids)
	}
}

// generateBundle copies the generator's tally verbatim; the signatures must
// survive that copy or there is nothing for the ceremony to filter.
func TestGenerateBundleKeepsTallySignatures(t *testing.T) {
	s, _, exec := testServer(t, nil)
	c := good()
	runID, dir, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tallyHex := hexSignedTally(t, runID, 3)
	header, err := json.Marshal(electionHeader{ElectionID: runID, Params: "aa", Dkg: "bb", N: 0, Tally: tallyHex})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "header.json"), header, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.generateBundle(runID); err != nil {
		t.Fatal(err)
	}
	b, err := exec.readBundle(runID)
	if err != nil {
		t.Fatal(err)
	}
	if ids := signaturesIn(t, b.Tally); !reflect.DeepEqual(ids, []string{"1", "2", "3"}) {
		t.Fatalf("bundle tally signatures = %v, want all three", ids)
	}
}
