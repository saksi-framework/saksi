package campaign

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// partialChain is a fakeLedger that behaves like the chaincode for partial
// decryptions: a committed partial is readable back, and a second one for the
// same (contest, trustee) is refused as a partial-duplicate.
type partialChain struct {
	*fakeLedger
	// commitThenFail is a contest id whose SubmitPartialDecryption commits
	// and is still reported as failed, once — the commit status lost after
	// the transaction was ordered.
	commitThenFail string
	submits        []string // contest ids SubmitPartialDecryption was sent, in order
}

func (p *partialChain) SubmitWithReceipt(fn string, args ...string) ([]byte, clientsdk.Receipt, error) {
	if fn != "SubmitPartialDecryption" {
		return p.fakeLedger.SubmitWithReceipt(fn, args...)
	}
	raw, err := hex.DecodeString(args[1])
	if err != nil {
		return nil, clientsdk.Receipt{}, err
	}
	var pd saksiprotocolv1.PartialDecryption
	if err := proto.Unmarshal(raw, &pd); err != nil {
		return nil, clientsdk.Receipt{}, err
	}
	key := pd.GetContestId() + "|" + pd.GetTrusteeId()
	p.mu.Lock()
	p.submits = append(p.submits, pd.GetContestId())
	_, dup := p.Partials[key]
	p.mu.Unlock()
	if dup {
		return nil, clientsdk.Receipt{}, errors.New("gate=partial-duplicate: trustee already submitted")
	}
	out, receipt, err := p.fakeLedger.SubmitWithReceipt(fn, args...)
	if err != nil {
		return out, receipt, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Partials == nil {
		p.Partials = map[string]string{}
	}
	p.Partials[key] = args[1]
	if pd.GetContestId() == p.commitThenFail {
		p.commitThenFail = ""
		return nil, clientsdk.Receipt{}, errors.New("commit status unavailable")
	}
	return out, receipt, nil
}

func (p *partialChain) submitted() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.submits)
}

// ceremonyStatusBody is the /api/ceremony JSON contract the three browser
// apps read, decoded by name so the test checks the wire shape.
type ceremonyStatusBody struct {
	Ready    bool   `json:"ready"`
	Busy     string `json:"busy"`
	Trustees []struct {
		ID          string `json:"id"`
		Submitted   bool   `json:"submitted"`
		Submitting  *bool  `json:"submitting"`
		SubmitError string `json:"submit_error"`
	} `json:"trustees"`
}

func getCeremony(t *testing.T, h http.Handler, runID string) ceremonyStatusBody {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ceremony/"+runID, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/ceremony: %d %s", w.Code, w.Body)
	}
	var body ceremonyStatusBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

const stateContests = 6

func stateContestID(i int) string { return "president/cand" + strconv.Itoa(i) }

// onChainCeremony is a run on an on-chain console whose ceremony talks to
// chain: a bundle with stateContests contests, 3 trustees, params naming the
// contests.
func onChainCeremony(t *testing.T) (*Server, http.Handler, *Executor, string, ElectionConfig, *partialChain) {
	t.Helper()
	s, h, exec := testServer(t, nil)
	c := good()
	c.Mode = "onchain"
	runID, dir, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeBundle(t, dir, runID, stateContests, 3)
	b, err := exec.readBundle(runID)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := 0; i < stateContests; i++ {
		ids = append(ids, stateContestID(i))
	}
	params, err := proto.Marshal(&saksiprotocolv1.ElectionParameters{ContestIds: ids})
	if err != nil {
		t.Fatal(err)
	}
	b.Params = hex.EncodeToString(params)
	if err := writeJSON(filepath.Join(dir, "bundle.json"), b); err != nil {
		t.Fatal(err)
	}
	if err := exec.writeCeremony(runID, c, nil); err != nil { // CeremonyStart finished
		t.Fatal(err)
	}
	exec.fabric = unreachableFabric(t)
	chain := &partialChain{fakeLedger: &fakeLedger{Partials: map[string]string{}}}
	exec.dialCeremony = func() (ceremonyChain, clientsdk.Ledger, func(), error) {
		return chain, chain, func() {}, nil
	}
	return s, h, exec, runID, c, chain
}

// bundlePartial is trustee's bundle share for contest i.
func bundlePartial(t *testing.T, exec *Executor, runID, trustee string, i int) string {
	t.Helper()
	b, err := exec.readBundle(runID)
	if err != nil {
		t.Fatal(err)
	}
	by, err := partialsByTrustee(b)
	if err != nil {
		t.Fatal(err)
	}
	return by[trustee][i]
}

// While a trustee's submit phase runs, the ceremony says so, and a second
// click for that trustee is refused with its own text rather than the generic
// busy-run one.
func TestCeremonyShowsSubmitInFlight(t *testing.T) {
	_, h, exec, runID, c, chain := onChainCeremony(t)
	entered := make(chan struct{}, stateContests)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAll)
	chain.beforeCommit = func(string) {
		entered <- struct{}{}
		<-release
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, postJSON("/ceremony/submit", map[string]string{"run_id": runID, "trustee_id": "1"}))
	if w.Code != http.StatusAccepted {
		t.Fatalf("first submit: %d %s", w.Code, w.Body)
	}
	<-entered

	st := getCeremony(t, h, runID)
	if st.Busy != "1" {
		t.Errorf("busy = %q mid-submit, want \"1\"", st.Busy)
	}
	for _, tr := range st.Trustees {
		if tr.Submitting == nil {
			t.Fatalf("trustee %s has no submitting field", tr.ID)
		}
		if *tr.Submitting != (tr.ID == "1") {
			t.Errorf("trustee %s submitting = %v", tr.ID, *tr.Submitting)
		}
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, postJSON("/ceremony/submit", map[string]string{"run_id": runID, "trustee_id": "1"}))
	if w.Code != http.StatusConflict {
		t.Fatalf("second submit: %d, want 409", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "trustee 1's shares are already being recorded" {
		t.Errorf("second submit body = %q", got)
	}

	releaseAll()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := exec.CeremonyStatus(runID, c)
		if err != nil {
			t.Fatal(err)
		}
		if st.Trustees[0].Submitted && getCeremony(t, h, runID).Busy == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("submit never finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A phase that failed after some contests committed is retried by skipping
// what the chain already holds, never by resubmitting it; its error shows on
// the trustee until the retry succeeds.
func TestCeremonyResubmitSkipsWhatTheChainHolds(t *testing.T) {
	_, h, exec, runID, c, chain := onChainCeremony(t)
	chain.commitThenFail = stateContestID(3)

	if err := exec.CeremonySubmit(context.Background(), runID, c, "1"); err == nil {
		t.Fatal("first submit should fail at contest 3")
	}
	st := getCeremony(t, h, runID)
	if st.Trustees[0].Submitted {
		t.Fatal("trustee 1 marked submitted after a failed phase")
	}
	if st.Trustees[0].SubmitError == "" {
		t.Fatal("no submit_error after a failed phase")
	}

	before := len(chain.submitted())
	if err := exec.CeremonySubmit(context.Background(), runID, c, "1"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	retried := chain.submitted()[before:]
	want := []string{stateContestID(4), stateContestID(5)}
	if !slices.Equal(retried, want) {
		t.Fatalf("retry submitted %v, want only %v (contests 0-3 skipped)", retried, want)
	}
	st = getCeremony(t, h, runID)
	if !st.Trustees[0].Submitted {
		t.Fatal("trustee 1 not submitted after a successful retry")
	}
	if st.Trustees[0].SubmitError != "" {
		t.Fatalf("submit_error %q survived a successful retry", st.Trustees[0].SubmitError)
	}
	dir, _ := exec.store.Dir(runID)
	trail, _ := os.ReadFile(filepath.Join(dir, trailNDJSONFile))
	if n := strings.Count(string(trail), "SubmitPartialDecryption"); n != stateContests-1 {
		t.Errorf("trail holds %d SubmitPartialDecryption receipts, want %d (the lost commit writes none, skips write none)", n, stateContests-1)
	}
}

// A share on chain that is not the bundle's is never overwritten or skipped:
// the phase fails and says which contest.
func TestCeremonySubmitRefusesADifferentShare(t *testing.T) {
	_, _, exec, runID, c, chain := onChainCeremony(t)
	chain.Partials[stateContestID(0)+"|1"] = "deadbeef"

	err := exec.CeremonySubmit(context.Background(), runID, c, "1")
	want := "a different share is already recorded for contest president/cand0 (trustee 1)"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}
	if got := chain.submitted(); len(got) != 0 {
		t.Fatalf("submitted %v after a conflicting share", got)
	}
}

// The chain marks a trustee submitted only when every contest's share is on
// it with the bundle's bytes.
func TestRefreshFromChainNeedsEveryContestsBytes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, exec *Executor, runID string, chain *partialChain)
		want  bool
	}{
		{"only the first contest", func(t *testing.T, exec *Executor, runID string, chain *partialChain) {
			chain.Partials[stateContestID(0)+"|1"] = bundlePartial(t, exec, runID, "1", 0)
		}, false},
		{"first contest differs", func(t *testing.T, exec *Executor, runID string, chain *partialChain) {
			for i := 0; i < stateContests; i++ {
				chain.Partials[stateContestID(i)+"|1"] = bundlePartial(t, exec, runID, "1", i)
			}
			chain.Partials[stateContestID(0)+"|1"] = "deadbeef"
		}, false},
		{"every contest matches", func(t *testing.T, exec *Executor, runID string, chain *partialChain) {
			for i := 0; i < stateContests; i++ {
				chain.Partials[stateContestID(i)+"|1"] = bundlePartial(t, exec, runID, "1", i)
			}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, exec, runID, c, chain := onChainCeremony(t)
			tc.plant(t, exec, runID, chain)
			st, err := exec.CeremonyStatus(runID, c)
			if err != nil {
				t.Fatal(err)
			}
			if st.Trustees[0].Submitted != tc.want {
				t.Fatalf("trustee 1 submitted = %v, want %v", st.Trustees[0].Submitted, tc.want)
			}
		})
	}
}

// A trustee this console already recorded is not probed again.
func TestRefreshFromChainSkipsLocallySubmitted(t *testing.T) {
	_, _, exec, runID, c, chain := onChainCeremony(t)
	if err := exec.markSubmitted(runID, c, "1"); err != nil {
		t.Fatal(err)
	}
	var probed []string
	exec.dialCeremony = func() (ceremonyChain, clientsdk.Ledger, func(), error) {
		return probeChain{chain, &probed}, chain, func() {}, nil
	}
	if _, err := exec.CeremonyStatus(runID, c); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(probed, "1") {
		t.Fatal("trustee 1 was probed although submitted locally")
	}
	if !slices.Contains(probed, "2") {
		t.Fatal("trustee 2 was not probed")
	}
}

type probeChain struct {
	*partialChain
	probed *[]string
}

func (p probeChain) GetPartialDecryption(e, contest, trustee string) (string, error) {
	*p.probed = append(*p.probed, trustee)
	return p.partialChain.GetPartialDecryption(e, contest, trustee)
}

// Trustees may act only once the election is closed: a generated bundle
// alone is not ready.
func TestCeremonyReadyOnlyAfterClose(t *testing.T) {
	s, _, exec := testServer(t, nil)
	c := good()
	runID, dir, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeBundle(t, dir, runID, 2, 3)
	st, err := exec.CeremonyStatus(runID, c)
	if err != nil {
		t.Fatal(err)
	}
	if st.Ready {
		t.Fatal("ready with a bundle and no close")
	}
	if err := exec.CeremonyStart(context.Background(), runID, c); err != nil {
		t.Fatal(err)
	}
	st, err = exec.CeremonyStatus(runID, c)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Ready || st.ClosedAt == nil {
		t.Fatalf("after CeremonyStart: ready=%v closed_at=%v", st.Ready, st.ClosedAt)
	}
}

// /runs carries the latest Verify's verdict and its failed check ids.
func TestRunsCarryTheAuditVerdict(t *testing.T) {
	s, h, exec := testServer(t, nil)
	c := good()
	runID, _, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	exec.run = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte(`{"overall":"fail","contests":[],"failed_checks":[{"check":"tally.accuracy","detail":"x"},{"check":"ballots.cds","detail":"y"}]}`), nil
	}
	if _, err := exec.Verify(context.Background(), runID, c); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/runs", nil))
	var rows []struct {
		RunID        string   `json:"run_id"`
		AuditOverall string   `json:"audit_overall"`
		AuditFailed  []string `json:"audit_failed_checks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("%v: %s", err, w.Body)
	}
	for _, r := range rows {
		if r.RunID != runID {
			continue
		}
		if r.AuditOverall != "fail" || !slices.Equal(r.AuditFailed, []string{"tally.accuracy", "ballots.cds"}) {
			t.Fatalf("audit_overall=%q audit_failed_checks=%v", r.AuditOverall, r.AuditFailed)
		}
		return
	}
	t.Fatalf("run %s not in /runs: %s", runID, w.Body)
}

// The in-flight mark is set before the 202 is written, so a poll straight
// after the POST can never see the trustee idle and re-offer the button.
func TestCeremonySubmitMarkedBeforeAccepted(t *testing.T) {
	_, h, _, runID, _, chain := onChainCeremony(t)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAll)
	chain.beforeCommit = func(string) { <-release }

	w := httptest.NewRecorder()
	h.ServeHTTP(w, postJSON("/ceremony/submit", map[string]string{"run_id": runID, "trustee_id": "2"}))
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body)
	}
	st := getCeremony(t, h, runID)
	if st.Busy != "2" || st.Trustees[1].Submitting == nil || !*st.Trustees[1].Submitting {
		t.Fatalf("straight after 202: busy=%q trustee 2 submitting=%v", st.Busy, st.Trustees[1].Submitting)
	}
	releaseAll()
	for deadline := time.Now().Add(5 * time.Second); getCeremony(t, h, runID).Busy != ""; {
		if time.Now().After(deadline) {
			t.Fatal("submit never finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A submit the run refuses (another phase holds it) leaves no in-flight mark.
func TestCeremonySubmitRefusedLeavesNoMark(t *testing.T) {
	s, h, _, runID, _, _ := onChainCeremony(t)
	if why := s.claim(runID, func() {}); why != "" {
		t.Fatal(why)
	}
	defer s.finish(runID)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, postJSON("/ceremony/submit", map[string]string{"run_id": runID, "trustee_id": "1"}))
	if w.Code != http.StatusConflict {
		t.Fatalf("submit on a busy run: %d, want 409", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "a phase is already running on this run" {
		t.Errorf("body = %q", got)
	}
	if st := getCeremony(t, h, runID); st.Busy != "" || *st.Trustees[0].Submitting {
		t.Fatalf("refused submit left busy=%q submitting=%v", st.Busy, *st.Trustees[0].Submitting)
	}
}

// A trustee the chain confirms in full is recorded, so later polls do not
// probe its shares again; SubmittedAt stays nil because the chain, not this
// console, observed it.
func TestRefreshFromChainRecordsAChainConfirmedTrustee(t *testing.T) {
	_, _, exec, runID, c, chain := onChainCeremony(t)
	for i := 0; i < stateContests; i++ {
		chain.Partials[stateContestID(i)+"|1"] = bundlePartial(t, exec, runID, "1", i)
	}
	var probed []string
	exec.dialCeremony = func() (ceremonyChain, clientsdk.Ledger, func(), error) {
		return probeChain{chain, &probed}, chain, func() {}, nil
	}
	st, err := exec.CeremonyStatus(runID, c)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Trustees[0].Submitted {
		t.Fatal("trustee 1 not confirmed from the chain")
	}
	probed = nil
	st, err = exec.CeremonyStatus(runID, c)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Trustees[0].Submitted || st.Trustees[0].SubmittedAt != nil {
		t.Fatalf("second poll: submitted=%v submitted_at=%v", st.Trustees[0].Submitted, st.Trustees[0].SubmittedAt)
	}
	if slices.Contains(probed, "1") {
		t.Fatalf("second poll probed trustee 1 again: %v", probed)
	}
}

// A ceremony.json written before closed_at existed still means the election
// closed; a bundle with no ceremony.json does not.
func TestCeremonyReadyForLegacyCeremonyFile(t *testing.T) {
	s, _, exec := testServer(t, nil)
	c := good()
	runID, dir, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeBundle(t, dir, runID, 2, 3)
	if st, _ := exec.CeremonyStatus(runID, c); st.Ready {
		t.Fatal("ready with a bundle and no ceremony.json")
	}
	legacy := `{"threshold":2,"trustees":[{"id":"1","name":"TA","submitted":false,"contests":0}],"ready":true,"started_at":"2026-09-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, CeremonyFile), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := exec.CeremonyStatus(runID, c)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Ready || st.ClosedAt != nil {
		t.Fatalf("legacy ceremony.json: ready=%v closed_at=%v, want ready with no closed_at", st.Ready, st.ClosedAt)
	}
}

// A start that wrote the bundle and then failed leaves the election unclosed:
// a submit is refused before any phase runs and creates no ceremony.json,
// and markSubmitted refuses on its own too.
func TestCeremonySubmitRefusedBeforeClose(t *testing.T) {
	s, h, exec := testServer(t, nil)
	c := good()
	c.AttackPlan = &AttackPlan{Stages: []string{StageDKG}}
	runID, dir, err := s.store.Create(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	writeBundle(t, dir, runID, 2, 3)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the operator cancels at the first attack pause
	if err := exec.CeremonyStart(ctx, runID, c); err == nil {
		t.Fatal("cancelled CeremonyStart reported success")
	}
	if _, err := os.Stat(filepath.Join(dir, "bundle.json")); err != nil {
		t.Fatal("the failed start should leave its bundle behind")
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, postJSON("/ceremony/submit", map[string]string{"run_id": runID, "trustee_id": "1"}))
	if w.Code != http.StatusConflict {
		t.Fatalf("submit before close: %d, want 409", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "the election is not closed yet: trustees can submit after Encrypt & record finishes" {
		t.Errorf("body = %q", got)
	}
	if err := exec.markSubmitted(runID, c, "1"); err == nil {
		t.Error("markSubmitted succeeded with no ceremony.json")
	}
	if _, err := os.Stat(filepath.Join(dir, CeremonyFile)); err == nil {
		t.Fatal("ceremony.json created before the election closed")
	}
}
