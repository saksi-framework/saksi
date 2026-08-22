package campaign

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	clientsdk "github.com/saksi-framework/saksi/packages/saksi-bulletin/client-sdk"
	pb "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// fakeChainReader is the chainReader mock. Errors are per-method so table
// tests can target exactly the call that should fail.
type fakeChainReader struct {
	status       string
	statusErr    error
	tally        string
	tallyErr     error
	election     string // hex-encoded ElectionParameters returned by GetElection
	electionErr  error
	nullifiers   int
	nullifierErr error
}

func (f *fakeChainReader) GetElectionStatus(string) (string, error) { return f.status, f.statusErr }
func (f *fakeChainReader) GetElection(string) (string, error)       { return f.election, f.electionErr }
func (f *fakeChainReader) GetDKGTranscript(string) (string, error)  { return "", nil }
func (f *fakeChainReader) GetTally(string) (string, error)          { return f.tally, f.tallyErr }
func (f *fakeChainReader) CountCommittedBallots(string) (int, error) {
	return f.nullifiers, f.nullifierErr
}

// hexTallyResult builds a real TallyResult proto with totals for
// "president/cand0", "president/cand1", "vp/cand0" and hex-encodes it.
func hexTallyResult(t *testing.T) string {
	t.Helper()
	raw, err := proto.Marshal(&pb.TallyResult{
		ElectionId: "run-1",
		Totals:     []uint64{7, 3, 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

// hexElectionParams builds ElectionParameters with the given contest ids
// (aligned index-for-index with hexTallyResult's totals when there are 3,
// deliberately mismatched otherwise) and hex-encodes it.
func hexElectionParams(t *testing.T, contestIDs []string) string {
	t.Helper()
	raw, err := proto.Marshal(&pb.ElectionParameters{
		ElectionId: "run-1",
		ContestIds: contestIDs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

// writeFixtureTrail writes a 2-event trail.json into dir, mirroring what
// appendReceipt would have produced during an on-chain Submit.
func writeFixtureTrail(t *testing.T, dir string) {
	t.Helper()
	events := []TrailEvent{
		{Event: "CreateElection", Ref: "election", Receipt: clientsdk.Receipt{TxID: "tx-1", BlockNumber: 1}},
		{Event: "SubmitBallot", Ref: "n0", Receipt: clientsdk.Receipt{TxID: "tx-2", BlockNumber: 2}},
	}
	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trail.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildTrail(t *testing.T) {
	cases := []struct {
		name        string
		reader      *fakeChainReader
		operator    bool
		wantSealed  bool
		wantResults map[string]map[string]uint64
	}{
		{
			name:       "tally absent seals",
			reader:     &fakeChainReader{status: "open"},
			wantSealed: true,
		},
		{
			name: "tally present opens with events and live proof",
			reader: &fakeChainReader{
				status:     "closed",
				tally:      hexTallyResult(t),
				election:   hexElectionParams(t, []string{"president/cand0", "president/cand1", "vp/cand0"}),
				nullifiers: 2,
			},
			wantSealed: false,
			wantResults: map[string]map[string]uint64{
				"president": {"cand0": 7, "cand1": 3},
				"vp":        {"cand0": 5},
			},
		},
		{
			name:       "reader error seals",
			reader:     &fakeChainReader{status: "closed", tallyErr: errors.New("chain down")},
			wantSealed: true,
		},
		{
			name:       "operator bypasses absent tally",
			reader:     &fakeChainReader{status: "open"},
			operator:   true,
			wantSealed: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFixtureTrail(t, dir)
			led := &fakeLedger{}

			got, err := buildTrail(tc.reader, led, dir, "run-1", tc.operator)
			if err != nil {
				t.Fatalf("buildTrail: %v", err)
			}
			if got.Sealed != tc.wantSealed {
				t.Fatalf("Sealed = %v, want %v (resp: %+v)", got.Sealed, tc.wantSealed, got)
			}
			if got.Election != "run-1" {
				t.Fatalf("Election = %q, want run-1", got.Election)
			}
			if tc.wantSealed {
				if len(got.Events) != 0 {
					t.Fatalf("sealed response must carry no events, got %v", got.Events)
				}
				if got.Live != nil {
					t.Fatalf("sealed response must carry no live proof, got %+v", got.Live)
				}
				if got.Results != nil {
					t.Fatalf("sealed response must carry no results, got %+v", got.Results)
				}
				return
			}
			if len(got.Events) != 2 {
				t.Fatalf("open response events = %d, want 2 (from fixture trail.json)", len(got.Events))
			}
			if got.Live == nil {
				t.Fatal("open response must carry a live proof")
			}
			if got.Live.Partial {
				t.Fatalf("live proof should not be partial when all reads succeed: %+v", got.Live)
			}
			if tc.wantResults != nil && !reflect.DeepEqual(got.Results, tc.wantResults) {
				t.Fatalf("Results = %+v, want %+v", got.Results, tc.wantResults)
			}
		})
	}
}

func TestBuildTrailPartialLiveProofOnCountCommittedBallotsError(t *testing.T) {
	dir := t.TempDir()
	writeFixtureTrail(t, dir)
	reader := &fakeChainReader{
		status:       "closed",
		tally:        "aabbcc",
		nullifierErr: errors.New("peer unavailable"),
	}
	got, err := buildTrail(reader, &fakeLedger{}, dir, "run-1", false)
	if err != nil {
		t.Fatalf("buildTrail: %v", err)
	}
	if got.Sealed {
		t.Fatal("want open (tally published)")
	}
	if got.Live == nil {
		t.Fatal("want a live proof")
	}
	if !got.Live.Partial {
		t.Fatalf("want Partial=true when CountCommittedBallots errors, got %+v", got.Live)
	}
	if got.Live.PartialReason == "" {
		t.Fatal("want a non-empty PartialReason")
	}
}

func TestBuildTrailPartialLiveProofOnTallyDecodeFailure(t *testing.T) {
	dir := t.TempDir()
	writeFixtureTrail(t, dir)
	reader := &fakeChainReader{
		status: "closed",
		tally:  hexTallyResult(t), // 3 totals: president/cand0,cand1, vp/cand0
		election: hexElectionParams(t, []string{ // only 2 contest ids -> length mismatch
			"president/cand0", "president/cand1",
		}),
		nullifiers: 1,
	}
	got, err := buildTrail(reader, &fakeLedger{}, dir, "run-1", false)
	if err != nil {
		t.Fatalf("buildTrail: %v", err)
	}
	if got.Sealed {
		t.Fatal("want open (tally published)")
	}
	if got.Results != nil {
		t.Fatalf("want Results nil on decode failure, got %+v", got.Results)
	}
	if got.Live == nil {
		t.Fatal("want a live proof")
	}
	if !got.Live.Partial {
		t.Fatalf("want Partial=true when tally decode fails, got %+v", got.Live)
	}
	if got.Live.PartialReason != "tally decode failed" {
		t.Fatalf("PartialReason = %q, want %q", got.Live.PartialReason, "tally decode failed")
	}
}

func TestBuildTrailMissingTrailJSONIsEmptyEvents(t *testing.T) {
	dir := t.TempDir() // no trail.json written
	reader := &fakeChainReader{status: "closed", tally: "aabbcc"}
	got, err := buildTrail(reader, &fakeLedger{}, dir, "run-1", false)
	if err != nil {
		t.Fatalf("buildTrail: %v", err)
	}
	if got.Sealed {
		t.Fatal("want open (tally published)")
	}
	if len(got.Events) != 0 {
		t.Fatalf("want 0 events, got %v", got.Events)
	}
}

// --- HTTP-level tests --------------------------------------------------

func TestHandleTrailAPISealedWithoutOperator(t *testing.T) {
	s, h, _ := testServer(t, nil)
	dir, err := s.store.Dir("run-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixtureTrail(t, dir)
	s.dial = func() (chainReader, clientsdk.Ledger, error) {
		return &fakeChainReader{status: "open"}, &fakeLedger{}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/trail/run-1", nil)
	req.RemoteAddr = "203.0.113.5:1234" // not loopback
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	var resp trailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode trailResponse: %v", err)
	}
	if !resp.Sealed {
		t.Fatalf("want sealed, got %+v", resp)
	}
	if resp.Results != nil {
		t.Fatalf("sealed response must carry no results, got %+v", resp.Results)
	}
}

func TestHandleTrailAPILoopbackOperatorUnsealed(t *testing.T) {
	s, h, _ := testServer(t, nil)
	dir, err := s.store.Dir("run-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixtureTrail(t, dir)
	s.dial = func() (chainReader, clientsdk.Ledger, error) {
		return &fakeChainReader{
			status:     "open",
			nullifiers: 1,
		}, &fakeLedger{}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/trail/run-1?operator=1", nil)
	req.RemoteAddr = "127.0.0.1:54321" // loopback
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	var resp trailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode trailResponse: %v", err)
	}
	if resp.Sealed {
		t.Fatalf("operator from loopback should see unsealed trail, got %+v", resp)
	}
	if resp.Election != "run-1" || len(resp.Events) != 2 || resp.Live == nil {
		t.Fatalf("unexpected trailResponse: %+v", resp)
	}
}

func TestHandleTrailAPIChainUnreachableIs502(t *testing.T) {
	s, h, _ := testServer(t, nil)
	dir, err := s.store.Dir("run-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	s.dial = func() (chainReader, clientsdk.Ledger, error) {
		return nil, nil, errors.New("dial tcp: connection refused")
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/trail/run-1", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d: %s", rec.Code, rec.Body)
	}
}

func TestHandleTrailAPIUnknownRunIs400(t *testing.T) {
	s, h, _ := testServer(t, nil)
	s.dial = func() (chainReader, clientsdk.Ledger, error) {
		return &fakeChainReader{status: "open"}, &fakeLedger{}, nil
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/trail/Bad_Id", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestHandleTrailPageServesHTML(t *testing.T) {
	_, h, _ := testServer(t, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/trail/run-1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("want text/html, got %q", ct)
	}
}
