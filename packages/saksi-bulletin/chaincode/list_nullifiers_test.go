package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/ledger/queryresult"
	"github.com/hyperledger/fabric-protos-go/peer"
)

// fakeNullifierIterator is an in-memory shim.StateQueryIteratorInterface over a
// fixed KV slice (see fakeStub.GetStateByPartialCompositeKeyWithPagination).
type fakeNullifierIterator struct {
	kvs []*queryresult.KV
	pos int
}

func (it *fakeNullifierIterator) HasNext() bool { return it.pos < len(it.kvs) }
func (it *fakeNullifierIterator) Next() (*queryresult.KV, error) {
	if !it.HasNext() {
		return nil, fmt.Errorf("iterator exhausted")
	}
	kv := it.kvs[it.pos]
	it.pos++
	return kv, nil
}
func (it *fakeNullifierIterator) Close() error { return nil }

// GetStateByPartialCompositeKeyWithPagination mirrors the real peer semantics
// the resume path depends on: keys are returned in lexical order, a non-empty
// bookmark starts the page AT that key (inclusive), the returned metadata
// bookmark is the key AFTER the page (empty when the result set is exhausted),
// and at most pageSize records are returned per call.
func (f *fakeStub) GetStateByPartialCompositeKeyWithPagination(
	objectType string, attributes []string, pageSize int32, bookmark string,
) (shim.StateQueryIteratorInterface, *peer.QueryResponseMetadata, error) {
	prefix, err := f.CreateCompositeKey(objectType, attributes)
	if err != nil {
		return nil, nil, err
	}
	prefix += "\x00"
	var keys []string
	for k := range f.state {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	start := 0
	if bookmark != "" {
		start = sort.SearchStrings(keys, bookmark)
	}
	end := start + int(pageSize)
	if end > len(keys) {
		end = len(keys)
	}
	next := ""
	if end < len(keys) {
		next = keys[end]
	}
	kvs := make([]*queryresult.KV, 0, end-start)
	for _, k := range keys[start:end] {
		kvs = append(kvs, &queryresult.KV{Key: k, Value: f.state[k]})
	}
	meta := &peer.QueryResponseMetadata{
		FetchedRecordsCount: int32(len(kvs)),
		Bookmark:            next,
	}
	return &fakeNullifierIterator{kvs: kvs}, meta, nil
}

// SplitCompositeKey inverts fakeStub.CreateCompositeKey ("type\x00a\x00b").
func (f *fakeStub) SplitCompositeKey(key string) (string, []string, error) {
	parts := strings.Split(key, "\x00")
	if len(parts) < 2 {
		return "", nil, fmt.Errorf("malformed composite key %q", key)
	}
	return parts[0], parts[1:], nil
}

func seedNullifiers(t *testing.T, stub *fakeStub, electionID string, hexes []string) {
	t.Helper()
	for _, n := range hexes {
		key, err := stub.CreateCompositeKey(nullifierIndex, []string{electionID, n})
		if err != nil {
			t.Fatalf("create key: %v", err)
		}
		stub.state[key] = []byte{1}
	}
}

func TestListNullifiersPaginatesWithoutGapOrOverlap(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()

	want := []string{"aa01", "bb02", "cc03", "dd04", "ee05"}
	seedNullifiers(t, ctx.stub, "election-2026", want)
	// A second election that must NOT leak into the listing.
	seedNullifiers(t, ctx.stub, "other-election", []string{"ff99"})

	// Page through with pageSize 2 → expect pages of 2, 2, 1.
	var got []string
	bookmark := ""
	pages := 0
	for {
		raw, err := sc.ListNullifiers(ctx, "election-2026", 2, bookmark)
		if err != nil {
			t.Fatalf("ListNullifiers page %d: %v", pages, err)
		}
		var page NullifierPage
		if err := json.Unmarshal([]byte(raw), &page); err != nil {
			t.Fatalf("page %d is not valid JSON: %v", pages, err)
		}
		if len(page.Nullifiers) > 2 {
			t.Fatalf("page %d has %d records, page size is 2", pages, len(page.Nullifiers))
		}
		got = append(got, page.Nullifiers...)
		pages++
		if page.NextBookmark == "" {
			break
		}
		bookmark = page.NextBookmark
		if pages > 10 {
			t.Fatal("bookmark loop did not terminate")
		}
	}

	if pages != 3 {
		t.Fatalf("expected 3 pages (2+2+1), got %d", pages)
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("union of pages has %d nullifiers, want %d (no gap, no overlap)", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("nullifier %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestListNullifiersEmptyElection(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	raw, err := sc.ListNullifiers(ctx, "no-such-election", 100, "")
	if err != nil {
		t.Fatalf("ListNullifiers on empty election: %v", err)
	}
	var page NullifierPage
	if err := json.Unmarshal([]byte(raw), &page); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if len(page.Nullifiers) != 0 || page.NextBookmark != "" {
		t.Fatalf("expected empty page, got %+v", page)
	}
}

func TestListNullifiersRejectsBadPageSize(t *testing.T) {
	sc := &SmartContract{}
	ctx := newContext()
	if _, err := sc.ListNullifiers(ctx, "election-2026", 0, ""); err == nil {
		t.Fatal("pageSize 0 must be rejected")
	}
	if _, err := sc.ListNullifiers(ctx, "election-2026", -5, ""); err == nil {
		t.Fatal("negative pageSize must be rejected")
	}
	if _, err := sc.ListNullifiers(ctx, "election-2026", maxNullifierPageSize+1, ""); err == nil {
		t.Fatalf("pageSize above the %d cap must be rejected (peer totalQueryLimit)", maxNullifierPageSize)
	}
}
