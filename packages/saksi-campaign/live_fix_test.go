package campaign

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// Tests added by the task 3 review's fix round (S1 to S6, M2, M4, M8 and the
// /vote/ mount). The fixtures are live_test.go's.

// rawGET is a request the pollers can make from any goroutine: it touches
// none of liveConsole's own bookkeeping.
func rawGET(s *Server, path string) int {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "192.0.2.9:52000"
	s.ServeHTTP(rec, req)
	return rec.Code
}

// S1: the board and the election view are read while trustees post partials
// and signatures. Before the snapshot, the board iterated the live maps after
// releasing mu, which the race detector (and, on a bad day, the runtime)
// reports as a concurrent map read and write. Run with -race.
func TestLiveBoardAndViewReadWhileTrusteesPost(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveClosed)

	stop := make(chan struct{})
	var polls atomic.Int64
	var bad atomic.Value
	var wg sync.WaitGroup
	for _, path := range []string{"/api/board/" + runID, "/api/live/election", "/api/board/" + runID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if code := rawGET(c.s, path); code != http.StatusOK {
					bad.Store(fmt.Sprintf("%s: %d", path, code))
				}
				polls.Add(1)
			}
		}()
	}
	for id := 1; id <= 3; id++ {
		c.partials(id, liveContests)
	}
	c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(1), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(1)})
	c.ok(http.MethodPost, "/api/live/tally-sig", c.tok(2), map[string]any{"totals": []int{1, 0, 0, 1}, "signature": sig(2)})
	close(stop)
	wg.Wait()
	if v := bad.Load(); v != nil {
		t.Fatalf("a poll failed: %v", v)
	}
	if polls.Load() == 0 {
		t.Fatal("the pollers never ran")
	}
	if c.state() != LiveTallied {
		t.Fatalf("state %s, want tallied", c.state())
	}
	board := c.ok(http.MethodGet, "/api/board/"+runID, "", nil)
	dec := board["live"].(map[string]any)["decryption"].(map[string]any)
	if dec["trustees_decrypted"].(float64) != 3 || len(dec["tally_signatures"].([]any)) != 2 {
		t.Fatalf("board decryption after the posts: %v", dec)
	}
}

// S6: the board and the election view answer while a transition holds mu
// (as one does across a stalled chain submit).
func TestLiveBoardAndViewDoNotWaitOnTheStateLock(t *testing.T) {
	fx := newLiveFixture(t)
	c := fx.console()
	runID := c.toState(LiveOpen)
	c.s.live.mu.Lock()
	done := make(chan []int)
	go func() {
		done <- []int{rawGET(c.s, "/api/board/"+runID), rawGET(c.s, "/api/live/election")}
	}()
	codes := <-done // would deadlock (and time out) if either waited on mu
	c.s.live.mu.Unlock()
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK {
		t.Fatalf("board and view while mu is held: %v", codes)
	}
}
