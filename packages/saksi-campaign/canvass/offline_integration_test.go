//go:build canvassoffline

package canvass

// Integration test of the offline engine against the real saksi-demo and the
// balotachain attack tools:
//
//	go test -tags canvassoffline -run TestOfflineEngine -v ./canvass/
//
// SAKSI_DEMO_BIN defaults to <repo>/target/release/saksi-demo; the tools come
// from SAKSI_CANVASS_TOOLS or the sibling balotachain checkout.
// SAKSI_CANVASS_FIXTURE, when set, is the fixture folder (kept between runs).

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestOfflineEngine(t *testing.T) {
	bin := os.Getenv("SAKSI_DEMO_BIN")
	if bin == "" {
		bin, _ = filepath.Abs(filepath.Join("..", "..", "..", "target", "release", "saksi-demo"))
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("saksi-demo: %v (cargo build --release -p saksi-demo)", err)
	}
	tools := toolsDir(t)
	if tools == "" {
		t.Fatal("balotachain tools/security/canvass not found (set SAKSI_CANVASS_TOOLS)")
	}
	root := t.TempDir()
	fixture := os.Getenv("SAKSI_CANVASS_FIXTURE")
	if fixture == "" {
		fixture = filepath.Join(root, "fixture")
	}
	t0 := time.Now()
	if err := BuildFixture(context.Background(), fixture, bin, tools, testLog{t}); err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture ready in %v", time.Since(t0))
	t1 := time.Now()
	if err := BuildFixture(context.Background(), fixture, bin, tools, testLog{t}); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t1); d > time.Second {
		t.Errorf("cached fixture took %v: not reused", d)
	}

	attempts := filepath.Join(root, "attempts")
	old := ArrivalDelay
	ArrivalDelay = 0
	defer func() { ArrivalDelay = old }()

	for _, sc := range Scenarios() {
		if !sc.Live {
			continue
		}
		t.Run(sc.ID, func(t *testing.T) {
			var events []Event
			start := time.Now()
			res, err := RunAttempt(context.Background(), fixture, attempts, bin, tools, sc.ID, func(e Event) { events = append(events, e) })
			if err != nil {
				t.Fatalf("attempt: %v", err)
			}
			t.Logf("%s: %s in %v", sc.ID, res.Final.Assert, time.Since(start).Round(time.Millisecond))
			if res.Final.Verdict != "PASS" {
				t.Fatalf("verdict %s: %s", res.Final.Verdict, res.Final.Assert)
			}
			if !sameSet(res.Final.Got, sc.Expected) {
				t.Errorf("got %v, expected %v", res.Final.Got, sc.Expected)
			}
			if events[0].Type != EventStart || events[len(events)-1].Type != EventFinal {
				t.Errorf("event order: first %s last %s", events[0].Type, events[len(events)-1].Type)
			}
			arrivals := 0
			for _, e := range events {
				if e.Type == EventArrival {
					arrivals++
					if e.Seq != arrivals {
						t.Errorf("arrival seq %d at #%d", e.Seq, arrivals)
					}
				}
			}
			if arrivals != 10 {
				t.Errorf("%d arrivals, want 10", arrivals)
			}
			if sc.ID != "clean" {
				want := wantTiles[sc.ID]
				for state, w := range map[string][]string{TileTampered: want.tampered, TileRejected: want.rejected, TileMissing: want.missing} {
					if got := byState(res.Tiles, state); !reflect.DeepEqual(got, w) && !(len(got) == 0 && len(w) == 0) {
						t.Errorf("final %s tiles = %v, want %v", state, got, w)
					}
				}
			} else if got := byState(res.Tiles, TileReceived); len(got) != 10 {
				t.Errorf("clean: received %v", got)
			}
			if _, err := os.Stat(filepath.Join(res.Dir, EventsFile)); err != nil {
				t.Error(err)
			}
			if _, err := os.Stat(filepath.Join(res.Dir, AttemptFile)); err != nil {
				t.Error(err)
			}
		})
	}

	// One attempt with the production arrival delay: the console's budget is
	// 30 s end to end.
	ArrivalDelay = old
	start := time.Now()
	var mid []string
	res, err := RunAttempt(context.Background(), fixture, attempts, bin, tools, "T13", func(e Event) {
		if e.Type == EventArrival && e.Seq == 3 {
			mid = byState(e.Tiles, TileWaiting)
		}
	})
	if err != nil || res.Final.Verdict != "PASS" {
		t.Fatalf("timed T13: %v %+v", err, res)
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("timed attempt took %v, budget 30 s", d)
	} else {
		t.Logf("timed attempt (600 ms between arrivals): %v", d.Round(time.Millisecond))
	}
	if want := []string{"p04", "p05", "p06", "p07", "p08", "p09", "p10"}; !reflect.DeepEqual(mid, want) {
		t.Errorf("waiting after arrival 3 = %v, want %v", mid, want)
	}
	if want := fmt.Sprintf("%d-T13", res.N); filepath.Base(res.Dir) != want || res.N < 2 {
		t.Errorf("attempt folder %s (n=%d), want %s after the earlier attempts", res.Dir, res.N, want)
	}
}

func sameSet(a, b []string) bool {
	x := append([]string{}, a...)
	y := append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	return reflect.DeepEqual(x, y) || (len(x) == 0 && len(y) == 0)
}

type testLog struct{ t *testing.T }

func (l testLog) Write(p []byte) (int, error) {
	l.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}
