package campaign

import "testing"

func TestHubPublishDeliversToSubscriber(t *testing.T) {
	h := NewHub()
	ch, cancel := h.Subscribe("r1")
	defer cancel()

	h.Publish("r1", Event{Phase: "generate", Level: "info", Msg: "hello"})
	got := <-ch
	if got.Msg != "hello" || got.Phase != "generate" {
		t.Fatalf("unexpected event: %+v", got)
	}
}

func TestHubIsolatesRuns(t *testing.T) {
	h := NewHub()
	ch, cancel := h.Subscribe("r1")
	defer cancel()

	h.Publish("r2", Event{Msg: "other"}) // different run
	select {
	case e := <-ch:
		t.Fatalf("r1 should not receive r2 events, got %+v", e)
	default:
	}
}

func TestHubCancelClosesChannel(t *testing.T) {
	h := NewHub()
	ch, cancel := h.Subscribe("r1")
	cancel()
	if _, open := <-ch; open {
		t.Fatal("channel should be closed after cancel")
	}
	cancel() // idempotent, must not panic
}

func TestHubPublishNeverBlocks(t *testing.T) {
	h := NewHub()
	_, cancel := h.Subscribe("r1") // never drained
	defer cancel()
	// Far more than the buffer; must not block or panic (excess dropped).
	for i := 0; i < 1000; i++ {
		h.Publish("r1", Event{Msg: "flood"})
	}
}
