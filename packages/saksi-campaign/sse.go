package campaign

import "sync"

// Event is one server-sent progress line for a run.
type Event struct {
	Phase string `json:"phase"`
	Level string `json:"level"` // info | error | done
	Msg   string `json:"msg"`
}

// Hub fans events out to per-run subscribers. Publishers (phase executors) never
// block on a slow subscriber — a full channel drops the event rather than
// stalling the run.
type Hub struct {
	mu   sync.Mutex
	subs map[string]map[chan Event]struct{}
}

// NewHub returns an empty hub.
func NewHub() *Hub {
	return &Hub{subs: make(map[string]map[chan Event]struct{})}
}

// Subscribe registers a listener for runID and returns its channel plus a
// cancel func that unsubscribes and closes the channel exactly once.
func (h *Hub) Subscribe(runID string) (<-chan Event, func()) {
	ch := make(chan Event, 64)
	h.mu.Lock()
	if h.subs[runID] == nil {
		h.subs[runID] = make(map[chan Event]struct{})
	}
	h.subs[runID][ch] = struct{}{}
	h.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			h.mu.Lock()
			if m, ok := h.subs[runID]; ok {
				delete(m, ch)
				if len(m) == 0 {
					delete(h.subs, runID)
				}
			}
			close(ch)
			h.mu.Unlock()
		})
	}
	return ch, cancel
}

// Publish delivers e to every current subscriber of runID. Non-blocking: a
// subscriber whose buffer is full misses this event.
func (h *Hub) Publish(runID string, e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[runID] {
		select {
		case ch <- e:
		default:
		}
	}
}
