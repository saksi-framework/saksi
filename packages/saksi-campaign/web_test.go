package campaign

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIndexServesSelfContainedUI(t *testing.T) {
	_, h, _ := testServer(t, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`id="name"`, `id="trustees"`, `id="voters"`, `id="mode"`,
		"new EventSource", "/generate", "/run-all",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("UI is missing %q", want)
		}
	}
	// No external asset references (self-contained, CSP-friendly).
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
		t.Fatal("UI must not reference external assets")
	}
}

func TestTrailPageServesSelfContainedUI(t *testing.T) {
	_, h, _ := testServer(t, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/trail/some-run", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /trail/some-run want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`id="sealed-banner"`, `id="timeline"`, `id="results"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("trail UI is missing %q", want)
		}
	}
	// No external asset references (self-contained, CSP-friendly).
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
		t.Fatal("trail UI must not reference external assets")
	}
}
