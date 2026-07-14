package bench

import (
	"strings"
	"testing"
)

func TestReconcilePassesWhenAllEqual(t *testing.T) {
	if err := Reconcile(1000, 1000, 1000); err != nil {
		t.Fatalf("clean run must reconcile, got: %v", err)
	}
}

func TestReconcileFailsOnSilentDrop(t *testing.T) {
	err := Reconcile(1000, 998, 1000)
	if err == nil || !strings.Contains(err.Error(), "dropped") {
		t.Fatalf("a drop must fail loudly, got: %v", err)
	}
}

func TestReconcileFailsOnGroundTruthMismatch(t *testing.T) {
	// No drops (submitted == committed) but the population is the wrong size.
	err := Reconcile(999, 999, 1000)
	if err == nil || !strings.Contains(err.Error(), "ground-truth") {
		t.Fatalf("a ground-truth mismatch must fail, got: %v", err)
	}
}
