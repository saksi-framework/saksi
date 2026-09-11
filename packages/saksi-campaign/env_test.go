package campaign

import (
	"path/filepath"
	"testing"
)

// The committed configtx.yaml must carry the orderer parameters declared for
// the measurement environment (balotachain
// docs/desktop-runs/2026-09-11-orderer-probe.md §6). A silent edit there would
// change every run's throughput and latency, so pin the values here.
func TestCommittedConfigtxDeclaresAdoptedOrdererParameters(t *testing.T) {
	got, err := parseOrdererBatch(filepath.Join("..", "saksi-bulletin", "network", "configtx.yaml"))
	if err != nil {
		t.Fatalf("parseOrdererBatch: %v", err)
	}
	want := map[string]string{
		"BatchTimeout":         "2s",
		"MaxMessageCount":      "50",
		"AbsoluteMaxBytes":     "99 MB",
		"PreferredMaxBytes":    "2 MB",
		"SnapshotIntervalSize": "268435456", // 256 MB
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

// The snapshot records the opt-out rather than claiming the declared values
// apply when the operator asked for stock Fabric.
func TestProbeOrdererBatchRecordsOptOut(t *testing.T) {
	t.Setenv("SAKSI_CONFIGTX", "default")
	env := map[string]any{}
	probeOrdererBatch("irrelevant", env, func(string) { t.Fatal("should not be a null probe") })

	batch, ok := env["orderer_batch"].(map[string]any)
	if !ok {
		t.Fatalf("orderer_batch = %#v", env["orderer_batch"])
	}
	if batch["saksi_configtx"] != "default" {
		t.Errorf("saksi_configtx = %v, want default", batch["saksi_configtx"])
	}
	if _, present := batch["MaxMessageCount"]; present {
		t.Errorf("declared values must not be reported under the opt-out: %v", batch)
	}
}
