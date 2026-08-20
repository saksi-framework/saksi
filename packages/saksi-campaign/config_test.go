package campaign

import "testing"

// mk builds n trustees with default names.
func mk(n int) []Trustee {
	ts := make([]Trustee, n)
	for i := range ts {
		ts[i] = Trustee{Name: "T" + string(rune('A'+i))}
	}
	return ts
}

func good() ElectionConfig {
	return ElectionConfig{
		Name: "midterm", Trustees: mk(3), Threshold: 2,
		Positions: 1, Candidates: 2, Voters: 10,
		Distribution: "uniform", Mode: "offline",
	}
}

func TestValidateAcceptsGood(t *testing.T) {
	if err := good().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateRejectsThresholdAboveTrustees(t *testing.T) {
	c := good()
	c.Threshold = 4 // > 3 trustees
	if err := c.Validate(); err == nil {
		t.Fatal("t>n must be rejected")
	}
}

func TestValidateRejectsTooManyTrustees(t *testing.T) {
	c := good()
	c.Trustees = mk(16) // > MaxTrustees
	c.Threshold = 9
	if err := c.Validate(); err == nil {
		t.Fatalf("n>%d must be rejected", MaxTrustees)
	}
}

func TestValidateRejectsEmptyName(t *testing.T) {
	c := good()
	c.Name = "   "
	if err := c.Validate(); err == nil {
		t.Fatal("empty name must be rejected")
	}
}

func TestValidateRejectsEmptyTrusteeName(t *testing.T) {
	c := good()
	c.Trustees[1].Name = ""
	if err := c.Validate(); err == nil {
		t.Fatal("empty trustee name must be rejected")
	}
}

func TestValidateRejectsZeroVoters(t *testing.T) {
	c := good()
	c.Voters = 0
	if err := c.Validate(); err == nil {
		t.Fatal("zero voters must be rejected")
	}
}

func TestValidateRejectsBadDistribution(t *testing.T) {
	c := good()
	c.Distribution = "bell-curve"
	if err := c.Validate(); err == nil {
		t.Fatal("unknown distribution must be rejected")
	}
}

func TestValidateRejectsBadMode(t *testing.T) {
	c := good()
	c.Mode = "sideways"
	if err := c.Validate(); err == nil {
		t.Fatal("unknown mode must be rejected")
	}
}

func TestValidateEnforcesOfflineCeiling(t *testing.T) {
	c := good()
	c.Voters = OfflineVoterCeiling + 1
	if err := c.Validate(); err == nil {
		t.Fatalf("offline voters > %d must be rejected", OfflineVoterCeiling)
	}
	// The same population is allowed on-chain.
	c.Mode = "onchain"
	if err := c.Validate(); err != nil {
		t.Fatalf("on-chain should allow large tiers: %v", err)
	}
}

func TestTrusteeNames(t *testing.T) {
	c := good()
	names := c.TrusteeNames()
	if len(names) != 3 || names[0] != "TA" {
		t.Fatalf("unexpected trustee names: %v", names)
	}
}
