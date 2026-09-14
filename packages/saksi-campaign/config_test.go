package campaign

import (
	"fmt"
	"strings"
	"testing"
)

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
		Concurrency: DefaultConcurrency,
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

// Offline takes every thesis tier up to row 8's MP-3.5M (3,524,078 voters x 3
// positions) and refuses a record more; what a tier can really afford is
// preflight's disk and memory guard, not Validate.
func TestValidateBoundsOfflineRecords(t *testing.T) {
	c := good()
	c.Positions, c.Candidates = 3, 4
	for _, voters := range []int{10_001, 483_000, 1_000_000, 1_921_917, 3_524_078} {
		c.Voters = voters
		if err := c.Validate(); err != nil {
			t.Fatalf("offline %d x 3 must be accepted: %v", voters, err)
		}
	}
	c.Voters = 3_524_079
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "bounded at 10572234 ballot records") {
		t.Fatalf("offline 3,524,079 x 3 must be rejected with the bound, got %v", err)
	}
	c.Positions, c.Voters = 1, OfflineRecordCeiling+1
	if err := c.Validate(); err == nil {
		t.Fatal("the bound is on records: one position over it must be rejected too")
	}
	c.Voters = 1 << 62 // voters x positions would overflow int
	c.Positions = 4
	if err := c.Validate(); err == nil {
		t.Fatal("an overflowing voters x positions must not slip under the bound")
	}
	// The same population is allowed on-chain.
	c.Mode, c.Voters, c.Positions = "onchain", 3_524_079, 3
	if err := c.Validate(); err != nil {
		t.Fatalf("on-chain has no record bound: %v", err)
	}
}

// Ground-truth mode runs no cryptography, so the capstone tiers pass
// validation there too.
func TestValidateAllowsCapstoneTiersInGroundTruthMode(t *testing.T) {
	c := good()
	c.Mode = ModeGroundTruth
	for _, voters := range []int{OfflineRecordCeiling + 1, 1_921_917, 3_524_078} {
		c.Voters = voters
		if err := c.Validate(); err != nil {
			t.Fatalf("ground-truth mode must accept %d voters: %v", voters, err)
		}
	}
}

func TestTrusteeNames(t *testing.T) {
	c := good()
	names := c.TrusteeNames()
	if len(names) != 3 || names[0] != "TA" {
		t.Fatalf("unexpected trustee names: %v", names)
	}
}

// Concurrency 1 measures the console's own round-trip, not the network's
// throughput; 0 or less is not a load at all. The wizard sends whatever the
// advanced field holds, so the floor is enforced here.
func TestValidateRejectsConcurrencyBelowOne(t *testing.T) {
	for _, n := range []int{0, -1} {
		c := good()
		c.Concurrency = n
		err := c.Validate()
		if err == nil {
			t.Fatalf("concurrency %d must be rejected", n)
		}
		if want := fmt.Sprintf("concurrency must be >= 1 (got %d)", n); err.Error() != want {
			t.Fatalf("error = %q, want %q", err, want)
		}
	}
}

// A negative send rate is a nonsense arrival rate; 0 is the documented "as
// fast as the workers drain" and must stay legal.
func TestValidateRejectsNegativeSendRate(t *testing.T) {
	c := good()
	c.SendRate = -0.5
	err := c.Validate()
	if err == nil {
		t.Fatal("a negative send rate must be rejected")
	}
	if want := "send rate must be >= 0 (got -0.5)"; err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
	c.SendRate = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("send rate 0 is the default and must be accepted: %v", err)
	}
}
