// Package campaign is the Research Election Console: a loopback web app that
// configures an election and runs it in independent phases (Generate | Submit |
// Verify | Scenarios) over a run-folder store, shelling the parameterized
// saksi-demo generator/auditor (offline) or driving the Fabric lifecycle
// (on-chain).
//
// All business logic (validation, run state, correctness, scenario verdicts)
// lives here server-side and is unit-tested; the embedded web UI is a logic-free
// view (see server.go / web/index.html).
package campaign

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// MaxTrustees is the UI/validation cap on trustee count.
const MaxTrustees = 15

// OfflineVoterCeiling caps offline-mode voters. Offline generation is not
// parallelized, so the 50k/483k/1M tiers need ground-truth mode until the
// streaming generator lands; a researcher clicking a huge offline tier gets a
// clear error, not a run that never finishes.
const OfflineVoterCeiling = 10000

// Trustee is one DKG trustee's display identity.
type Trustee struct {
	Name string `json:"name"`
}

// ElectionConfig is the full console configuration for one run. It is POSTed as
// JSON by the web UI and validated server-side.
type ElectionConfig struct {
	Name         string    `json:"name"`
	Trustees     []Trustee `json:"trustees"`
	Threshold    int       `json:"threshold"`
	Positions    int       `json:"positions"`
	Candidates   int       `json:"candidates"`
	Voters       int       `json:"voters"`
	Distribution string    `json:"distribution"` // uniform | skewed | realistic
	Mode         string    `json:"mode"`         // offline | onchain | groundtruth
	// SenateSeats is how many senators are elected — the Senate is a
	// multi-seat race decided by plurality (the top SenateSeats candidates
	// win), while President and Vice President stay single-winner.
	//
	// Each voter still selects exactly ONE candidate per position, so this
	// changes nothing cryptographic: the CDS proof still shows each ciphertext
	// encrypts 0 or 1, and the auditor's gate still requires each position's
	// aggregate to equal the ballot count. Seats decide how the result is
	// READ, not how it is produced, which is why this never reaches
	// saksi-demo. Zero means "single-winner", the previous behaviour.
	SenateSeats int `json:"senate_seats"`
	// Concurrency is how many ballot submissions are in flight at once during
	// the on-chain ballot window. Serial submission measures the driver's own
	// round-trip ceiling rather than Fabric throughput, so this is never 1 by
	// default. Zero means DefaultConcurrency (configs recorded before this
	// field existed read as zero).
	Concurrency int `json:"concurrency"`
	// SendRate caps dispatch to that many submissions per second (open-loop
	// load). Zero dispatches as fast as the workers drain (closed-loop).
	SendRate float64 `json:"send_rate"`
	// WindowS time-bounds the ballot window to that many seconds
	// (bench.RunOpts.MaxDuration). Zero means unbounded: the window closes
	// when every ballot has been dispatched. A sweep step sets it so each
	// step measures the same slice of wall clock at a different offered rate.
	WindowS float64 `json:"window_s"`
	// Rep tags this run as one repetition of a --repeat campaign. Optional and
	// purely descriptive: it is stamped into the journal at run.start (and onto
	// the ballot window's segment) so a run folder says which repetition it is.
	Rep *RepTag `json:"rep,omitempty"`
	// SkipAttacks hides the in-lifecycle attack panels for a clean end-to-end
	// run. The attacks are opt-in either way; this removes the offer entirely
	// so a straight demonstration is one click.
	SkipAttacks bool `json:"skip_attacks"`
	// AttackPlan makes this a SECURITY RUN: the lifecycle pauses at each listed
	// stage and that stage's attacks are mounted at the moment they belong to
	// (timeline.go). Nil runs the lifecycle straight through, exactly as before.
	// A security run's throughput is perturbed by design and marked so in
	// perf.csv (security_run).
	AttackPlan *AttackPlan `json:"attack_plan,omitempty"`
	// FaultPlan makes this a security run too: the ballot window stops the
	// peer part-way through (fault.go). Armed only by POST
	// /api/runs/<id>/fault, never accepted with a posted config.
	FaultPlan *FaultPlan `json:"fault_plan,omitempty"`
}

// securityRun reports that this run was perturbed by design, by attacks or a
// fault: its throughput is not a measurement.
func (c ElectionConfig) securityRun() bool { return c.AttackPlan != nil || c.FaultPlan != nil }

// AttackPlan is ElectionConfig.attack_plan.
type AttackPlan struct {
	// Stages are the lifecycle stages to pause at: dkg, ballots, close, ceremony.
	Stages []string `json:"stages"`
	// BallotsAt is the fraction of the ballots the window dispatches before the
	// ballots stage pauses. Zero means DefaultBallotsAt.
	BallotsAt float64 `json:"ballots_at"`
	// TimeoutS is how long a paused stage waits for the operator; when it runs
	// out, every attack at that stage not yet run is run and the lifecycle
	// continues, so an unattended security run still carries out its plan.
	// Zero means DefaultPauseTimeout.
	TimeoutS float64 `json:"timeout_s,omitempty"`
}

// DefaultBallotsAt pauses the ballot window half way through.
const DefaultBallotsAt = 0.5

// DefaultPauseTimeout bounds how long a paused stage waits for the operator.
const DefaultPauseTimeout = 5 * time.Minute

// DefaultConcurrency is the in-flight ballot submission count when the config
// does not say otherwise.
const DefaultConcurrency = 8

// RepTag identifies one repetition of a --repeat campaign: which repetition it
// is and what it counts as. Kind is "warmup" (discarded), "measured" (counted
// in summary.csv), "sweep" (one rate step) or "burst".
type RepTag struct {
	Index int    `json:"index"`
	Kind  string `json:"kind"`
}

// Window is the ballot window's time bound, or 0 for unbounded.
func (c ElectionConfig) Window() time.Duration {
	if c.WindowS <= 0 {
		return 0
	}
	return time.Duration(c.WindowS * float64(time.Second))
}

// applyDefaults fills the fields the UI may omit. Called on every decoded
// config before Validate, so validation never has to special-case "unset".
func (c *ElectionConfig) applyDefaults() {
	if c.Concurrency == 0 {
		c.Concurrency = DefaultConcurrency
	}
}

// submitConcurrency is the worker count the on-chain ballot window runs with,
// defaulting for run records written before Concurrency existed.
func (c ElectionConfig) submitConcurrency() int {
	if c.Concurrency < 1 {
		return DefaultConcurrency
	}
	return c.Concurrency
}

// SenatePosition is the ballot index of the multi-seat race (President 0,
// Vice President 1, Senator 2), matching ph_position_id in the generator.
const SenatePosition = 2

// Seats returns how many candidates win position p.
func (c ElectionConfig) Seats(p int) int {
	if p == SenatePosition && c.SenateSeats > 1 {
		return c.SenateSeats
	}
	return 1
}

// ModeGroundTruth generates ONLY the Stage-4 plaintext ground-truth tables
// (paper Appendix A) — no DKG, no credentials, no encryption, no proofs, and
// nothing submitted on-chain. Because it runs no cryptography, it is not
// subject to OfflineVoterCeiling, which is what makes the capstone tiers
// (1,921,917 and 3,524,078 voters) reachable from the console.
const ModeGroundTruth = "groundtruth"

// Validate returns the first invariant violation, or nil. This is the single
// source of truth for config validity — the UI mirrors these checks only for
// instant feedback, never as the gate.
func (c ElectionConfig) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("election name must not be empty")
	}
	n := len(c.Trustees)
	if n < 1 || n > MaxTrustees {
		return fmt.Errorf("trustees must be between 1 and %d (got %d)", MaxTrustees, n)
	}
	if c.Threshold < 1 || c.Threshold > n {
		return fmt.Errorf("threshold must be 1..=%d (got %d)", n, c.Threshold)
	}
	for i, t := range c.Trustees {
		if strings.TrimSpace(t.Name) == "" {
			return fmt.Errorf("trustee %d has an empty name", i+1)
		}
	}
	if c.Positions < 1 || c.Candidates < 1 || c.Voters < 1 {
		return fmt.Errorf("positions, candidates, voters must each be >= 1")
	}
	switch c.Distribution {
	case "uniform", "skewed", "realistic":
	default:
		return fmt.Errorf(
			"distribution must be 'uniform', 'skewed', or 'realistic' (got %q)", c.Distribution)
	}
	// A cut needs at least one candidate below it, or every candidate is
	// elected and the race decides nothing.
	if c.SenateSeats < 0 || c.SenateSeats >= c.Candidates {
		return fmt.Errorf("senate seats must be 0..%d (got %d)", c.Candidates-1, c.SenateSeats)
	}
	if c.Concurrency < 1 {
		return fmt.Errorf("concurrency must be >= 1 (got %d)", c.Concurrency)
	}
	if c.SendRate < 0 {
		return fmt.Errorf("send rate must be >= 0 (got %v)", c.SendRate)
	}
	if c.WindowS < 0 {
		return fmt.Errorf("window must be >= 0 seconds (got %v)", c.WindowS)
	}
	switch c.Mode {
	case "offline", "onchain", ModeGroundTruth:
	default:
		return fmt.Errorf("mode must be 'offline', 'onchain', or %q (got %q)", ModeGroundTruth, c.Mode)
	}
	if c.Mode == "offline" && c.Voters > OfflineVoterCeiling {
		return fmt.Errorf(
			"offline mode is capped at %d voters (got %d); use ground-truth mode for larger tiers until the streaming generator lands",
			OfflineVoterCeiling, c.Voters)
	}
	// Every posted config passes through here (/generate, /run-all, campaigns),
	// and those routes lack the fault route's loopback and confirmation guards.
	if c.FaultPlan != nil {
		return fmt.Errorf("fault_plan cannot come with a config: arm it on the generated run with POST /api/runs/<id>/fault")
	}
	return c.validateAttackPlan()
}

// validateAttackPlan admits a plan only for a single election that runs its
// attacks: a campaign repetition is a measurement and never runs them, and a
// ground-truth run has no ciphertexts to attack.
func (c ElectionConfig) validateAttackPlan() error {
	p := c.AttackPlan
	if p == nil {
		return nil
	}
	switch {
	case c.SkipAttacks:
		return fmt.Errorf("attack_plan contradicts skip_attacks: drop one of them")
	case c.Rep != nil:
		return fmt.Errorf("attack_plan is for a single election: a campaign repetition never runs attacks")
	case c.Mode == ModeGroundTruth:
		return fmt.Errorf("attack_plan needs encrypted ballots; %q mode produces none", ModeGroundTruth)
	case len(p.Stages) == 0:
		return fmt.Errorf("attack_plan lists no stages")
	case p.BallotsAt < 0 || p.BallotsAt >= 1:
		return fmt.Errorf("attack_plan ballots_at must be between 0 and 1, exclusive (got %v)", p.BallotsAt)
	case p.TimeoutS < 0:
		return fmt.Errorf("attack_plan timeout_s must be >= 0 (got %v)", p.TimeoutS)
	}
	seen := make(map[string]bool, len(p.Stages))
	for _, st := range p.Stages {
		if !slices.Contains(StageOrder, st) {
			return fmt.Errorf("attack_plan stage %q is not one of %v", st, StageOrder)
		}
		if seen[st] {
			return fmt.Errorf("attack_plan lists stage %q twice", st)
		}
		seen[st] = true
	}
	// Pausing mid-window needs a ballot already cast (to reuse its nullifier)
	// and one not yet cast (to tamper with before it reaches the chain).
	if seen[StageBallots] && c.Voters*c.Positions < 2 {
		return fmt.Errorf("attack_plan's ballots stage needs at least 2 ballots (got %d)", c.Voters*c.Positions)
	}
	return nil
}

// TrusteeNames returns the trustee display names in order.
func (c ElectionConfig) TrusteeNames() []string {
	names := make([]string, len(c.Trustees))
	for i, t := range c.Trustees {
		names[i] = t.Name
	}
	return names
}
