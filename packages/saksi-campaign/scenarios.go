package campaign

import "context"

// NegativeTestsFile is the per-run negative/vulnerability results CSV.
const NegativeTestsFile = "negative-tests.csv"

// RunScenarios runs the selected negative/vulnerability scenarios over a
// generated run.
//
// ponytail: Phase 4 stub. The real scenario library (decode→mutate→re-encode
// protobuf ballots on a copied run, attack→verifier-layer matrix, fail-loud
// verdicts → negative-tests.csv) lands next; this keeps the server building and
// reports the phase as unavailable rather than silently passing.
func (e *Executor) RunScenarios(_ context.Context, runID string, _ []string) error {
	e.publish(runID, "scenarios", "error", "scenario library lands in the next build")
	return nil
}
