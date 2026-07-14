package bench

import "fmt"

// Reconcile is the Phase 3 fail-loud accuracy gate: before any tally error is
// scored, the committed ballot count must equal both the submitted count (no
// silent drop) and the expected ground-truth population size. A silent drop at
// high tps — an endorsement timeout or MVCC conflict — would otherwise read as a
// clean undercount, so a mismatch is a hard error, never swallowed.
//
// Returns nil only when submitted == committed == expected.
func Reconcile(submitted, committed, expected int) error {
	if committed != submitted {
		return fmt.Errorf(
			"reconcile: %d of %d ballots dropped during submission (committed != submitted)",
			submitted-committed, submitted,
		)
	}
	if committed != expected {
		return fmt.Errorf(
			"reconcile: committed %d != expected ground-truth population %d",
			committed, expected,
		)
	}
	return nil
}
