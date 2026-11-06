package canvass

// Scenario is one attack the offline canvass console can mount, or the clean
// baseline. Expected and Mount mirror EXPECTED and MOUNT in balotachain's
// tools/security/canvass/assert_outcome.py; TestScenarioTableMatchesAssertOutcome
// fails on any drift.
type Scenario struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Mount is assert_outcome.py's MOUNT text (empty for clean).
	Mount string `json:"mount"`
	// Where the attacker acts: path (between precinct and national server),
	// precinct (with the precinct's real key), national (on the national
	// server after acceptance) or chain (on Fabric). Empty for clean.
	Where string `json:"where"`
	// Expected failing checks, primary first (assert_outcome.py EXPECTED).
	Expected []string `json:"expected"`
	// Live scenarios run offline; the chain ones are shown with Recorded.
	Live     bool      `json:"live"`
	Recorded *Recorded `json:"recorded,omitempty"`

	// attack is the mutate_return.py --scenario / SAKSI_ATTACK id (T14a and
	// T14b are both T14); t14 is CANVASS_T14 ("close" for T14b).
	attack string
	t14    string
}

// Recorded is the outcome of a chain scenario taken from the 2026-10-18
// desktop run. Evidence: balotachain branch origin/feat/precinct-evidence,
// docs/desktop-runs/2026-10-18-precinct-canvass/attacks/T19/t19-onchain.txt,
// attacks/T20/t20-onchain.txt and negative-tests-canvass.csv (rows T19, T20:
// expected "refused on chain: none", failed checks empty, verdict PASS).
type Recorded struct {
	Note     string `json:"note"`
	OnChain  string `json:"onchain"`
	Expected string `json:"expected"`
	Got      string `json:"got"`
	Verdict  string `json:"verdict"`
	Evidence string `json:"evidence"`
}

// RecordedNote labels the chain scenarios on the page.
const RecordedNote = "on-chain, needs Fabric — recorded 2026-10-18"

const evidenceDir = "balotachain origin/feat/precinct-evidence:docs/desktop-runs/2026-10-18-precinct-canvass/attacks/"

var scenarios = []Scenario{
	{ID: "clean", Label: "Clean canvass", Expected: []string{}, Live: true},
	{ID: "T9", Label: "Aggregate byte flipped in transit", Where: "path", attack: "T9", Live: true,
		Mount:    "one aggregate byte flipped after signing",
		Expected: []string{"canvass.signature", "canvass.completeness", "canvass.precinct_recompute", "canvass.national_sum"}},
	{ID: "T10", Label: "Return delivered twice", Where: "path", attack: "T10", Live: true,
		Mount:    "return delivered twice",
		Expected: []string{"canvass.registry"}},
	{ID: "T11", Label: "Unregistered precinct injected", Where: "path", attack: "T11", Live: true,
		Mount:    "unregistered precinct, fresh-key signature",
		Expected: []string{"canvass.registry"}},
	{ID: "T12", Label: "Sibling return substituted", Where: "path", attack: "T12", Live: true,
		Mount:    "sibling return relabelled and substituted",
		Expected: []string{"canvass.signature", "canvass.completeness", "canvass.precinct_recompute", "canvass.national_sum"}},
	{ID: "T13", Label: "Return dropped", Where: "path", attack: "T13", Live: true,
		Mount:    "return dropped on the path",
		Expected: []string{"canvass.completeness", "canvass.national_sum"}},
	{ID: "T14a", Label: "Wrong election id, real key", Where: "precinct", attack: "T14", Live: true,
		Mount:    "wrong election id, re-signed with the real key",
		Expected: []string{"canvass.registry", "canvass.completeness", "canvass.national_sum"}},
	{ID: "T14b", Label: "Stale close reference, real key", Where: "precinct", attack: "T14", t14: "close", Live: true,
		Mount:    "stale close reference, re-signed with the real key",
		Expected: []string{"canvass.precinct_recompute"}},
	{ID: "T15", Label: "Ledger missing a ballot, real key", Where: "precinct", attack: "T15", Live: true,
		Mount:    "real key over a ledger missing one ballot",
		Expected: []string{"canvass.precinct_recompute", "canvass.national_sum"}},
	{ID: "T16", Label: "Doctored aggregate, stolen key", Where: "precinct", attack: "T16", Live: true,
		Mount:    "doctored aggregate re-signed with the stolen real key",
		Expected: []string{"canvass.precinct_recompute", "canvass.national_sum"}},
	{ID: "T21", Label: "Signed with another precinct's key", Where: "path", attack: "T21", Live: true,
		Mount:    "signed with another registered precinct's key",
		Expected: []string{"canvass.signature", "canvass.completeness", "canvass.national_sum"}},
	{ID: "T24", Label: "Accepted return replaced at national", Where: "national", attack: "T24", Live: true,
		Mount:    "accepted national/returns file replaced after acceptance",
		Expected: []string{"canvass.signature", "canvass.completeness", "canvass.precinct_recompute", "canvass.national_sum"}},
	{ID: "T19", Label: "Ballot resubmitted across precincts", Where: "chain", attack: "T19",
		Mount:    "ballot resubmitted across precincts (submit-raw --channel)",
		Expected: []string{"canvass.nullifier_unique", "canvass.accuracy"},
		Recorded: &Recorded{
			Note:     RecordedNote,
			OnChain:  `[REFUSED] T19 -> submit ballot: rpc error: code = Aborted desc = failed to endorse transaction, see attached details for more info; chaincode response 500, gate=election-open: election "cv-T19-p03" is not open for ballots`,
			Expected: "refused on chain: none",
			Got:      "none",
			Verdict:  "PASS",
			Evidence: evidenceDir + "T19/t19-onchain.txt",
		}},
	{ID: "T20", Label: "Tally published on another precinct", Where: "chain", attack: "T20",
		Mount:    "a precinct's tally published on another precinct",
		Expected: []string{"canvass.accuracy"},
		Recorded: &Recorded{
			Note:     RecordedNote,
			OnChain:  `[REFUSED] T20 -> publish tally: rpc error: code = Aborted desc = failed to endorse transaction, see attached details for more info; chaincode response 500, a tally is already published for election "cv-T20-p03"`,
			Expected: "refused on chain: none",
			Got:      "none",
			Verdict:  "PASS",
			Evidence: evidenceDir + "T20/t20-onchain.txt",
		}},
}

// Scenarios returns the scenario table: clean, the live attacks, then the
// recorded chain attacks. The slice is a copy.
func Scenarios() []Scenario {
	out := make([]Scenario, len(scenarios))
	copy(out, scenarios)
	return out
}

// LookupScenario finds a scenario by its exact id.
func LookupScenario(id string) (Scenario, bool) {
	for _, s := range scenarios {
		if s.ID == id {
			return s, true
		}
	}
	return Scenario{}, false
}
