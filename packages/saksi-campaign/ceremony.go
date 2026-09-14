package campaign

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	saksiprotocolv1 "github.com/saksi-framework/saksi/packages/saksi-protocol/go/saksiprotocolv1"
	"google.golang.org/protobuf/proto"
)

// The threshold-decryption ceremony: the election is set up and closed, then
// each trustee institution acts on its own, and the tally is published only
// once at least `threshold` of them have contributed.
//
// HONEST SCOPE — where the threshold is enforced. The chaincode validates every
// partial decryption it receives (trustee must be in the election's trustee
// set, contest must exist, Chaum-Pedersen proof must be present, election must
// be closed) and rejects a repeat submission from the same trustee for the same
// contest. It still does NOT count partials.
//
// It does now count SIGNATURES: PublishTally verifies each trustee's Schnorr
// signature over the published totals and refuses a tally fewer than
// `threshold` distinct trustees endorsed (chaincode/sigverify). That is why
// CeremonyPublish sends only the submitted trustees' signatures — the ledger
// gate has to be counting what actually happened in this ceremony, not the
// full set the generator signed with. A chaincode built before that gate
// existed accepts any tally, so on such a network the t-of-n rule is still
// this console's alone.
//
// Either way the property is independently checked: the auditor counts
// distinct verified trustees per contest and fails below threshold
// (saksi-auditor/src/decryption.rs), and verifies the same signatures
// (saksi-auditor/src/tally.rs, finding `tally.signatures`).
//
// Note also that the published tally is the generator's seeded result, not a
// recomputation from the shares that happened to be submitted. The ceremony
// gates publication; the auditor is what proves enough trustees contributed.

// CeremonyFile records ceremony progress inside the run folder. It is the
// authority in offline mode; on-chain the ledger is the authority and this file
// is only a convenience record.
const CeremonyFile = "ceremony.json"

// CeremonyTrustee is one institution's row in the roster.
type CeremonyTrustee struct {
	// ID is the wire trustee id ("1".."n"), matching ElectionParameters.trustee_ids.
	ID string `json:"id"`
	// Name is the operator-supplied display name for the institution.
	Name string `json:"name"`
	// Submitted reports whether this trustee has contributed its partials.
	Submitted bool `json:"submitted"`
	// Contests counts the partial decryptions this trustee owns (one per contest).
	Contests int `json:"contests"`
	// SubmittedAt is when this console recorded the contribution. Offline it is
	// the only timestamp that exists; on-chain the ledger receipt in trail.json
	// is the authority and this is a convenience record. Nil when the trustee
	// has not contributed, or when the chain (not this console) observed it.
	SubmittedAt *time.Time `json:"submitted_at,omitempty"`
}

// CeremonyState is the /api/ceremony/<runID> body and the ceremony.json shape.
type CeremonyState struct {
	Threshold int               `json:"threshold"`
	Trustees  []CeremonyTrustee `json:"trustees"`
	Submitted int               `json:"submitted"`
	// Unlocked reports whether enough trustees have contributed to publish.
	Unlocked bool `json:"unlocked"`
	// Published reports whether the tally has been published.
	Published bool `json:"published"`
	// OnChain distinguishes a ledger-backed ceremony from a local one, so the
	// UI can say which it is rather than implying a ledger that isn't there.
	OnChain bool `json:"on_chain"`
	// Ready reports whether setup has run and trustees may act.
	Ready bool `json:"ready"`
	// StartedAt and ClosedAt are both stamped at CeremonyStart: that call is
	// what runs the lifecycle prefix up to and including CloseElection, so it
	// is the moment the election stopped accepting ballots. Offline there is
	// no ledger receipt to read a close time from, and this is the only
	// honest source for it.
	StartedAt *time.Time `json:"started_at,omitempty"`
	ClosedAt  *time.Time `json:"closed_at,omitempty"`
	// PublishedAt is when the tally was published.
	PublishedAt *time.Time `json:"published_at,omitempty"`
}

// partialsByTrustee groups a bundle's partial decryptions by the trustee_id
// carried inside each protobuf.
//
// The canonical layout is index-derivable (partial_decryptions[c*n + t]), but
// decoding the trustee_id is exact and survives any future layout change — and
// the generated type is already a dependency here.
func partialsByTrustee(b *onChainBundle) (map[string][]string, error) {
	byTrustee := make(map[string][]string)
	for i, ph := range b.PartialDecryptions {
		raw, err := hex.DecodeString(ph)
		if err != nil {
			return nil, fmt.Errorf("partial decryption %d is not valid hex: %w", i, err)
		}
		var pd saksiprotocolv1.PartialDecryption
		if err := proto.Unmarshal(raw, &pd); err != nil {
			return nil, fmt.Errorf("decode partial decryption %d: %w", i, err)
		}
		id := pd.GetTrusteeId()
		if id == "" {
			return nil, fmt.Errorf("partial decryption %d carries no trustee id", i)
		}
		byTrustee[id] = append(byTrustee[id], ph)
	}
	return byTrustee, nil
}

// bundlePath is where the run's cached on-chain bundle lives. It is generated
// once at ceremony start and only ever read afterwards.
func (e *Executor) bundlePath(runID string) (string, error) {
	dir, err := e.store.Dir(runID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "bundle.json"), nil
}

// readBundle loads the run's cached bundle.
func (e *Executor) readBundle(runID string) (*onChainBundle, error) {
	path, err := e.bundlePath(runID)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no generated bundle for this run — start the ceremony first: %w", err)
	}
	var b onChainBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	return &b, nil
}

// generateBundle writes the run's bundle.json from the stream Generate already
// produced, exactly once.
//
// The small artifacts (parameters, DKG transcript, partial decryptions, tally)
// are copied out of header.json and the population is REFERENCED by file. It
// deliberately does NOT re-run the generator: `saksi-demo gen` draws from
// OsRng, so a second generation would produce a bundle whose ballots are not
// the ones in ballots.ndjson — the election would be created from one
// population and filled from another.
// The stage boundary is stamped here rather than at the call sites so both
// entry points (Submit and CeremonyStart) record it identically.
func (e *Executor) generateBundle(runID string) (string, error) {
	j := e.journalFor(runID)
	defer j.Close()
	_ = j.Stamp("stage.bundle.start", nil)
	path, err := e.bundleFrom(runID)
	_ = j.Stamp("stage.bundle.end", stageEnd(err))
	return path, err
}

func (e *Executor) bundleFrom(runID string) (string, error) {
	path, err := e.bundlePath(runID)
	if err != nil {
		return "", err
	}
	if _, statErr := os.Stat(path); statErr == nil {
		e.publish(runID, "ceremony", "info", "reusing this run's generated bundle")
		return path, nil
	}
	dir, err := e.store.Dir(runID)
	if err != nil {
		return "", err
	}
	var h electionHeader
	if err := readJSON(filepath.Join(dir, "header.json"), &h); err != nil {
		return "", fmt.Errorf("this run has no generated election to submit — run Generate first: %w", err)
	}
	e.publish(runID, "ceremony", "info", "preparing the election bundle…")
	b := onChainBundle{
		ElectionID:         h.ElectionID,
		Params:             h.Params,
		DKG:                h.Dkg,
		BallotsFile:        BallotsFile,
		BallotCount:        h.N,
		PartialDecryptions: h.PartialDecryptions,
		Tally:              h.Tally,
	}
	if err := writeJSON(path, b); err != nil {
		return "", err
	}
	return path, nil
}

// CeremonyStart generates the bundle once and, on-chain, runs the lifecycle
// prefix up to and including CloseElection. It deliberately stops there: the
// next move belongs to the trustees.
// errNoFabric explains why an on-chain run cannot proceed. Selecting on-chain
// without a configured network used to fall through to the local path and
// report success, while the page said "committing to Fabric" — a run that
// looked committed and was not. Failing here is the whole point.
func errNoFabric() error {
	return fmt.Errorf(
		"on-chain mode needs a Fabric network: start the console with " +
			"--fabric-tls-cert, --fabric-cert and --fabric-key (and --fabric-peer " +
			"if the peer is not at the default endpoint)")
}

// onChainRun reports whether this run's phases may touch the ledger: the
// operator asked for on-chain mode AND a network is configured.
//
// Every other mode is local in EVERY phase, the ceremony included. Gating the
// ceremony on e.fabric.Enabled() alone is what let an offline run on a
// Fabric-wired console commit its whole lifecycle on-chain — Submit honoured
// the mode and no-opped, then CeremonyStart put the same election, all its
// ballots, the partials and the tally on the chain anyway.
func (e *Executor) onChainRun(c ElectionConfig) bool {
	return c.Mode == "onchain" && e.fabric.Enabled()
}

// useLedger decides, once, whether a ceremony action goes to the chain, and
// says why when it does not. An on-chain run with no network is a
// misconfiguration and fails (errNoFabric); any other mode runs locally, and on
// a Fabric-wired console it says so in Submit's words, so a simulated ceremony
// is never read as a committed one.
func (e *Executor) useLedger(runID string, c ElectionConfig) (bool, error) {
	if c.Mode == "onchain" {
		if !e.fabric.Enabled() {
			e.publish(runID, "ceremony", "error", errNoFabric().Error())
			return false, errNoFabric()
		}
		return true, nil
	}
	if e.fabric.Enabled() {
		e.publish(runID, "ceremony", "info", c.Mode+
			" mode: ceremony is simulated locally, nothing submitted on-chain")
	}
	return false, nil
}

func (e *Executor) CeremonyStart(ctx context.Context, runID string, c ElectionConfig) error {
	j := e.journalFor(runID)
	defer j.Close()
	path, err := e.generateBundle(runID)
	if err != nil {
		return err
	}
	_ = j.Stamp("stage.ceremony.start", nil)
	defer func() { _ = j.Stamp("stage.ceremony.end", nil) }()
	onChain, err := e.useLedger(runID, c)
	if err != nil {
		return err
	}
	if !onChain {
		// The local lifecycle has the same stages; its attacks are simulated,
		// and with no ledger there is no election state to record.
		if c.AttackPlan != nil {
			for _, stage := range []string{StageDKG, StageBallots, StageClose} {
				e.pauseForAttacks(ctx, runID, c, stage, MountContext{}, false, e.simulatedMount(ctx, runID, false))
			}
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		e.publish(runID, "ceremony", "done",
			"local ceremony ready — no ledger; the threshold gate is enforced by this console")
		return e.writeCeremony(runID, c, nil)
	}
	conn, err := e.fabric.Connect()
	if err != nil {
		e.publish(runID, "ceremony", "error", "connect to Fabric: "+err.Error())
		return err
	}
	defer conn.Close()

	b, step, err := e.lifecycle(runID, conn.Ledger(), path, "ceremony")
	if err != nil {
		return err
	}
	defer e.closeReceipts(runID)
	if err := e.setupOnChain(ctx, runID, c, b, conn.Ledger(), step); err != nil {
		return err
	}
	e.publish(runID, "ceremony", "done", "election closed — trustees may now contribute")
	return e.writeCeremony(runID, c, nil)
}

// CeremonySubmit submits exactly one trustee's partial decryptions — one per
// contest. Every other trustee's shares stay untouched, which is what makes the
// threshold visible: the tally cannot be published until enough of them act.
func (e *Executor) CeremonySubmit(ctx context.Context, runID string, c ElectionConfig, trusteeID string) error {
	b, err := e.readBundle(runID)
	if err != nil {
		return err
	}
	byTrustee, err := partialsByTrustee(b)
	if err != nil {
		return err
	}
	mine, ok := byTrustee[trusteeID]
	if !ok {
		return fmt.Errorf("trustee %q holds no shares in this election", trusteeID)
	}

	name := trusteeDisplayName(c, trusteeID)
	j := e.journalFor(runID)
	defer j.Close()
	_ = j.Stamp("stage.ceremony.trustee.start", map[string]any{"trustee": trusteeID, "partials": len(mine)})
	defer func() { _ = j.Stamp("stage.ceremony.trustee.end", map[string]any{"trustee": trusteeID}) }()
	onChain, err := e.useLedger(runID, c)
	if err != nil {
		return err
	}
	if !onChain {
		e.publish(runID, "ceremony", "info",
			fmt.Sprintf("%s contributed %d partial decryptions (local ceremony)", name, len(mine)))
		return e.markSubmitted(runID, c, trusteeID)
	}

	conn, err := e.fabric.Connect()
	if err != nil {
		e.publish(runID, "ceremony", "error", "connect to Fabric: "+err.Error())
		return err
	}
	defer conn.Close()

	path, err := e.bundlePath(runID)
	if err != nil {
		return err
	}
	_, step, err := e.lifecycle(runID, conn.Ledger(), path, "ceremony")
	if err != nil {
		return err
	}
	defer e.closeReceipts(runID)
	for i, pd := range mine {
		ref := fmt.Sprintf("%s/%d", name, i)
		if err := step(ctx, "SubmitPartialDecryption", ref, "SubmitPartialDecryption", b.ElectionID, pd); err != nil {
			return err
		}
	}
	e.publish(runID, "ceremony", "info",
		fmt.Sprintf("%s contributed %d partial decryptions", name, len(mine)))
	return e.markSubmitted(runID, c, trusteeID)
}

// CeremonyPublish publishes the tally. The threshold is checked here, before
// anything is submitted — below it, nothing is published.
func (e *Executor) CeremonyPublish(ctx context.Context, runID string, c ElectionConfig) error {
	state, err := e.CeremonyStatus(runID, c)
	if err != nil {
		return err
	}
	if !state.Unlocked {
		return fmt.Errorf("tally needs %d of %d trustees; %d have contributed",
			state.Threshold, len(state.Trustees), state.Submitted)
	}
	b, err := e.readBundle(runID)
	if err != nil {
		return err
	}
	j := e.journalFor(runID)
	defer j.Close()
	_ = j.Stamp("stage.ceremony.publish.start", map[string]any{"submitted": state.Submitted, "threshold": state.Threshold})
	defer func() { _ = j.Stamp("stage.ceremony.publish.end", nil) }()
	onChain, err := e.useLedger(runID, c)
	if err != nil {
		return err
	}
	if !onChain {
		// The ceremony stage pauses here: trustees have acted, nothing is
		// published yet.
		if c.AttackPlan.has(StageCeremony) {
			e.pauseForAttacks(ctx, runID, c, StageCeremony, MountContext{}, false, e.simulatedMount(ctx, runID, false))
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		e.publish(runID, "ceremony", "done",
			fmt.Sprintf("threshold met (%d of %d) — tally unlocked", state.Submitted, state.Threshold))
		return e.markPublished(runID, c)
	}
	conn, err := e.fabric.Connect()
	if err != nil {
		e.publish(runID, "ceremony", "error", "connect to Fabric: "+err.Error())
		return err
	}
	defer conn.Close()
	if c.AttackPlan.has(StageCeremony) {
		dir, _ := e.store.Dir(runID)
		e.pauseForAttacks(ctx, runID, c, StageCeremony,
			MountContext{ElectionStatus: "closed", BallotsCommitted: committedFromMetrics(dir), BlockHeight: chainHeight(conn.Ledger())},
			true, e.simulatedMount(ctx, runID, true))
	}

	path, err := e.bundlePath(runID)
	if err != nil {
		return err
	}
	_, step, err := e.lifecycle(runID, conn.Ledger(), path, "ceremony")
	if err != nil {
		return err
	}
	defer e.closeReceipts(runID)
	tallyHex, err := tallyToPublish(b.Tally, state)
	if err != nil {
		e.publish(runID, "ceremony", "error", err.Error())
		return err
	}
	if err := step(ctx, "PublishTally", "", "PublishTally", tallyHex); err != nil {
		return err
	}
	e.publish(runID, "ceremony", "done",
		fmt.Sprintf("threshold met (%d of %d) — tally published on-chain", state.Submitted, state.Threshold))
	return e.markPublished(runID, c)
}

// tallyToPublish re-encodes the bundle's tally carrying only the signatures of
// the trustees that actually submitted, and returns it hex-encoded.
//
// The generator signs the tally with EVERY trustee's share, because it holds
// them all. Publishing that list unfiltered would put a 5-of-5 endorsement
// on-chain for a ceremony only two trustees took part in — the ledger's own
// threshold gate (the chaincode counts these signatures) would then be
// counting a claim this console made up rather than what happened here.
//
// A bundle generated before tally signatures existed carries none; it is
// returned verbatim, and the chaincode refuses it. Rewriting an old artifact to
// look endorsed is exactly what must not happen.
func tallyToPublish(tallyHex string, state CeremonyState) (string, error) {
	raw, err := hex.DecodeString(tallyHex)
	if err != nil {
		return "", fmt.Errorf("this run's tally is not valid hex: %w", err)
	}
	var tally saksiprotocolv1.TallyResult
	if err := proto.Unmarshal(raw, &tally); err != nil {
		return "", fmt.Errorf("decode this run's tally: %w", err)
	}
	if len(tally.GetSignatures()) == 0 {
		return tallyHex, nil
	}

	submitted := make(map[string]bool, len(state.Trustees))
	for _, tr := range state.Trustees {
		if tr.Submitted {
			submitted[tr.ID] = true
		}
	}
	kept := make([]*saksiprotocolv1.TrusteeSignature, 0, len(tally.GetSignatures()))
	for _, sig := range tally.GetSignatures() {
		if submitted[sig.GetTrusteeId()] {
			kept = append(kept, sig)
		}
	}
	tally.Signatures = kept

	out, err := proto.Marshal(&tally)
	if err != nil {
		return "", fmt.Errorf("re-encode tally: %w", err)
	}
	return hex.EncodeToString(out), nil
}

// CeremonyStatus reports the roster. On-chain the ledger is consulted as the
// authority; the local file is the fallback and the offline authority.
func (e *Executor) CeremonyStatus(runID string, c ElectionConfig) (CeremonyState, error) {
	state := e.readCeremony(runID, c)
	state.OnChain = e.onChainRun(c)

	if b, err := e.readBundle(runID); err == nil {
		state.Ready = true
		if byTrustee, err := partialsByTrustee(b); err == nil {
			for i := range state.Trustees {
				state.Trustees[i].Contests = len(byTrustee[state.Trustees[i].ID])
			}
		}
		if state.OnChain {
			e.refreshFromChain(&state, b)
		}
	}

	state.Submitted = 0
	for _, t := range state.Trustees {
		if t.Submitted {
			state.Submitted++
		}
	}
	state.Unlocked = state.Submitted >= state.Threshold
	return state, nil
}

// refreshFromChain lets the ledger correct the local record — it is the
// authority for what was actually committed. A trustee counts as having
// contributed when its partial decryption for the first contest is readable
// back from the chain.
func (e *Executor) refreshFromChain(state *CeremonyState, b *onChainBundle) {
	conn, err := e.fabric.Connect()
	if err != nil {
		return // keep the local view; the UI still shows on_chain
	}
	defer conn.Close()

	contest, err := firstContestID(b)
	if err != nil {
		return
	}
	for i := range state.Trustees {
		if _, err := conn.Bulletin.GetPartialDecryption(b.ElectionID, contest, state.Trustees[i].ID); err == nil {
			state.Trustees[i].Submitted = true
		}
	}
	if _, err := conn.Bulletin.GetTally(b.ElectionID); err == nil {
		state.Published = true
	}
}

// firstContestID decodes the election parameters to find a contest id to probe
// with. Every trustee owns exactly one partial per contest, so one contest is
// enough to tell whether a trustee has acted.
func firstContestID(b *onChainBundle) (string, error) {
	raw, err := hex.DecodeString(b.Params)
	if err != nil {
		return "", err
	}
	var params saksiprotocolv1.ElectionParameters
	if err := proto.Unmarshal(raw, &params); err != nil {
		return "", err
	}
	ids := params.GetContestIds()
	if len(ids) == 0 {
		return "", fmt.Errorf("election has no contests")
	}
	return ids[0], nil
}

// trusteeDisplayName maps a wire trustee id ("1".."n") back to the operator's
// display name, falling back to the id.
func trusteeDisplayName(c ElectionConfig, trusteeID string) string {
	idx, err := strconv.Atoi(trusteeID)
	if err != nil || idx < 1 || idx > len(c.Trustees) {
		return trusteeID
	}
	if name := strings.TrimSpace(c.Trustees[idx-1].Name); name != "" {
		return name
	}
	return trusteeID
}

// newCeremony builds the roster from the config: wire ids "1".."n" aligned to
// the operator's trustee names by position, the same alignment the generator
// uses.
func newCeremony(c ElectionConfig) CeremonyState {
	state := CeremonyState{Threshold: c.Threshold}
	for i, t := range c.Trustees {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			name = fmt.Sprintf("Trustee %d", i+1)
		}
		state.Trustees = append(state.Trustees, CeremonyTrustee{
			ID:   strconv.Itoa(i + 1),
			Name: name,
		})
	}
	return state
}

func (e *Executor) ceremonyPath(runID string) (string, error) {
	dir, err := e.store.Dir(runID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, CeremonyFile), nil
}

// readCeremony loads the recorded roster, or a fresh one if none exists yet.
func (e *Executor) readCeremony(runID string, c ElectionConfig) CeremonyState {
	fresh := newCeremony(c)
	path, err := e.ceremonyPath(runID)
	if err != nil {
		return fresh
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fresh
	}
	var stored CeremonyState
	if err := json.Unmarshal(raw, &stored); err != nil {
		return fresh
	}
	// Trust the config for the roster shape and the file only for progress, so
	// an edited config can never desync the card list from the trustee ids.
	submitted := make(map[string]bool, len(stored.Trustees))
	submittedAt := make(map[string]*time.Time, len(stored.Trustees))
	for _, t := range stored.Trustees {
		submitted[t.ID] = t.Submitted
		submittedAt[t.ID] = t.SubmittedAt
	}
	for i := range fresh.Trustees {
		fresh.Trustees[i].Submitted = submitted[fresh.Trustees[i].ID]
		fresh.Trustees[i].SubmittedAt = submittedAt[fresh.Trustees[i].ID]
	}
	fresh.Published = stored.Published
	fresh.Ready = stored.Ready
	fresh.StartedAt = stored.StartedAt
	fresh.ClosedAt = stored.ClosedAt
	fresh.PublishedAt = stored.PublishedAt
	return fresh
}

func (e *Executor) writeCeremony(runID string, c ElectionConfig, state *CeremonyState) error {
	path, err := e.ceremonyPath(runID)
	if err != nil {
		return err
	}
	s := e.readCeremony(runID, c)
	if state != nil {
		s = *state
	}
	s.Ready = true
	// The first write is CeremonyStart's, which has just closed the election.
	now := time.Now().UTC()
	if s.StartedAt == nil {
		s.StartedAt = &now
	}
	if s.ClosedAt == nil {
		s.ClosedAt = &now
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (e *Executor) markSubmitted(runID string, c ElectionConfig, trusteeID string) error {
	s := e.readCeremony(runID, c)
	now := time.Now().UTC()
	for i := range s.Trustees {
		if s.Trustees[i].ID == trusteeID {
			s.Trustees[i].Submitted = true
			if s.Trustees[i].SubmittedAt == nil {
				s.Trustees[i].SubmittedAt = &now
			}
		}
	}
	return e.writeCeremony(runID, c, &s)
}

func (e *Executor) markPublished(runID string, c ElectionConfig) error {
	s := e.readCeremony(runID, c)
	s.Published = true
	if s.PublishedAt == nil {
		now := time.Now().UTC()
		s.PublishedAt = &now
	}
	return e.writeCeremony(runID, c, &s)
}
