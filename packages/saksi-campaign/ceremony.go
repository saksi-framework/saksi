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
// contest. It does NOT count partials before accepting PublishTally. So the
// t-of-n gate here is enforced by this console, not by the ledger.
//
// That does not make the property unproven: the independent auditor verifies it
// at audit time, counting distinct verified trustees per contest and failing
// below threshold (saksi-auditor/src/decryption.rs). Threshold integrity is a
// verification-time guarantee. Adding an endorsement-time check to PublishTally
// would be a genuine improvement, and needs a chaincode redeploy.
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

// generateBundle shells the demo binary to write the run's bundle exactly once.
// Regenerating would draw fresh randomness, changing every share and making
// CreateElection a duplicate, so an existing bundle is reused as-is.
func (e *Executor) generateBundle(ctx context.Context, runID string, c ElectionConfig) (string, error) {
	path, err := e.bundlePath(runID)
	if err != nil {
		return "", err
	}
	if _, statErr := os.Stat(path); statErr == nil {
		e.publish(runID, "ceremony", "info", "reusing this run's generated bundle")
		return path, nil
	}
	args := []string{
		"gen",
		"--voters", strconv.Itoa(c.Voters),
		"--positions", strconv.Itoa(c.Positions),
		"--candidates", strconv.Itoa(c.Candidates),
		"--trustees", strconv.Itoa(len(c.Trustees)),
		"--threshold", strconv.Itoa(c.Threshold),
		"--election-id", runID,
		"--election-name", c.Name,
		"--trustee-names", strings.Join(c.TrusteeNames(), ","),
		"--distribution", c.Distribution,
		path,
	}
	e.publish(runID, "ceremony", "info", "generating the election bundle…")
	if _, err := e.run(ctx, e.demoBin, args...); err != nil {
		e.publish(runID, "ceremony", "error", "bundle generation failed: "+err.Error())
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

// localCeremonyOK reports whether running the ceremony without a ledger is what
// the operator actually asked for. offline and ground-truth runs never involve
// a chain; an on-chain run without one is a misconfiguration, not a fallback.
func localCeremonyOK(c ElectionConfig) bool {
	return c.Mode != "onchain"
}

func (e *Executor) CeremonyStart(ctx context.Context, runID string, c ElectionConfig) error {
	path, err := e.generateBundle(ctx, runID, c)
	if err != nil {
		return err
	}
	if !e.fabric.Enabled() {
		if !localCeremonyOK(c) {
			e.publish(runID, "ceremony", "error", errNoFabric().Error())
			return errNoFabric()
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
	if err := e.setupOnChain(ctx, b, step); err != nil {
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
	if !e.fabric.Enabled() {
		if !localCeremonyOK(c) {
			return errNoFabric()
		}
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
	if !e.fabric.Enabled() {
		if !localCeremonyOK(c) {
			return errNoFabric()
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

	path, err := e.bundlePath(runID)
	if err != nil {
		return err
	}
	_, step, err := e.lifecycle(runID, conn.Ledger(), path, "ceremony")
	if err != nil {
		return err
	}
	if err := step(ctx, "PublishTally", "", "PublishTally", b.Tally); err != nil {
		return err
	}
	e.publish(runID, "ceremony", "done",
		fmt.Sprintf("threshold met (%d of %d) — tally published on-chain", state.Submitted, state.Threshold))
	return e.markPublished(runID, c)
}

// CeremonyStatus reports the roster. On-chain the ledger is consulted as the
// authority; the local file is the fallback and the offline authority.
func (e *Executor) CeremonyStatus(runID string, c ElectionConfig) (CeremonyState, error) {
	state := e.readCeremony(runID, c)
	state.OnChain = e.fabric.Enabled()

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
	for _, t := range stored.Trustees {
		submitted[t.ID] = t.Submitted
	}
	for i := range fresh.Trustees {
		fresh.Trustees[i].Submitted = submitted[fresh.Trustees[i].ID]
	}
	fresh.Published = stored.Published
	fresh.Ready = stored.Ready
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
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (e *Executor) markSubmitted(runID string, c ElectionConfig, trusteeID string) error {
	s := e.readCeremony(runID, c)
	for i := range s.Trustees {
		if s.Trustees[i].ID == trusteeID {
			s.Trustees[i].Submitted = true
		}
	}
	return e.writeCeremony(runID, c, &s)
}

func (e *Executor) markPublished(runID string, c ElectionConfig) error {
	s := e.readCeremony(runID, c)
	s.Published = true
	return e.writeCeremony(runID, c, &s)
}
