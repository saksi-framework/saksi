package campaign

import (
	"context"
	"fmt"
	"path/filepath"
)

// The precinct seam: the exported entry points the precinct canvass driver
// (cmd/saksi-canvass-demo, package canvass) uses to run one generator precinct
// folder through the console's own on-chain lifecycle.
//
// The driver builds an Executor whose RunStore is rooted at the generator's
// output directory (`saksi-demo gen --stream <dir> --precincts N`), so each
// precinct-NN folder is a run folder and its name is the run id. The one thing
// that differs from a console run is the election id: the generator gives
// precinct NN the election <base>-pNN, not the folder name. precinctRun records
// that mapping so the ledger dump reads the right election (electionID).
//
// Nothing here is reached from the console or /wizard: the study path never
// calls these functions and never populates precinctIDs, so its behaviour, its
// journal events and its perf.csv rows are unchanged.

// electionID is the on-chain election id of runID's run: the precinct mapping
// when the driver registered one, else the run id itself (every console run).
func (e *Executor) electionID(runID string) string {
	if id, ok := e.precinctIDs[runID]; ok {
		return id
	}
	return runID
}

// precinctRun reads a precinct folder's header.json, registers its election id
// and returns the run config the lifecycle and verify stages need. The config
// is derived, not stored: the generator's header is the only source of truth.
func (e *Executor) precinctRun(folder string) (ElectionConfig, error) {
	dir, err := e.store.Dir(folder)
	if err != nil {
		return ElectionConfig{}, err
	}
	var h electionHeader
	if err := readJSON(filepath.Join(dir, headerFile), &h); err != nil {
		return ElectionConfig{}, fmt.Errorf("precinct %s: %w", folder, err)
	}
	if h.ElectionID == "" || h.Positions < 1 {
		return ElectionConfig{}, fmt.Errorf("precinct %s: header.json has no election id or positions", folder)
	}
	if e.precinctIDs == nil {
		e.precinctIDs = map[string]string{}
	}
	e.precinctIDs[folder] = h.ElectionID
	c := ElectionConfig{
		Name: h.ElectionName, Mode: "onchain",
		Positions: h.Positions, Candidates: h.Candidates, Voters: h.N / h.Positions,
	}
	c.applyDefaults()
	return c, nil
}

// PrecinctLifecycle runs the console's on-chain lifecycle for one precinct
// folder on the configured channel: CreateElection, PublishDKGTranscript, the
// measured ballot window (the same closed-loop submitter, receipts,
// latencies.csv and submit-metrics.json as a console run), CloseElection, the
// partial decryptions and PublishTally.
//
// beforeClose, when non-nil, runs after the ballot window and before
// CloseElection; an error from it stops the lifecycle there. It is the hook
// for chain-level attacks on an open election (T19/T20).
//
// The composition is setupOnChain + submitOnChain's tail with no attack-plan
// pauses (a precinct run has no AttackPlan, so those pauses would not fire
// anyway) and the beforeClose call inserted between the window and the close.
// The journal opens with run.start and brackets the lifecycle with
// stage.submit.start/end, as Generate and Submit do for a console run.
func (e *Executor) PrecinctLifecycle(ctx context.Context, folder string, beforeClose func(context.Context) error) error {
	c, err := e.precinctRun(folder)
	if err != nil {
		return err
	}
	dir, err := e.store.Dir(folder)
	if err != nil {
		return err
	}
	j, jerr := OpenJournal(dir, CollectEnv(e.demoBin))
	if jerr != nil {
		e.publish(folder, "submit", "info", "run journal unavailable: "+jerr.Error())
	}
	defer j.Close()
	_ = j.Stamp("run.start", map[string]any{
		"run_id": folder, "election_id": e.electionID(folder), "mode": c.Mode,
		"voters": c.Voters, "positions": c.Positions, "candidates": c.Candidates,
		"precinct": true,
	})
	_ = j.Stamp("stage.submit.start", nil)
	err = e.precinctLifecycle(ctx, folder, c, beforeClose)
	_ = j.Stamp("stage.submit.end", stageEnd(err))
	return err
}

func (e *Executor) precinctLifecycle(ctx context.Context, folder string, c ElectionConfig, beforeClose func(context.Context) error) error {
	bundlePath, err := e.generateBundle(folder)
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	led, closeLedger, err := e.openLedger()
	if err != nil {
		return fmt.Errorf("connect to Fabric: %w", err)
	}
	defer closeLedger()
	b, step, err := e.lifecycle(folder, led, bundlePath, "submit")
	if err != nil {
		return err
	}
	defer e.closeReceipts(folder)
	if err := step(ctx, "CreateElection", "", "CreateElection", b.Params); err != nil {
		return err
	}
	if err := step(ctx, "PublishDKGTranscript", "", "PublishDKGTranscript", b.DKG); err != nil {
		return err
	}
	if err := e.submitBallots(ctx, folder, c, b, led); err != nil {
		return err
	}
	if beforeClose != nil {
		if err := beforeClose(ctx); err != nil {
			return fmt.Errorf("before close: %w", err)
		}
	}
	if err := e.closeElection(ctx, folder, c, b, led, step); err != nil {
		return err
	}
	if err := submitPartials(ctx, b, step); err != nil {
		return err
	}
	return step(ctx, "PublishTally", "", "PublishTally", b.Tally)
}

// PrecinctVerify is Verify for one precinct folder: the chain's record of the
// precinct's election is dumped to <folder>/ledger/ (header.json and
// ballots.ndjson, in the chain's nullifier order), both directories are
// audited, correctness.csv and timings.json are written and the run is
// finalised (run.end and the perf.csv row). A dump that fails is recorded
// "not run" exactly as on the console; the caller checks for the dump.
func (e *Executor) PrecinctVerify(ctx context.Context, folder string) (StreamAudit, error) {
	c, err := e.precinctRun(folder)
	if err != nil {
		return StreamAudit{}, err
	}
	lr, done, err := e.openLedgerReader()
	if err != nil {
		return StreamAudit{}, fmt.Errorf("connect to Fabric: %w", err)
	}
	defer done()
	return e.verify(ctx, folder, c, lr)
}

// PrecinctChainInfo reports the channel height (ChainInfo.Height, the number
// of blocks) and the current block hash: the close reference a precinct return
// binds.
func (e *Executor) PrecinctChainInfo() (uint64, []byte, error) {
	led, done, err := e.openLedger()
	if err != nil {
		return 0, nil, fmt.Errorf("connect to Fabric: %w", err)
	}
	defer done()
	return led.ChainInfo()
}

// openLedgerReader opens the chain's read side for the ledger dump. Tests set
// dialLedger to a fake that also serves the reads.
func (e *Executor) openLedgerReader() (ledgerReader, func(), error) {
	if e.dialLedger != nil {
		led, done, err := e.dialLedger()
		if err != nil {
			return nil, nil, err
		}
		lr, ok := led.(ledgerReader)
		if !ok {
			done()
			return nil, nil, fmt.Errorf("test ledger does not serve ledger reads")
		}
		return lr, done, nil
	}
	conn, err := e.fabric.Connect()
	if err != nil {
		return nil, nil, err
	}
	return conn.Bulletin, func() { _ = conn.Close() }, nil
}
