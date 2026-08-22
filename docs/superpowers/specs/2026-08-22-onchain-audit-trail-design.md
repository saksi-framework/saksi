# On-Chain Audit-Trail View — Design

Date: 2026-08-22. Branch: `onchain-audit-trail` (off `research-election-console`).
Fulfils §6 of `docs/onchain-explorer-handoff.md`. §4 decisions are LOCKED and
inherited: full lifecycle trail with ledger receipts; the console holds the read
identity and serves outsiders; the public view stays sealed until the tally is
published (threshold unlock); voter identity never appears (none exists on-chain);
permissioned-read model.

QSCC spike result (CI-verified, balotachain run 32551023972): a committed
ballot's receipt IS retrievable — `Commit.Status()` gives the block number at
submit; `qscc GetBlockByTxID` is the required call; `GetChainInfo.CurrentBlockHash`
is the block hash only at tip; non-tip blocks need the ASN.1-DER header hash
(no block field stores its own hash). Known-good pair for tests: block 28 of that
run hashed to `5f896f60ee4a5a755dacd92ba162a707299621442683754c2469de8a123c43da`.

## Decisions (brainstormed, approved)

1. **Full §6 in one plan** — SDK receipt API, console on-chain Submit, trail
   view, unlock gate, tests.
2. **Network = WSL local** for dev/demo (space-free clone; Docker publishes
   peer ports to Windows localhost) + the CI fabric job for integration
   verification.
3. **Console imports client-sdk directly** (both Go, same repo). No shelling of
   `cmd/saksi-console`; the SDK boundary is a mockable interface.
4. **Public route + operator view**: `/trail/<election-id>` renders the sealed/
   open outsider view; the operator console panel sees live status throughout.
5. **Live reads + receipts export**: trail routes re-query the chain on each
   load; the Submit phase also records `receipts.csv` into the run folder
   (joins the evidence-CSV set).

## Components

### 1. client-sdk: ledger receipt API (`packages/saksi-bulletin/client-sdk`)

New `ledger.go`:

```go
type Receipt struct {
    TxID         string
    BlockNumber  uint64
    BlockHash    []byte // computed ASN.1-DER header hash — valid for ANY block
    DataHash     []byte
    PreviousHash []byte
}

// Ledger is the seam the console mocks in unit tests.
type Ledger interface {
    SubmitWithReceipt(fn string, args ...string) ([]byte, Receipt, error)
    LedgerReceipt(txID string) (Receipt, error)   // qscc GetBlockByTxID + header hash
    ChainInfo() (height uint64, currentBlockHash []byte, err error)
}
```

- `Connection` implements `Ledger` (submits target the bulletin contract;
  receipts come from `Commit.Status()` + qscc).
- `blockHeaderHash(number, previousHash, dataHash)` — SHA256 over the ASN.1-DER
  sequence, exactly Fabric's definition. Golden unit test: spike block 28
  fields must reproduce `5f896f60…`.
- `Gateway()` accessor (from the spike) stays, doc comment promoted from
  THROWAWAY.
- `cmd/qscc-probe` is DELETED — superseded by this API.
- The existing narrow `Contract` interface in `bulletin.go` is untouched;
  offline/bulletin behavior unchanged.

### 2. Console on-chain Submit (`packages/saksi-campaign`)

- New `fabric.go`: `FabricConfig` (peer endpoint, gateway peer, TLS cert, MSP
  id, cert, key, channel, chaincode — CLI flags `--fabric-*` with test-network
  defaults; nil/absent = on-chain mode unavailable, offline unaffected).
- Executor Submit phase, `mode=onchain`:
  1. Gen a one-blob bundle for the run's config (shells the existing
     `saksi-demo gen` with the run's voters/positions/candidates/trustees/
     threshold/election-id — the run id IS the election id, fresh per run).
  2. Drive the lifecycle through `Ledger`: CreateElection → PublishDKGTranscript
     → SubmitBallot × N → CloseElection → SubmitPartialDecryption × t →
     PublishTally.
  3. Each event: append to `receipts.csv` (event, ref, tx_id, block_number,
     block_hash, data_hash, previous_hash) and `trail.json` in the run folder;
     stream progress to the SSE log.
- Mid-lifecycle failure: fail loud, keep the run folder with partial
  receipts.csv, log the failing event. Re-run = new run = new election id;
  no resume of half-committed elections.

### 3. Trail routes + gate

- `GET /api/trail/<election-id>`:
  - `GetElectionStatus` first. Fail-closed: any error, or status ≠ tallied →
    `{"sealed":true,"status":…}` and nothing else.
  - Open (tally published): full trail JSON — per lifecycle event the chaincode
    record reference + `Receipt`; ballots show ONLY on-chain fields (nullifier,
    credential commitment, ciphertext/proof counts); tally results included.
  - `?operator=1` — honored only when the request's remote address is loopback
    (stricter than the host guard, which `--allow-host` can widen for LAN
    outsiders): live trail regardless of seal (insider view per §4). Non-loopback
    requests with `operator=1` get the sealed behavior.
- `GET /trail/<election-id>`: public single-file page rendering the JSON —
  sealed banner or block-linked timeline. Same theme system as the console.
- Chain unreachable → 502 + plain error; never a fabricated/stale trail.

### 4. UI

- Operator: new Trail panel in `web/index.html` — appears for on-chain runs,
  polls `/api/trail/<id>?operator=1`, renders events as they commit.
- Public: `web/trail.html` (embedded like index) — sealed state prominent;
  open state: timeline of events, each row: event type, ref, tx id, block
  number, block hash; tally table at the end.

### 5. Tests

- Unit (mock `Ledger`): header-hash golden test; gate open/closed/error⇒sealed;
  receipts.csv writer; trail JSON assembly; Submit orchestration incl.
  mid-failure ordering.
- CI integration (replaces the spike step in balotachain's fabric job): drive
  the console binary headless over HTTP against the CI network — on-chain run,
  assert `/api/trail` sealed before PublishTally, open after, receipts chain
  (each event block's previous_hash consistency), tally matches the bundle.
- All existing offline console + SDK tests stay green.

## Data flow

```
run config ──▶ saksi-demo gen (bundle, election-id = run-id)
bundle ──▶ executor onchain Submit ──▶ client-sdk Ledger ──▶ chaincode
                       │ per event                              │
                       ▼                                        ▼
             receipts.csv / trail.json                 world state + blocks
                                                                │
   /trail/<id>  ◀── sealed?──GetElectionStatus──live reads──────┘
   /api/trail/<id>            (+ qscc receipts, ASN.1 block hash)
```

## Out of scope

- Multi-org / production topology (network README's target topology).
- Auth on the public route beyond the existing host guard (thesis demo).
- Balotachain-side write path (stub credentials — separate locked decision).
- Hyperledger Explorer integration.

## Environment (WSL, one-time)

Docker Desktop WSL integration for Ubuntu; Go + Rust in WSL; clone saksi to
`~/saksi`; install-fabric.sh **pinned 2.5.15** with fabric-samples sibling;
`network.sh all`. Console runs on Windows against `localhost:7051`
(certs read via `\\wsl$` paths).
