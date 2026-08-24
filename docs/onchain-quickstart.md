# On-chain quickstart — one command

Bring up Hyperledger Fabric, deploy the chaincode, and start the console wired
to it:

```bash
./tools/up.sh
```

That is the whole thing. It prints a URL; open the wizard and **on-chain mode
will be selectable**, because the console reports its own capability and the
wizard reads it.

```
Saksi — bringing up the full stack
  ✓ fabric-samples present
  ✓ network up, chaincode deployed on channel saksi
  ✓ identity resolved (Org1MSP, User1)
  ✓ binaries built

Console starting — on-chain mode ENABLED
  wizard   http://127.0.0.1:8090/wizard
  trail    http://127.0.0.1:8090/trail/
```

| Command | Does |
|---|---|
| `./tools/up.sh` | Everything: install Fabric if missing, network up, deploy, build, run |
| `./tools/up.sh down` | Stop the Fabric network (run folders are kept) |
| `./tools/up.sh status` | What is running, and whether on-chain is actually enabled |

Ctrl-C stops the console and **leaves the network up**, so restarting is
instant. Use `down` when you want Fabric stopped too.

---

## Requirements

| Need | Note |
|---|---|
| Docker | Must be **running**. Fabric's peers and orderer are containers. |
| Go 1.23+, Rust stable | The console and the generator are built from source |
| A repo path with **no spaces** | see below — this is not negotiable |

The script checks all of these before touching anything, and each failure says
what to do rather than what went wrong.

### The path cannot contain a space

`fabric-samples` resolves paths through shell scripts that do not quote
consistently. A space anywhere above the repo breaks the chaincode deploy, and
the error points nowhere near the cause.

```
✗ the repo path contains a space:
    /q/Code - LAPTOP/Code/projects/saksi
  fabric-samples cannot handle it. Clone somewhere like ~/Code/saksi and retry.
```

On the Mac, `~/Code/saksi` is fine. This is exactly why the primary Windows dev
box cannot run Fabric locally and verifies through CI instead.

### First run downloads Fabric

If `fabric-samples` is not found beside the repo, the script installs it —
binaries, Docker images and samples, pinned to the version CI uses. That is
about **1 GB of images** and takes a few minutes. Later runs skip it entirely.

Point it at an existing checkout to avoid the download:

```bash
FABRIC_SAMPLES=~/fabric-samples ./tools/up.sh
```

---

## Confirming it is really on-chain

Three checks, increasingly independent:

**1. Ask the console.**

```bash
curl -s localhost:8090/api/capabilities
# {"fabric":true,"peer":"localhost:7051","channel":"saksi"}
```

`"fabric":true` is what unlocks the wizard's on-chain option. If it is `false`,
the console was started without the certificate flags and **on-chain mode will
be refused** rather than silently running locally.

**2. Watch the receipts.** Run an election with mode **on-chain**. The Encrypt
step shows a real ledger receipt per transaction — block number, transaction id,
block hash — and writes them to `receipts.csv` in the run folder.

**3. Read the ledger without us.** The receipts come from Fabric's `qscc` system
chaincode. Anyone with peer access can fetch the same block directly, so nothing
in our code has to be trusted:

```bash
export PATH=$FABRIC_SAMPLES/bin:$PATH
export FABRIC_CFG_PATH=$FABRIC_SAMPLES/config
peer channel getinfo -c saksi     # height and current block hash
```

`/trail/` lists every election the console has recorded, each checked against
the ledger; `/trail/<election-id>` is one election's full audit trail.

---

## What "forever" means here

The chaincode has **no delete function** — every write is `PutState`, and there
is no `DelState` anywhere in it. Writes cannot overwrite either:
`CreateElection` rejects a duplicate id, `PublishDKGTranscript` rejects a second
transcript, `PublishTally` rejects a second tally, and `SubmitBallot` rejects a
spent nullifier. So no transaction from anyone can remove or alter a committed
election.

Two clarifications worth having ready:

**Resetting the chaincode does not erase anything.** The ledger belongs to the
channel, not to the chaincode. Deploying a new chaincode version reads the same
existing state. There is no chaincode operation that wipes an election.

**What does destroy it** is `./tools/up.sh down`, which tears the network down
and removes the peers' storage volumes. That is deleting the database, not
rolling back the chain.

**And the honest limit:** this is the Fabric *test network* — one organisation,
peers you control. Immutability in Fabric comes from independent organisations
each holding a copy and endorsing. A single operator holding every peer can
always delete the volumes and start again.

So the accurate claim is: *the chaincode and protocol make the record
append-only and tamper-evident — any alteration breaks the block-hash chain and
is detectable. Distributed immutability additionally requires independent
organisations, which a single-org test network does not provide.*

That is a deployment property, not a gap in the protocol, and stating it that
way is stronger than claiming a permanence a one-org network cannot back.

---

## If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| `the Docker daemon is not running` | Docker Desktop not started | Start it; `docker info` should succeed |
| `the repo path contains a space` | see above | Clone to `~/Code/saksi` |
| Deploy fails with a vendor error | chaincode deps not vendored | The script vendors them; if it still fails, run `go mod vendor` in `packages/saksi-bulletin/chaincode` |
| Wizard still greys out on-chain | console has no certificate flags | `./tools/up.sh status` — it says whether on-chain is enabled |
| Network half-up after a failure | leftover containers | `./tools/up.sh down`, then rerun |

`./tools/up.sh down` followed by `./tools/up.sh` is the reliable reset. It is
also the fastest way to get a clean ledger for a fresh demonstration.

## Related

- `research-election-console-runbook.md` — running the console without Fabric
  (offline mode, no Docker needed).
- `wizard/4-encrypt.md` — what the on-chain lifecycle actually submits.
- `wizard/deep-dive.md` — every step, and where each guarantee is enforced.
