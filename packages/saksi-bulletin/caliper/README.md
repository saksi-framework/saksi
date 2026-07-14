# Saksi Caliper benchmark

Hyperledger Caliper benchmark for the bulletin-board `SubmitBallot` workload
(thesis Phase 2, the paper-mandated tool). Caliper reports the paper's metrics
natively: send rate, committed-tps throughput, latency percentiles, success
rate, and (via the docker monitor) peak CPU/mem.

The custom Go harness (`../client-sdk/bench/`) stays as an independent
**cross-check** of these numbers — two tools, one comparison.

## What Caliper measures here

Only the **ballot-submission** path — the axis compared against the Galal
baseline (on-chain CDS + credential + nullifier verification all run at
endorsement). Election setup (`CreateElection` + `PublishDKGTranscript`) is a
one-time prerequisite done out-of-band by `saksi-console`, not part of the
measured round.

## Prerequisites

- Node 18+ and the live test-network (`../network/network.sh all`) with Docker.
- A generated bundle per tier/axis: `saksi-demo gen --voters N --positions P`
  (`P=1` single, `P=3` multi) → put the JSON where the benchmark config points
  (default `../../../bundles/bundle-1k-<axis>.json`).

## Run

```bash
cd packages/saksi-bulletin/caliper
npm install
npm run bind                 # binds the Fabric 2.2 SUT connector

# 1. bring up the network + deploy the chaincode
../network/network.sh all

# 2. one-time election setup (CreateElection + PublishDKGTranscript) via console
#    — point it at the SAME bundle the Caliper round will submit ballots from,
#    so Caliper owns the measured ballot round.
go run ../client-sdk/cmd/saksi-console --bundle ../../../bundles/bundle-1k-multi.json --setup-only

# 3. run the benchmark
npm run bench
```

The HTML/JSON report lands in `report.html` in this directory.

## Scaling to the paper's tiers

Each round's `txNumber` MUST equal its bundle's ballot count (each unique ballot
is submitted exactly once — a re-submit is nullifier-rejected and would count as
a failure). To add a tier: generate the bundle, uncomment its round in
`benchmarks/ballot-submission.yaml`, set `txNumber` to the ballot count, and
point `arguments.bundle` at it. Sweep offered load via each round's
`rateControl` (`fixed-rate` tps for a send-rate sweep, `fixed-load` to hold a
target backlog).

## Self-check

`npm test` runs `workloads/partition.test.js` — verifies the worker
ballot-partitioning tiles every ballot exactly once (no gap, no double-submit)
for a range of (total, workers). No live network needed.

## Network-gated

The actual campaign runs (especially 483k / 1M) need a live Fabric on a
space-free path (WSL / Linux); the same gate as the Phase 6 evaluation
campaigns. This directory is the ready-to-run harness; executing it is the
campaign step.
