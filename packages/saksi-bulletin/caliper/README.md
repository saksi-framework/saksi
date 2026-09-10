# Saksi Caliper benchmark

Hyperledger Caliper benchmark for the bulletin-board `SubmitBallot` workload
(thesis Phase 2, the paper-mandated tool).

**What comes from which tool.** Caliper is the **cross-check on throughput and
success rate**: it reports send rate, committed-tps throughput, succ/fail
counts, and (via the docker monitor) peak CPU/mem. It does **not** report
latency percentiles — its summary carries max/min/avg only
([Caliper issue #407](https://github.com/hyperledger-caliper/caliper/issues/407)).
The paper's **p50/p95/p99 come from the Go bench driver**
(`../client-sdk/bench/`), which is the percentile source of record.

So that Caliper's own runs are still comparable, `workloads/submit-ballot.js`
logs each transaction's `startMs,endMs` to `latencies.ndjson` and `report.js`
derives p50/p95/p99 from that log using the **same nearest-rank rule** as the Go
driver (`index = ceil(p/100 * N) - 1` on the sorted samples). With no such log,
`report.js` prints Caliper's max/min/avg and the line
`percentiles: unavailable (Caliper reports max/min/avg only)` — never a guess.

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

# 3. run the benchmark (clears any stale latencies.ndjson first)
npm run bench

# 4. summarise it, with percentiles derived from latencies.ndjson
npm run report
```

Caliper's own report lands in `report.html` (or `report.json` when launched with
`--caliper-report-format json`) in this directory; `report.js` reads whichever
is present. Pass explicit paths to override:
`node report.js path/to/report.json path/to/latencies.ndjson`.

## Scaling to the paper's tiers

Each round's `txNumber` MUST equal its bundle's ballot count (each unique ballot
is submitted exactly once — a re-submit is nullifier-rejected and would count as
a failure). To add a tier: generate the bundle, uncomment its round in
`benchmarks/ballot-submission.yaml`, set `txNumber` to the ballot count, and
point `arguments.bundle` at it. Sweep offered load via each round's
`rateControl` (`fixed-rate` tps for a send-rate sweep, `fixed-load` to hold a
target backlog).

## Self-check

`npm test` runs `workloads/partition.test.js` (the worker ballot-partitioning
tiles every ballot exactly once — no gap, no double-submit) and
`report.test.js` (JSON + HTML report parsing, nearest-rank percentiles, and the
`percentiles: unavailable` path). No live network needed.

## Network-gated

The actual campaign runs (especially 483k / 1M) need a live Fabric on a
space-free path (WSL / Linux); the same gate as the Phase 6 evaluation
campaigns. This directory is the ready-to-run harness; executing it is the
campaign step.
