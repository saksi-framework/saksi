'use strict';

// Caliper workload module for the Saksi bulletin-board SubmitBallot throughput
// benchmark (thesis Phase 2). Each ballot is a unique, pre-generated,
// chaincode-valid record from the SAME bundle JSON that `saksi-demo gen`
// produces and `saksi-console` consumes — one artifact contract, no parallel
// format. Election setup (CreateElection + PublishDKGTranscript) is done ONCE
// out-of-band by `saksi-console` before this runs; this module measures only
// the ballot-submission path (the axis compared against Galal's baseline).

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const fs = require('fs');
const path = require('path');
const { partitionRange } = require('./partition');

// Caliper's own report carries max/min/avg latency and no percentiles (Caliper
// issue #407), so every transaction's start/end is logged here and ../report.js
// derives p50/p95/p99 from it with the same nearest-rank rule as the Go driver.
const LATENCY_LOG = path.join(__dirname, '..', 'latencies.ndjson');

class SubmitBallotWorkload extends WorkloadModuleBase {
  async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
    await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);

    const bundlePath = roundArguments.bundle;
    if (!bundlePath) {
      throw new Error('submit-ballot workload requires roundArguments.bundle (path to the saksi-demo gen bundle JSON)');
    }
    this.contractId = roundArguments.contractId || 'saksi-bulletin';
    this.channel = roundArguments.channel || 'saksi';

    const bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
    const ballots = bundle.ballots || [];
    if (ballots.length === 0) {
      throw new Error(`bundle ${bundlePath} carries no ballots`);
    }

    // This worker owns a disjoint contiguous slice — every ballot submitted
    // exactly once across all workers (no double-submit, no gap).
    const { start, end } = partitionRange(ballots.length, totalWorkers, workerIndex);
    this.myBallots = ballots.slice(start, end);
    this.cursor = 0;
    this.roundIndex = roundIndex;
    this.workerIndex = workerIndex;
    this.latencies = [];
  }

  async submitTransaction() {
    if (this.cursor >= this.myBallots.length) {
      // Caliper drives tx count via the round config; if it overshoots this
      // worker's slice, wrap would re-submit (nullifier-rejected). Fail loud
      // instead so the misconfig surfaces rather than logging phantom errors.
      throw new Error('worker ran out of unique ballots — set round txNumber == bundle ballot count');
    }
    const ballotHex = this.myBallots[this.cursor++];
    const startMs = Date.now();
    try {
      await this.sutAdapter.sendRequests({
        contractId: this.contractId,
        channel: this.channel,
        contractFunction: 'SubmitBallot',
        contractArguments: [ballotHex],
        readOnly: false,
      });
    } finally {
      // Buffered, not written per transaction: a synchronous file write inside
      // the measured path would inflate the very latency it records.
      this.latencies.push(JSON.stringify({
        round: this.roundIndex, worker: this.workerIndex, startMs, endMs: Date.now(),
      }));
    }
  }

  async cleanupWorkloadModule() {
    if (this.latencies.length === 0) return;
    // ponytail: one append per worker, relying on O_APPEND atomicity to keep
    // the workers' blocks from tearing. If a torn line ever shows up (report.js
    // skips them), give each worker its own latencies-w<N>.ndjson instead.
    try {
      fs.appendFileSync(LATENCY_LOG, this.latencies.map((l) => l + '\n').join(''));
    } catch (err) {
      // Never fail a benchmark round over the side-channel log.
      console.warn(`could not write ${LATENCY_LOG}: ${err.message}`);
    }
    this.latencies = [];
  }
}

function createWorkloadModule() {
  return new SubmitBallotWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;
