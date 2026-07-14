'use strict';

// Contiguous partition of `total` items across `workers`, returning the
// [start, end) index range this `workerIndex` owns. Remainder is spread over
// the first `r` workers so every ballot is submitted exactly once, never twice
// (a re-submitted ballot is nullifier-rejected on-chain and would falsely count
// as a failure). Pure + deterministic so Caliper workers agree without
// coordination.
function partitionRange(total, workers, workerIndex) {
  const base = Math.floor(total / workers);
  const rem = total % workers;
  const start = workerIndex * base + Math.min(workerIndex, rem);
  const len = base + (workerIndex < rem ? 1 : 0);
  return { start, end: start + len };
}

module.exports = { partitionRange };
