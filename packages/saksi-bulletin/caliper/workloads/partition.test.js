'use strict';

// ponytail: assert-based self-check, run with `node workloads/partition.test.js`.
// Guards the one failure-prone bit: partitions must tile [0,total) with no gap
// and no overlap for any (total, workers) — a gap drops ballots, an overlap
// double-submits (nullifier-rejected → false failure).
const assert = require('assert');
const { partitionRange } = require('./partition');

for (const total of [0, 1, 5, 1000, 1001, 50000]) {
  for (const workers of [1, 2, 3, 7, 16]) {
    const covered = new Array(total).fill(0);
    for (let w = 0; w < workers; w++) {
      const { start, end } = partitionRange(total, workers, w);
      assert(start <= end, `start<=end for ${total}/${workers}#${w}`);
      for (let i = start; i < end; i++) covered[i]++;
    }
    for (let i = 0; i < total; i++) {
      assert.strictEqual(covered[i], 1, `ballot ${i} covered once (total=${total} workers=${workers})`);
    }
  }
}

console.log('partition.test.js: ok');
