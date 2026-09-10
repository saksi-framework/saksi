'use strict';

// Run with: node --test report.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { parseReport, readLatencies, percentile, formatReport, UNAVAILABLE } = require('./report');

const tmpFile = (name, body) => {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'caliper-report-')), name);
  fs.writeFileSync(p, body);
  return p;
};

const JSON_REPORT = JSON.stringify({
  summary: [
    {
      label: 'submit-ballots-1k',
      succ: 1000,
      fail: 0,
      sendRate: 50.4,
      throughput: 49.2,
      latency: { max: 2.3, min: 0.11, avg: 0.85 },
    },
  ],
});

const HTML_REPORT = `<html><body><table>
<tr><th>Name</th><th>Succ</th><th>Fail</th><th>Send Rate (TPS)</th>
<th>Max Latency (s)</th><th>Min Latency (s)</th><th>Avg Latency (s)</th><th>Throughput (TPS)</th></tr>
<tr><td>submit-ballots-1k</td><td>1000</td><td>0</td><td>50.4</td><td>2.30</td><td>0.11</td><td>0.85</td><td>49.2</td></tr>
</table></body></html>`;

// The whole reason this file exists: Caliper gives max/min/avg only (issue
// #407), so the percentiles must come from the per-tx log — and land on the
// same element the Go bench driver would pick.
test('nearest-rank percentile matches the Go bench rule', () => {
  const sorted = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
  // index = ceil(p/100 * N) - 1
  assert.strictEqual(percentile(sorted, 50), 5); // ceil(5)-1 = 4
  assert.strictEqual(percentile(sorted, 95), 10); // ceil(9.5)-1 = 9
  assert.strictEqual(percentile(sorted, 99), 10);
  assert.strictEqual(percentile([7], 99), 7);
  assert.strictEqual(percentile([], 50), null);
});

test('JSON report + latencies.ndjson yields percentiles per round', () => {
  const rounds = parseReport(JSON_REPORT);
  assert.strictEqual(rounds.length, 1);
  assert.strictEqual(rounds[0].label, 'submit-ballots-1k');
  assert.strictEqual(rounds[0].throughput, 49.2);

  const lines = [];
  for (let i = 1; i <= 100; i++) lines.push(JSON.stringify({ round: 0, startMs: 0, endMs: i }));
  const byRound = readLatencies(tmpFile('latencies.ndjson', lines.join('\n') + '\n'));
  assert.strictEqual(byRound.get(0).length, 100);

  const out = formatReport(rounds, byRound);
  assert.match(out, /p50 50\.0 {2}p95 95\.0 {2}p99 99\.0 {2}\(n=100\)/);
  assert.ok(!out.includes(UNAVAILABLE), `percentiles were available:\n${out}`);
});

test('HTML report parses and, with no latencies, says percentiles are unavailable', () => {
  const rounds = parseReport(HTML_REPORT);
  assert.deepStrictEqual(
    [rounds.length, rounds[0].label, rounds[0].succ, rounds[0].avgLatency, rounds[0].throughput],
    [1, 'submit-ballots-1k', 1000, 0.85, 49.2]
  );

  const out = formatReport(rounds, readLatencies(path.join(os.tmpdir(), 'no-such-latencies.ndjson')));
  assert.ok(out.includes(UNAVAILABLE), out);
  assert.match(out, /max 2\.30 {2}min 0\.11 {2}avg 0\.85/);
});

// A half-written line (a worker killed mid-flush) must not poison the sort.
test('malformed and negative latency lines are skipped', () => {
  const body = [
    JSON.stringify({ round: 0, startMs: 10, endMs: 30 }),
    '{"round":0,"startMs":',
    JSON.stringify({ round: 0, startMs: 50, endMs: 40 }),
    JSON.stringify({ round: 1, startMs: 0, endMs: 5 }),
  ].join('\n');
  const byRound = readLatencies(tmpFile('latencies.ndjson', body));
  assert.deepStrictEqual(byRound.get(0), [20]);
  assert.deepStrictEqual(byRound.get(1), [5]);
});
