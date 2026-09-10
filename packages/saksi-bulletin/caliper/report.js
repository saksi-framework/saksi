'use strict';

// Caliper reports Max/Min/Avg latency and nothing else — there is no percentile
// in its output (Caliper issue #407). This reads a finished run's report plus
// the per-transaction latencies the workload writes to latencies.ndjson and
// prints p50/p95/p99 per round, using the SAME nearest-rank rule as the Go
// bench driver (index = ceil(p/100 * N) - 1 on the sorted list) so the two
// tools' numbers are comparable. Without the ndjson it prints what Caliper
// gives and says the percentiles are unavailable — never a guessed number.
//
// Usage: node report.js [report.json|report.html] [latencies.ndjson]

const fs = require('fs');
const path = require('path');

const UNAVAILABLE = 'percentiles: unavailable (Caliper reports max/min/avg only)';

const num = (v) => {
  const n = typeof v === 'string' ? parseFloat(v.replace(/,/g, '')) : v;
  return Number.isFinite(n) ? n : null;
};
// Caliper's JSON round objects have moved field names between versions; take
// the first name that is actually present rather than pinning one spelling.
const pick = (obj, names) => {
  for (const n of names) {
    if (obj && obj[n] !== undefined && obj[n] !== null) return obj[n];
  }
  return null;
};

// parseReport accepts either Caliper's JSON report or its HTML report and
// returns one entry per round.
function parseReport(text) {
  const trimmed = text.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return parseJSONReport(JSON.parse(trimmed));
  }
  return parseHTMLReport(text);
}

function parseJSONReport(doc) {
  const rounds = Array.isArray(doc)
    ? doc
    : pick(doc, ['summary', 'results', 'rounds', 'benchmarks']) || [];
  return rounds.map((r) => {
    const lat = pick(r, ['latency', 'latencies']) || r;
    return {
      label: String(pick(r, ['label', 'name', 'testName', 'round']) ?? ''),
      succ: num(pick(r, ['succ', 'success', 'passed'])),
      fail: num(pick(r, ['fail', 'failed'])),
      sendRate: num(pick(r, ['sendRate', 'send_rate'])),
      throughput: num(pick(r, ['throughput', 'tps'])),
      maxLatency: num(pick(lat, ['max', 'maxLatency', 'max_latency'])),
      minLatency: num(pick(lat, ['min', 'minLatency', 'min_latency'])),
      avgLatency: num(pick(lat, ['avg', 'avgLatency', 'avg_latency'])),
    };
  });
}

// Caliper's HTML summary table is one row per round:
// Name | Succ | Fail | Send Rate | Max Latency | Min Latency | Avg Latency | Throughput
function parseHTMLReport(html) {
  const rows = [];
  for (const [, row] of html.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)) {
    const cells = [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/gi)].map((m) =>
      m[1].replace(/<[^>]*>/g, '').trim()
    );
    if (cells.length < 8 || num(cells[1]) === null) continue; // header / prose row
    rows.push({
      label: cells[0],
      succ: num(cells[1]),
      fail: num(cells[2]),
      sendRate: num(cells[3]),
      maxLatency: num(cells[4]),
      minLatency: num(cells[5]),
      avgLatency: num(cells[6]),
      throughput: num(cells[7]),
    });
  }
  return rows;
}

// readLatencies groups per-transaction durations (ms) by round index. Lines the
// workload could not write cleanly are skipped rather than poisoning the sort.
function readLatencies(file) {
  const byRound = new Map();
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (_) {
    return byRound;
  }
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    let tx;
    try {
      tx = JSON.parse(line);
    } catch (_) {
      continue;
    }
    const ms = num(tx.endMs) - num(tx.startMs);
    if (!Number.isFinite(ms) || ms < 0) continue;
    const round = Number.isFinite(tx.round) ? tx.round : 0;
    if (!byRound.has(round)) byRound.set(round, []);
    byRound.get(round).push(ms);
  }
  for (const list of byRound.values()) list.sort((a, b) => a - b);
  return byRound;
}

// percentile is the nearest-rank rule the Go bench driver uses: on a sorted
// list of N samples the p-th percentile is element ceil(p/100 * N) - 1. Any
// other rounding puts the two tools' p99 in different places.
function percentile(sorted, p) {
  if (sorted.length === 0) return null;
  const idx = Math.min(Math.ceil((p / 100) * sorted.length) - 1, sorted.length - 1);
  return sorted[Math.max(idx, 0)];
}

const fmt = (v, digits) => (v === null || v === undefined ? '?' : v.toFixed(digits));

function formatReport(rounds, byRound) {
  const out = [];
  rounds.forEach((r, i) => {
    out.push(`round ${i}: ${r.label}`);
    out.push(
      `  succ/fail: ${r.succ ?? '?'}/${r.fail ?? '?'}` +
        `   send rate: ${fmt(r.sendRate, 1)} tps   throughput: ${fmt(r.throughput, 1)} tps`
    );
    out.push(
      `  latency (s): max ${fmt(r.maxLatency, 2)}  min ${fmt(r.minLatency, 2)}  avg ${fmt(r.avgLatency, 2)}`
    );
    const samples = byRound.get(i) || [];
    if (samples.length === 0) {
      out.push(`  ${UNAVAILABLE}`);
      return;
    }
    out.push(
      `  latency (ms): p50 ${fmt(percentile(samples, 50), 1)}` +
        `  p95 ${fmt(percentile(samples, 95), 1)}` +
        `  p99 ${fmt(percentile(samples, 99), 1)}  (n=${samples.length})`
    );
  });
  return out.join('\n');
}

function main(argv) {
  const here = __dirname;
  const reportPath = argv[0] || (fs.existsSync(path.join(here, 'report.json'))
    ? path.join(here, 'report.json')
    : path.join(here, 'report.html'));
  const latPath = argv[1] || path.join(here, 'latencies.ndjson');
  const rounds = parseReport(fs.readFileSync(reportPath, 'utf8'));
  if (rounds.length === 0) {
    throw new Error(`no rounds found in ${reportPath}`);
  }
  console.log(formatReport(rounds, readLatencies(latPath)));
}

if (require.main === module) {
  main(process.argv.slice(2));
}

module.exports = { parseReport, readLatencies, percentile, formatReport, UNAVAILABLE };
