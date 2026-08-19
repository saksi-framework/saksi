# Design — Research Election Console

Status: design (brainstormed + approved 2026-08-19). Supersedes the "live
dashboard" scope of the campaign suite plan
(`2026-07-15-research-campaign-suite.md`, Phase 3.2): that dashboard becomes this
full configure-and-run console. Implementation plan follows via writing-plans.

## Problem

The researchers need to run the paper's tests from a real interface — configure
an election (name, trustees, scale), run it, verify correctness, inspect the
generated ballots before they reach saksi, and run the negative/vulnerability
scenarios the paper requires — instead of hand-driving `saksi-demo` /
`saksi-console` on the command line. It is an internal researcher/ops tool + a
defense-demo artifact, not a consumer product.

## Decisions (brainstorming Q1–Q7)

1. **Unified console** — configure an election AND run it at a chosen scale.
2. **Both run targets, selectable:** Offline (`saksi-demo gen → audit`, no
   network) or On-chain (real Fabric lifecycle, the perf numbers).
3. **Go-served localhost web app** — the `saksi-campaign` binary serves it; single
   binary, no new toolchain (consistent with the campaign-suite decision).
4. **Configurable trustees** — election name + `t`-of-`n` (any `1 ≤ t ≤ n`, UI cap
   `n ≤ 15`, default majority) + per-trustee names. Real n-dealer DKG.
5. **Single scale per run** — preset tiers (1/10/100/1000/10k/50k/483k/1M) or
   custom N; results accumulate in a history table.
6. **Independent phases with artifact export/import** — Generate | Submit | Verify
   | Scenarios, each runnable alone over a `run/<id>/` folder; a "Run all" chains
   them. Ballots are exportable/inspectable BEFORE Submit.
7. **Scenarios = inject + capture evidence** — a deliberate phase over a generated
   run: mutate one artifact per scenario, submit/verify, capture the real
   rejection (chaincode error / auditor Fail + log), fill a Table-3.8 row.

## Architecture

```
Browser  (config form · phase bar · live SSE view · results · history)
   ⇅ HTTP + Server-Sent Events
saksi-campaign serve   (Go, 127.0.0.1:8090, loopback only)
   POST /generate {config}        → run/<id>/ (header, ballots.ndjson, ground_truth)
   POST /submit   {run_id}        → saksi/Fabric (on-chain) | no-op (offline)
   POST /verify   {run_id}        → audit → correctness.csv (+ independent-verify)
   POST /scenarios{run_id,list}   → inject each → negative-tests.csv
   POST /run-all  {config}        → chain generate→submit→verify(→scenarios)
   GET  /events?run=<id>          → SSE phase progress + log lines
   GET  /runs                     → history (JSON)
   GET  /export/<id>/<artifact>   → download a run artifact
   executors:
     offline  → saksi-demo gen (parameterized) ; saksi-demo audit
     on-chain → console --auto lifecycle + Reconcile ; saksi-auditor
   scenario library → deterministic mutations of a run's artifacts
```

Single Go pkg `packages/saksi-campaign`. Loopback bind + tier/axis/run-id
allowlist (no user string interpolated into a filesystem path) — the hardening
from the campaign-suite eng review.

## Components

### 1. Config model (Go)
`ElectionConfig{ name, trustees []Trustee{name}, threshold, positions,
candidates, distribution (uniform|skewed), voters, mode (offline|onchain) }`.
Validated server-side: `1 ≤ threshold ≤ len(trustees) ≤ 15`, `voters ≥ 1`,
non-empty name, positions/candidates ≥ 1. Client mirrors the checks for instant
feedback. Persisted to `run/<id>/config.json`.

### 2. Generator parameterization (Rust — the real backend change)
Today the generator hardcodes 3-of-5, `election_id = "election-2026"`, trustee
ids `"1".."5"`. Parameterize:
- `saksi-demo gen` gains `--election-id <s>`, `--threshold <t>`, `--trustees <n>`
  (trustee display names carried in the stream header, off-wire).
- `multi_position_fixture(election_id, threshold, trustees, names, voters,
  positions, candidates, profile)`; the DKG uses `DkgConfig::new(t, n)` instead of
  `default_3_of_5()` (the dealer loop already keys off `config.trustees/threshold`).
- `write_election_stream_params` / `election_bundle_json_params` gain the same
  params; the header records `election_name` + `trustee_names`.
- Validation gate already fail-closed; extend it to the new params (t ≤ n).

### 3. Run-folder store (Go)
`run/<id>/` = `config.json` · `header.json` · `ballots.ndjson` ·
`ground_truth.json` · `correctness.csv` · `perf.csv` (on-chain) ·
`negative-tests.csv` (if scenarios ran) · `run.log`. `id` is a validated slug
(no path traversal). History = enumerate the run dirs, newest first.

### 4. Phase executors (Go)
- **Generate**: shell `saksi-demo gen` with the config → run folder; emit a ballot
  preview (first K decoded ballots: contest ids, position, nullifier prefix — no
  secrets). Streams progress via SSE.
- **Submit**: offline → skip (documented); on-chain → the Fabric lifecycle
  (CreateElection → DKG → SubmitBallot… ) + Reconcile (committed == submitted).
  Requires the network up; a clear error if not reachable.
- **Verify**: run the auditor over the run's public artifacts → `correctness.csv`
  (per contest: `ground_truth`, `decoded_tally`, `E = decoded − truth`,
  `pass`), plus the independent-verification (public-record-only) PASS/FAIL.
- **Scenarios**: for each selected scenario, copy the run, apply one mutation from
  the scenario library, submit/verify, capture the rejection → a
  `negative-tests.csv` row (scenario, precondition, action, expected, actual,
  evidence-log, verdict, security-property). Positive control per scenario (the
  unmutated run passes) so a false-green is impossible.

### 5. Scenario library (Go, mutations)
The 11-case negative catalog + adversary classes, each a pure mutation of a
run's artifacts, mirroring the existing auditor/chaincode tamper patterns
(`verification-tests.md`): reused nullifier, flipped CDS proof, malformed
ciphertext, altered contest id/manifest, dropped ballot, reordered ballots,
sub-threshold trustees, tampered partial-decryption, wrong issuer key, corrupted
bytes. (Expired credential — pending M20.)

### 6. Web UI (single self-contained HTML page + minimal JS)
- **Config panel**: the form (§1), trustee add/remove rows.
- **Phase bar**: `[Generate] [Submit] [Verify] [Scenarios]` + `[Run all]`; each
  shows idle / running / done / failed.
- **Live view**: SSE progress + tail of `run.log`; Cancel while running.
- **Results**: tally card per contest, E=0 pass/fail, independent-verify result,
  on-chain tps/latency (if on-chain); scenarios table.
- **History**: accumulated runs (name, N, t-of-n, mode, E=0, tps, time) + export
  buttons. Theme-aware, loopback-only.

## Data flow (Generate → Verify, offline)

```
config ──▶ POST /generate ──▶ saksi-demo gen ──▶ run/<id>/{header,ballots,ground_truth}
                                     │
                              (inspect/export ballots BEFORE submit)
                                     ▼
run/<id> ──▶ POST /verify ──▶ auditor ──▶ correctness.csv (ground_truth vs decoded, E)
                                     └──▶ independent-verification PASS/FAIL
```

## Error handling
- Config invalid → 400 + field errors (no run created).
- Generate/gen failure → phase `failed`, `run.log` surfaced, run folder kept for
  inspection.
- Submit with no reachable Fabric → explicit "network unreachable" (never a silent
  hang); offline mode never submits.
- Scenario whose mutation is NOT rejected → the scenario **fails loudly** (a gate
  that should have rejected did not) — this is a real finding, not an error to
  swallow.
- Single-run lock: one phase executes at a time per run; the server rejects a
  concurrent phase on the same run.

## Testing
- Generator parameterization: 2-of-3 and 4-of-7 elections round-trip + audit
  clean (Rust unit tests); validation gate rejects t > n.
- Config validation (Go): t > n, n > 15, empty name, voters 0 → rejected.
- Scenario library (Go): each mutation produces a rejection (offline audit Fail
  or a chaincode reject), with its positive control passing.
- `correctness.csv` content: E = 0 on a clean run; a tampered ground truth yields
  E ≠ 0 and `pass = false`.
- Run-folder store: id slug rejects path traversal; history ordering.
- SSE + handler smoke (offline generate→verify end to end, no network).
- On-chain submit/perf: network-gated (same as the campaign runs).

## NOT in scope
- Multi-scale sweep in one run (single scale per run; history accumulates) —
  possible follow-up.
- The voter/trustee/admin *write-path* apps (deferred; this console drives the
  protocol via saksi-demo / console, not the Tauri/Flutter apps).
- Dashboard auth (loopback-only research tool).
- Expired-credential scenario until M20 lands.

## Dependencies / sequencing
- Builds on `packages/saksi-campaign` (new; this design defines it — it is the
  campaign-suite Phase 3 expanded).
- Generator parameterization (Rust) is a prerequisite for Generate.
- On-chain Submit/perf need the live Fabric network (space-free path / WSL).
- Verified via CI (cargo + go) + the offline path locally; on-chain gated.
