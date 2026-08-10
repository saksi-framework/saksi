# Plan — Research Campaign Suite (Saksi thesis empirical evaluation)

## Problem

The paper (`balotachain/docs/BalotaChain_Main_Paper.docx`) is a Design-Science
empirical evaluation. Everything shipped so far — generate → validate → run →
tally — exists only at **demo scale** (small in-memory fixtures, one-shot). There
is no machine that runs the actual research: generate per tier, run the tier,
collect results, verify completeness across the tier×axis matrix, assemble the
paper's Tables 3.4–3.6 + Appendix C.

## Codebase investigation (2026-07-21) — verified, not assumed

### Resolved (NOT blockers)

- **Generated ballots commit through the REAL chaincode.** balotachain's `fabric`
  CI job: network up → deploy → `saksi-demo.sh gen` → `cycle` (CreateElection →
  DKG → SubmitBallot → close → partials → tally) → adapter asserts the real
  on-chain election + tally.
- **The crypto is real, not stubs.** `nizk/cds.rs` is a genuine ristretto255
  Chaum-Pedersen OR-proof with Fiat-Shamir challenge splitting; `saksi-credentials`
  states "full implementations, not stubs". **`balotachain/CLAUDE.md` is STALE** —
  it still claims all proofs are SHA-256 stubs. Fix that note.
- **No MVCC hot key.** `SubmitBallot` READS `statusKey`/`dkgKey`/`nullifierKey` and
  WRITES only `ballotKey` + `nullifierKey`, both unique per ballot. No shared
  counter → concurrent submit yields no write-write conflicts, so **concurrency and
  zero-drop `Reconcile` are compatible**. Caveat: never run `CloseElection`
  concurrently with submits (it writes `statusKey`, which submits read).
- Concurrency driver (`bench.Run`), percentiles, and the Caliper harness all exist.

### Missing code (the actual work)

| # | Gap | Evidence |
|---|-----|----------|
| 1 | `saksi-campaign` orchestrator (gen/run/resume/verify/serve, manifest, tier×axis matrix) | pkg does not exist |
| 2 | Streamed NDJSON generation | gen is one in-memory `to_string_pretty` blob |
| 3 | `Reconcile` wired into a run path | defined in `bench/accuracy.go`, never called |
| 4 | Ground-truth `E=0` check | auditor compares decrypted vs *published* totals only |
| 5 | **Phase timings + CDS-verify cost** | `PhaseTimings` + 5 CSV columns exist; `ToRow` sets only end-to-end latency — nothing populates them |
| 6 | Warmup / repetitions / variance / CI | zero code |
| 7 | Galal baseline producer (no-CDS chaincode variant) | only a string label + a test fixture |
| 8 | Send-rate sweep / saturation knee | `bench.Run` takes one rate; nothing sweeps |
| 9 | **Chaincode range/count query** (needed by chain-authoritative resume) | only point `GetBallot(electionID, nullifier)` |
| 10 | Abstention/turnout model | fixtures force 1 selection/position; gate asserts Σ == N |
| 11 | Independent ground-truth derivation | emitted by the same generator that builds the ballots |
| 12 | Tier×axis matrix definitions | tiers exist only as a `Row.Tier` int |

**#5 is the highest-risk gap**: the isolated CDS-verify cost is the paper's headline
claim against the Galal baseline, and there is currently no mechanism to measure it.
It needs chaincode-internal instrumentation plus a component microbenchmark; it will
not fall out of the Fabric Gateway SDK.

## Decisions (locked via brainstorming + CEO review)

| # | Decision |
|---|----------|
| D1 | Full Go orchestrator + live dashboard (ideal architecture, defense-demo artifact) |
| D2 | Review posture HOLD SCOPE |
| — | Streamed NDJSON (`header.json` + `ballots.ndjson`), atomic temp+rename |
| D6 | Keep dashboard + manifest; **drop the run-ledger** — chain is authoritative for resume |
| D4 | Phase 0 feasibility spike gates the build (largely de-risked by the CI evidence above) |
| D5 | Adopt all four benchmark-validity corrections (concurrency+sweep, phase/CDS source, warmup/reps/CI + pinned config + same-box Galal, independent ground truth + turnout) |
| D3 | Fold in 7 hardening findings (single-run lock, atomic gen + N-count gate, loopback bind + allowlist, one NDJSON contract, progress logs, E=0 decode bound) |

## Build order

**Phase 0 — de-risk + unblock (no scale needed)**
- 0.1 WSL/space-free Fabric bring-up; `saksi-demo.sh all` green locally.
- 0.2 Chaincode: add `CountBallots`/`ListNullifiers` range query (gap 9) — unblocks D6 resume.
- 0.3 Fix the stale stubs note in `balotachain/CLAUDE.md`.

**Phase 1 — correctness wiring (network-independent, buildable now)**
- 1.1 Streamed NDJSON gen + atomic write + `header.N == line count` gate (gaps 2, and hardening).
- 1.2 Independent ground-truth derivation + abstention/turnout model, gate Σ ≤ N (gaps 10, 11).
- 1.3 Wire `Reconcile` + ground-truth `E=0` (decode bound = per-tier N) into the run path (gaps 3, 4).

**Phase 2 — measurement validity (the science)**
- 2.1 Chaincode CDS-verify instrumentation + component microbenchmark; block-event
  attribution for order/validate/commit. Populate the 5 phase columns (gap 5).
- 2.2 Concurrent open-loop submit + send-rate sweep to the saturation knee; record
  retry rate (gap 8).
- 2.3 Warmup discard, ≥3 repetitions, mean ± CI; pin + record orderer
  BatchTimeout/BatchSize + state DB in the manifest (gap 6).
- 2.4 No-CDS chaincode variant → same-box Galal baseline row (gap 7).

**Phase 3 — orchestration + UI**
- 3.1 `saksi-campaign` pkg: tier×axis matrix, `gen|run|resume|verify`, `campaign.json`
  manifest, single-run lock, progress logs (gaps 1, 12).
- 3.2 `serve` dashboard: loopback bind, tier/axis allowlist, SSE live matrix,
  run/resume/verify buttons, table export.

**Phase 3.5 — correctness ladder (advisor gate, do BEFORE any perf tier)**
Advisor guidance (2026-07): complexity is the biggest risk; prove the *complete
protocol* correct at tiny scale before scaling. Run the full cycle (gen → submit
→ close → partial-decrypt → tally → **E=0 == ground truth** + Reconcile
zero-drop) at **N = 1, 10, 100, 1000 voters**, each a pass/fail milestone. These
are correctness gates, not performance runs: single-thread submit is fine, no
warmup/sweep needed. Perf tiers (Phase 4) do not start until N=1000 passes E=0.
The generator already takes `--voters N`, so the micro-tiers are free.

```
N=1 ─▶ N=10 ─▶ N=100 ─▶ N=1000    (each: E=0 + zero-drop, else STOP)
  └─ correctness proven ─┴─▶ Phase 4 perf tiers
```

**Phase 4 — perf campaigns** (network + time gated; only after Phase 3.5 passes)
- 1k → 10k local, then 50k/483k/1M on a dedicated box; projection fallback for
  any tier that cannot finish. The million-voter run is NOT attempted before the
  correctness ladder is green (advisor's explicit constraint).

## Sequencing decision — apps vs evaluation (RESOLVED 2026-07)

Investigated the apps' distance to real Fabric (evidence in the eng review /
apps-readiness report). Findings:
- **Auditor read path is code-complete + CI-proven** — SMALL (needs only a live
  network). `services/fabric-adapter` `GET /bulletin` + `BulletinSource::from_env`.
- **Write path is ABSENT, not stubbed** — balotachain has no chaincode-submit
  code at all; voter/trustee/admin write ballots to a JSON file, credential
  material is sha256 stubs, and the real credential FFI (`present_credential_v2`,
  `derive_nullifier_v2`) exists in saksi but is unwired. Building it = DKG
  ceremony + real issuance + on-chain submit = LARGE, and reverses the locked
  "stubs as-is" decision.
- **The complete protocol is already correctness-provable** without the apps:
  `saksi-demo.sh` runs the real full lifecycle (DKG, credentials, ballots,
  on-chain CDS verify) end-to-end. That IS the advisor's prove-small-first.

**Decision: eval-track + cheap app demos.** Order:
1. Correctness ladder — `saksi-demo` at N=1/10/100/1000 with E=0 (Phase 3.5).
2. Auditor real-Fabric demo (SMALL) — the Objective-1 "app works on real chain".
3. Perf eval (Phase 4) — the paper's novel contribution.

The LARGE voter/trustee/admin write path stays **deferred** (balotachain Phase 7):
re-implementing it reverses a locked decision, produces no evaluation data, and
duplicates what `saksi-demo` already proves. Revisit only if the advisor requires
the interactive apps (not just the auditor) demonstrated on real Fabric.

## Eng review hardening (E1–E6, all accepted)

- **E1 pagination**: the Phase 0.2 range query uses
  `GetStateByPartialCompositeKeyWithPagination` + client-side bookmark loop —
  Fabric `totalQueryLimit` (default 100k) truncates un-paginated queries, which
  would break resume exactly at the 483k/1M tiers.
- **E2 golden contract**: NDJSON writer is Rust, readers Go+JS — pin a golden
  `header.json` + `ballots.ndjson` fixture in `saksi-protocol/test-vectors/`
  (byte-pinned Rust writer test + Go reader test, same pattern as `ballot-v1.hex`).
- **E3 instrumentation channel**: chaincode CDS timing goes to **stdout → peer
  container logs only** — never state writes or chaincode events (endorsement
  content must stay deterministic).
- **E4 baseline build tag**: no-CDS Galal variant via `//go:build nocds` no-oping
  only the CDS-verify call — one codebase, no fork drift.
- **E6 parallel gen**: rayon-parallel per-voter generation (deterministic
  per-voter seeds, index-ordered writer) — 1M gen drops from hours to minutes.

## Testing (local, no network)

streamed-gen round-trip; gen-truncation rejected by the N-count gate; single-run
lock; `Reconcile` + `E=0` at the decode bound; manifest `verify` exit code;
percentile/variance math; dashboard smoke (loopback bind, matrix renders).
**E5 additions:** chain-query resume (kill mid-run → restart, no double-submit /
no gap); range query > 1 page (pagination edge); NDJSON cross-language golden
fixture; no-CDS parity (both builds agree on every non-CDS accept/reject case).

## Parallelization lanes

| Lane | Work | Modules | Depends on |
|---|---|---|---|
| A | Phase 1 streamed gen + ground truth + turnout (Rust) | saksi-demo, saksi-auditor | — |
| B | Phase 0.2 paginated query + E4 build tag (Go chaincode) | saksi-bulletin/chaincode | — |
| C | Phase 1.3 + 2.x console/bench wiring (Go client) | client-sdk | A (bundle format), B (query) |
| D | Phase 3 campaign pkg + dashboard | saksi-campaign (new) | C |

Lanes A + B run in parallel; C after both; D last. No shared modules between A and B.

## NOT in scope

Standing up production Fabric; dashboard auth (loopback-only research tool); BSGS
decode (linear is fine at these N); balotachain Phase 7 apps (last).

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | issues_open→resolved | HOLD SCOPE; D1–D6 + 7 hardening + 4 validity corrections, all folded in |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | usage-limited | Claude-subagent outside voice ran in CEO pass (14 findings, absorbed via D4–D6) |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | clean | 6 issues (E1 pagination, E2 golden contract, E3 log-only instrumentation, E4 build-tag baseline, E5 four test gaps, E6 rayon gen), all accepted + folded |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | n/a | Dashboard is an internal loopback ops tool; states covered in plan |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | n/a | — |

- **CROSS-MODEL:** CEO-pass outside voice (Claude subagent) drove the methodology corrections (D5) and the ledger drop (D6); eng pass extended with scale-correctness (E1) and contract-binding (E2) findings. No unresolved tension — eng outside voice skipped by user.
- **VERDICT:** CEO + ENG CLEARED — ready to implement. Lanes A+B start in parallel.

NO UNRESOLVED DECISIONS
