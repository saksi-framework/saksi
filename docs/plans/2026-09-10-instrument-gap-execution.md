# Instrument-gap execution plan

Spec: the reviewed plan at `C:\Users\User\.claude\plans\hazy-beaming-willow.md`
(eng-reviewed 2026-09-09, NO UNRESOLVED DECISIONS) and the audit it answers,
`balotachain/docs/instrument-gap-report.md`. This file restates that plan as
ordered, self-contained tasks. Where this file and the reviewed plan disagree,
the reviewed plan wins.

Repos: this worktree is `saksi` (branch `instrument-gap`). Task 13 touches the
sibling `balotachain` repo only for a docs file.

## Global Constraints

- **Timed path.** Ballot latency is measured from `SubmitAsync` to
  `commit.Status()` only. No qscc call, no file write, no JSON rewrite inside
  the timed region. Receipts are fetched after the measured window, one qscc
  `GetBlockByNumber` per distinct block.
- **Monotonic durations.** Every duration is computed with `time.Time.Sub` on
  values captured in memory (Go) or `Instant` (Rust). Wall-clock strings in
  files are labels; nothing is parsed back and subtracted.
- **Journal.** `journal.ndjson` is append-only, one JSON object per line, opened
  `O_APPEND|O_CREATE|O_WRONLY`, a single `Write` per line under a mutex, and
  `Sync()` after every checkpoint event (`run.start`, `stage.*`, `rep.*`,
  `ballots.progress`, `segment.*`, `run.end`). A `Sync()` error is returned to
  the caller, the run is marked failed with that reason, and nothing further is
  written. Line 1 is the environment snapshot. The journal carries events only:
  never per-ballot latencies, never docker samples' raw output beyond one line
  per sample.
- **No fabricated numbers.** A CSV column with no producer is written as an
  empty cell, never `0`. `perf.csv` has no comment lines; provenance is in the
  column name (`_inproc_ms` for in-process Rust timers, `_wall_ms` for console
  wall clock, `_cpu_ms` for thread-summed CPU time).
- **Memory.** Nothing loads a whole population into memory: the generator emits
  chunks, the auditor iterates lines, the executor reads `ballots.ndjson` by
  line with a `bufio.Scanner` whose buffer cap is 4 MiB (the `check.go:143`
  pattern), the Go CSV export scans.
- **Resume.** The committed set is `ListNullifiers` ∩ the bundle's nullifiers,
  by ballot index. `receipts.csv` is a cross-check. A nullifier-gate rejection
  on an index in the committed set is `ok=replay` in `latencies.csv` and never
  reaches `writeNegativeTestsCSV`. Throughput is per segment; a resumed run is
  `sustained:false` and has no whole-run TPS.
- **Failed run.** `runFailed` = any stage error OR `Dropped > 0` OR Reconcile
  mismatch OR `E != 0` on any contest OR interrupted. The reason string is
  recorded. Failed runs are excluded from throughput statistics and counted in
  `runs_failed / runs_measured`.
- **Scaling limit.** `arrival_tps = voters / 36000`; `scaling_limit =
  sustained_tps < arrival_tps`, computed per segment, and reported only when
  `committed_tps < 0.8 × driver_ceiling_tps` is false (i.e. the driver was not
  the ceiling); otherwise the verdict is `inconclusive`.
- **Ladder gate** applies to modes `offline` and `onchain` only; `groundtruth`
  is exempt.
- **Tally signatures** are Schnorr proofs from `saksi-crypto`
  `SchnorrProof::prove(base = G, statement = trustee_public_share, witness =
  trustee_secret_share, context = b"saksi.tally.sig.v1" || election_id bytes ||
  totals as little-endian u64s)`; verification keys are derived from the DKG
  transcript's `coefficient_commitments` by evaluating every trustee's
  commitment polynomial at the signer's index and summing. Chaincode verifies
  every signature, rejects duplicate and unknown trustee ids, and requires
  `valid >= threshold`. The auditor finding `tally.signatures` is strict: no
  signatures = FAIL.
- **Chaincode/library scope.** Only the changes named in Tasks 5, 10, 11 touch
  `saksi-auditor`, `saksi-demo`, `saksi-protocol`, or the chaincode.
- **Tests.** Every new branch has a test. Go: `go test ./...` in each module.
  Rust: `cargo test --workspace`. Byte-identity and regression-guard tests are
  named in their tasks. Existing tests stay green; if one must change, the
  report says why.
- **Commits.** Conventional Commits. Each task commits its own work. Message
  trailer:
  ```
  Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01US7qZGVxRdVwQqf1KVsE7t
  ```

## Existing code to reuse (do not rebuild)

| Existing | Where |
|---|---|
| `bench.Run`, `Percentiles`, `ThroughputTPS`, `Reconcile` | `packages/saksi-bulletin/client-sdk/bench/` |
| `lifecycleStep`, `lifecycle()`, `setupOnChain` | `packages/saksi-campaign/executor.go:293-362` |
| `appendReceipt`, receipts CSV header | `packages/saksi-campaign/receipts.go` |
| `publish` SSE hook | `packages/saksi-campaign/executor.go:79` |
| Streaming scanner with 4 MiB cap | `packages/saksi-campaign/check.go:143` |
| `blockHeaderHash`, `LedgerReceipt`, `receiptFromBlock` | `packages/saksi-bulletin/client-sdk/ledger.go` |
| `fakeLedger` | `packages/saksi-campaign/executor_onchain_test.go:15-32` |
| `SchnorrProof::prove/verify` with `context` | `packages/saksi-crypto/src/nizk/schnorr.rs` |
| Golden-vector loader pattern | `packages/saksi-bulletin/chaincode/credverify/credverify_test.go:11-20` reading `packages/saksi-protocol/test-vectors/credential-sig-v1.hex` |
| Ballot stream writer / reader | `packages/saksi-auditor/src/stream.rs` |
| Generator | `packages/saksi-auditor/src/fixtures.rs` (stream path ~line 664-830, `write_election_stream_params`) |
| Auditor entry | `packages/saksi-auditor/src/demo.rs:419` `audit_stream_dir`; `lib.rs` `audit_with_evidence` |
| Chaincode | `packages/saksi-bulletin/chaincode/contract.go` (`PublishTally` ~733, `SubmitPartialDecryption` ~640) |
| Wire | `packages/saksi-protocol/proto/saksi/protocol/v1/wire.proto` (`TallyResult` at 98, `DKGTranscript` 79, `TrusteeCommitment` 68) |

---

## Task 1: Run journal, environment snapshot, sampler, finaliser

**Files:** new `packages/saksi-campaign/journal.go`, `journal_test.go`;
`runstore.go` (`RunRecord.Commit`); `config.go` (error text).

**Journal API** (package `main` in saksi-campaign, same as the rest):

```go
type Journal struct { mu sync.Mutex; f *os.File; path string; failed error }
func OpenJournal(runDir string, env map[string]any) (*Journal, error)   // writes line 1 = {"event":"env", ...env, "ts": RFC3339} and fsyncs
func (j *Journal) Stamp(event string, fields map[string]any) error       // appends {"event":event,"ts":...,"mono_ms":<since open>,...fields}; Sync() if isCheckpoint(event)
func (j *Journal) Close() error
func isCheckpoint(event string) bool  // run.start, stage.*, rep.*, ballots.progress, segment.*, run.end
```

`mono_ms` is `time.Since(j.opened).Milliseconds()` where `opened` is a
`time.Time` captured in `OpenJournal`. A `Sync()` error sets `j.failed`, is
returned, and every later `Stamp` returns the same error without writing.

**Environment snapshot** `CollectEnv(demoBin string) map[string]any`:
`go_os`, `go_arch`, `go_version`, `saksi_demo_version` (output of `<demoBin>
--version` trimmed; if the flag is unsupported, the binary's SHA-256 hex as
`saksi_demo_sha256`), `git_head_saksi` (`git rev-parse HEAD` run in the
directory containing `demoBin`'s repo: walk up from the binary until a `.git`
is found, else null), `git_head_console` (same, from the console's own
executable), `docker_version` (`docker version --format '{{json .}}'`
parsed), `docker_info` (`docker info --format '{{json .}}'` reduced to
`NCPU, MemTotal, ServerVersion, OSType`), `containers` (for each container
whose name starts with `peer` or `orderer`: `docker inspect` → `Name,
HostConfig.NanoCpus, HostConfig.Memory`), `uname` (`uname -a`, or `ver` on
Windows), `cpu_model` (first of `/proc/cpuinfo` "model name", `sysctl -n
machdep.cpu.brand_string`, or `wmic cpu get name`), `null_probes` (list of
keys whose probe failed). Every probe has a 10 s timeout and failure records
`null` for that key; `CollectEnv` never returns an error.

**Sampler** (in `journal.go`): `StartSampler(ctx, j *Journal, containers
[]string, interval time.Duration) (stop func() Samples)`. Every `interval`
(default 5 s): run `docker stats --no-stream --format '{{json .}}'` with a
10 s timeout, parse one JSON object per line, keep lines whose `Name` is in
`containers`, stamp one `sample` event per kept line with `container,
cpu_pct (parsed from "12.34%"), mem_bytes (parsed from "123.4MiB / 31.2GiB"
left side), net_in_bytes, net_out_bytes (from NetIO "1.2kB / 3.4MB"), block_in_bytes,
block_out_bytes`. Malformed lines are skipped and counted in
`Samples.Malformed`. The console's own process is sampled too as container
name `client` using `runtime.ReadMemStats` (`Sys`) and process CPU time via
`syscall` where available, else `cpu_pct: null`. If `docker` is not on PATH
the sampler stamps one `sampler` event `{"docker": null}` and returns
immediately. `stop()` returns `Samples{PerContainer map[string]struct{PeakCPU,
MeanCPU float64; PeakMem, MeanMem int64}; Malformed int}`.

Disk: `LedgerBytes(peerVolume string) (int64, error)` runs `du -sb` on the
volume path (or `docker system df -v` fallback; on Windows `Get-ChildItem`
sum). Called by the executor at `stage.ballots.start` and `run.end`
(Task 6 wires it); `journal.go` just provides it.

**Finaliser** `Finalise(j *Journal, f FinaliseInput) FinaliseResult`:

```go
type Segment struct { Index int; Committed int; WindowMs int64; TPS float64; P50Ms float64; DriverCeilingTPS float64 }
type FinaliseInput struct { Voters, Positions int; Segments []Segment; Dropped int; ReconcileOK bool; EByContest map[string]int64; StageErr error; Interrupted bool }
type FinaliseResult struct { Failed bool; Reason string; SustainedTPS *float64; ArrivalTPS float64; ScalingLimit string /* "true"|"false"|"inconclusive" */; Sustained bool }
```

`runFailed(FinaliseInput) (bool, string)` implements the Global Constraints
definition with the reason as the first clause that fired, in this order:
`stage_error: <err>`, `dropped: <n>`, `reconcile_mismatch`, `e_nonzero:
<contest>=<E>`, `interrupted`. `Sustained = len(Segments) == 1 &&
!Interrupted`. `SustainedTPS` is the single segment's TPS when sustained, else
nil. `ArrivalTPS = float64(Voters) / 36000`. `ScalingLimit`: if not sustained →
`"inconclusive"`; else if `seg.TPS >= 0.8*seg.DriverCeilingTPS` (driver-bound)
→ `"inconclusive"`; else `"true"` if `seg.TPS < ArrivalTPS` else `"false"`.
Zero window → TPS nil, never division by zero. Result is stamped as
`run.end` with all fields.

**runstore.go:** `RunRecord` gains `Commit map[string]string
json:"commit"` (`saksi`, `console`) filled from the env snapshot by the
caller (Task 6 wires it; here just the field).

**config.go:** replace the error text `"offline mode is capped at %d voters
(got %d); select on-chain/perf mode for larger tiers"` with `"offline mode is
capped at %d voters (got %d); use ground-truth mode for larger tiers until the
streaming generator lands"`; the comment at line ~21 stops mentioning "perf
mode".

**Tests (`journal_test.go`):** (1) line 1 of a fresh journal is the env event
with every key present (null allowed); (2) checkpoint events call Sync and
non-checkpoint events do not — use an `io.Writer`/`syncer` interface injected
for the test, or a fake file; (3) an injected Sync error is returned, `failed`
is set, and a subsequent Stamp returns the same error and writes nothing (file
length unchanged); (4) 8 goroutines × 1,000 `Stamp` calls produce exactly
8,000 parseable lines; (5) sampler parses a fixture of three docker-stats
lines including one malformed → two samples, `Malformed == 1`; (6)
`runFailed` table test, one row per clause plus the all-clear row; (7)
`Finalise` table: sustained/driver-bound/scaling-limit true/false/zero-window
/interrupted; (8) `CollectEnv` with a fake `demoBin` path and `PATH` cleared
returns a map with `null_probes` listing the docker/git keys and no error.

---

## Task 2: Concurrency-safe receipts writer; no per-ballot trail.json

**Files:** `packages/saksi-campaign/receipts.go`, `receipts_test.go`,
`executor.go` (`lifecycle`), `ceremony.go` (call sites), `trail.go` (reader).

Replace `appendReceipt(runDir, ev)` with a per-run writer:

```go
type receiptsWriter struct { mu sync.Mutex; f *os.File; trail *os.File; runDir string }
func openReceipts(runDir string) (*receiptsWriter, error)  // opens receipts.csv O_APPEND|O_CREATE|O_WRONLY; writes receiptsCSVHeader once iff the file was empty at open (check size, not existence)
func (w *receiptsWriter) Append(ev TrailEvent) error       // one locked fmt.Fprintf of the CSV row (same columns/order as today)
func (w *receiptsWriter) Lifecycle(ev TrailEvent) error    // Append + append one JSON line to trail.ndjson (NOT a rewrite)
func (w *receiptsWriter) Close() error
```

`trail.json` (whole-array rewrite) is retired: lifecycle events (`CreateElection`,
`PublishDKGTranscript`, `CloseElection`, `SubmitPartialDecryption`,
`PublishTally`) go to `trail.ndjson` as one JSON object per line via
`Lifecycle`; `SubmitBallot` events go only to `receipts.csv` via `Append`.
`trail.go` reads `trail.ndjson` (line by line) and, for backwards
compatibility, falls back to `trail.json` when `trail.ndjson` is absent.
`readReceipts(runDir) ([]TrailEvent, error)` parses `receipts.csv` with
`encoding/csv` and tolerates a truncated last line by returning the rows
parsed so far plus `ErrTruncatedReceipts` (a sentinel the caller may treat as a
warning).

`lifecycle()` opens the writer once per run and the `step` closure uses
`Lifecycle` for non-ballot events and `Append` for `SubmitBallot`. The
executor holds the writer on the run (e.g. `e.receipts[runID]`) and closes it
at run end; the ceremony path opens/closes it around its own steps.

**Tests:** (1) 8 goroutines × 1,000 `Append` → file has exactly one header and
8,000 data rows, all parse; (2) header is written once when the file
pre-exists and is non-empty; (3) `Lifecycle` writes to both files, `Append`
only to receipts.csv; (4) `readReceipts` on a file with a truncated last line
returns N−1 rows and `ErrTruncatedReceipts`; (5) `trail.go` reads
`trail.ndjson` and falls back to `trail.json`; existing trail tests stay
green.

---

## Task 3: Bench statistics, honest rows, ctx-aware driver; delete legacy console bench

**Files:** `packages/saksi-bulletin/client-sdk/bench/metrics.go`,
`metrics_test.go`, `driver.go`, `driver_test.go`;
`packages/saksi-bulletin/client-sdk/cmd/saksi-console/main.go`.

**metrics.go:**
- `Summary(durs []time.Duration) Stats` with `Stats{Min, Median, Mean, P95,
  P99, StdDev time.Duration; N int}`; population standard deviation; nearest-rank
  percentiles as today; `N == 0` → zero-value Stats with `N: 0` (callers must
  not print zeros for N==0 — see Row).
- `Row`: delete `EndorseP50, CDSVerifyP50, OrderP50, ValidateP50, CommitP50`
  and their CSV columns; add `LatencyMin, LatencyMean, LatencyStdDev
  time.Duration`; change `DecryptTime *time.Duration`, `PeakCPUPct *float64`,
  `PeakMemMB *float64` to pointers. `csvHeader` and the row serialiser emit an
  empty cell for a nil pointer and for any latency field when `Committed ==
  0`. Column names: `latency_min_ms, latency_p50_ms, latency_mean_ms,
  latency_p95_ms, latency_p99_ms, latency_stddev_ms, decrypt_ms,
  peak_cpu_pct, peak_mem_mb`.
- **Regression guard test** `TestRowWithoutProducersEmitsEmptyCells`: a Row
  from `ToRow` with no producers serialises with empty cells for `decrypt_ms`,
  `peak_cpu_pct`, `peak_mem_mb`, and the test asserts the literal string `,0,`
  does not appear in those column positions (assert per column, not by
  substring across the row).

**driver.go:** new signature

```go
type RunOpts struct { Concurrency int; SendRate float64; MaxDuration time.Duration; OnProgress func(done int) }
func Run(ctx context.Context, n int, submit SubmitFunc, opts RunOpts) RunResult
```

Semantics: `ctx` cancellation or `MaxDuration` elapsed stops dispatching new
indices; in-flight submits finish; the result covers submitted indices only
and `RunResult` gains `Stopped bool` and `LastIndex int`. `OnProgress` (if
non-nil) is called from the dispatcher every 1,000 dispatched indices and
once at the end. `RunResult.Latencies` keeps per-index order: add `ByIndex
[]time.Duration` (length n, zero for unsubmitted) and `OK []bool` so callers
can write `latencies.csv` by index. `DriverCeilingTPS()` method =
`float64(Concurrency) / p50.Seconds()` (0 when p50 is 0). `Reconcile`
unchanged.

**saksi-console/main.go:** delete `--metrics-csv`, `benchConfig`,
`submitBallotsBenchmarked`, `appendCSVRow`, and the `--concurrency`,
`--send-rate`, `--bench-axis` flags; the console keeps its lifecycle
subcommands. Update the README section that described the flag.

**Tests:** Summary known-vector (e.g. 1..10 ms: min 1, median 5 or 6 per
nearest-rank rule documented in code, mean 5.5, p95 10, p99 10, stddev
2.872); n=1; n=2; all-equal → stddev 0; cancelled ctx at index 500 with
concurrency 8 → `Stopped`, `LastIndex ≥ 500`, no submit called for index >
LastIndex + concurrency; `MaxDuration` stops; `OnProgress` fires at 1,000
boundaries; regression guard above; `go build ./...` in client-sdk succeeds
with the console changes and `grep -r appendCSVRow` returns nothing.

---

## Task 4: Ledger interface: untimed submit, off-path receipts, chain walk

**Files:** `packages/saksi-bulletin/client-sdk/ledger.go`, `ledger_test.go`,
`interfaces.go` (or wherever `Ledger` is declared),
`packages/saksi-campaign/executor_onchain_test.go` (`fakeLedger` gains the
new methods).

Add to the `Ledger` interface and implement on `*ledger`:

```go
Submit(fn string, args ...string) (txID string, blockNumber uint64, err error)   // SubmitAsync → Status(); no qscc
GetBlockByNumber(n uint64) (*common.Block, error)                                 // qscc GetBlockByNumber
ReceiptsForBlock(n uint64, txIDs []string) ([]Receipt, error)                     // one GetBlockByNumber, receiptFromBlock per txID present
VerifyChain(from, to uint64, sample []Receipt) (ChainReport, error)
```

`Submit` returns the block number from `commit.Status()` (`status.BlockNumber`).
`VerifyChain` walks blocks `from..to`, recomputes `blockHeaderHash(number,
previousHash, dataHash)` for each, asserts block n's `previous_hash` equals
block n−1's recomputed hash, and for each `Receipt` in `sample` asserts
`receipt.BlockHash == blockHeaderHash(block_{receipt.BlockNumber})` as served
now. `ChainReport{Blocks int; Linked bool; FirstBreak *uint64;
ReceiptsChecked, ReceiptMismatches int; Status string /* PASS|FAIL|not run */}`.
Any fetch error → `Status: "not run"` with the error; never PASS by default.

**Tests:** fixture of three synthetic `common.Block`s built with the same
hashing as `blockHeaderHash` (helper in the test): linked chain → PASS;
tampered `previous_hash` on block 2 → FAIL with `FirstBreak == 2`; tampered
receipt hash → `ReceiptMismatches == 1`, FAIL; fetch error → `not run`.
`ReceiptsForBlock` with two of three txIDs present returns two receipts.
`fakeLedger` implements the new methods; existing on-chain tests green.

---

## Task 5: Rust: stage timers, chunked streaming generator, streaming auditor

**Files:** `packages/saksi-auditor/src/{lib.rs,demo.rs,fixtures.rs,stream.rs}`,
`packages/saksi-demo/src/main.rs`, tests in `packages/saksi-auditor/src/tests.rs`
(or a new `stream_tests.rs`). Add `rayon` to `saksi-auditor`'s Cargo.toml.

**Timings.** `audit_with_evidence` records `Timings { verify_ballots,
aggregate, combine, decode: Duration }` with `Instant::now()` at the four
existing boundaries and returns it in the evidence; `demo.rs`
`audit_stream_dir` copies them into `StreamAudit` as `timings_ms: {verify_ballots,
aggregate, combine, decode}` (u64 ms) so the console can write `timings.json`.

**Chunked streaming generator.** New
`write_election_stream_chunked(dir: &Path, params: &GenParams, chunk_voters:
usize) -> Result<(), String>` in `stream.rs` (default chunk 5,000, exposed as
`saksi-demo gen --stream --chunk N`). Prologue runs once: DKG, issuer key,
election parameters, header fields. Then for each chunk of voter indices in
order: build the chunk's ballots with `rayon::prelude::*` `par_iter` over
voters (each voter constructs its own `OsRng`), collect into a `Vec` in voter
order, append their hex lines to `ballots.ndjson` (`BufWriter`, flushed per
chunk), append plaintext rows to the ground-truth tables through the
existing pure selection function, then drop the chunk. The aggregate
ciphertext per contest and the running tally are accumulated per chunk so the
header's `tally` / `partial_decryptions` are computed without holding
ballots. Per-ballot `credential`, `encrypt`, `cds_prove` durations are
summed per chunk into `gen-timings.json` as `{credential_cpu_ms, encrypt_cpu_ms,
cds_prove_cpu_ms, wall_ms, chunks, chunk_voters}` — CPU sums are thread-summed
and labelled `_cpu_ms`; `wall_ms` is the prologue-to-end wall time. The existing
serial path stays for `gen` without `--stream`.

**Streaming auditor.** `stream.rs` gains `BallotLines` (an iterator over
`ballots.ndjson` lines via `BufReader::lines()` with a 4 MiB line cap returning
`Result<Ballot, String>` with the line number in errors). `lib.rs`
`audit_with_evidence` accepts ballots as `impl Iterator<Item = Result<Ballot,
String>>` (keep a thin `&[Ballot]` wrapper for existing callers/tests):
per-ballot verification, nullifier uniqueness (`HashSet<[u8; 32]>`), and the
homomorphic aggregate are incremental; only the per-contest aggregate
ciphertexts, the nullifier set, and counters are retained. `demo.rs`
`audit_stream_dir` uses the iterator and no longer calls `read_to_string`.

**Tests:** (1) differential: at 1,000 voters × 3 positions × 4 candidates,
`realistic`, the chunked writer (chunk 100) and the serial writer produce
byte-identical `ground-truth-ballots.csv` and `ground-truth-summary.csv`,
equal ballot line counts, and both audit to `E = 0`; (2) chunk boundary
correctness: chunk sizes 1, 7, 1000 all pass the audit; (3) streaming auditor
on the serial fixture reports identical findings to the in-memory path; (4)
`BallotLines` reports the line number of a corrupt line; (5) timings are all
non-zero on a 100-voter audit and `verify_ballots + aggregate + combine +
decode <= wall`; (6) `gen-timings.json` is written with all keys. Memory
bound is documented, not tested.

---

## Task 6: Bundle references ballots.ndjson; bench in the wizard on-chain path; perf.csv

**Files:** `packages/saksi-campaign/{ceremony.go,executor.go,config.go,server.go,csvexport.go,scenarios.go}`,
tests alongside; `packages/saksi-campaign/web/wizard.html` (two config fields).

**Bundle.** `generateBundle` writes `bundle.json` with `election_id, params,
dkg, partial_decryptions, tally, ballots_file: "ballots.ndjson", ballot_count`.
`onChainBundle` drops `Ballots []string`. `lifecycle()` no longer unmarshals
ballots; `readBallotLine`-style access is replaced by a `ballotReader` that
opens `ballots.ndjson` once and yields `(index, hexLine)` with a
`bufio.Scanner` (4 MiB cap); a truncated or non-hex line aborts with its line
number.

**Streaming Go export.** `csvexport.go` and `scenarios.go` `readBallotLines`
stop using `os.ReadFile + strings.Split`; they scan. `ballots.csv` is written
line by line while scanning.

**Bench in `setupOnChain`.** Replace the serial ballot loop with
`bench.Run(ctx, n, submit, bench.RunOpts{Concurrency: c.Concurrency, SendRate:
c.SendRate, OnProgress: progress})` where `submit(i)` reads line i, calls
`led.Submit("SubmitBallot", line)`, and records `(i, txID, block)` in an
in-memory slice. After `Run` returns: group by block, call
`led.ReceiptsForBlock` per distinct block, and `receipts.Append` each
(Task 2 writer). Write `latencies.csv` with header
`index,segment,ms,ok` and one row per submitted index (`ok ∈
{commit,drop,replay}`; `replay` is set by Task 7). `progress(done)` stamps
`ballots.progress {done}`. `ElectionConfig` gains `Concurrency int` (default
8) and `SendRate float64` (default 0) with validation (`Concurrency >= 1`,
`SendRate >= 0`); `wizard.html` exposes both as advanced fields.

**Journal wiring.** `Generate` calls `OpenJournal` with `CollectEnv` and
stamps `run.start`, `stage.generate.start/end`; `Check`, `Submit`/`Verify`,
ceremony steps stamp their stage boundaries; `setupOnChain` stamps
`stage.ballots.start` (with `LedgerBytes` if a peer volume path is configured
via `FabricConfig.PeerVolume`) and `stage.ballots.end`; the sampler runs
between them; `Verify` stamps `stage.verify.start/end`, writes `timings.json`
from `StreamAudit.timings_ms`, and calls `Finalise` → `run.end`. `RunRecord.Commit`
is filled from the env snapshot.

**perf.csv** written by `Verify` (one row per run) with columns exactly:
`run_id,mode,voters,positions,candidates,profile,gen_wall_ms,gen_cpu_ms,
proof_gen_cpu_ms,proof_verify_inproc_ms,aggregate_inproc_ms,combine_inproc_ms,
decrypt_inproc_ms,submit_window_ms,committed,dropped,committed_tps,
driver_ceiling_tps,latency_min_ms,latency_p50_ms,latency_mean_ms,latency_p95_ms,
latency_p99_ms,latency_stddev_ms,peak_cpu_pct_peer,peak_cpu_pct_orderer,
peak_cpu_pct_client,peak_mem_mb_peer,peak_mem_mb_orderer,peak_mem_mb_client,
ledger_bytes_delta,sustained,scaling_limit,failed,fail_reason`. Empty cell
for anything without a producer (offline runs have no submit/peak columns).
`perf-schema.md` beside it describes every column and its provenance.
`server.go` `exportOrder` keeps `perf.csv` (now real) and adds
`latencies.csv`, `journal.ndjson`, `timings.json`, `perf-schema.md`.

**Tests:** fakeLedger run of 1,000 ballots with concurrency 8 makes ≤
(distinct blocks + 6) qscc calls (count `GetBlockByNumber`/`LedgerReceipt`
calls on the fake); `latencies.csv` has 1,000 rows; `perf.csv` row has no
`0` in the peak/decrypt columns and no empty cell in `committed_tps`;
truncated `ballots.ndjson` line aborts with the line number; offline run
writes `perf.csv` with empty submit columns; `ballot_count` mismatch between
bundle and file is an error; existing executor/ceremony tests green.

---

## Task 7: Checkpoint / resume with nullifier-based committed set

**Files:** `packages/saksi-campaign/{executor.go,server.go}`,
`executor_resume_test.go`; `packages/saksi-bulletin/client-sdk/bulletin.go`
(`ListNullifiers` is already paged — reuse).

`POST /api/runs/{id}/resume`: refuse (409) unless the run is `onchain` and its
journal's last checkpoint is a `ballots.progress` or `stage.ballots.start`
without a `stage.ballots.end`. Build the committed set: page through
`ListNullifiers(electionID)`, intersect with the bundle's nullifiers (a
`nullifier → index` map built by scanning `ballots.ndjson` and decoding each
ballot's nullifier field — streaming, no full load), producing a bitset by
index. Cross-check against `readReceipts`: any receipt whose index is not in
the chain set is stamped as `receipt_without_nullifier` (a finding); a
truncated receipts file stamps a warning, not a refusal. Stamp `interrupted_at
{last_done}` if not already present and `segment.start {index: k}`. Run
`bench.Run` over the non-committed indices only (the submit closure maps the
compact index back to the ballot index). If the chaincode still rejects an
index that IS in the committed set (in-flight at crash), record `ok=replay`
in `latencies.csv` and do not count it as a drop; such rejections are never
passed to `writeNegativeTestsCSV` (assert by construction: the negative-test
writer only reads scenario results, never latencies). Each segment gets its
own `Segment` in `FinaliseInput`; `Sustained` is false.

**Tests (`executor_resume_test.go`)** using `fakeLedger` extended with
`FailAt int` (returns an error and cancels the context at ballot N),
`ListNullifiers` backed by its accepted set, and `RejectDuplicates`: run
1,000 ballots with concurrency 8, crash at 500 → resume → assert: committed
set == fake's accepted set; every accepted index is skipped; a deliberately
"committed but receipt-less" index (fake accepted it, receipts row omitted) is
skipped, not re-submitted; a deliberately "receipt but not committed" row
produces `receipt_without_nullifier`; two `segment.start` events; `run.end`
has `sustained:false`, `scaling_limit:"inconclusive"`; `negative-tests.csv`
is unchanged before/after; `receipts.csv` has exactly one header; total
committed after resume == 1,000; a non-onchain run gets 409.

---

## Task 8: Ledger audit for on-chain runs

**Files:** `packages/saksi-campaign/executor.go` (`Verify`), `ledger_dump.go`,
`ledger_dump_test.go`; `packages/saksi-bulletin/client-sdk/bulletin.go` if a
`GetBallot` client method is missing (chaincode `GetBallot` exists at
`contract.go:~304`).

On an `onchain` run, `Verify` first dumps the record: page `ListNullifiers`,
call `GetBallot` per nullifier, write hex lines to `ledger-ballots.ndjson` in
the order returned, and write `ledger-header.json` from on-chain
`GetElection`/DKG/partials/tally (the same shape as `header.json` so
`audit-stream` accepts the directory) into `<runDir>/ledger/`. Run
`audit-stream` on `<runDir>/ledger/`; `correctness.csv` rows carry
`source=ledger`. Then also audit the console-written directory as today, and
write `ledger_matches_local` (true iff the SHA-256 of the sorted nullifier
set and the per-contest aggregate ciphertexts agree) into `run.end` and
`correctness.csv`. A mismatch is a finding (red on the trail), not an error.
`GetBallot` failure mid-dump aborts the dump, stamps `ledger_audit: "not
run"`, and Verify continues with the local audit only.

**Tests:** fakeLedger with `Ballots map[nullifier]hex` and a mutated ballot →
`ledger_matches_local:false`; identical → true; `GetBallot` error →
`ledger_audit:"not run"` and local audit still runs; the dump is streamed
(assert the fake is asked for ballots one at a time, no whole-list call).
Whether `saksi-demo audit-stream` accepts `ledger-header.json` is exercised
by a Go test that shells out only if `saksi-demo` is on PATH (skip otherwise).

---

## Task 9: `--repeat`, sweep, ladder, T3, per-tier reset, disk guard

**Files:** `packages/saksi-campaign/repeat.go`, `repeat_test.go`, `main.go`
(flag), `server.go` (disk guard in `handleGenerate`, ladder gate);
`tools/ladder.sh`, `tools/t3-restart.sh`, `tools/tier.sh`.

**`saksi-campaign --repeat --config run.json --warmups 2 --reps 10 [--sweep
1.5] [--window 120s] [--burst N] [--base-url http://localhost:PORT]`:** drives
the HTTP API of a running console. Each repetition creates a run via the API
with the config, tags its journal with `rep {index, kind: "warmup"|"measured"}`
(the API accepts an optional `rep` object at run creation), drives generate →
check → submit → ceremony → verify, and collects `perf.csv` and `run.end`.
`summary.csv` across **measured** reps only: one row per metric name in
`perf.csv`'s numeric columns with `min,median,mean,p95,p99,stddev,n`; plus
rows `runs_measured`, `runs_failed`, `failure_rate`, and a `failed_reasons`
column listing reasons. Failed runs (per `run.end.failed`) are excluded from
every throughput/latency statistic.

**Sweep:** with `--sweep k`, each step is a time-bounded window
(`MaxDuration = --window`, default 120 s) at target `SendRate` starting from
the config's rate (or 10 if 0) and multiplying by `k` per step; concurrency
per step = `ceil(rate × p99_of_previous_step_seconds) + 4` (first step uses
the config's concurrency); the journal records `driver_ceiling_tps` per step;
stop when `committed_tps` falls below the previous step's or `Dropped > 0`;
`plateau_tps` = last good step's TPS, written to `summary.csv`. **Burst:**
after the measured window, submit `N` ballots with `SendRate=0` as its own
segment tagged `burst`.

**Ladder:** `tools/ladder.sh` runs 1, 10, 100, 1,000 voters (3 positions, 4
candidates, realistic) offline through the API, asserts every contest `E = 0`
and the check gate passes, and writes `<data-dir>/ladder.json {commit, ran_at,
runs: [ids]}`. `handleGenerate` refuses `Voters > 1000` when mode is
`offline` or `onchain` unless `ladder.json` exists and its `commit` equals
the console's own git head (from the env snapshot); `groundtruth` is exempt.
Error text: `"validation ladder has not been run for this build; run
tools/ladder.sh first"`.

**T3:** `tools/t3-restart.sh <run-id>`: `docker stop peer0.org1.example.com`,
sleep 30, `docker start`, then `curl -X POST /api/runs/<id>/verify-only`,
which reconciles `CountCommittedBallots` against the committed set, runs
`VerifyChain`, and stamps `interrupted_at`.

**Per-tier reset + disk guard:** `tools/tier.sh <voters> <positions>` runs
`network.sh down && network.sh up createChannel` + chaincode deploy (reusing
`tools/up.sh` functions) before a tier. `handleGenerate` for `onchain` refuses
to start when `voters × positions × 12_000` bytes exceeds free space on the
peer volume (or the run directory's volume when no peer volume is configured),
with the numbers in the message.

**Tests:** `repeat_test.go` against an `httptest` console: 1 warm-up + 3
measured, one measured run failed via a fake `run.end` → `summary.csv` has
`n=2` for throughput rows, `failure_rate=0.333`, warm-up absent; sweep with a
fake that degrades at step 3 → `plateau_tps` = step 2; ladder gate: offline
2,000 refused without `ladder.json`, allowed with a matching commit, refused
with a stale commit; groundtruth 3.5M allowed; disk guard refuses when
projected > free (inject free-space function).

---

## Task 10: Tally signatures: wire, Rust signing, golden vector, auditor check

**Files:** `packages/saksi-protocol/proto/saksi/protocol/v1/wire.proto` +
regenerated Go/Rust; `packages/saksi-auditor/src/{fixtures.rs,tally.rs,lib.rs}`;
`packages/saksi-protocol/test-vectors/tally-sig-v1.hex`; `packages/saksi-crypto`
untouched except a public helper if needed.

**Wire:** `TallyResult` gains `repeated TrusteeSignature signatures = 5;`
with `message TrusteeSignature { string trustee_id = 1; bytes signature = 2; }`
(`signature` = the 64-byte Schnorr proof bytes from `SchnorrProof::to_bytes`).
Regenerate both languages with the repo's existing codegen command
(document the command in the report).

**Signing** where partials are built in `fixtures.rs` (both sites, ~256 and
~820): for each trustee `i` with secret share `s_i` and public share `P_i =
s_i·G`, `SchnorrProof::prove(&G, &P_i, &s_i, &tally_sig_context(election_id,
&totals), rng)` with `tally_sig_context = b"saksi.tally.sig.v1" ||
election_id.as_bytes() || concat(totals[j].to_le_bytes())`. The
`TallyResult` carries all trustees' signatures in trustee order.

**Verification key derivation** (`tally.rs` or a new `dkg.rs` helper):
`verification_key(transcript, trustee_index i) = Σ_j Σ_k C_{j,k} · i^k` over
all trustees' `coefficient_commitments` (decompressed ristretto points),
where trustee indices are 1-based in evaluation order matching the DKG code's
own share indexing (confirm against `saksi-crypto` DKG and document).

**Auditor finding** `tally.signatures` (id string exactly that): FAIL with
reasons if any signature fails to verify against its derived key, if a
`trustee_id` is duplicated or unknown, or if `valid < threshold`; FAIL with
`missing` when `signatures` is empty. Included in `audit_with_evidence` and
in the finding list the console reads.

**Golden vector** `tally-sig-v1.hex`: written by a Rust test (deterministic
RNG for the vector only) as hex lines: `dkg_transcript`, `election_id`,
`totals` (comma-separated), `threshold`, then per trustee
`trustee_id,verification_key_hex,signature_hex`, and one `negative` line with
a signature over different totals. `credverify_test.go`'s vector file layout is
the model.

**Tests:** signatures verify; tampered totals fail; duplicate trustee id fails;
below-threshold fails; missing → FAIL `missing`; derived verification keys
equal `s_i·G` computed from the DKG secret shares in the fixture; the vector
file round-trips (Rust reads it back and verifies every line); all existing
auditor tests green; `independent_verification` tests now include the
signature check.

---

## Task 11: Chaincode sigverify + PublishTally gate; console ceremony signatures; trail label

**Files:** new `packages/saksi-bulletin/chaincode/sigverify/{sigverify.go,
sigverify_test.go}`; `contract.go` (`PublishTally`), `contract_test.go`;
`packages/saksi-campaign/{ceremony.go,trail.go,web/trail.html}` + tests.

**sigverify:** `DeriveVerificationKey(transcript *DKGTranscript, trusteeID
string) ([]byte, error)` (index resolved from the transcript's trustee order,
same convention as Task 10) and `VerifySchnorr(verificationKey, context,
signature []byte) error` with a Merlin transcript byte-identical to Rust's
`SchnorrProof::verify` (label constants copied from `schnorr.rs`; the
ristretto255 library already vendored for `cdsverify` is reused). Golden
vector test reads `../../../saksi-protocol/test-vectors/tally-sig-v1.hex`
exactly as `credverify_test.go` does: every positive line verifies, the
negative line fails, derived keys match the vector's.

**PublishTally:** after the existing checks, load the DKG transcript, and for
each `signatures[i]`: reject unknown `trustee_id`, reject a duplicate id,
verify against `tally_sig_context(election_id, totals)`; require
`valid >= params.threshold` else error `"tally has %d valid trustee
signatures, threshold is %d"`. Tests: vector-backed happy path; below
threshold; duplicate id; unknown id; signature over different totals; a tally
with no signatures is rejected.

**Console:** `generateBundle` keeps the signatures inside the bundle's
`tally`; `CeremonySubmit(trusteeID)` records which trustee has submitted;
`CeremonyPublish` assembles the tally with only the signatures of trustees
who submitted (filter the bundle's signature list) and publishes. Below
threshold stays 409 as today. `trail.go`/`trail.html`: a tally whose
`signatures` is empty renders the label `unsigned (legacy)` beside the tally
row and the verifier check list shows `tally.signatures` as the tenth check.

**Tests:** ceremony publishes with exactly the submitted trustees' signatures;
trail renders the legacy label for an old run fixture and the signature count
for a new one; chaincode tests above; `go test ./...` green in chaincode and
campaign.

---

## Task 12: Wizard defaults, Caliper report, rejection rates, negative-tests

**Files:** `packages/saksi-campaign/web/wizard.html`, `scenarios.go`
(`writeNegativeTestsCSV`), tests; `packages/saksi-bulletin/caliper/{report.js,
report.test.js,README.md,benchmarks/ballot-submission.yaml}`.

- `wizard.html`: default trustees `["COMELEC","Civil Society Watch","University
  IT","Academe Observer","Bar Association"]`, threshold default `3`; the
  helper text says "3 of 5 (paper configuration)".
- `negative-tests.csv` gains columns `attempted,rejected,rate` per scenario
  (live: attempted = 1 per mounting; simulated: attempted = 1, rejected = 1
  iff verdict PASS); `summary` row at the bottom with totals.
- `caliper/report.js`: reads Caliper's JSON report (`report.json` produced
  with `--caliper-report-format json` if 0.6 supports it; else parses the
  HTML table) and, when per-transaction latencies are present in the txUpdate
  log the workload writes to `caliper/latencies.ndjson` (add that write to
  `workloads/submit-ballot.js`: one line per tx with `startMs,endMs`), emits
  `p50,p95,p99` per round; if only max/min/avg exist it prints them and a line
  `percentiles: unavailable (Caliper reports max/min/avg only)`. README
  rewritten: Caliper cross-checks TPS and success rate; the Go driver is the
  percentile source; cite Caliper issue #407. Remove the claim that Caliper
  "reports latency percentiles natively".
- Tests: `report.test.js` with a fixture ndjson → correct percentiles;
  fixture without latencies → the unavailable line. Go test for the new
  negative-tests columns.

---

## Task 13: Manuscript amendments and docs mirror

**Files (balotachain repo, sibling `../balotachain` on its current branch):**
`docs/manuscript-amendments.md` (new). **Files (this repo):** `docs/` runbook
updates for `--repeat`, ladder, tier, t3, resume, perf-schema.

`manuscript-amendments.md` sections, each citing the artifact that backs it
(journal event, CSV column, test name, chaincode function):
1. Appendix A sample: replace 142/119/131/108 with the regenerated
   `realistic` 500×1×4 row (run `python3 docs/saksi/reference_generator.py
   --voters 500 --positions 1 --candidates 4 --distribution realistic` in
   balotachain and paste the exact output), stating the profile.
2. §3 performance: repetition counts per tier as executed (leave a table with
   the tiers and blank counts to be filled from `summary.csv`); stage timers
   as implemented (four in-process Rust timers, generator CPU sums, console
   wall clocks); Fabric per-phase columns removed and why.
3. Algorithm 4 / hot-key paragraph rewritten: aggregation is performed by the
   verifier from the public record; no on-chain accumulator exists, so no
   write-set contention arises.
4. T5: drop "expired"; C4: nullifier uniqueness is a verifier check, not a
   data-validation-gate check.
5. Table 3.5: executed tiers marked with rep counts; unreached tiers "not
   evaluated" with the journal reason.
6. Table 3.11: "signed final tally" now true; cite `PublishTally` +
   `sigverify`; state the simulated-ceremony limitation (partials and
   signatures generated in one process and forwarded by the console).
7. Measure-first note: the ~100 TPS planning figure had no source; the
   SP-1K measured `committed_tps` replaces it (blank to fill).
8. Fallback text if Fabric is unavailable on the desktop: all tiers offline;
   on-chain columns "not evaluated on-chain (network unavailable)".
9. C17: Caliper reports max/min/avg; percentiles come from the Go driver.

No code in this task. Verify: the Appendix A numbers in the file equal the
generator's output byte for byte (run it and paste).
