# Research Election Console — Runbook & Turnover

The Research Election Console is a local web app for running the paper's election
tests: configure an election (name, `t`-of-`n` trustees + names, scale,
distribution), run it in independent phases (**Generate → Submit → Verify →
Scenarios**), cross-check correctness (`E = 0`), export the ballots/CSVs, and run
the negative/vulnerability scenarios — offline or on-chain.

- Backend: `packages/saksi-demo` (Rust CLI — generator + auditor).
- Console: `packages/saksi-campaign` (Go — web server + phase orchestration).
- Branch: `research-election-console` (PR #33). Built + verified end-to-end.

This machine (Linux laptop-server) is **dev-only**. Build + run the console on the
**PC server or MacBook**.

---

## Paste-ready turnover prompt

> I'm running the Research Election Console from the `saksi` repo on this
> machine (PC server / MacBook). It's on branch `research-election-console`.
> Please: (1) confirm Rust (stable) + Go (1.22+) are installed — no protoc or
> Docker is needed, the Rust build vendors protoc; (2) build the two binaries per
> `docs/research-election-console-runbook.md`; (3) start `saksi-campaign serve`
> pointed at the built `saksi-demo`; (4) give me the URL to open. Then help me
> run the paper's tiers offline and export the correctness + negative-tests CSVs.

---

## 1. Prerequisites

- **Rust** (stable) — `rustup` toolchain. The build vendors `protoc`
  (`protoc_bin_vendored`), so **no system protoc and no Docker** are required.
- **Go** 1.22+ (CI uses 1.25).
- A C linker (`build-essential` / Xcode CLT) for the Rust link step.

Verify: `rustc --version && cargo --version && go version`.

### macOS (Apple Silicon and Intel)

Both binaries are verified to build for `darwin/arm64` and `darwin/amd64`; the
stack is pure Rust and pure Go, with no C dependency of its own and no cgo. The
commands in this runbook are the same on macOS as on Linux — nothing below is
platform-specific.

The one prerequisite Apple does not ship by default is the linker Rust needs:

```bash
xcode-select --install     # once per machine; skip if Xcode is installed
```

`protoc` is **not** needed — `protoc-bin-vendored` carries an Apple Silicon
build and the Rust build selects it automatically.

Homebrew is the shortest route to the toolchains if they are not present:

```bash
brew install go
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Locally built binaries are not quarantined by Gatekeeper, so no
right-click-to-open dance is required.

## 2. Get the code

```bash
git fetch origin
git switch research-election-console   # or merge PR #33 first
```

## 3. Build (both binaries)

```bash
# From the repo root — the Rust CLI the console shells:
cargo build -p saksi-demo --release
#   -> target/release/saksi-demo

# The Go console binary:
cd packages/saksi-campaign
go build -o saksi-campaign ./cmd/saksi-campaign
#   -> packages/saksi-campaign/saksi-campaign
```

## 4. Run

```bash
# From packages/saksi-campaign (adjust the --demo path to the built binary):
./saksi-campaign serve \
  --addr 127.0.0.1:8090 \
  --demo ../../target/release/saksi-demo \
  --runs ~/.saksi/campaign/runs
```

It prints the URL. Open it in a browser **on the same machine** (loopback).

Flags:
- `--addr` bind address (default `127.0.0.1:8090`). Port busy? pick another (e.g. `:8099`).
- `--demo` path to the `saksi-demo` binary (default: `saksi-demo` on `PATH`).
- `--runs` run-folder store root (default `~/.saksi/campaign/runs`).
- `--console` on-chain driver path (optional; leave unset for offline).
- `--allow-host host[:port]` extra accepted Host header (for LAN — see below).
- `--timeout` per-phase timeout (default `60m`).
- `--auth-file` users file that turns on login (env `SAKSI_AUTH_FILE`; see below).

### Authentication

**Off unless you pass `--auth-file`.** Without it the console is open to anyone
who can reach the address, exactly as before. `--repeat`, `tools/ladder.sh` and
the other `tools/*.sh` scripts do not log in, so run measurement campaigns
against a console started without it — or start them from the console itself
(`POST /api/ladder`, `POST /api/campaigns`, §9), which needs only an admin session.

1. Hash each password. It is read from stdin (never argv), one line, and echoed:
   ```bash
   ./saksi-campaign hash-password      # type the password, press Enter
   ```
2. Write the users file, one object per user. `trustee_id` is the trustee's wire
   id (`"1"`..`"n"`, in the order of the election's trustee list), trustees only:
   ```json
   [
     {"username": "admin",   "role": "admin",   "password_bcrypt": "$2a$12$..."},
     {"username": "comelec", "role": "trustee", "trustee_id": "1", "password_bcrypt": "$2a$12$..."}
   ]
   ```
   The console refuses to start on an unknown role, a trustee without
   `trustee_id`, a `trustee_id` that is not digits without a leading zero, an
   admin with one, a duplicate username or `trustee_id`, a username over 256
   bytes, or a value that is not a cost-12 bcrypt hash (what `hash-password`
   makes).
3. Start it: `./saksi-campaign serve --auth-file users.json ...`

The apps sign in with `POST /api/login` (a 12-hour `saksi_session` cookie),
`POST /api/logout` and `GET /api/me`. Five failed logins for one username from
one address lock that username out, from that address, for 30 s; fifty failures
from one address across any usernames lock the whole address out for 30 s. No
session → `401 {"error":"login required"}`; wrong role → `403 {"error":"..."}`.
The trail's unsealed operator view (`/api/trail/<id>?operator=1`) needs an admin
session; anyone else gets the sealed view.

| Role | Routes |
| --- | --- |
| public | `/api/board/`, `/api/verify-code/`, `/trail/`, `/api/trail`, `/api/trail/`, `/api/capabilities`, `/api/ceremony/` (status), `/runs`, the `/board/`, `/trustee/`, `/admin/` apps, `/api/login`, `/api/logout`, `/api/me` |
| trustee or admin | `POST /ceremony/publish`, `GET /events` |
| trustee, own shares only | `POST /ceremony/submit` — `403` unless the body's `trustee_id` is the session's; an admin cannot submit for a trustee |
| admin | `/generate`, `/submit`, `/verify`, `/run-all`, `/cancel`, `/scenarios`, `/attack`, `/ceremony/start`, `/api/runs/…`, `/api/check/`, `/api/scenarios/`, `/export/` (exports carry the seeded ground truth), `/wizard`, `/api/preflight`, `/api/ladder`, `/api/jobs/`, `/api/campaigns`, `/api/campaigns/…`, `/` (and any unknown path) |

Stated limits — say so wherever the admin console is shown:

- Demo-grade: users in a file, sessions in memory (a restart logs everyone out),
  no TLS termination (the cookie is `Secure` only when served over TLS), no audit
  log of logins. Keep the loopback bind; reach it remotely through an SSH tunnel.
- Anyone on loopback (every tunnel user arrives as loopback) can lock one named
  account for 30 s with 5 guesses, or all of loopback with 50.
- Cookies are not isolated by port: any other HTTP service on 127.0.0.1 (for
  example the Vite dev server) receives `saksi_session`. Cross-port POSTs are
  still refused by the console's Origin check.
- The admin app's voter-roll and credential steps do not issue real voter
  credentials; the thesis's voter-side claims still come from the harness.
- `/events` needs a session, so the public board cannot subscribe to progress;
  it polls `/api/board` instead.

### Orderer batch parameters

The Fabric orderer's batching parameters are part of the **declared measurement
environment**, not an operator choice. `packages/saksi-bulletin/network/configtx.yaml`
is the stock `test-network` file with four values changed, and `network.sh`
installs it into `$FABRIC_SAMPLES/test-network/configtx/` before the channel is
created — so `tools/up.sh`, `tools/tier.sh` and `./network.sh all` all bring the
network up under it, and the genesis block carries it.

| Parameter | Declared | test-network default |
| --- | --- | --- |
| `Orderer.BatchTimeout` | `2s` | `2s` (unchanged) |
| `Orderer.BatchSize.MaxMessageCount` | **50** | 10 |
| `Orderer.BatchSize.PreferredMaxBytes` | **2 MB** | 512 KB |
| `Orderer.BatchSize.AbsoluteMaxBytes` | `99 MB` | `99 MB` (unchanged) |
| `EtcdRaft.Options.SnapshotIntervalSize` | **256 MB** | 16 MB (Fabric default) |

Measured 2026-09-11 (SP-10K, NVMe-backed Docker storage): 812 TPS at
concurrency 96 and 1006 at 192, against 488 and 465 on the defaults, with p99
submit latency halved and zero block gaps. Full write-up, including the two
rejected variants, in balotachain `docs/desktop-runs/2026-09-11-orderer-probe.md`.

The rule behind the numbers, to re-apply before changing any of them:
**`MaxMessageCount` must be ≤ the steady in-flight ballot count, or
`BatchTimeout` must be far below the target per-ballot latency.** A
configuration satisfying neither never fills a block, so every block waits out
the timeout and the run measures the timeout and nothing else. `MaxMessageCount`
50 and the declared operating point of concurrency ≥ 96 therefore go together.

**Opting out (A/B runs).** Set `SAKSI_CONFIGTX=default` before the bring-up and
`network.sh` restores the pristine test-network file (backed up on first
install) instead:

```bash
SAKSI_CONFIGTX=default ./tools/tier.sh 10000 1
```

The run journal's environment snapshot records which was used, as
`orderer_batch.saksi_configtx`, with the four values alongside it when the
declared file is in force.

## 5. Reaching it from another device

Without `--auth-file` the server has **no login** — anyone who can reach the
address can drive it — and with it the login is demo-grade (see §4). Pick one:

- **SSH tunnel (most private):** keep the loopback bind and, from your other
  device: `ssh -L 8090:127.0.0.1:8090 <user>@<run-host>` then open
  `http://localhost:8090`.
- **LAN / private mesh:** bind wider and allowlist the reachable host:
  ```bash
  ./saksi-campaign serve --addr 0.0.0.0:8090 \
    --allow-host <lan-or-tailscale-ip>:8090 \
    --demo ../../target/release/saksi-demo
  ```
  Only do this on a network you trust.

## 6. Using the console

1. **Configure**: election name; add/remove trustees (with names); threshold `t`;
   positions/candidates; voters (scale presets — offline caps at 10,000; use
   ground-truth mode for larger tiers until the streaming generator lands);
   distribution; mode (offline / on-chain / groundtruth). Two advanced fields
   drive the on-chain ballot window: **concurrency** (in-flight submissions,
   default 8) and **send rate** (dispatches per second; 0 = unthrottled).
2. **Phases**: `Generate` (writes the real ballots), `Verify` (audits →
   correctness table, `E = 0`), `Scenarios` (runs the negative tests),
   `Submit` (on-chain only), or `Run all` (chains them). `Cancel` stops a phase.
3. **Results**: per-contest `ground_truth / decoded / E / pass`, overall PASS/FAIL,
   and export links.
4. **History**: past runs accumulate; each is exportable.

## 6b. Serving the browser apps (`--web-dir`)

The console can host three standalone browser apps alongside the wizard: the
**public bulletin board** at `/board/`, the **trustee console** at `/trustee/`
and the **admin console** at `/admin/` (served from `<dir>/admin` once
balotachain builds it). They live in the sibling **balotachain** repo
(`apps/auditor`, `apps/trustee`, `apps/admin`) and are served as built static bundles — the
console does not build them.

```bash
# in balotachain, once:
pnpm install
./tools/build-web.sh          # or tools\build-web.ps1 on Windows
#   -> <balotachain>/dist-web/board  and  <balotachain>/dist-web/trustee

# then start the console pointed at that directory:
saksi-campaign serve --demo ../../target/release/saksi-demo \
                     --web-dir <balotachain>/dist-web
```

`--web-dir` also reads the environment variable `SAKSI_WEB_DIR` (the flag wins).
Unset, the app routes are simply not registered and the console behaves exactly
as it did before.

Both apps select their election with a query parameter:

| URL | Shows |
|---|---|
| `/board/?run=<run-id>` | the public bulletin board for that election |
| `/trustee/?run=<run-id>&trustee=<n>` | the ceremony as trustee `n` (`1`..`n`) |

Omitting `?run=` picks the newest run. Omitting `?trustee=` shows a picker.

They are served **same-origin with the API**, which is what keeps the
cross-origin POST guard in `server.go` protecting `/ceremony/submit` and
`/ceremony/publish`. Serving them from a different origin would defeat it.

**The trustee console has no authentication.** `POST /ceremony/submit` takes a
`trustee_id` and no credential, so anyone who can reach the page can submit any
trustee's share. That is true of the wizard too; it is a research console on a
loopback bind. Do not expose it to an untrusted network.

### The JSON these apps read

| Endpoint | Body |
|---|---|
| `GET /api/board/<run>` | `BoardResponse` — ranked contests with seats/elected/ties, ballot accounting, cryptographic digests, the check list, and the artifact list. **Offline-first**: it reads the run folder and only *enriches* from the ledger, so unlike `/api/trail/<id>` it never 502s without a network |
| `GET /api/verify-code/<run>/<code>` | `VerifyCodeResponse` — the ballot record whose nullifier starts with the code's eight hex characters. `409` if the prefix is ambiguous, `400` if the code is not hex |
| `GET /api/ceremony/<run>` | `CeremonyView` — `CeremonyState` (unchanged, same JSON paths the wizard reads) plus the run's decryption context and an audit-log timeline |

A tracking code `BC-XXXX-XXXX` is the first eight hex characters of a ballot's
nullifier. Nullifiers are derived **per voter per position**, so a code
identifies one ballot *record*, not a voter's whole ballot — and it reveals
nothing about the selection.

## 7. What works offline vs. network-gated

- **Offline (fully working, no network):** Generate → Verify → correctness.csv,
  and 6 of 7 scenarios (CDS-proof tamper, nullifier reuse, dropped ballot,
  corrupted bytes, tampered partial-decryption, tampered DKG) — each proven
  rejected by the real auditor.
- **Network-gated (needs a live Fabric network):** on-chain `Submit` + perf
  numbers. These error clearly when no network/driver is present — never a
  silent hang.
- **Not checked anywhere:** `reordered-ballots`. Neither the chaincode (no
  ordering or digest check) nor the stateless auditor checks ballot order, so the
  scenario is always `SKIPPED` with "no gate exists to test".

## 8. Where the data lands

Each run is a folder under `--runs`, named `<slug>-<timestamp>-<n>`:

| File | What |
|------|------|
| `run.json` | config + created_at + `commit` (saksi and console git heads, so a result traces to a build) |
| `header.json` | election params/DKG/issuer/binding/partials/tally/ground-truth (hex protobuf) |
| `ballots.ndjson` | one hex-protobuf ballot per line |
| `correctness.csv` | 13 columns (written by Verify) — see below |
| `negative-tests.csv` | one row per attack plus a `summary` row (written by Scenarios and by every attack mounted during the election) — see below |
| `scenarios.json` | the accumulated attack verdicts `negative-tests.csv` is rebuilt from |
| `scenarios/<id>/` | the mutated copy each scenario audited |
| `journal.ndjson` | the run's event log — see below |
| `perf.csv` | one row per run: the whole performance record — see below |
| `perf-schema.md` | every `perf.csv` column and its producer, dropped beside the CSV |
| `latencies.csv` | `index,segment,ms,ok` — one row per dispatched ballot |
| `timings.json` | the auditor's four in-process stage timers (`timings_ms`) and the `verify_threads` they ran on |
| `gen-timings.json` | the generator's CPU/wall sidecar (`saksi-demo gen --stream`) |
| `receipts.csv` | one row per on-chain receipt (ballots and lifecycle) |
| `trail.ndjson` | lifecycle events, one JSON object per line (`trail.json` for legacy runs) |
| `ground-truth-check.json` | the validation gate's report |

### `correctness.csv` — the accuracy record

Thirteen columns, one row per contest per audited directory:

```
contest,ground_truth,decoded,E,pass,
published_tally,recovered_point,aggregate_ciphertext,
dkg_sha256,tally_sha256,ballots_sha256,
source,ledger_matches_local
```

The three `_sha256` columns are the provenance hashes of the directory that row
was audited **from**, so a `source=ledger` row is checkable against the ledger
dump rather than against the console's artifacts.

`source` is `local` (the console's own run folder) or `ledger` (the chain's own
record, dumped to `<run>/ledger/` and audited with the same auditor). An
on-chain run writes both blocks; an offline run writes the `local` block only.
`ledger_matches_local` carries the cross-check verdict — whether the two
directories hold the same ballots (by nullifier set) and recovered the same
per-contest aggregate ciphertexts — and is empty when no comparison ran.

**On `source=ledger` rows, `ground_truth` comes from the local header.** The
chain publishes no ground truth — the seeded plaintext totals are secret from
the ledger, which is the whole point — so the ledger dump's header copies the
console's, and a ledger row scores the CHAIN's ciphertexts against the
CONSOLE's ground truth. `voter_ids` is the one header field that cannot be
copied: the chain publishes none, and the reader requires one per ballot, so it
is resized to the chain's own ballot count.

### `journal.ndjson` — the run's event log

Append-only, one JSON object per line, `fsync`ed after every checkpoint event.
**Line 1 is the environment snapshot** captured at run start: Go OS/arch/version,
the `saksi-demo` version or binary SHA-256, both repos' git heads, `docker
version` / `docker info` / per-container `docker inspect` limits, `uname`, and
the CPU model. A probe that fails records `null` and is listed in `null_probes`;
the run continues.

Every later line carries `event`, a wall-clock `ts` (a label — never parsed back
and subtracted) and `mono_ms`, milliseconds since the journal opened, from a
monotonic reading. Checkpoint events (fsynced): `run.start`, `stage.*`,
`rep.*`, `ballots.progress`, `segment.*`, `run.end`. A `Sync()` failure fails
the run with that reason and stops the journal — a truncated journal is never
silently continued.

`ballots.progress` is the one event stamped from inside the measured submission
window, so it alone is written by a journal-owned writer goroutine rather than
by the goroutine that stamped it: its line, fields and fsync are unchanged, but
the fsync no longer stalls ballot dispatch. Every other event still writes
synchronously, waiting on a barrier that the writer releases only once it has
drained the queued lines, so no progress line can land after the event that
closes its window and none is left unwritten when the journal closes. If the
queue ever filled, the journal would coalesce towards the latest count rather
than wait, and the next progress line carries a `coalesced_total` saying how
many were folded away.

Two consequences worth knowing:

- **A progress event is no longer durable at the moment it is stamped.** It is
  fsynced shortly after, so a hard kill can lose up to 64 of them — 64,000
  ballots. The last `ballots.progress` on disk is therefore a **lower bound** on
  what the window had dispatched, and so are `interrupted_at {last_done}` and
  the resume API's `remaining`: a resume may offer ballots the chain already
  holds. The chain's nullifier set, not the journal, decides what is committed,
  so a resume is still correct — it just does slightly more work. Every event
  that CLOSES a window is still fsynced before its stamp returns, so the
  interrupted-or-not decision a resume makes is unaffected.
- **Order within one goroutine, not across goroutines.** A progress line and a
  `sample` stamped concurrently (the dispatcher and the docker-stats sampler)
  have no defined order between them and may appear either way round.
  `mono_ms` is the ordering of record; line order is only guaranteed against
  the events that close a window.

Useful events: `stage.generate.*`, `stage.bundle.*`, `stage.ballots.*`,
`stage.ceremony.*`, `stage.verify.*`, `segment.start`/`segment.end`,
`ballots.progress {done}`, `interrupted_at {last_done}`, `sample` (one per
container per sampler tick), the attack timeline's `attack.pause {stage,
election_status, ballots_committed, block_height, scenarios, live}`,
`attack.result {scenario, verdict, gate_expected, gate_observed}` and
`attack.resume {stage, reason, paused_ms}` (`reason` is `run-all`, `skip`,
`timeout` or `cancelled`), and `run.end`, which carries the finaliser's
verdict: `failed`, `reason`, `sustained`, `arrival_tps`, `sustained_tps` and
`scaling_limit` (`true` / `false` / `inconclusive`). The same reason string is
`perf.csv`'s `fail_reason` column.

The journal holds **events only**. Per-ballot latencies live in `latencies.csv`
so the journal stays small at capstone tiers.

### `perf.csv` and `perf-schema.md`

`perf.csv` is one row per run, written by Verify; re-verifying a run replaces
its row rather than appending a second one. Columns, in order:

```
run_id,mode,voters,positions,candidates,profile,
gen_wall_ms,gen_cpu_ms,proof_gen_cpu_ms,
proof_verify_inproc_ms,aggregate_inproc_ms,combine_inproc_ms,decrypt_inproc_ms,
submit_window_ms,committed,dropped,committed_tps,driver_ceiling_tps,
latency_min_ms,latency_p50_ms,latency_mean_ms,latency_p95_ms,latency_p99_ms,latency_stddev_ms,
peak_cpu_pct_peer,peak_cpu_pct_orderer,peak_cpu_pct_client,
peak_mem_mb_peer,peak_mem_mb_orderer,peak_mem_mb_client,
ledger_bytes_delta,sustained,scaling_limit,failed,fail_reason,
verify_threads,security_run
```

Read the suffixes: `_inproc_ms` is measured inside the auditor process,
`_cpu_ms` is thread-summed CPU time (so it can legitimately exceed wall time),
`_wall_ms` is a wall clock. **An empty cell means the column had no producer for
this run** — an offline run opens no submission window, so its submit, peak and
ledger cells are blank. An empty cell is never a measured zero, and a zero is
never written where nothing was measured. `perf-schema.md` is written into the
run folder alongside, so a downloaded CSV carries its own definitions;
`perf.csv` itself has no comment lines and loads straight into a spreadsheet.

Three caveats worth knowing before quoting a number:

- `proof_verify_inproc_ms` is the **wall-clock** time of the auditor's parallel
  ballot verification on `verify_threads` threads (every core by default), not
  CPU time summed across them. Compare it only between runs at the same thread
  count, and not with figures from before verification went parallel. Set
  `SAKSI_AUDIT_THREADS=<n>` in the console's environment to pin the count
  (`1` is the serial path); the audit output is identical at any count.
- `aggregate_inproc_ms` times **point addition only** — point decompression
  moved into ballot verification, so this figure is not comparable with any
  aggregation number from before that change.
- `driver_ceiling_tps` is concurrency ÷ median submit latency: the harness's own
  ceiling. A `committed_tps` close to it means the driver, not the network, was
  the limit, and the finaliser reports `scaling_limit: inconclusive`.
- `security_run` is `true` when the run had an `attack_plan`. Its lifecycle
  paused to mount attacks, so its throughput is **perturbed — not for RQ3**.
  The ballot window leaves the pause out (its two halves are summed), but the
  ledger still processed the attacks, and the `peak_cpu_pct_*` and
  `peak_mem_mb_*` columns come from a sampler that ran through the pause, so
  they include the attacks and the idle wait. A security run never reports a
  sustained TPS or a scaling verdict (`scaling_limit` is `inconclusive`, and
  `run.end` carries `security_run: true`). Empty for every other run.

### `negative-tests.csv` — the attack record

```
scenario,stage,layer,action,expected,actual,verdict,property,on_chain,
attempted,rejected,rate,
mounted_stage,election_status,ballots_committed,block_height,live,
gate_expected,gate_observed
```

Every attack declares the gate that must refuse it: a chaincode gate id when it
is submitted to a live election (the chaincode's rejections start
`gate=<id>:`), an auditor check id when it runs as a simulation
(`audit-stream --json` reports `failed_checks`). The verdict is judged against
that gate:

| `verdict` | Meaning |
|---|---|
| `PASS` | refused **by the declared gate** |
| `INCONCLUSIVE` | refused by a different gate (`actual` = `rejected by <gate>: <text>`), by one that names no gate, or never mounted faithfully (`actual` starts `not mounted:`) |
| `FAIL` | nothing refused it: the ledger accepted it, or the audit passed the mutated copy |
| `SKIPPED` | never mounted |

`attempted`/`rejected`/`rate` count PASS and FAIL only: an INCONCLUSIVE row is
not a trial of its gate. `gate_observed` is the chaincode gate that refused a
live attack, or every auditor check that failed, `;`-joined (a ballot-level
mutation also breaks the aggregate, so the decryption and tally checks fail
beside the declared one).

The mount context records the election as the attack found it.
`mounted_stage` is `dkg`, `ballots`, `close` or `ceremony` for an attack
mounted at a pause of the attack timeline, `unstaged` for one mounted any
other time (the step-7 catalogue, or `/attack` on its own). `election_status`
(`open`, `closed`, `published`), `ballots_committed` and `block_height` are
empty when there was no ledger to read them from. `live` repeats `on_chain`
beside the rest of the mount context: `true` only for a real submission.

Read a **simulated row mounted at a live pause** (`live=false` with an
`election_status`) with care: its mount context describes the live election at
that moment, but the mutation and the audit act on a copy of the generated run,
not on the chain. It records when the attack was mounted, not what the ledger
did with it.

Which attacks go live: only those with an on-chain gate that leaves no state
behind when it refuses — `tamper-ballot-proof` (`cds`), `reused-nullifier`
(`nullifier`) and `corrupted-ballot-bytes` (`decode`), mounted at the `ballots`
pause while the election is open. `tamper-dkg-transcript` and
`tamper-partial-decryption` would be **accepted** by the chaincode (it checks
transcript shape and proof presence, not the points or the proof, and not who
submits them), so they are always simulated and their `actual` says "on-chain:
not checked (shape/presence only, no caller authorization); caught by the
auditor" on a live election.
`dropped-ballot` is not expressible as one submission; `reordered-ballots`
stays `SKIPPED`.

One row per scenario. A verdict mounted at a pause is never replaced by an
`unstaged` one: re-running an attack from step 7 after a security run leaves the
staged (often live) row in place, and the re-run is recorded in the journal as
`attack.rerun.unstaged {scenario, verdict, actual, live, gate_expected,
gate_observed, kept_mounted_stage}`.

#### Findings: two front-running denial-of-service paths

The chaincode never asks who is calling (no `GetClientIdentity` anywhere), and
the DKG and partial-decryption gates check shape and presence, not content. Any
client with write access to the channel can therefore get in first:

- **DKG transcript.** Right after `CreateElection`, an attacker publishes a
  transcript with the right threshold and commitment count but a tampered
  commitment. `PublishDKGTranscript` accepts it. The operator's real transcript
  is then refused as `gate=dkg-duplicate: a DKG transcript is already published
  for election …`, and the election is unusable: with a non-canonical constant
  term every `SubmitBallot` fails in `deriveElectionPublicKey` with an error that
  carries no gate id ("derive election public key: trustee commitment 0 constant
  term is not a canonical ristretto255 point"); with a substituted valid point
  the joint key is wrong and every honest ballot fails `gate=cds`.
- **Partial decryption.** After `CloseElection`, an attacker submits a share
  under trustee id X for contest C with any 32-byte share and any proof attached.
  `SubmitPartialDecryption` stores it under (election, C, X). Trustee X's real
  share is then refused as `gate=partial-duplicate: trustee "X" already submitted
  a partial decryption for contest "C" …`. The auditor rejects the planted share
  (`decryption.cp_proof`), and front-running enough trustees leaves fewer than
  the threshold of valid shares, so no tally for that contest can be verified.

`CreateElection` (squatting an election id) and `CloseElection` (closing an
election early) have no caller check either. The console does not mount these
attacks live, because they would poison the election under test; the scenarios
run simulated and their rows say "on-chain: not checked (shape/presence only, no
caller authorization)". Adding caller authorization to the chaincode is a
separate decision and is not part of this change.

`latencies.csv` is `index,segment,ms,ok` with `ok ∈ {commit, drop, replay}`.
`replay` appears only on resumed runs (see §9) and marks a ballot the chain had
already committed — a resume artifact, never an attack, and never counted in the
negative-test totals.

### Driving the backend without the UI

```bash
saksi-demo gen --stream /tmp/run --voters 1000 --positions 3 --candidates 4 \
  --trustees 5 --threshold 3 --election-id e1 --election-name "Election 1" \
  --trustee-names A,B,C,D,E --distribution uniform
saksi-demo audit-stream /tmp/run --json     # -> {overall, contests:[{ground_truth,decoded,E,pass}]}
```

`gen --stream` also accepts `--chunk N` (default 5,000): the generator builds
ballots one chunk at a time and drops each chunk after writing it, so memory is
bounded by the chunk rather than by the tier. `--chunk 0` selects the old
single-pass writer. Either way it writes `gen-timings.json` beside the run —
`credential_cpu_ms`, `encrypt_cpu_ms`, `cds_prove_cpu_ms` (thread-summed CPU,
so they can exceed wall time), `wall_ms`, `chunks`, `chunk_voters`.

## 9. Measurement runs

The measurement tooling below drives the console's HTTP API; start the server as
in §4 and point the tools at it.

### Repetitions, sweeps and bursts — `--repeat`

```bash
saksi-campaign --repeat --config run.json \
  --warmups 2 --reps 10 \
  [--sweep 1.5] [--window 120s] [--burst N] \
  [--base-url http://127.0.0.1:8090]
```

Each repetition creates its own run folder through the API, tags its journal
with `rep {index, kind}` where `kind` is `warmup` or `measured`, and drives
generate → check → submit → ceremony → verify. `summary.csv` is written across
the **measured** repetitions only: per numeric `perf.csv` column, one row of
`min,median,mean,p95,p99,stddev,n`, plus `runs_measured`, `runs_failed`,
`failure_rate` and `failed_reasons`. A run that failed — per `run.end`'s
`failed` flag: a stage error, any drop, a reconcile mismatch, a non-zero `E`, or
an interruption — is excluded from every throughput and latency statistic and
counted in the failure rate instead.

`--sweep k` runs time-bounded windows (`--window`, default 120 s) at a target
send rate multiplied by `k` each step, sizing each step's concurrency from the
previous step's p99 so the closed-loop driver is not the ceiling, and recording
`driver_ceiling_tps` per step. It stops when committed TPS falls or ballots
drop; `plateau_tps` is the last good step. `--burst N` submits N ballots
unthrottled after the measured window, as its own segment.

### Validation ladder — `tools/ladder.sh`

```bash
tools/ladder.sh
```

Runs 1, 10, 100 and 1,000 voters (3 positions, 4 candidates, `realistic`)
offline through the API, asserts every contest's `E = 0` and a passing
validation gate at each step, and writes `<data-dir>/ladder.json` with the
commit it validated and the four run ids.

**This is a gate, not a convenience.** `handleGenerate` refuses `voters > 1000`
in `offline` and `onchain` mode unless a `ladder.json` exists whose `commit`
matches the console's own git head, with the error `validation ladder has not
been run for this build; run tools/ladder.sh first`. `groundtruth` mode is
exempt — it runs no cryptography.

### Per-tier reset — `tools/tier.sh`

```bash
tools/tier.sh <voters> <positions>
```

Brings the network down and back up (`network.sh down && network.sh up
createChannel`) and redeploys the chaincode before a tier, so no tier runs on a
peer still holding the previous tier's blocks. It reuses `tools/up.sh`'s
functions.

On-chain runs also refuse to start when the projected ledger size
(`voters × positions × 12,000` bytes) exceeds free space on the peer volume — or
on the run directory's volume when no peer volume is configured — with both
numbers in the message.

### Node restart under load (T3) — `tools/t3-restart.sh`

```bash
tools/t3-restart.sh <run-id>
```

Stops `peer0.org1.example.com`, waits 30 s, starts it again, then posts to the
console's verify-only endpoint, which reconciles the chain's committed ballot
count against the committed set, runs the append-only chain walk
(`VerifyChain`), and stamps `interrupted_at` in the journal.

### Resuming an interrupted run — `POST /api/runs/{id}/resume`

```bash
curl -X POST http://127.0.0.1:8090/api/runs/<run-id>/resume
```

Refused with **409** unless the run is `onchain` and its journal's last
checkpoint is a `ballots.progress` or a `stage.ballots.start` with no matching
`stage.ballots.end` — the decision is made from the journal alone, no network
needed.

The committed set is the chain's `ListNullifiers` intersected with the bundle's
nullifiers, by ballot index; `receipts.csv` is a cross-check, and a receipt
whose nullifier is not on the chain is stamped `receipt_without_nullifier` as a
finding (a truncated receipts file is a warning, not a refusal). Committed
indices are skipped; the rest are re-submitted as a new segment, stamped
`segment.start {index}`.

If the chaincode rejects an index that *is* in the committed set — a ballot that
was in flight when the run died — the row is written `ok=replay` in
`latencies.csv`, is not counted as a drop, and never reaches
`negative-tests.csv`. A resumed run reports throughput **per segment**, is
marked `sustained: false` in `run.end`, contributes no whole-run TPS figure, and
classifies as `scaling_limit: inconclusive`.

### Study API — preflight, ladder job, campaigns, export

The console can run the ladder and `--repeat` campaigns itself. It reuses
`RunLadder` and `Repeat` unchanged, driving its own API in-process: no socket,
no credential. The requests carry a context marker only the console can set,
still pass the Host/Origin guard, have no session, and may reach only the
routes the driver calls (`POST /generate`, `GET /api/check/`, `POST /submit`,
`POST /ceremony/start`, `GET /api/ceremony/`, `POST /ceremony/submit`,
`POST /ceremony/publish`, `POST /verify`, `GET /api/runs/…/status`,
`GET /export/`); anything else answers `403`, auth on or off. A console campaign
and a CLI campaign on the same config therefore produce the same run folders
and the same `summary.csv`. Every route below is admin-only when auth is on.
The wizard buttons for them and the operator walkthrough come later.

| Route | What it does |
| --- | --- |
| `GET /api/preflight[?mode=&voters=&positions=&concurrency=]` | One report: `fabric` (enabled, `reachable` by a 2 s TCP dial, peer, channel), `orderer_batch` (declared `configtx.yaml`), `ladder` (`ok`, `ladder_commit`, `console_commit`), `disk` (`free_bytes` on the disk guard's volume, `projected_ledger_bytes` = voters × positions × 12,000), `host` (`guest_load1`, `guest_load5` from `/proc/loadavg`; under WSL2 also `host_cpu_pct`, the Windows host's CPU sampled through `powershell.exe` with a 5 s timeout, because the guest's load average cannot see Windows programs; each null when unreadable; `cpus`), `verify_threads_default`, `concurrency_min_advised` (= `MaxMessageCount`), and `warnings[]` of `{severity, code, message, forceable}`. `mode` defaults to `onchain` |
| `POST /api/ladder` | Runs the validation ladder as a job → `202 {"job": id}`. Writes `ladder.json` on a pass, exactly as `tools/ladder.sh` does |
| `GET /api/jobs/<id>` | `{kind, status: queued\|running\|done\|failed\|cancelled, started_at, finished_at, error, log: [last 200 lines], result}`. A ladder's `result` is its `ladder.json` |
| `POST /api/campaigns` `{config, warmups, reps, sweep?, window_s?, burst?, force?}` | Starts a campaign → `202 {"campaign": id}`. Unknown fields are `400`; `reps` must be ≥ 1 unless `sweep` or `burst` is set. Forces `skip_attacks: true`. Runs preflight on the config, and checks the burst (an election at `burst` voters) against validation, the ladder gate and the disk guard. A `block` answers `409 {error, warnings}`; `force: true` overrides only `fabric_unreachable` |
| `GET /api/campaigns` | Every campaign, newest first |
| `GET /api/campaigns/<id>` | Status (`running`, `done`, `failed`, `cancelled`, `interrupted`), `save_error` if a `campaign.json` write failed, the preflight snapshot, a row per repetition (`index`, `kind`, `run_id`, `status`, `committed_tps`, `latency_p99_ms`, `failed`, `fail_reason` from the run's `perf.csv` and `run.end`; `host_start` sampled before its `/generate` and `host_end` after its verify phase), and `summary` (the parsed `summary.csv`) once written. A finished repetition's values are cached; only the one in progress is read live |
| `POST /api/campaigns/<id>/cancel` | Stops the campaign after the current repetition (`cancelled`, no `summary.csv`). Cancelling during the last repetition, with no sweep or burst after it, has nothing left to stop: the campaign ends `done` with its `summary.csv` |
| `GET /api/campaigns/<id>/export` | A streamed zip: `<run-id>/run.json`, `perf.csv`, `perf-schema.md`, `correctness.csv`, `negative-tests.csv`, `ground-truth-check.json`, `timings.json` (each when present) and `<run-id>/journal-line1.json` for every run, plus `summary.csv`, `campaign.json`, `preflight.json` and `MANIFEST.txt` (per run, the files included and missing). A file that exists but cannot be read aborts the download instead of finishing a zip without it |

Preflight findings:

| Severity | Code | When | Forceable |
| --- | --- | --- | --- |
| block | `fabric_not_configured` | On-chain, and the console was started without Fabric | no |
| block | `fabric_unreachable` | Fabric is configured, the peer does not answer, and the run is on-chain | yes |
| block | `ladder_missing` | Above 1,000 voters (not ground truth), for the config or the burst, with no `ladder.json` for this build | no |
| block | `disk_short` | On-chain, and the projected ledger exceeds free space: of one run, or, for a campaign, of all its runs together, since no network reset runs between them: (warm-ups + reps) × voters × positions × 12,000, plus 12 × that per-run figure for a sweep (its maximum step count), plus burst × positions × 12,000 | no |
| block | `verify_threads_invalid` | `SAKSI_AUDIT_THREADS` is set to anything but a positive integer (empty included): the auditor would refuse to run | no |
| warn | `host_load` | Guest 1-minute load average above 25 % of the CPUs | — |
| warn | `host_cpu` | Under WSL2, the Windows host's CPU above 25 % | — |
| warn | `concurrency_low` | On-chain, ballots in flight below the orderer's `MaxMessageCount` | — |
| warn | `verify_threads` | The auditor would verify on one thread | — |

One job runs at a time, console-wide: starting a ladder or campaign while
another runs answers `409` naming the running job. A campaign lives in
`<runs>/campaigns/<id>/` as `campaign.json` (config, options, preflight, status,
rows), `summary.csv` and `log.txt`. If the console stops mid-campaign, the next
read settles its rows from their run folders and marks it `interrupted`.

## 10. Troubleshooting

- **`bind: address already in use`** — another service owns the port; pass a free
  one via `--addr`.
- **`saksi-demo` not found** — pass `--demo <absolute path to the built binary>`.
- **A phase shows failed** — the run folder is kept; the live log pane shows the
  error, and the exports are there to inspect. A scenario `FAIL` means a gate that
  should have rejected did not — a real finding, not a tooling error.
