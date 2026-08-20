# Desktop Session Prompt — Run the Research Election Console

Paste everything below the line into a fresh Claude Code session on the **desktop
run machine** (PC server or MacBook). It brings that session fully up to speed and
tells it what to do.

---

You are picking up the **Research Election Console** in the `saksi` repo
(`github.com/saksi-framework/saksi`). A previous session on a Linux dev laptop
designed, built, and verified it; this desktop machine is where it actually runs.
Do NOT re-architect or re-plan — the work is done and CI-green. Your job is to
build it, run it, give me a URL, and help me run the paper's election tests.

## What this is

A local web app to run the thesis's election experiments: configure an election
(name, `t`-of-`n` trustees + names, scale, distribution), run it in independent
phases **Generate → Submit → Verify → Scenarios**, cross-check correctness
(`E = 0`), export the ballots + CSVs, and run negative/vulnerability scenarios —
offline (no network) or on-chain (live Fabric).

- `packages/saksi-demo` — Rust CLI: the real generator + auditor.
- `packages/saksi-campaign` — Go: the web server + phase orchestration + UI.

## Current state (already done — do not redo)

- Branch: **`research-election-console`** (PR **#33** into `paper-alignment-evaluation`).
- **CI is green** on Linux + macOS (Build / Lint / Security / Test): full Rust +
  Go build, `clippy -D warnings`, `staticcheck`, and two real end-to-end tests
  (`gen → audit-stream`, and the Go scenario runner against the real auditor).
- Verified live: real 2-of-3 ElGamal election → audit → **E = 0 on every
  contest**; all 6 offline attack scenarios rejected by the real auditor.

## Environment facts

- Needs **Rust (stable)** + **Go (1.22+)**. **No protoc, no Docker** — the Rust
  build vendors protoc.
- This machine RUNS it. (The Linux laptop the prior session used is dev-only;
  ignore it.)
- The full mechanical runbook is `docs/research-election-console-runbook.md` —
  read it for exact build/run/flags/troubleshooting. Summary below.

## Your task

1. **Confirm toolchain**: `rustc --version && cargo --version && go version`.
   If Rust or Go is missing, help me install it (rustup for Rust; go.dev tarball
   or Homebrew `go` for Go). No protoc/Docker.
2. **Get the code**: `git fetch origin && git switch research-election-console`.
3. **Build both binaries**:
   ```
   cargo build -p saksi-demo --release            # -> target/release/saksi-demo
   cd packages/saksi-campaign && go build -o saksi-campaign ./cmd/saksi-campaign
   ```
4. **Run it** (from `packages/saksi-campaign`; pick a free port if 8090 is taken):
   ```
   ./saksi-campaign serve --addr 127.0.0.1:8090 \
     --demo ../../target/release/saksi-demo --runs ~/.saksi/campaign/runs
   ```
   Then **give me the URL** and confirm `GET /` returns the console. If I want to
   reach it from another device, offer: SSH tunnel (keep loopback), or
   `--addr 0.0.0.0:PORT --allow-host <ip>:PORT` for LAN (warn: no login).
5. **Smoke it** before handing over: configure a small offline 2-of-3 / 10-voter
   election, `Run all`, confirm the correctness table shows `E = 0` PASS, then run
   `Scenarios` and confirm the offline attacks come back rejected.
6. **Then help me run the paper's tiers** and export `correctness.csv` +
   `negative-tests.csv` from each run.

## Facts you'll need while helping me

- **Offline vs network-gated**: Generate/Verify + 6 of 7 scenarios work fully
  offline. On-chain `Submit` + perf numbers + the `reordered-ballots` scenario
  need a live Fabric network (ordering is a *ledger* property the stateless
  auditor doesn't check — so it's chaincode-layer, network-gated, not a bug).
- **Offline scale ceiling**: the console caps offline voters at 10,000 (offline
  generation isn't parallelized). Bigger tiers (50k/483k/1M) are on-chain/perf
  mode only.
- **Run folder** (under `--runs`, one per run): `run.json`, `header.json`,
  `ballots.ndjson`, `correctness.csv` (Verify), `negative-tests.csv` (Scenarios),
  `scenarios/<id>/` (mutated copies). All exportable from the UI.
- **Direct CLI** (no UI) if I want to script tiers:
  ```
  saksi-demo gen --stream <dir> --voters N --positions P --candidates C \
    --trustees n --threshold t --election-id <id> --election-name "<name>" \
    --trustee-names a,b,c,... --distribution uniform|skewed
  saksi-demo audit-stream <dir> --json   # {overall, contests:[{ground_truth,decoded,E,pass}]}
  ```

## Guardrails

- The plan + design are settled: `docs/plans/2026-08-19-research-election-console-{design,plan}.md`.
  Read for context; don't reopen decisions.
- A scenario `FAIL` = a gate that should have rejected didn't — a real finding to
  surface to me, not a tooling error to paper over.
- If a phase errors, the run folder is kept; the live log pane shows why.
