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

## 5. Reaching it from another device

The server has **no login** — anyone who can reach the address can drive it. Pick one:

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
   positions/candidates; voters (scale presets — offline caps at 10,000, larger
   tiers are on-chain/perf mode); distribution; mode (offline / on-chain).
2. **Phases**: `Generate` (writes the real ballots), `Verify` (audits →
   correctness table, `E = 0`), `Scenarios` (runs the negative tests),
   `Submit` (on-chain only), or `Run all` (chains them). `Cancel` stops a phase.
3. **Results**: per-contest `ground_truth / decoded / E / pass`, overall PASS/FAIL,
   and export links.
4. **History**: past runs accumulate; each is exportable.

## 7. What works offline vs. network-gated

- **Offline (fully working, no network):** Generate → Verify → correctness.csv,
  and 6 of 7 scenarios (CDS-proof tamper, nullifier reuse, dropped ballot,
  corrupted bytes, tampered partial-decryption, tampered DKG) — each proven
  rejected by the real auditor.
- **Network-gated (needs a live Fabric network):** on-chain `Submit` + perf
  numbers, and the `reordered-ballots` scenario (ordering is a ledger property the
  stateless auditor does not check, so it is enforced by the chain, not
  `audit-stream`). These are skipped/errored clearly when no network/driver is
  present — never a silent hang.

## 8. Where the data lands

Each run is a folder under `--runs`, named `<slug>-<timestamp>-<n>`:

| File | What |
|------|------|
| `run.json` | config + created_at |
| `header.json` | election params/DKG/issuer/binding/partials/tally/ground-truth (hex protobuf) |
| `ballots.ndjson` | one hex-protobuf ballot per line |
| `correctness.csv` | `contest,ground_truth,decoded,E,pass` (written by Verify) |
| `negative-tests.csv` | `scenario,layer,action,expected,actual,verdict,property` (written by Scenarios) |
| `scenarios/<id>/` | the mutated copy each scenario audited |

You can also drive the backend directly without the UI:

```bash
saksi-demo gen --stream /tmp/run --voters 1000 --positions 3 --candidates 4 \
  --trustees 5 --threshold 3 --election-id e1 --election-name "Election 1" \
  --trustee-names A,B,C,D,E --distribution uniform
saksi-demo audit-stream /tmp/run --json     # -> {overall, contests:[{ground_truth,decoded,E,pass}]}
```

## 9. Troubleshooting

- **`bind: address already in use`** — another service owns the port; pass a free
  one via `--addr`.
- **`saksi-demo` not found** — pass `--demo <absolute path to the built binary>`.
- **A phase shows failed** — the run folder is kept; the live log pane shows the
  error, and the exports are there to inspect. A scenario `FAIL` means a gate that
  should have rejected did not — a real finding, not a tooling error.
