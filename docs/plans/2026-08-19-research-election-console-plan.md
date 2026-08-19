# Research Election Console — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Go-served localhost console that configures an election (name, t-of-n
trustees + names, scale, distribution, offline/on-chain) and runs it in
independent phases — Generate | Submit | Verify | Scenarios — with pre-submit
ballot export, a correctness cross-check CSV, and a negative/vulnerability
scenario runner.

**Architecture:** A new Go package `packages/saksi-campaign` serves a
self-contained web UI and orchestrates runs over a `run/<id>/` folder, shelling
the parameterized `saksi-demo` generator/auditor (offline) or driving the Fabric
lifecycle (on-chain). The Rust generator is first parameterized on
(election_id, threshold, trustees, names); everything else builds on that.

**Tech Stack:** Rust (curve25519-dalek, prost) for the generator; Go (net/http +
SSE stdlib) for the console **plus `google.golang.org/protobuf` + the existing
`packages/saksi-protocol/go` (`saksiprotocolv1`) module** — the scenario library
decodes hex-protobuf ballots, so this is NOT a stdlib-only package (verified: the
on-disk ballot lines are `hex(prost::encode_to_vec)`); a single self-contained
HTML page + minimal JS.

**Spec:** `docs/plans/2026-08-19-research-election-console-design.md`

## Global Constraints

- **Build environment split:** the Linux dev box has NO Rust/Go/protoc toolchain
  (edit + git only). All verification is via **CI** (cargo fmt/clippy/test + go
  lint/test/build on PRs) and the **offline path on Windows**. On-chain
  Submit/perf are network-gated (live Fabric on a space-free path / WSL).
- **DKG:** any `1 ≤ threshold ≤ trustees`; UI caps `trustees ≤ 15`. Real n-dealer
  DKG via `DkgConfig::new(t, n)` (exists in `saksi-crypto/src/dkg.rs`).
- **Server:** bind `127.0.0.1` only; validate every run-id / path segment against
  an allowlist (no user string interpolated into a filesystem path).
- **Fail-loud:** a scenario mutation that is NOT rejected is a real finding, not a
  swallowed error; a dropped/mismatched ballot count fails the run.
- **Rust style:** `cargo fmt` + `clippy -D warnings` clean; new pub items used or
  `#[cfg(test)]`-gated (CI treats dead code as an error under the demo feature).

## File structure

Rust (Phase 1):
- Modify `packages/saksi-auditor/src/fixtures.rs` — `GenParams` + parameterized
  `multi_position_fixture`.
- Modify `packages/saksi-auditor/src/demo.rs` — `election_bundle_json_params` /
  `write_election_stream_params` take `GenParams`; `validate_population` extends.
- Modify `packages/saksi-auditor/src/stream.rs` — `StreamHeader` gains
  `election_name`, `trustee_names`.
- Modify `packages/saksi-demo/src/main.rs` — `--election-id/--threshold/--trustees`.

Go (Phases 2–5), new `packages/saksi-campaign/`:
- `config.go` — `ElectionConfig` + validation.
- `runstore.go` — `run/<id>/` folder store + history.
- `executor.go` — Generate/Submit/Verify executors (shell saksi-demo / console).
- `scenarios.go` — scenario library (mutations) + evidence capture.
- `sse.go` — Server-Sent Events hub.
- `server.go` — HTTP handlers + routing + loopback bind.
- `web/index.html` — self-contained UI (embedded via `go:embed`).
- `cmd/saksi-campaign/main.go` — `serve` entrypoint.
- `*_test.go` per file.

---

## Phase 1 — Rust generator parameterization (CI-verifiable; do first)

### Task 1: `GenParams` + parameterize `multi_position_fixture`

**Files:**
- Modify: `packages/saksi-auditor/src/fixtures.rs`
- Test: same file (`#[cfg(test)] mod tally_selection_tests` sibling, or a new mod)

**Interfaces:**
- Produces: `pub struct GenParams { pub election_id: String, pub election_name:
  String, pub threshold: usize, pub trustees: usize, pub trustee_names:
  Vec<String>, pub voters: usize, pub positions: usize, pub candidates: usize, pub
  profile: SelectionProfile }` and `pub(crate) fn multi_position_fixture(p:
  &GenParams) -> ElectionFixture`. **`GenParams` MUST be `pub` (not `pub(crate)`):
  `saksi-demo` is a separate crate that constructs it in Task 4 (verified: today
  `multi_position_fixture` is `pub(crate)` and `saksi-demo` reaches only the `pub
  demo::` entry points).** `election_name` is distinct from `election_id` (id =
  the cryptographically-bound identifier; name = display metadata for the header).
- Produces: `impl GenParams { pub(crate) fn simple(voters: usize, positions:
  usize, candidates: usize, profile: SelectionProfile) -> Self }` — the
  back-compat constructor filling today's defaults (`election_id =
  "election-2026"`, `election_name = "election-2026"`, 3-of-5, names `"1".."5"`). Every existing caller migrates
  mechanically: `multi_position_fixture(4, 2, 2, Uniform)` →
  `multi_position_fixture(&GenParams::simple(4, 2, 2, Uniform))`, with no
  behavior change. **(F1: this is the blast-radius shrinker — ~10+ call sites
  across `tests.rs`, `security_privacy.rs`, `demo.rs`, `stream.rs`,
  `independent_verification.rs` change one line each, in this same commit, so CI
  goes red→green in one pass rather than staying red across the migration.)**
- Consumes: existing `DkgConfig::new(t, n)`, `ph_position_id`, `select_candidate`.

- [ ] **Step 1: Write the failing test** (a 2-of-3 election generates + audits, and
  the parameters are honored)

```rust
#[test]
fn parameterized_fixture_honors_trustees_and_name() {
    let p = GenParams {
        election_id: "midterm-2026".into(),
        threshold: 2,
        trustees: 3,
        trustee_names: vec!["Alice".into(), "Bob".into(), "Carol".into()],
        voters: 4,
        positions: 2,
        candidates: 2,
        profile: SelectionProfile::Uniform,
    };
    let f = multi_position_fixture(&p);
    assert_eq!(f.parameters.election_id, "midterm-2026");
    assert_eq!(f.parameters.trustee_ids.len(), 3);
    assert_eq!(f.parameters.threshold, 2);
    // one ballot per (voter, position)
    assert_eq!(f.ballots.len(), 4 * 2);
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p saksi-auditor --all-features parameterized_fixture` → FAIL (GenParams/signature not defined). *(CI or Windows.)*

- [ ] **Step 3: Implement** — add `GenParams` + `GenParams::simple`; migrate every
  existing `multi_position_fixture(...)` / positional caller to
  `&GenParams::simple(...)` in this commit (grep `multi_position_fixture` first to
  enumerate the sites); change `multi_position_fixture` to take `&GenParams`;
  replace the hardcoded pieces:
  - `let trustee_ids: Vec<String> = (1..=p.trustees as u32).map(|i| i.to_string()).collect();`
  - `let threshold = p.threshold as u32;`
  - `election_id: p.election_id.clone()`
  - DKG: `let config = DkgConfig::new(p.threshold, p.trustees).expect("valid t-of-n");`
    and the dealers loop over `1..=config.trustees` with `0..config.threshold`
    coefficients (unchanged shape, now parameterized).
  - keep `select_candidate(p.profile, voter_idx, pos, p.candidates)` and the
    independent `tally_selections` unchanged.
  - store `trustee_names` on the fixture (add a field) for the header.

- [ ] **Step 4: Run to verify it passes** — same command → PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/saksi-auditor/src/fixtures.rs
git commit -m "feat(auditor): parameterize multi_position_fixture via GenParams (t-of-n, name)"
```

### Task 2: update `demo.rs` params entry points + validation gate

**Files:**
- Modify: `packages/saksi-auditor/src/demo.rs`
- Test: same file `#[cfg(test)] mod tests`

**Interfaces:**
- Produces: `pub fn election_bundle_json_params(p: &GenParams) -> Result<String,
  String>` and `pub fn write_election_stream_params(dir: &Path, p: &GenParams) ->
  Result<(), String>` (both now take `GenParams` instead of positional args).
- Consumes: Task 1's `GenParams` + `multi_position_fixture`.

- [ ] **Step 1: Write the failing test** (4-of-7 round-trips through the gate + audit)

```rust
#[test]
fn params_entry_generates_and_audits_for_4_of_7() {
    let p = GenParams {
        election_id: "e".into(), threshold: 4, trustees: 7,
        trustee_names: (1..=7).map(|i| format!("T{i}")).collect(),
        voters: 5, positions: 1, candidates: 2, profile: SelectionProfile::Uniform,
    };
    let bundle = election_bundle_json_params(&p).expect("gate passes");
    let report = audit_bundle_json(&bundle).expect("audits");
    assert_eq!(report.overall, AuditStatus::Pass, "{report:#?}");
}

#[test]
fn gate_rejects_threshold_above_trustees() {
    let p = GenParams { threshold: 6, trustees: 5, /* …valid rest… */ ..sample() };
    assert!(election_bundle_json_params(&p).is_err());
}
```

- [ ] **Step 2: Run to verify it fails** — signatures don't take `GenParams` yet.

- [ ] **Step 3: Implement** — change both entry points to accept `&GenParams`, call
  `multi_position_fixture(p)`, and in `validate_population` add the check
  `if p.threshold == 0 || p.threshold > p.trustees { return Err("threshold must be
  1..=trustees".into()); }` and `if p.trustee_names.len() != p.trustees { return
  Err(...) }`. Update the `fixture_to_bundle_json` caller and existing callers/tests.

- [ ] **Step 4: Run to verify it passes.**

- [ ] **Step 5: Commit**

```bash
git add packages/saksi-auditor/src/demo.rs
git commit -m "feat(auditor): GenParams entry points + t<=n validation gate"
```

### Task 3: `StreamHeader` gains `election_name` + `trustee_names`

**Files:**
- Modify: `packages/saksi-auditor/src/stream.rs`
- Test: same file `mod tests`

**Interfaces:**
- Produces: `StreamHeader { …, pub election_name: String, pub trustee_names:
  Vec<String> }` written by `write_election_stream`.

- [ ] **Step 1: Write the failing test** — extend `stream_round_trips…` to assert
  `read_header(&dir).election_name == p.election_id`-derived name and
  `trustee_names.len() == p.trustees`.

- [ ] **Step 2: Run — FAIL** (fields absent).

- [ ] **Step 3: Implement** — add the two fields to `StreamHeader`, both
  `#[serde(default)]` so a pre-existing v1 stream (no names) still parses — this
  keeps the change **additive within v1**, not a wire break (codex flagged the
  golden re-pin; `serde(default)` + extending the golden is the backward-reader
  strategy, no v2 bump needed). Populate from the fixture in
  `write_election_stream`; extend the pinned `stream-v1/header.json` golden + its
  parse test with the two new fields (E2 byte-exact contract).

- [ ] **Step 4: Run — PASS.**

- [ ] **Step 5: Commit**

```bash
git add packages/saksi-auditor/src/stream.rs packages/saksi-protocol/test-vectors/stream-v1/header.json
git commit -m "feat(auditor): stream header carries election_name + trustee_names"
```

### Task 4: `saksi-demo gen` CLI flags

**Files:**
- Modify: `packages/saksi-demo/src/main.rs`

**Why (codex-confirmed gap):** today `cmd_gen` writes a **single bundle JSON** and
parses only `--voters/--positions/--candidates/--distribution` + a positional
outfile — there is **no `--stream`, no `--election-name`, no `--trustee-names`**
(the `--stream` doc-comment on `write_election_stream_params` is stale — the flag
was never wired). The console needs (a) a stream folder to audit + mutate, and
(b) a way to pass the UI-collected election name + trustee names through to the
header. Both land here.

**Interfaces:**
- Produces: `gen` accepts `--election-id <s>`, `--election-name <s>`,
  `--threshold <t>`, `--trustees <n>`, `--trustee-names <comma,sep>` (+ existing
  `--voters/--positions/--candidates/--distribution`), builds a `GenParams`, and:
  - default (positional outfile) → `election_bundle_json_params` (bundle, existing);
  - `--stream <dir>` → `write_election_stream_params(dir, &p)` (the **stream folder**
    the console's offline Generate consumes). Mutually exclusive with the outfile.

- [ ] **Step 1: Write the failing test** — a `#[test]` in main.rs that parses
  `["gen","--trustees","3","--threshold","2","--election-id","x",
  "--election-name","Midterm","--trustee-names","Alice,Bob,Carol","--stream",
  "/tmp/r", …]` into the expected `GenParams` (+ an output-target enum) via an
  extracted `parse_gen_args(args) -> Result<(GenParams, GenTarget), String>`,
  where `GenTarget = Bundle(PathBuf) | Stream(PathBuf)`.

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement** — extract `parse_gen_args`; add the flags mirroring the
  existing `--voters` arm (`--threshold`/`--trustees` parse positive usize;
  `--election-id`/`--election-name` take the next arg; `--trustee-names` splits on
  `,` and must yield exactly `trustees` names, else parse error; `--stream` sets
  `GenTarget::Stream`). Defaults when unspecified (back-compat): `trustees = 5`,
  `threshold = default_majority(n)`, `election_id = election_name = "election-2026"`,
  `trustee_names = (1..=n).map(|i| i.to_string())`. Dispatch on `GenTarget`:
  bundle → write JSON (existing); stream → `write_election_stream_params`.

- [ ] **Step 4: Run — PASS**; plus a manual (Windows) smoke of BOTH targets:
  `cargo run -p saksi-demo -- gen --voters 4 --positions 2 --candidates 2
  --trustees 3 --threshold 2 --election-id demo --election-name Demo
  --trustee-names A,B,C /tmp/b.json && cargo run -p saksi-demo -- audit /tmp/b.json`
  → PASS; and `… --stream /tmp/run` → writes `/tmp/run/{header.json,ballots.ndjson}`.

- [ ] **Step 5: Commit**

```bash
git add packages/saksi-demo/src/main.rs
git commit -m "feat(saksi-demo): gen --election-id/--threshold/--trustees flags"
```

### Task 4b: `saksi-demo audit-stream <dir> --json` (offline Verify's data source)

**Files:**
- Modify: `packages/saksi-demo/src/main.rs`
- Modify: `packages/saksi-auditor/src/demo.rs` (or a new small `audit_stream`
  helper) — audit a **stream run folder**, not just a one-blob bundle.

**Why (F2+F3):** the console's offline Generate writes a *stream* — `header.json`
(which **embeds** parameters, dkg_transcript, issuer_public_key, binding_context,
partial_decryptions, tally, AND ground_truth, each as hex-protobuf) + a streamed
`ballots.ndjson` (one `hex(prost::encode_to_vec)` ballot per line). Today's
`saksi-demo audit` consumes a *one-blob bundle* instead — so the Go Verify
executor has nothing to shell over the run folder, and even if it did, the
auditor emits correctness numbers only inside human-readable finding *strings*
(`"decoded tally = 4 == ground truth"`), which the Go side would have to regex.
This task fixes both: audit the stream folder AND emit machine-readable
correctness. (Verified: the two stream files already contain every field of the
auditor's `ElectionArtifacts` — no new serialization is invented here, just a
loader + a structured projection.)

**Interfaces:**
- Produces: `gen`-sibling subcommand `audit-stream <dir> [--json]` that loads the
  run folder (reusing the stream reader from Task 3 + `ground_truth.json`),
  audits it, and with `--json` prints exactly:
  `{"overall":"pass|fail","contests":[{"contest":"<id>","ground_truth":N,
  "decoded":N,"E":N,"pass":true|false}, …]}`.
- Produces (Rust side): `pub fn audit_stream_dir(dir: &Path) -> Result<StreamAudit,
  String>` and a serde-serializable `StreamAudit { overall: AuditStatus, contests:
  Vec<ContestCorrectness> }` so the JSON shape is tested in Rust, not just shelled.

- [ ] **Step 1: Write the failing test** — generate a 2-of-3 stream to a temp dir
  (Task 3's writer), call `audit_stream_dir(&dir)`, assert `overall == Pass` and
  every `contest.E == 0` and `contest.decoded == contest.ground_truth`.

```rust
#[test]
fn audit_stream_dir_reports_zero_error_on_clean_run() {
    let dir = tempdir().unwrap();
    let p = GenParams::simple(6, 2, 2, SelectionProfile::Uniform);
    write_election_stream_params(dir.path(), &p).expect("write stream");
    let audit = audit_stream_dir(dir.path()).expect("audits");
    assert_eq!(audit.overall, AuditStatus::Pass);
    assert!(audit.contests.iter().all(|c| c.e == 0 && c.decoded == c.ground_truth));
}
```

- [ ] **Step 2: Run — FAIL** (`audit_stream_dir` / subcommand absent).
- [ ] **Step 3: Implement** — read `header.json` (hex-decode its embedded
  params/dkg/issuer_pk/binding_context/partial_decryptions/tally/ground_truth) +
  hex-decode each `ballots.ndjson` line into the `ElectionArtifacts` the auditor
  already consumes; run the existing audit; project per-contest `{ground_truth,
  decoded, E, pass}` out of the tally-accuracy phase into `StreamAudit`; add the
  `audit-stream` arm + `--json` printing (serde_json) to `main.rs`. Reuse the
  stream reader from Task 3 rather than re-parsing.
- [ ] **Step 4: Run — PASS**; manual (Windows) smoke:
  `saksi-demo gen … --stream /tmp/run && saksi-demo audit-stream /tmp/run --json`
  → `{"overall":"pass",…"E":0…}`.
- [ ] **Step 5: Commit** `feat(saksi-demo): audit-stream <dir> --json for run-folder correctness`.

### Task 4c: real `gen → audit-stream` integration test in CI

**Files:**
- Create: `packages/saksi-demo/tests/gen_audit_stream.rs` (a Rust integration test
  that runs the built binary), OR a small step in `.github/workflows/ci.yml`.
- Modify: `.github/workflows/ci.yml` (add the invocation to the `test` job).

**Why (codex-confirmed):** every Go executor/scenario test uses a FAKE runner, so
nothing checks that the Go-emitted flags + the `audit-stream --json` schema match
the REAL binary. Today CI runs only `cargo test` / `go test` unit tests — it never
executes `saksi-demo` end-to-end (verified). This test is the one place Rust↔Go
interop drift (a renamed flag, a changed JSON shape) gets caught, and it is fully
**CI-verifiable from the Linux dev box** — no Windows, no network.

**Interfaces:** none new — exercises the Task 4/4b CLI surface.

- [ ] **Step 1: Write the failing test** — a `#[test]` that shells the release
  binary (`env!("CARGO_BIN_EXE_saksi-demo")`): `gen --voters 6 --positions 2
  --candidates 2 --trustees 3 --threshold 2 --election-id it --election-name IT
  --trustee-names A,B,C --stream <tmp>` then `audit-stream <tmp> --json`; parse the
  stdout JSON and assert `overall == "pass"` and every contest `E == 0`.
- [ ] **Step 2: Run — FAIL** (flags/subcommand not wired until Tasks 4/4b land;
  this task is authored last in Phase 1 so it goes red→green as the gate).
- [ ] **Step 3: Implement** — nothing beyond Tasks 4/4b; ensure the CI `test` job
  builds the binary before running (`cargo test -p saksi-demo` picks up
  `CARGO_BIN_EXE_*` automatically). Add a one-line comment in `ci.yml` noting this
  is the Rust↔Go contract gate.
- [ ] **Step 4: Run — PASS** on CI.
- [ ] **Step 5: Commit** `test(saksi-demo): real gen→audit-stream integration gate`.

**End of Phase 1 → open/refresh the CI PR; all Rust tasks verify via cargo on CI.**

---

## Phase 2 — `saksi-campaign` config + run-folder store (Go)

### Task 5: `ElectionConfig` + validation

**Files:**
- Create: `packages/saksi-campaign/config.go`, `config_test.go`

**Interfaces:**
- Produces: `type Trustee struct{ Name string }`; `type ElectionConfig struct{
  Name string; Trustees []Trustee; Threshold int; Positions, Candidates, Voters
  int; Distribution string; Mode string }`; `func (c ElectionConfig) Validate()
  error`.

- [ ] **Step 1: Failing test**

```go
func TestValidateRejectsThresholdAboveTrustees(t *testing.T) {
    c := ElectionConfig{Name: "e", Trustees: mk(3), Threshold: 4,
        Positions: 1, Candidates: 2, Voters: 10, Distribution: "uniform", Mode: "offline"}
    if err := c.Validate(); err == nil { t.Fatal("t>n must be rejected") }
}
func TestValidateAcceptsGood(t *testing.T) { /* 2-of-3, 10 voters → nil */ }
```

- [ ] **Step 2: Run — FAIL** (`go test ./packages/saksi-campaign/`).
- [ ] **Step 3: Implement** — `Validate`: name non-empty; `1 ≤ Threshold ≤
  len(Trustees) ≤ 15`; `Positions,Candidates,Voters ≥ 1`; `Distribution ∈
  {uniform,skewed}`; `Mode ∈ {offline,onchain}`; each trustee name non-empty.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** `feat(campaign): ElectionConfig + validation`.

### Task 6: run-folder store

**Files:** Create `packages/saksi-campaign/runstore.go`, `runstore_test.go`.

**Interfaces:**
- Produces: `func NewRunStore(root string) *RunStore`; `func (s *RunStore)
  Create(c ElectionConfig) (runID string, dir string, err error)`; `func (s
  *RunStore) Dir(runID string) (string, error)` (rejects traversal); `func (s
  *RunStore) List() ([]RunSummary, error)` (newest first).

- [ ] **Step 1: Failing test** — `Create` writes `config.json`; `Dir("../etc")`
  errors; `List` returns the created run.
- [ ] **Step 2: FAIL.**
- [ ] **Step 3: Implement** — `runID` = sanitized slug of name + timestamp passed
  IN (no `time.Now()` in the store; caller passes it) + a short counter; validate
  `runID` matches `^[a-z0-9-]{1,64}$`; `Dir` = `filepath.Join(root, runID)` after
  the regex check; `List` reads subdirs + their `config.json`.
- [ ] **Step 4: PASS.**
- [ ] **Step 5: Commit** `feat(campaign): run-folder store with traversal-safe ids`.

---

## Phase 3 — phase executors + SSE (Go)

### Task 7: SSE hub

**Files:** Create `sse.go`, `sse_test.go`.

**Interfaces:** Produces `type Hub struct{…}`; `func (h *Hub) Subscribe(runID
string) (<-chan Event, func())`; `func (h *Hub) Publish(runID string, e Event)`;
`type Event struct{ Phase, Level, Msg string }`.

- [ ] Steps: test publish→subscribe delivers an event + unsubscribe closes;
  implement a per-runID fan-out with a mutex + buffered channels; PASS; commit.

### Task 8: Generate + Verify executors (offline path — CI/Windows testable)

**Files:** Create `executor.go`, `executor_test.go`.

**Interfaces:** Produces `func (e *Executor) Generate(ctx, runID string, c
ElectionConfig) error` (shells `saksi-demo gen` with the config into the run dir)
and `func (e *Executor) Verify(ctx, runID string) (Correctness, error)` (runs the
auditor over the run's artifacts → writes `correctness.csv`).

- [ ] **Step 1: Failing test** — with a FAKE `gen`/`audit` command injected (an
  `Executor.cmd` func field), `Generate` writes the expected files and `Verify`
  writes a `correctness.csv` with the header
  `contest,ground_truth,decoded_tally,E,pass`.
- [ ] **Step 2: FAIL.**
- [ ] **Step 3: Implement** — `Executor` holds a `runner func(name string, args
  ...string) ([]byte, error)` (real = `exec.CommandContext`; test = fake). Generate
  maps `ElectionConfig` → `gen` flags. Verify shells `saksi-demo audit-stream
  <run-dir> --json` (Task 4b) and unmarshals the `{overall, contests:[{contest,
  ground_truth,decoded,E,pass}]}` JSON straight into the `correctness.csv` rows —
  **no string-parsing of finding messages** (F2). `pass = (E == 0)`.
  **Three outcomes are kept DISTINCT (codex #12):** (1) exit 0 + valid JSON +
  `overall=pass` → clean run; (2) exit 0 + valid JSON + `overall=fail` → a real
  audit rejection (the tool WORKED and found tampering — this is a *success* of
  the verifier, the signal scenarios rely on), returned as
  `Correctness{overall:fail}` not an `error`; (3) non-zero exit OR unparseable
  JSON → an executor `error` (the binary crashed / drifted), surfaced as a phase
  failure, never silently read as "audit fail". Verify's return type carries the
  audit verdict; only case (3) returns a Go `error`.
- [ ] **Step 4: PASS.**
- [ ] **Step 5: Commit** `feat(campaign): Generate + Verify executors + correctness.csv`.

### Task 9: Submit executor (on-chain; network-gated)

**Files:** Modify `executor.go`, `executor_test.go`.

**Interfaces:** Produces `func (e *Executor) Submit(ctx, runID string) error` —
offline mode returns nil (documented no-op); on-chain drives the Fabric lifecycle
via the console driver + `Reconcile` (committed == submitted).

- [ ] Steps: test that offline Submit is a no-op and on-chain Submit calls the
  driver with the run's bundle (fake runner asserts the args); implement; the real
  on-chain execution is **network-gated** (documented, not CI-run); commit.

---

## Phase 4 — scenario library (Go)

### Task 10: scenario mutations + evidence capture

**Files:** Create `scenarios.go`, `scenarios_test.go`.

**Interfaces:** Produces `type Layer int` (`LayerOffline | LayerChaincode`);
`type Scenario struct{ ID, Property string; Layer Layer; Mutate func(dir string)
error; ExpectReject bool }`; `func Registry() []Scenario`; `func
RunScenario(e *Executor, srcRun, dstRunID, id string) (ScenarioResult, error)`
(copies the source run to a FRESH run id — never mutates the source in place —
mutates the copy, verifies, captures the rejection) → appends a
`negative-tests.csv` row
`scenario,layer,precondition,action,expected,actual,evidence,verdict,property`.

**Attack→verifier-layer matrix (codex-confirmed; the correctness crux):** each
scenario declares the layer that PROVABLY rejects it, and `RunScenario` runs it
against that layer only — never asserting a guarantee the verifier does not
provide (which would be a false FAIL, not a finding):
- **`LayerOffline`** — rejected by the offline auditor (`audit-stream`): flipped
  CDS proof, tampered partial-decryption, altered contest id, dropped ballot,
  reordered ballots, wrong issuer key, corrupted ciphertext bytes, sub-threshold
  trustees. These run in offline mode, no network.
- **`LayerChaincode`** — only rejected at on-chain endorsement (e.g. cross-ballot
  **nullifier reuse / double-spend**, if the offline auditor does not maintain a
  spent-nullifier set). These are **network-gated**: skipped with an explicit
  "chaincode-only, network required" row in offline mode, run only against live
  Fabric.

**Grounding the layer per attack (do this BEFORE writing the registry):** the
`LayerOffline` set is not invented — it is exactly the tamper cases the offline
auditor already proves it detects in
`packages/saksi-auditor/src/independent_verification.rs` (the 6-case tamper matrix:
ballot-proof, tally-total, dropped-ballot, reordered-ballots, partial-decryption,
dkg-transcript) plus `security_privacy.rs`. Any attack NOT covered by an existing
auditor tamper test is marked `LayerChaincode` (or added to the auditor first with
its own Rust tamper test — do not assert offline rejection the auditor's own tests
don't demonstrate). Cross-reference `spec/verification-tests.md`'s claims→tests
index for the authoritative mapping.

Mutating pure display metadata (election_name / trustee_names) is NOT a scenario:
those bytes are not cryptographically bound, so no layer rejects them (codex #8).

**Mutation mechanism (F4 — the crux, spell it out):** each `Mutate` operates on
the copied run at the level the console actually controls the bytes:
- **Protobuf-field attacks** (flipped CDS proof, tampered partial-decryption,
  corrupted ciphertext bytes): the target is **hex-encoded protobuf wire bytes**
  (`ballots.ndjson` lines, and the hex fields embedded in `header.json`). So:
  **hex-decode → `proto.Unmarshal` into the generated `saksiprotocolv1` type →
  mutate one field → `proto.Marshal` → hex-encode → write back**. Byte-level
  surgery on the wire bytes is NOT allowed — go through the typed struct so the
  mutation is exactly one semantic change. (Verified: the on-disk format is
  `hex(prost::encode_to_vec)`, same wire format the Go `.pb.go` types decode.)
- **Structural attacks** (dropped ballot, reordered ballots): edit `ballots.ndjson`
  lines directly (remove one / swap two) — no decode needed.
- **Manifest/parameter attacks** (altered contest id, wrong issuer key,
  sub-threshold trustees): hex-decode + mutate the corresponding embedded field in
  `header.json`, re-hex-encode.

Each scenario carries its **expected rejection** and `RunScenario` asserts it:
`verdict = (rejected == ExpectReject)`. A mutation that is NOT rejected (by its
declared layer) → `verdict = FAIL` and a real finding (fail-loud), never a
swallowed error. **Positive control (codex #11 — fixed):** verify the copied run
**BEFORE** mutating it (or use two independent copies) and assert it passes clean;
a mutated copy is no longer a valid control. This catches a false-green where
Verify would reject for an unrelated reason.

- [ ] **Step 1: Failing test** — the `reused-nullifier` scenario over a generated
  offline run yields `verdict = PASS` (rejected as expected) with a non-empty
  evidence line; the positive control (no mutation) verifies clean.
- [ ] **Step 2: FAIL.**
- [ ] **Step 3: Implement** — registry mirrors the auditor/chaincode tamper patterns
  from `spec/verification-tests.md` (reused nullifier, flipped CDS proof, dropped
  ballot, reordered ballots, altered contest id, sub-threshold, tampered partial
  decryption, wrong issuer, corrupted bytes) using the mutation mechanism above
  (decode→mutate→re-encode via `saksiprotocolv1` for field attacks; line edits for
  structural; header/param edits for manifest attacks). `RunScenario` copies the
  source run to `dstRunID`, mutates the copy, runs Verify (`audit-stream`), and
  records whether a Fail finding / rejection appeared; `verdict = (rejected ==
  ExpectReject)`; a NOT-rejected attack → `verdict = FAIL` (a real finding); the
  positive control on the unmutated copy must verify clean. Each scenario carries
  its `Layer`; in offline mode `RunScenario` executes `LayerOffline` scenarios and
  writes a "skipped: chaincode-only, network required" row for `LayerChaincode`
  ones (never a FAIL). (Expired credential deferred to M20.)
- [ ] **Step 4: PASS.**
- [ ] **Step 5: Commit** `feat(campaign): scenario library + negative-tests.csv`.

---

## Phase 5 — HTTP server + web UI

### Task 11: HTTP handlers + routing

**Files:** Create `server.go`, `server_test.go`, `cmd/saksi-campaign/main.go`.

**Interfaces:** Produces `func NewServer(store *RunStore, exec *Executor, hub
*Hub) http.Handler` with routes `POST /generate|/submit|/verify|/scenarios|
/run-all`, `GET /events`, `GET /runs`, `GET /export/{id}/{artifact}`, `GET /`
(the UI). Binds `127.0.0.1` in main.

- [ ] **Step 1: Failing test** — `httptest` POST `/generate` with a valid config →
  202 + a run id; invalid config → 400; `/export/../x` → 400; GET `/runs` → the
  run. Single-run lock: a second phase on a busy run → 409. **Hardening:** a POST
  with a cross-origin `Origin` header (or a non-loopback `Host`) → 403; an offline
  config above the runnable ceiling → 400 with the ceiling message.
- [ ] **Step 2: FAIL.**
- [ ] **Step 3: Implement** — handlers decode JSON, `Validate()`, dispatch to the
  executor in a goroutine publishing to the Hub, return the run id; `/export`
  validates id + artifact against an allowlist before `http.ServeFile`; a per-run
  mutex enforces the single-run lock. **Hardening (codex #16/#17, consistent with
  the prior "all hardening" call):**
  - **Anti-CSRF / DNS-rebinding:** a middleware rejects any state-changing POST
    whose `Origin` is present and not `http://127.0.0.1:<port>`/`localhost`, and
    any request whose `Host` is not the loopback bind — a bare loopback bind does
    NOT stop a malicious web page from POSTing to `127.0.0.1:8090`.
  - **Timeout + cancel:** each phase runs under a `context.WithTimeout` (generous
    but finite) wired to `exec.CommandContext`; the UI `Cancel` cancels that ctx
    (kills the child process), so a runaway generation is stoppable.
  - **Offline scale ceiling (Q1 decision):** `Validate` (or the handler) rejects an
    **offline** `Voters` above the runnable ceiling (e.g. 10_000) — offline gen is
    not parallelized (N=1000 ≈ 908s), so 50k/483k/1M are on-chain/perf-mode only.
    The error names the ceiling and points at perf mode.
- [ ] **Step 4: PASS.**
- [ ] **Step 5: Commit** `feat(campaign): HTTP server + routes + loopback bind`.

### Task 12: self-contained web UI

**Files:** Create `web/index.html` (embedded via `//go:embed`), `web_test.go`
(a smoke test that GET `/` returns the page + it references `/events`).

**Interfaces:** Consumes the server routes. One HTML file: config form (name;
trustee rows with add/remove; election-name; threshold/trustees;
positions/candidates; distribution; scale presets + custom N; mode toggle); phase
bar
`[Generate][Submit][Verify][Scenarios]`+`[Run all]` with per-phase state;
`EventSource('/events?run=…')` live log; results (tally card, E=0, verify, perf);
history table + export buttons. Theme-aware (`prefers-color-scheme`), no external
assets.

**Logic-free UI constraint (F5 — makes the thin test suite sufficient):** the
page carries **zero business logic**. It POSTs the raw config and renders SSE +
JSON responses; ALL validation (`ElectionConfig.Validate`, Task 5), run-state,
correctness (`E==0`), and scenario verdicts live server-side in Go, where they
are unit-tested. The JS does DOM wiring only (build the POST body, add/remove a
trustee row, open the `EventSource`, paint a returned field). No client-side
`t≤n` check that could drift from the server, no derived correctness computed in
JS. Consequence: there is nothing untestable hiding in the page, so the `GET /`
smoke test + the manual Windows walkthrough genuinely cover it; the server tests
(Tasks 5/6/8/10/11) are the real coverage.

- [ ] **Step 1: Failing test** — `GET /` returns 200, body contains the config
  form ids + `new EventSource`.
- [ ] **Step 2: FAIL** (no embed yet).
- [ ] **Step 3: Implement** — write `index.html` (form + fetch POSTs + SSE +
  render); `//go:embed web/index.html`; serve at `/`. Interaction states from the
  spec (idle/running/done/failed/empty) driven by the phase responses + SSE.
  **Scale presets (Q1):** in **offline** mode the preset list stops at the runnable
  ceiling (1/10/100/1000/10k) and 50k/483k/1M are disabled with a "perf mode only"
  hint; selecting **on-chain/perf** mode unlocks the full 483k/1M set. Show the
  measured runtime next to each tier as history accumulates. The server still
  enforces the ceiling (Task 11) — the UI hint is convenience, not the gate.
- [ ] **Step 4: PASS** + a manual (Windows) smoke: `saksi-campaign serve`, open
  `127.0.0.1:8090`, configure a 2-of-3 / 10-voter offline election, Run all → tally
  + E=0 PASS; run a scenario → rejected row.
- [ ] **Step 5: Commit** `feat(campaign): self-contained web console UI`.

---

## Self-review (author)

- **Spec coverage:** Q1 unified console (Phases 2–5) ✓; Q2 offline/on-chain modes
  (Task 8/9) ✓; Q3 Go-served web (Task 11/12) ✓; Q4 t-of-n + names (Task 1–4) ✓;
  Q5 single scale + history (Task 6/12) ✓; Q6 independent phases + export (Task
  8–11, `/export`) ✓; Q7 scenarios inject+evidence (Task 10) ✓. Correctness CSV
  (Task 8), negative-tests CSV (Task 10), pre-submit ballot export (`/export` +
  offline Generate) ✓.
- **Placeholders:** none — each task carries real signatures + representative test
  code; the web UI's exact markup is written at Task 12 from the spec's field list.
- **Type consistency:** `GenParams` (Task 1) used by Tasks 2–4; `ElectionConfig`
  (Task 5) used by Task 8/11; `Executor.runner` fake used by Tasks 8–10; `Hub`
  (Task 7) used by Task 11.

## Verification note (environment)

Phase 1 (Rust) verifies entirely via `cargo` on CI + Windows, now including the
**real `gen → audit-stream` binary integration test (Task 4c)** — the Rust↔Go
contract gate. Phases 2–5 (Go) verify via `go test` on CI + Windows for everything
except the **on-chain Submit + perf** path, which is network-gated (live Fabric).
The Linux dev box authors + commits; it cannot build — open/refresh the CI PR
after each phase.

## What already exists (reuse, not rebuild)

- **The self-contained auditable run-artifact format already exists** — the stream
  format (`stream.rs`): `header.json` embeds params/dkg/issuer_pk/binding_context/
  partial_decryptions/tally/ground_truth (hex protobuf) + `ballots.ndjson` (hex
  protobuf ballots). Every field of the auditor's `ElectionArtifacts` is present.
  `audit-stream` (Task 4b) is a loader over this, not a new format.
- **The offline auditor + its tamper matrix** (`independent_verification.rs`,
  6-case; `security_privacy.rs`) — grounds the `LayerOffline` scenario set (Task 10).
- **Generated Go protobuf** (`packages/saksi-protocol/go`, `saksiprotocolv1`) —
  the scenario library decodes ballots with it; no codegen needed.
- **`DkgConfig::new(t,n)`** (`saksi-crypto/src/dkg.rs`) — the t-of-n DKG; the
  generator just stops hardcoding 3-of-5.
- **`saksi-demo audit` + bundle path** — extended, not replaced (bundle stays for
  back-compat; stream is the new console target).

## NOT in scope (considered, deferred)

- **On-chain Submit design depth** (identity/wallet, channel/chaincode selection,
  tx ordering, idempotency, submitted-bytes↔run binding) — network-gated; the
  console drives the existing console/Reconcile lifecycle, a full Fabric-submit
  design is its own spec.
- **Restart recovery / durable phase-state machine** — a research tool; the
  single-run lock + SSE cover the live session. Crash-mid-run leaves the folder for
  manual inspection (documented), no resume.
- **`LayerChaincode` scenarios executed** (nullifier double-spend, etc.) —
  registered + network-gated, run only against live Fabric.
- **Expired-credential scenario** — blocked on M20 (proto regen + golden re-pin).
- **E6 rayon-parallel generation** — the reason offline presets cap at 10k; a
  separate perf task, not a prerequisite for the console.
- **Client-side validation logic** — deliberately excluded (F5): the UI is logic-free.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Codex Review | `/codex review` | Independent 2nd opinion | 1 | issues_found | 18 raised: 11 confirmed+folded, 2 defused by code, 5 noted/deferred |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | clean | 5 own (F1–F5) + 11 codex, all folded; 0 unresolved, 0 critical gaps |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

**CODEX:** headline "build the artifact format first, UI premature" is **defused** —
the stream format already is that artifact format (verified in code). Confirmed
gaps folded: `GenParams` must be `pub` (cross-crate); `gen` lacked stream output +
`--election-name`/`--trustee-names`; ballots are hex-protobuf so Go needs the
protobuf runtime (not stdlib-only) + a hex step; header additive `serde(default)`;
audit-stream artifact set corrected; verify-vs-crash distinction; attack→verifier-
layer matrix; positive-control verify-before-mutate; real CI binary integration
test; offline scale ceiling; Origin/Host anti-CSRF + ctx timeout/cancel.

**CROSS-MODEL:** Own review (F1–F5) and codex agree on the two biggest risks — the
`GenParams` refactor blast radius (F1) and the offline handoff format (F3/F4b).
Codex went deeper on interop (hex-protobuf, cross-crate visibility, CI gap) and
methodology (attack-layer matrix); those were verified against the code and folded.

**VERDICT:** ENG CLEARED — ready to implement. Phase 1 (Rust, incl. the Task 4c
integration gate) is CI-verifiable from the Linux dev box; start there.

NO UNRESOLVED DECISIONS
