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
SSE, stdlib only) for the console; a single self-contained HTML page + minimal JS.

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
- Produces: `pub(crate) struct GenParams { pub election_id: String, pub threshold:
  usize, pub trustees: usize, pub trustee_names: Vec<String>, pub voters: usize,
  pub positions: usize, pub candidates: usize, pub profile: SelectionProfile }`
  and `pub(crate) fn multi_position_fixture(p: &GenParams) -> ElectionFixture`.
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

- [ ] **Step 3: Implement** — add `GenParams`; change `multi_position_fixture` to
  take `&GenParams`; replace the hardcoded pieces:
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

- [ ] **Step 3: Implement** — add the two fields to `StreamHeader`; populate from
  the fixture in `write_election_stream`; update the pinned `stream-v1/header.json`
  fixture + its parse test (E2 contract — add the two fields to the golden file).

- [ ] **Step 4: Run — PASS.**

- [ ] **Step 5: Commit**

```bash
git add packages/saksi-auditor/src/stream.rs packages/saksi-protocol/test-vectors/stream-v1/header.json
git commit -m "feat(auditor): stream header carries election_name + trustee_names"
```

### Task 4: `saksi-demo gen` CLI flags

**Files:**
- Modify: `packages/saksi-demo/src/main.rs`

**Interfaces:**
- Produces: `gen` accepts `--election-id <s> --threshold <t> --trustees <n>` (+
  existing `--voters/--positions/--candidates/--distribution`), builds a
  `GenParams`, and calls the Task 2 entry point.

- [ ] **Step 1: Write the failing test** — a small `#[test]` in main.rs (or an
  integration test) that parses `["gen","--trustees","3","--threshold","2",
  "--election-id","x", …]` into the expected `GenParams` via a extracted
  `parse_gen_args(args) -> Result<(GenParams, Option<String>), String>`.

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement** — extract `parse_gen_args`; add the three flags mirroring
  the existing `--voters` arm (`--threshold`/`--trustees` parse positive usize;
  `--election-id` takes the next arg as a string; default names `Trustee {i}`).
  Default `threshold = default_majority(n)`, `trustees = 5`, `election_id =
  "election-2026"` when unspecified (back-compat).

- [ ] **Step 4: Run — PASS**; plus a manual (Windows) smoke:
  `cargo run -p saksi-demo -- gen --voters 4 --positions 2 --candidates 2
  --trustees 3 --threshold 2 --election-id demo /tmp/b.json && cargo run -p
  saksi-demo -- audit /tmp/b.json` → audit PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/saksi-demo/src/main.rs
git commit -m "feat(saksi-demo): gen --election-id/--threshold/--trustees flags"
```

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
  maps `ElectionConfig` → `gen` flags. Verify parses the auditor's JSON report →
  per-contest correctness rows; `pass = (E == 0)`.
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

**Interfaces:** Produces `type Scenario struct{ ID, Property string; Mutate
func(dir string) error; ExpectReject bool }`; `func Registry() []Scenario`; `func
RunScenario(e *Executor, srcRun, id string) (ScenarioResult, error)` (copies the
run, mutates, verifies, captures the rejection) → appends a `negative-tests.csv`
row `scenario,precondition,action,expected,actual,evidence,verdict,property`.

- [ ] **Step 1: Failing test** — the `reused-nullifier` scenario over a generated
  offline run yields `verdict = PASS` (rejected as expected) with a non-empty
  evidence line; the positive control (no mutation) verifies clean.
- [ ] **Step 2: FAIL.**
- [ ] **Step 3: Implement** — registry mirrors the auditor/chaincode tamper patterns
  from `spec/verification-tests.md` (reused nullifier, flipped CDS proof, dropped
  ballot, reordered ballots, altered contest id, sub-threshold, tampered partial
  decryption, wrong issuer, corrupted bytes). Each `Mutate` edits the copied run's
  artifacts; `RunScenario` runs Verify and records whether a Fail finding /
  rejection appeared; `verdict = (rejected == ExpectReject)`; a NOT-rejected
  attack → `verdict = FAIL` (a real finding). (Expired credential deferred to M20.)
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
  run. Single-run lock: a second phase on a busy run → 409.
- [ ] **Step 2: FAIL.**
- [ ] **Step 3: Implement** — handlers decode JSON, `Validate()`, dispatch to the
  executor in a goroutine publishing to the Hub, return the run id; `/export`
  validates id + artifact against an allowlist before `http.ServeFile`; a per-run
  mutex enforces the single-run lock.
- [ ] **Step 4: PASS.**
- [ ] **Step 5: Commit** `feat(campaign): HTTP server + routes + loopback bind`.

### Task 12: self-contained web UI

**Files:** Create `web/index.html` (embedded via `//go:embed`), `web_test.go`
(a smoke test that GET `/` returns the page + it references `/events`).

**Interfaces:** Consumes the server routes. One HTML file: config form (name;
trustee rows with add/remove; threshold/trustees; positions/candidates;
distribution; scale presets + custom N; mode toggle); phase bar
`[Generate][Submit][Verify][Scenarios]`+`[Run all]` with per-phase state;
`EventSource('/events?run=…')` live log; results (tally card, E=0, verify, perf);
history table + export buttons. Theme-aware (`prefers-color-scheme`), no external
assets.

- [ ] **Step 1: Failing test** — `GET /` returns 200, body contains the config
  form ids + `new EventSource`.
- [ ] **Step 2: FAIL** (no embed yet).
- [ ] **Step 3: Implement** — write `index.html` (form + fetch POSTs + SSE +
  render); `//go:embed web/index.html`; serve at `/`. Interaction states from the
  spec (idle/running/done/failed/empty) driven by the phase responses + SSE.
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

Phase 1 (Rust) verifies entirely via `cargo` on CI + Windows. Phases 2–5 (Go)
verify via `go test` on CI + Windows for everything except the **on-chain Submit
+ perf** path, which is network-gated (live Fabric). The Linux dev box authors +
commits; it cannot build — open/refresh the CI PR after each phase.
