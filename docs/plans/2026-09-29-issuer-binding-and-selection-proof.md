# Issuer key bound on-chain, and a sum-to-one selection proof

Decided 2026-09-29, before the Chapter 4 study: fix both security gaps, then build the study on the merge commit.

## Problem

1. **Issuer key not bound.**
   - `SubmitBallot` (`packages/saksi-bulletin/chaincode/contract.go`) verifies the credential signature with `credverify.VerifyIssuerSignature(presentation.GetIssuerPublicKey(), …)`, which is the key the ballot carries itself.
   - `ElectionParameters` stores no issuer key.
   - So a ballot under a self-made issuer key is committed; only the auditor's `ballot.issuer_binding` refuses it. This was demonstrated on channel `sample-stuffing`, 2026-09-15, forged ballot at block 9.
2. **No overvote protection.**
   - Each candidate ciphertext has a CDS proof that it encrypts 0 or 1 (`cdsverify.VerifyBinaryCDS`, auditor `ballot.cds_proof`).
   - Nothing proves a position's ciphertexts sum to exactly 1, so a ballot marking several candidates passes the chaincode and the per-ballot audit.
   - saksi-crypto has only `nizk/cds.rs`, `chaum_pedersen.rs` and `schnorr.rs`.

## Global Constraints

- **Wire (`packages/saksi-protocol/proto/saksi/protocol/v1/wire.proto`), new optional fields only.** Existing field numbers are unchanged.
  - `ElectionParameters.issuer_public_key` = field **6** (bytes, 32-byte compressed ristretto point).
  - `Ballot.selection_proof` = field **8** (message `ChaumPedersenProof`, the existing wire message).
- **Chaincode gate ids** (the `rejectAt` first argument):
  - `issuer`: the presentation's `issuer_public_key` is not byte-equal to the stored `ElectionParameters.issuer_public_key`. Checked after the `shape` checks and before `credential`.
  - `selection`: the selection proof is missing or does not verify. Checked after `cds`.
- **Legacy behaviour.**
  - If `ElectionParameters.issuer_public_key` is empty (an election created before this change), the `issuer` gate is skipped.
  - A ballot with no `selection_proof` on an election that has an issuer key is refused `selection`.
  - Rule: an election with an issuer key requires every new check. An election without one keeps the old behaviour, so old chains stay readable.
- **Auditor check ids:**
  - `ballot.selection_sum`: the selection proof fails, or is missing when the params carry an issuer key;
  - `parameters.issuer_binding`: the params `issuer_public_key` is non-empty and differs from the header's `issuer_pk`.
- **Selection proof statement.**
  - For a ballot record with ciphertexts `(A_k, B_k)` over its position's contests, let `A = Σ A_k` and `B = Σ B_k − G` (G is the ristretto basepoint, m = 1).
  - The prover knows `R = Σ r_k` with `A = R·G` and `B = R·Y`, where Y is the joint election public key rebuilt from the DKG transcript as the chaincode already does (`electionpk.go`).
  - Prove it with the existing `ChaumPedersenProof::prove` / `verify` (`saksi-crypto/src/nizk/chaum_pedersen.rs`), bases (G, Y) and statements (A, B).
  - Fiat-Shamir context: `saksi.ballot.selection.v1` ‖ len-prefixed election_id ‖ len-prefixed position_id ‖ nullifier bytes. Use the same length-prefix style as the existing CDS `binding_context` in saksi-crypto.
  - The Go verifier must produce byte-identical challenges to the Rust prover. Add a golden test vector.
- **Scenario ids** (the attack catalogue in `packages/saksi-campaign/scenarios.go`):
  - `self-issued-credential`: stage ballots, chain gate `issuer`, audit gate `ballot.issuer_binding`.
  - `overvote`: stage ballots, chain gate `selection`, audit gate `ballot.selection_sum`.
  - Both are live-capable at the ballots pause, like the existing three ballot attacks.
- **Commit trailers:**
  - `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`
  - `Claude-Session: https://claude.ai/code/session_015q5U4NJTtwkhtHs9CyapZG`
- **Branch:** `feat/issuer-binding-selection-proof` off `main` c42f24f, worktree `C:\wt\saksi-f12`.

| Task | model | where | reviewer |
|---|---|---|---|
| 1 | executor (Opus) | worktree C:\wt\saksi-f12 | reviewer (Sonnet) |
| 2 | executor (Opus) | same worktree, after 1 | reviewer (Sonnet) + final-reviewer (Opus, crypto) |
| 3 | executor (Opus) | same worktree, after 2 | reviewer (Sonnet) |

## Task 1: Bind the issuer key on-chain

1. **wire.proto:** add `ElectionParameters.issuer_public_key = 6`, then regenerate the Rust (prost) and Go (`saksiprotocolv1`) code the way the repo already does. Find the generator config and document the command in the report. Re-vendor the chaincode's copy of the Go protocol package (`packages/saksi-bulletin/chaincode/vendor`), and the client-sdk and campaign copies if they vendor it.
2. **Generator** (`packages/saksi-auditor/src/fixtures.rs` `gen_prologue` and `happy_path_fixture`): fill `issuer_public_key` with the issuer's compressed public key, the same key already written as the header's `issuer_pk`.
3. **Chaincode:**
   - `CreateElection` keeps storing the params bytes as is; the field travels inside them.
   - `SubmitBallot` loads the params (already done later for contests; move or reuse `loadElection`).
   - If `issuer_public_key` is non-empty and differs from `presentation.GetIssuerPublicKey()`, `rejectAt("issuer", …)` before the credential check.
   - Keep the gate order documented in the contract comment.
4. **Auditor:** add a check `parameters.issuer_binding` when params carry a key that differs from the header's `issuer_pk`. The ballot check `ballot.issuer_binding` stays as it is.
5. **Tests:**
   - Chaincode: a self-issued ballot is refused `issuer`; an honest ballot passes; a legacy election without the field still accepts.
   - Auditor: params and header mismatch.
   - Update the golden vectors: `packages/saksi-protocol/test-vectors/*` and `wire_golden_test.go`, if the params encoding changes their bytes.
   - `cargo test --workspace`, including `-p saksi-auditor --features demo`.
   - `go test ./...` in the chaincode, client-sdk and saksi-campaign, with `SAKSI_DEMO_BIN` set to a freshly built `target/release/saksi-demo.exe`.
   - `gofmt`, `go vet`, `cargo fmt --check`, `cargo clippy`, if CI runs it.

## Task 2: Sum-to-one selection proof

1. **wire.proto:** `Ballot.selection_proof = 8` (`ChaumPedersenProof`). Regenerate and re-vendor as in Task 1.
2. **saksi-crypto:**
   - Add a small helper, e.g. `nizk/selection.rs` or a function in `chaum_pedersen.rs`, that builds the statement from a slice of ciphertexts and proves or verifies with the context in the Global Constraints.
   - Reuse `ChaumPedersenProof`; add no new proof system.
   - Unit tests: an honest one-hot ballot verifies; two ones (m = 2) fails; all zeros (m = 0) fails; the wrong context fails.
3. **Generator** (`build_voter` in fixtures.rs): accumulate `r` per position and produce the proof.
4. **Chaincode:**
   - New package `packages/saksi-bulletin/chaincode/selectionverify`, in the style of `cdsverify` (ristretto via the same Go library `cdsverify` uses).
   - Verify after the CDS loop and `rejectAt("selection", …)` on failure or absence, following the legacy rule in the Global Constraints.
   - A golden cross-language test: a proof produced by Rust, checked in as a test vector, verifies in Go.
5. **Auditor:**
   - `ballot.selection_sum` in `ballot.rs` `verify_ballot`.
   - A ballot failing it is ineligible for the tally, like a CDS failure.
   - Count passes as the other checks do.
6. **Streams and headers:** nothing else changes shape. Check `write_election_stream_chunked` and `audit_stream_dir_full` still round-trip.
7. **Tests:**
   - an overvote ballot (two candidates at 1, each with a valid CDS proof, reusing the honest selection proof or none) is refused `selection` by the chaincode and flagged `ballot.selection_sum` by the auditor;
   - an honest run audits clean with E = 0;
   - performance: note the added verify time per ballot in the report (one extra DLEQ verify).
8. **Docs:** in `docs/wizard/4-encrypt.md`, correct "sums to exactly one selection" to describe the new proof. Also update the runbook's gate list and the attack table if they list gates.

## Task 3: Live attack scenarios for both gates

1. **`self-issued-credential`** (scenarios.go Registry):
   - Its `MutateBallot` / `Mutate` replaces a target ballot with one forged under a fresh issuer key and a valid CDS.
   - Reuse `forge_self_issued_ballot` from saksi commit `7272837`, branch `feat/sample-chains`: port `packages/saksi-auditor/src/demo.rs` `forge_self_issued_ballot` and the `saksi-demo forge-ballot` subcommand. Do not merge the `cmd/samplechain` tool.
   - If the Go scenario needs the Rust forger, shell out to saksi-demo, as the auditor does elsewhere (`execRunner`).
   - Also add `selection_proof` to the forged ballot, so only the `issuer` gate can refuse it.
2. **`overvote`:**
   - Take a not-yet-submitted target ballot, keeping its credential presentation and nullifier.
   - Re-encrypt two candidate slots to 1 with fresh randomness and fresh valid CDS proofs bound to the same nullifier.
   - Keep the old selection proof (now invalid), so the declared gate `selection` is the one that refuses.
   - The attacker is the owner of that ballot, so a legitimate credential is realistic.
   - This probably needs a Rust helper (`saksi-demo overvote-ballot <dir> <line>`), because Go has no encryption code. Keep it in the demo binary.
3. Register both in the ballots stage so the wizard's attack timeline offers them. `classifyLive` / `classifyAudit` need no change: gate ids are declared per scenario.
4. **Tests:**
   - Simulated (offline): each is caught by its audit gate, with a positive control.
   - A live-mount unit test with a fake submitter, as the existing ballot attacks have: the refusal text `gate=issuer:` / `gate=selection:` classifies PASS.
5. **Docs:** add both rows to the runbook's attack table (§10.5) and to `docs/study-checklist.md` where the attack list appears. Also update the "seven scenarios" count wherever it appears.
