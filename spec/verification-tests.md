# Verification: claims → tests (traceability index)

Maps the thesis's testable claims to the named tests that back them, so every
claim traces to code. Hand-maintained (the test suites are the source of truth;
this index points at them). Backs the manuscript's Tables 3.6 / 3.8 and the panel
comments on correctness (#3), negative testing (#20/#24), the verifier's scope
(#28), and the three-tier test plan (#19/#23).

Run the whole suite from the two repos:

```text
saksi:       cargo test --workspace --all-features          # Rust
             (chaincode + SDK) go test ./...                # Go
balotachain: fabric CI job = full on-chain lifecycle (saksi-demo.sh)
```

## RQ1 — correctness criteria (panel #3)

"Operate correctly" = six measurable criteria, each with its check:

| Criterion | Backed by |
|-----------|-----------|
| Final tally equals ground truth | `saksi-auditor` **E=0** finding `tally.accuracy` (`audit_scores_e0_accuracy_against_ground_truth`; tamper → `tampered_ground_truth_fails_e0`) |
| Invalid ballots rejected | negative catalog below (chaincode `SubmitBallot` gate) |
| Duplicate votes rejected | `per_position_double_vote_is_caught`, chaincode `TestSubmitBallotRejectsDoubleVote` |
| All accepted ballots counted | **Reconcile** (`committed == submitted == N`): SDK `TestCountCommittedBallots*` + console `reconcileCommitted` |
| Independently verifiable from the public record | `saksi-auditor` runs on public artifacts only (I1 formal test, planned); tamper detection `malicious_bb_node_*`, `wrong_tally_is_caught`, `ledger_digest` |
| All cryptographic proofs verify | `ballot.cds_proof`, credential-signature, Chaum-Pedersen partial-decryption findings (auditor `happy_path_audit_passes`, `multi_position_audit_passes`) |

## Negative catalog (panel #20/#24) — 11 cases → the gate that rejects each

| # | Malicious input | Rejected by (test) |
|---|-----------------|--------------------|
| 1 | malformed ciphertext | chaincode `TestSubmitBallotRejectsMalformedCiphertext` |
| 2 | invalid proof (CDS) | `tampered_ballot_cds_proof_is_caught`, chaincode `TestSubmitBallotRejectsTamperedCDSProof` |
| 3 | invalid credential | `tampered_credential_presentation_proof_is_caught`, chaincode `TestSubmitBallotRejectsBadCredentialSignature` |
| 4 | **expired** credential | **M20 — pending** (add `valid_until` + on-chain voting-window reject + test) |
| 5 | reused nullifier | `reused_nullifier_is_caught`, chaincode `TestSubmitBallotRejectsDoubleVote` |
| 6 | duplicate vote (per position) | `per_position_double_vote_is_caught` (and `same_voter_different_positions_is_allowed` as the positive control) |
| 7 | altered transaction | `wrong_tally_is_caught`; ballot-byte tamper → `tampered_*` |
| 8 | altered manifest | `malicious_admin_altering_a_contest_id_is_detected`, `bad_parameters_version_is_caught` |
| 9 | insufficient trustee shares | `under_threshold_decryptions_are_caught`, `sub_threshold_decryption_fails_but_full_threshold_succeeds` |
| 10 | incorrect trustee proof | `tampered_chaum_pedersen_response_is_caught`, `tampered_partial_decryption_share_is_caught` |
| 11 | unauthorized identity | `wrong_issuer_pk_is_caught` (credential from a non-issuer key) |
| — | corrupted data (bad hex/bytes) | chaincode `TestSubmitBallotRejectsBadHex`, `...RejectsWrongVersion` |

## Verifier's scope (panel #28) — the 10 checks, all from the public record

The `saksi-auditor` `audit()` report (public artifacts only — no secret shares):

| Verifier check | Finding |
|----------------|---------|
| transaction / wire validity | `parameters.shape`, `ballot.shape`, `tally.shape` |
| credential validity | issuer-signature check inside `ballot` verification |
| nullifier uniqueness | `nullifier.unique` |
| ciphertext well-formedness | `ballot.cds_proof` (CDS `{0,1}`) |
| ballot validity proofs | `ballot.cds_proof` per contest |
| aggregate correctness | `tally.homomorphic_sum` (decode of the summed aggregate) |
| trustee decryption proofs | `decryption.chaum_pedersen` per partial |
| 3-of-5 threshold | `decryption.threshold` |
| announced tally == decrypted aggregate | `tally.homomorphic_sum` (decode == published) |
| append-only ledger consistency | `ledger_digest` (order-dependent hash chain; `malicious_bb_node_reordering_*`) |

## Three-tier test plan (panel #19/#23)

**Unit** (`saksi-crypto`, `saksi-credentials`): `encrypt`/`decrypt`,
`issuance_happy_path_verifies`, `partial_decrypt` + `combine_partial_decryptions`,
CDS `completeness_random_witness_verifies` + `invalid_parameters_*`,
`derive_nullifier_is_deterministic` + `different_{election,position,s_cred}_changes_nullifier`,
`present` / `credential_from_parts_round_trips_through_presentation`,
`decode_tally` differential test (`linear_and_bsgs_agree_across_range_and_boundaries`).

**Integration** (scoped to what exists — E3): app↔library (FFI), library↔chaincode
(`saksi-demo` lifecycle), chaincode↔ledger (chaincode `*_test.go`), verifier↔ledger
(`services/fabric-adapter` mapping test + the balotachain `fabric` CI job).
*App↔Fabric write integration is deferred* (the voter/trustee/admin write path is
out of scope; apps write to a JSON store, not Fabric).

**System**: the complete election lifecycle at the 1000-voter tier —
`saksi-demo.sh` (network up → deploy → gen → cycle → audit), CI-run; the
correctness ladder (N=1/10/100/1000) audits clean with E=0.

## Cross-language byte-parity (golden vectors)

`test-vectors/`: `credential-sig-v1.hex` (Rust signer ↔ Go `credverify`),
`cds-proof-v1.hex` (Rust CDS prover ↔ Go `cdsverify`), `ballot-v1.hex`,
`pinned_nullifier_vector`, `stream-v1/` (NDJSON format contract). These pin the
Rust↔Go agreement the on-chain gate depends on.
