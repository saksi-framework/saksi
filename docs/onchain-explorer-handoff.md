# On-Chain Audit-Trail View — Full Context & Handoff (for the PC session)

Paste this whole file into a fresh Claude Code session on the **PC / run machine**
(the one with Docker). It is the complete context: what the project is, what's
already built, the feature to build now (an on-chain audit-trail / "explorer"
view over the permissioned Fabric ledger), the **spike to run first**, and every
pointer you need. Nothing else is required to start.

---

## 0. Paste-ready kickoff prompt

> I'm continuing the Saksi / BalotaChain thesis project on this PC (the run box,
> has Docker). Read `docs/onchain-explorer-handoff.md` on branch
> `research-election-console` — it's my full context. We're building an **on-chain
> audit-trail view** for the Research Election Console, and the FIRST step is a
> **spike**: prove that for a ballot committed to the saksi Fabric chaincode we can
> pull its ledger receipt (block number, tx id, block hash) via Fabric's QSCC. Run
> the spike per §5, report yes/no + how, then we design + build the full feature
> end-to-end (§6). This project uses the superpowers brainstorming → writing-plans
> flow; the design decisions in §4 are already locked — don't re-litigate them.

---

## 1. What this project is

**Saksi** (`github.com/saksi-framework/saksi`) is the crypto + Fabric backend;
**BalotaChain** is the app layer. Together they're an end-to-end verifiable
cryptographic voting system on Hyperledger Fabric — a WMSU undergrad thesis (a
Design-Science empirical evaluation). Voting uses threshold ElGamal (lifted
`m·G`), Pedersen/Feldman DKG (t-of-n trustees), CDS OR-proofs of ballot
well-formedness, blind credentials, and per-position PRF nullifiers (no double
voting). The tally is homomorphic; the result is only decryptable when ≥t
trustees combine partial decryptions (the "threshold unlock").

The immediate vehicle is the **Research Election Console** (`packages/saksi-campaign`,
Go) — a loopback web app to run the paper's elections in phases and collect data.

## 2. Current state (built + CI-green on branch `research-election-console`, PR #33)

The console is done and verified end-to-end **offline**:
- **Configure** an election (name, `t`-of-`n` trustees + names, positions,
  candidates, voters/scale, distribution, offline/on-chain).
- **Phases:** Generate → Submit → Verify → Scenarios (+ Run all, Cancel). SSE live
  log, single-run lock, DNS-rebinding/CSRF guard, export allowlist.
- **Generate** shells the parameterized `saksi-demo gen --stream` (real ElGamal
  ballots) into a run folder.
- **Verify** shells `saksi-demo audit-stream --json` (real auditor) → writes CSVs.
- **Scenarios**: 7 negative/vuln tests on a copied run (verify-before-mutate
  control, fail-loud); 6 offline-detectable, `reordered-ballots` is chaincode-layer.
- **All exports are CSV evidence:**
  - `ballots.csv` — per ballot: index, election_id, position, voter_credential_commitment,
    nullifier, #ciphertexts, #proofs, **ballot_sha256**, **ballot_json** (the actual
    ElGamal ciphertexts + CDS proofs, as JSON).
  - `election.csv` — one-row summary + provenance: issuer_public_key, binding_context,
    dkg_sha256, tally_sha256, ballots_sha256.
  - `correctness.csv` — the **proof chain** per contest: ground_truth, decoded (real
    threshold decrypt), E, pass, published_tally, **recovered_point** (M), **aggregate_ciphertext**,
    dkg_sha256, tally_sha256, ballots_sha256. A reader confirms `recovered_point == decoded·G`.
  - `negative-tests.csv` — scenario results.
- **On-chain Submit is a network-gated placeholder** — the console has a Submit
  phase but no live Fabric is wired; offline is the only fully-working path today.
- CI (Ubuntu + macOS: Build/Lint/Security/Test) is green. Rust: `cargo fmt/clippy
  -D warnings/test`; Go: `go test`, `go vet`, `staticcheck`.

Docs on the branch: `docs/research-election-console-runbook.md` (build/run),
`docs/research-election-console-desktop-session.md` (console handoff),
`docs/plans/2026-08-19-research-election-console-{design,plan}.md`.

## 3. Environment / where things run

- **Linux laptop** (`ban`, where the console + this doc were authored) = dev/edit
  only. **PC / MacBook** = build + run. Nothing real runs on the laptop.
- **Console build:** Rust (stable) + Go (1.22+). **No protoc, no Docker** (the Rust
  build vendors protoc).
- **Fabric (this feature):** needs **Docker** + the Fabric binaries + `fabric-samples`
  (see §5). Runs on the PC. Use a **space-free path** (fabric-samples breaks on paths
  with spaces).
- Branch: `research-election-console`. `git pull` it on the PC.

## 4. The feature — LOCKED design decisions (do not re-litigate)

Build an **on-chain audit-trail view** in the console: proof that an election's
lifecycle is actually committed on the Fabric ledger, not just in the offline CSVs.

Decisions already made (via brainstorming):
1. **Full lifecycle audit trail** per election: CreateElection → PublishDKGTranscript
   → each SubmitBallot → CloseElection → each SubmitPartialDecryption → PublishTally,
   **each event with its ledger receipt** (block number, tx id, block/prev hash).
2. **Outsider gate = the threshold-ElGamal unlock.** On a permissioned chain an
   outsider has no channel identity and can't read the ledger themselves — so the
   **console holds a read identity and serves them** (like `services/fabric-adapter`'s
   `GET /bulletin`). The public/outside view stays **sealed** ("election in progress —
   results not yet unlocked") until `PublishTally` lands on-chain (≥t trustees
   decrypted); then it opens the full trail + results.
3. **Never a voter identity — hard rule.** The on-chain view shows ONLY on-chain
   data, which by saksi's design carries **no voter identity** (voter_ids are off-wire
   generation metadata; they stay in the researcher's private CSVs and never touch the
   ledger or this page). Anonymity holds by construction.
4. **Permissioned-read model** (not etherscan). See §7.

## 5. THE SPIKE — do this first

**Probe question:** for a ballot committed to the saksi chaincode, can we retrieve
its **ledger receipt — block number, tx id, block hash — via Fabric's QSCC**
(the `qscc` system chaincode)? Nothing in the repo queries QSCC yet; this de-risks
the core mechanic the whole audit-trail view relies on.

**Prerequisites (one-time, on the PC):**
```sh
# Docker running. Then install Fabric binaries + samples + images:
cd <parent of the saksi repo>       # a space-free path
curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh \
  | bash -s -- docker samples binary
export PATH="$PWD/fabric-samples/bin:$PATH"
# fabric-samples/ should sit as a SIBLING of the saksi repo (or set FABRIC_SAMPLES=...)
```

**Steps:**
1. Bring the network up + deploy the chaincode:
   ```sh
   cd saksi/packages/saksi-bulletin/network
   ./network.sh all          # up + create `saksi` channel + deploy `saksi-bulletin` chaincode
   ```
2. Get real data on-chain. Fastest: `./run-one-transaction.sh` (submits the golden
   ballot via `client-sdk/cmd/submit-ballot`, reads it back with `GetBallot`).
   Fuller lifecycle: `tools/saksi-demo.sh` drives CreateElection → … → PublishTally
   via `client-sdk/cmd/saksi-console`.
3. **The new bit — a throwaway QSCC probe.** The SDK (`client-sdk/connect.go`)
   holds a `*client.Gateway` but doesn't expose the network for system-chaincode
   queries. Add a throwaway accessor (or a standalone `cmd/qscc-probe`) that:
   - gets `network := gateway.GetNetwork("saksi")`, then `qscc := network.GetContract("qscc")`;
   - captures a ballot submit's **transaction id** (fabric-gateway returns it from the
     submit / `Commit`), then calls:
     - `qscc.EvaluateTransaction("GetBlockByTxID", "saksi", <txid>)` → the block,
     - or `qscc.EvaluateTransaction("GetBlockByNumber", "saksi", <n>)`,
     - and `qscc.EvaluateTransaction("GetChainInfo", "saksi")` → height + current block hash;
   - the returned `common.Block` / `BlockchainInfo` protobufs carry the block number,
     `data_hash`, `previous_hash`, and the tx ids in the block. Print tx id, block
     number, block hash and confirm they line up with the submitted ballot.

**Output:** a yes/no + exactly which QSCC calls give the receipt and what the fields
are (this shapes the end-to-end design). Label all probe code throwaway. Tear down
with `./network.sh down`.

**If it won't come up cleanly:** the saksi `fabric` path is known-fussy; try the
minimal `run-one-transaction.sh` first, keep the path space-free, ensure Docker has
enough resources. Report the blocker rather than forcing it.

## 6. After the spike — end-to-end build (design then implement)

Once the receipt mechanic is confirmed, resume the **superpowers brainstorming →
writing-plans** flow to design + build:
1. **Expose QSCC in the client-sdk** — a clean `Connection` method to fetch a
   ledger receipt (block #, tx id, block hash) for a tx / by block number, plus
   `GetChainInfo`. This is the reusable primitive.
2. **Wire the console's on-chain Submit** — make the Submit phase actually drive the
   Fabric lifecycle (via `cmd/saksi-console` / the client-sdk) so a run really lands
   on-chain, recording tx ids per lifecycle event into the run folder.
3. **Audit-trail view (the page)** — a console view that, for a run/election, reads
   the chaincode records (GetElection/ListNullifiers/GetBallot/GetDKGTranscript/
   GetPartialDecryption/GetTally/GetElectionStatus) + the QSCC receipts and renders the
   full lifecycle trail with block/tx/hash per event.
4. **The unlock gate** — the public/outside rendering stays sealed until
   `GetElectionStatus` shows the tally is published; insiders (the console operator)
   can watch status throughout. Never render voter identity (there is none on-chain).
5. **Tests** — mockable SDK boundary for unit tests; the live-network path is
   integration-gated (like the existing Fabric work).

## 7. How ledger lookup works (the conceptual answer)

- **Public chain (BTC/ETH):** the whole ledger is public; anyone hits a node or a
  public explorer (etherscan) and looks up an address → all txs. No permission to read.
- **Permissioned Fabric:** the ledger is NOT public; reading needs an **identity**
  (X.509 cert from an MSP authorized on the channel). No etherscan. WITH an identity:
  - **App level:** call the chaincode's read functions (saksi already has
    `GetElection`, `GetBallot`, `ListNullifiers`, `GetDKGTranscript`, `GetTally`,
    `GetPartialDecryption`, `GetElectionStatus`).
  - **Ledger level:** call the **QSCC** system chaincode — `GetChainInfo`,
    `GetBlockByNumber`, `GetBlockByTxID`, `GetTransactionByID` — for block/tx/hash.
  - **Proving a ballot is on-chain** = show both: the chaincode returns the record,
    AND QSCC says it committed in block N, tx X, under block-hash H, at height Z.
    Anyone else with a channel identity re-runs the queries and gets the same answer.
  - **Hyperledger Explorer** is an existing web UI that does this against a channel —
    an option, but the console-served view is more tied to our per-run proof story.

## 8. Key files / pointers

| Area | Path |
| --- | --- |
| Chaincode (queries + lifecycle) | `packages/saksi-bulletin/chaincode/contract.go` |
| Client SDK (wraps fabric-gateway) | `packages/saksi-bulletin/client-sdk/{connect,bulletin}.go` |
| On-chain lifecycle driver | `packages/saksi-bulletin/client-sdk/cmd/saksi-console` |
| One-tx submit | `packages/saksi-bulletin/client-sdk/cmd/submit-ballot` |
| Network bring-up | `packages/saksi-bulletin/network/{network.sh,run-one-transaction.sh,README.md}` |
| High-level demo (net + gen + lifecycle + audit) | `tools/saksi-demo.sh` |
| Existing read-only adapter (balotachain) | `services/fabric-adapter` → `GET /bulletin` |
| The console (where the view lands) | `packages/saksi-campaign/{server,executor,scenarios,csvexport}.go`, `web/index.html` |
| Auditor (evidence + audit-stream) | `packages/saksi-auditor/src/{lib,demo,tally,stream}.rs` |
| CLI | `packages/saksi-demo/src/main.rs` (`gen --stream`, `audit-stream --json`) |

## 9. Conventions / guardrails

- Conventional Commits. Co-Authored-By trailer:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Architecture changes need an ADR (`docs/adr/`). On-chain CDS verification is
  ADR-0007.
- Don't reverse the §4 decisions. The offline path + CSV evidence (§2) is done and
  CI-green — build the on-chain view ON it, don't disturb it.
- Threshold-unlock gate and the no-voter-identity rule are non-negotiable.
