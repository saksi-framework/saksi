# saksi-bulletin/network

Development Hyperledger Fabric network for the Saksi bulletin board, plus
helper scripts to deploy the chaincode and run a single end-to-end transaction.

This stage uses a **minimal** network — the standard Fabric `test-network` from
[`fabric-samples`](https://github.com/hyperledger/fabric-samples) (one peer
organization, one orderer, a CA) — to get one transaction working fast. The
locked architecture's five-trustee (`Org1`..`Org5`, 3-of-5) topology is a later,
additive step; see "Target topology" below. The scripts here are thin wrappers
around `test-network`, parameterized with Saksi's channel and chaincode.

> Development and integration testing only. Not safe for any real election.

## Prerequisites

- **Docker** (running) and Docker Compose.
- **Go** 1.22+ (to build the chaincode and run the client).
- **Fabric binaries + samples + images.** Install once:

  ```sh
  curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh \
    | bash -s -- docker samples binary
  ```

  This creates a `fabric-samples/` directory and downloads the Fabric Docker
  images and binaries. Put the binaries on your `PATH`
  (`export PATH=$PWD/fabric-samples/bin:$PATH`).

By default the scripts look for `fabric-samples/` as a sibling of the `saksi`
repository. Override with `FABRIC_SAMPLES=/path/to/fabric-samples`.

## Run one transaction

From this directory:

```sh
# 1. Start the network and create the `saksi` channel, then deploy the chaincode.
./network.sh all

# 2. Submit one ballot and read it back.
./run-one-transaction.sh

# 3. Tear it all down when finished.
./network.sh down
```

`run-one-transaction.sh` stands up the fixture election (CreateElection +
PublishDKGTranscript via `cmd/saksi-console --setup-only`) and then submits one
REAL ballot from the checked-in bundle fixture
([`../../saksi-protocol/test-vectors/bundle-v1.json`](../../saksi-protocol/test-vectors/bundle-v1.json))
via the client SDK's `cmd/submit-ballot`, using the Org1 `User1` identity the
test-network generated, then evaluates `GetBallot` and confirms the bulletin
board returned the same ballot. The chaincode verifies CDS proofs on-chain at
endorsement (ADR-0007), so the wire-format golden vector (`ballot-v1.hex`,
placeholder crypto) cannot commit — the real fixture is required. Submitting
the same ballot twice is rejected by the chaincode's nullifier-uniqueness
check (no double vote); tear the network down/up (or set `SAKSI_BUNDLE` to a
fresh `saksi-demo gen` bundle) to re-run. Requires `jq`.

### What each piece does

| Piece | Role |
| --- | --- |
| `network.sh up` | starts peers + orderer + CA and creates the `saksi` channel |
| `network.sh deploy` | packages, installs, approves, and commits the `saksi-bulletin` chaincode (`-ccp ../chaincode -ccl go`) |
| `run-one-transaction.sh` | submits + reads one ballot through the gateway with Org1 MSP material |

### Overrides

| Variable | Default | Meaning |
| --- | --- | --- |
| `FABRIC_SAMPLES` | sibling of the repo | fabric-samples checkout |
| `SAKSI_CHANNEL` | `saksi` | channel name |
| `SAKSI_CC_NAME` | `saksi-bulletin` | chaincode name |
| `SAKSI_BUNDLE` | `bundle-v1.json` fixture | election bundle (from `saksi-demo gen`) to set up + submit from |

## Target topology (per locked architecture)

The production-shaped development network — not yet built here — is:

- **5 trustee organizations** (`Org1`..`Org5`), each running one peer, matching
  the 3-of-5 threshold default.
- **Raft ordering service** (multi-node topology documented separately).
- **Fabric CA** per organization for identity issuance.

Growing the minimal network to this topology is additive: more orgs/peers and a
channel policy update, with the same chaincode and client.
