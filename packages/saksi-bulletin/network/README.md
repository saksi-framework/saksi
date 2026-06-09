# saksi-bulletin/network

Development Hyperledger Fabric network for BalotaChain.

**Status:** placeholder. The full network — `docker-compose.yml`, channel artifacts, crypto material generation, and helper scripts (`network.sh up`, `down`, `deployCC`) — lands in issue [#26](https://github.com/saksi-framework/balotachain/issues/26).

## Target topology (per locked architecture)

- **5 trustee organizations** (`Org1`..`Org5`), each running 1 peer. Matches the 3-of-5 threshold default.
- **1 ordering service node** running Raft. The production multi-node Raft topology is documented separately; this network targets local development only.
- **Fabric CA** per organization for identity issuance.
- **Channel:** `balota-board`.
- **Chaincode:** `saksi-bulletin` (from [`../chaincode/`](../chaincode/)).

The network is for development and CI integration tests only. It is not safe for any real election.
