# saksi-bulletin/client-sdk

Go client SDK wrapping `fabric-gateway`. Every non-chaincode caller — admin, trustee, auditor, voter-side relay — talks to the bulletin board through this package.

**Status:** empty Go module. Real implementation lands in issue [#30](https://github.com/saksi-framework/balotachain/issues/30).

## Identities

The chaincode takes `CreateElection`, `RegisterPrecinctMachine` and
`CloseElection` only from an administrator (MSP `Org1MSP`, certificate OU
`admin`), and a `SubmitBallot` only from the certificate registered as that
election's precinct machine. `ConnectionConfig.Admin` and
`ConnectionConfig.Machine` name those identities; `Connection.Bulletin` and
`Connection.Ledger()` route each transaction to the identity `RoleFor` names
(the default identity when a role has none). `Connection.MachineFingerprint()`
is the value to register: `CertFingerprint`, the SHA-256 of the certificate's
DER bytes as lower-case hex, the same value the chaincode computes.
`FillTestNetworkRoles` defaults the two roles to `Admin@<org>` and
`User1@<org>` beside `CertPath` in the test-network layout, and
`Connection.As(role)` gives a client pinned to one identity.

## Why a wrapper

Direct `fabric-gateway` usage scatters connection management, identity loading, retry policy, and chaincode-specific transaction shapes across every caller. The wrapper centralizes all of that, exposes typed methods matching the chaincode contract surface, and lets tests run against an in-memory mock so callers can be exercised without a live Fabric network.
