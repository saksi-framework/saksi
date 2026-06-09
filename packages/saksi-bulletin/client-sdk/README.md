# saksi-bulletin/client-sdk

Go client SDK wrapping `fabric-gateway`. Every non-chaincode caller — admin, trustee, auditor, voter-side relay — talks to the bulletin board through this package.

**Status:** empty Go module. Real implementation lands in issue [#30](https://github.com/saksi-framework/balotachain/issues/30).

## Why a wrapper

Direct `fabric-gateway` usage scatters connection management, identity loading, retry policy, and chaincode-specific transaction shapes across every caller. The wrapper centralizes all of that, exposes typed methods matching the chaincode contract surface, and lets tests run against an in-memory mock so callers can be exercised without a live Fabric network.
