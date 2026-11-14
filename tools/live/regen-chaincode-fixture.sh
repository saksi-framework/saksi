#!/usr/bin/env bash
# Regenerates packages/saksi-protocol/test-vectors/live-v1/election.json, the
# CLI-produced live election the chaincode test TestLiveArtifactsPassTheChaincode
# reads. Run it after any change to the live wire format; the Rust test
# committed_chaincode_fixture_is_current and the Go test both point here when
# the fixture is stale.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"
SAKSI_LIVE_FIXTURE_OUT="$repo/packages/saksi-protocol/test-vectors/live-v1/election.json" \
  cargo test -p saksi-demo --test live_cli full_pipeline_through_the_cli -- --exact
echo "regenerated packages/saksi-protocol/test-vectors/live-v1/election.json"
