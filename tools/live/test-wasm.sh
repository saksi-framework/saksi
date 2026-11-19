#!/usr/bin/env bash
# Runs the phone's WebAssembly under node: the voter's issuance, ballot and
# Benaloh steps execute in wasm (packages/saksi-wasm/pkg, the package the app
# imports) against the native `saksi-demo live` CLI as issuer and trustees,
# then the wasm-built ballots go through aggregate, partials, combine, tally
# signatures and verify-live with CLI-built ballots alongside, and finally
# through the chaincode (TestWasmBuiltBallotsPassTheChaincode) from the
# fixture this run wrote.
#
#   tools/live/test-wasm.sh                  # build, test, chaincode over a temp fixture
#   tools/live/test-wasm.sh --write-fixture  # same, and refresh the committed fixture
#   tools/live/test-wasm.sh --no-build       # reuse an existing pkg/ build
#
# The committed fixture packages/saksi-protocol/test-vectors/live-v1/wasm-election.json
# lets `go test ./...` check wasm-built ballots without node; regenerate it
# with --write-fixture after any change to the live wire format.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -d /opt/homebrew/opt/rustup/bin ]; then
  export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
fi
write_fixture=0
build=1
for arg in "$@"; do
  case "$arg" in
    --write-fixture) write_fixture=1 ;;
    --no-build) build=0 ;;
    *) echo "unknown argument $arg" >&2; exit 2 ;;
  esac
done

# Node 24. Homebrew's node is broken on the Mac, so prefer mise's.
if [ -n "${NODE:-}" ]; then
  node=("$NODE")
elif command -v mise >/dev/null 2>&1 && mise exec node@24 -- node --version >/dev/null 2>&1; then
  node=(mise exec node@24 -- node)
else
  node=(node)
fi
echo "node: $("${node[@]}" --version)"

if [ "$build" = 1 ]; then
  "$repo/tools/live/build-wasm.sh"
fi
(cd "$repo" && cargo build -p saksi-demo 2>&1 | tail -1)

work="$(mktemp -d "${TMPDIR:-/tmp}/saksi-wasm-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
committed="$repo/packages/saksi-protocol/test-vectors/live-v1/wasm-election.json"
if [ "$write_fixture" = 1 ]; then fixture="$committed"; else fixture="$work/wasm-election.json"; fi

SAKSI_DEMO="$repo/target/debug/saksi-demo" \
SAKSI_WASM_PKG="$repo/packages/saksi-wasm/pkg" \
SAKSI_WASM_PKG_NODE="$repo/packages/saksi-wasm/pkg-node" \
SAKSI_WASM_FIXTURE="$fixture" \
SAKSI_WASM_TIMINGS="${SAKSI_WASM_TIMINGS:-$work/timings.json}" \
  "${node[@]}" "$repo/packages/saksi-wasm/tests/voter-flow.mjs"

echo
echo "chaincode over the wasm-built ballots:"
# (The test file is live_wasm_ballots_test.go: a name ending in _wasm_test.go
# would be built for GOARCH=wasm only.)
go_out="$(cd "$repo/packages/saksi-bulletin/chaincode" && \
  SAKSI_WASM_FIXTURE="$fixture" go test -count=1 -run '^TestWasmBuiltBallotsPassTheChaincode$' -v . 2>&1)" || {
  echo "$go_out"; exit 1; }
echo "$go_out" | tail -3
if ! grep -q -- '--- PASS: TestWasmBuiltBallotsPassTheChaincode' <<<"$go_out"; then
  echo "TestWasmBuiltBallotsPassTheChaincode did not run" >&2
  exit 1
fi
if [ "$write_fixture" = 1 ]; then
  echo "regenerated packages/saksi-protocol/test-vectors/live-v1/wasm-election.json"
fi
