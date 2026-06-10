#!/usr/bin/env bash
#
# Drives the Hyperledger Fabric test-network (from fabric-samples) to run the
# Saksi bulletin board: brings up a minimal one-org network, creates the
# `saksi` channel, and deploys the saksi-bulletin chaincode.
#
# This is a thin wrapper. The heavy lifting (peers, orderer, CA, channel,
# chaincode lifecycle) is the standard Fabric test-network; we only pass Saksi's
# channel name, chaincode name, and chaincode path.
#
# Requirements: Docker (running), and a fabric-samples checkout with Fabric
# binaries on PATH. See README.md.
#
# Usage:
#   ./network.sh up       # start network + create the saksi channel
#   ./network.sh deploy   # package, install, approve, commit the chaincode
#   ./network.sh all      # up + deploy
#   ./network.sh down     # tear everything down
set -euo pipefail

CHANNEL="${SAKSI_CHANNEL:-saksi}"
CC_NAME="${SAKSI_CC_NAME:-saksi-bulletin}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAINCODE_PATH="$(cd "${SCRIPT_DIR}/../chaincode" && pwd)"

# fabric-samples checkout. Defaults to a sibling of the saksi repository; override
# with FABRIC_SAMPLES=/path/to/fabric-samples.
FABRIC_SAMPLES="${FABRIC_SAMPLES:-$(cd "${SCRIPT_DIR}/../../../.." && pwd)/fabric-samples}"
TEST_NETWORK="${FABRIC_SAMPLES}/test-network"

require_test_network() {
	if [ ! -d "${TEST_NETWORK}" ]; then
		cat >&2 <<EOF
fabric-samples test-network not found at:
  ${TEST_NETWORK}

Install Fabric samples, Docker images, and binaries first:
  curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh | bash -s -- docker samples binary

Then re-run, or point FABRIC_SAMPLES at your checkout:
  FABRIC_SAMPLES=/path/to/fabric-samples $0 ${1:-up}
EOF
		exit 1
	fi
}

cmd_up() {
	require_test_network up
	cd "${TEST_NETWORK}"
	./network.sh up createChannel -c "${CHANNEL}" -ca
}

cmd_deploy() {
	require_test_network deploy
	cd "${TEST_NETWORK}"
	./network.sh deployCC -c "${CHANNEL}" -ccn "${CC_NAME}" -ccp "${CHAINCODE_PATH}" -ccl go
}

cmd_down() {
	require_test_network down
	cd "${TEST_NETWORK}"
	./network.sh down
}

case "${1:-}" in
up) cmd_up ;;
deploy) cmd_deploy ;;
all)
	cmd_up
	cmd_deploy
	;;
down) cmd_down ;;
*)
	echo "usage: $0 {up|deploy|all|down}" >&2
	exit 1
	;;
esac
