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
#   ./network.sh up       # install configtx.yaml, start network + create channel
#   ./network.sh deploy   # package, install, approve, commit the chaincode
#   ./network.sh all      # up + deploy
#   ./network.sh down     # tear everything down
#   ./network.sh configtx # only install configtx.yaml (used by the tests)
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

# Single-org endorsement policy for dev: only Org1 must endorse, so the console
# can commit without wiring Org2. Override with SAKSI_CC_POLICY.
CC_POLICY="${SAKSI_CC_POLICY:-OR('Org1MSP.peer')}"

# Saksi declares the orderer's batching parameters (see configtx.yaml's header
# for the values and the measurements behind them). They only take effect if
# they are in the file the test-network reads when it generates the channel
# genesis block, so install ours there before creating the channel. Set
# SAKSI_CONFIGTX=default to restore the pristine test-network file instead,
# which is how an A/B run measures against stock Fabric.
SAKSI_CONFIGTX="${SAKSI_CONFIGTX:-saksi}"

# Marker line identifying our file, so a second run does not save it as the
# "pristine" backup and quietly make SAKSI_CONFIGTX=default a no-op.
CONFIGTX_MARKER="# Saksi's declared orderer configuration"

install_configtx() {
	local dst="${TEST_NETWORK}/configtx/configtx.yaml"
	local backup="${dst}.test-network-default"
	local src="${SCRIPT_DIR}/configtx.yaml"

	case "${SAKSI_CONFIGTX}" in
	saksi | default) ;;
	*)
		echo "SAKSI_CONFIGTX must be 'saksi' (default) or 'default', got '${SAKSI_CONFIGTX}'" >&2
		exit 1
		;;
	esac

	[ -f "${src}" ] || { echo "missing ${src}" >&2; exit 1; }
	if [ ! -f "${dst}" ]; then
		echo "test-network configtx.yaml not found at ${dst}" >&2
		exit 1
	fi

	if [ "${SAKSI_CONFIGTX}" = default ]; then
		if [ -f "${backup}" ]; then
			cp "${backup}" "${dst}"
			echo "configtx: test-network defaults restored (SAKSI_CONFIGTX=default)"
		elif grep -qF "${CONFIGTX_MARKER}" "${dst}"; then
			# Our file is installed and the pristine copy is gone: proceeding
			# would run an A/B "control" against the tuned parameters and
			# report it as the default. Refuse rather than lie.
			echo "no pristine backup at ${backup}; cannot restore test-network defaults" >&2
			echo "reinstall fabric-samples (or restore that file) and retry" >&2
			exit 1
		else
			echo "configtx: test-network defaults already in place (SAKSI_CONFIGTX=default)"
		fi
		return
	fi

	# Back up the pristine file once, and never over a copy of our own. Only
	# the install path needs it: the default path above restores from it, or
	# finds the pristine file already in place.
	if [ ! -f "${backup}" ] && ! grep -qF "${CONFIGTX_MARKER}" "${dst}"; then
		cp "${dst}" "${backup}"
	fi

	cp "${src}" "${dst}"
	echo "configtx: saksi orderer parameters installed (BatchTimeout 2s, MaxMessageCount 50, PreferredMaxBytes 2 MB, SnapshotIntervalSize 256 MB)"
}

cmd_up() {
	require_test_network up
	install_configtx
	cd "${TEST_NETWORK}"
	# cryptogen (no -ca): avoids needing fabric-ca-client on PATH for dev.
	./network.sh up createChannel -c "${CHANNEL}"
}

cmd_deploy() {
	require_test_network deploy
	cd "${TEST_NETWORK}"
	./network.sh deployCC -c "${CHANNEL}" -ccn "${CC_NAME}" -ccp "${CHAINCODE_PATH}" -ccl go \
		-ccep "${CC_POLICY}"
}

cmd_down() {
	require_test_network down
	cd "${TEST_NETWORK}"
	./network.sh down
}

case "${1:-}" in
up) cmd_up ;;
configtx)
	require_test_network configtx
	install_configtx
	;;
deploy) cmd_deploy ;;
all)
	cmd_up
	cmd_deploy
	;;
down) cmd_down ;;
*)
	echo "usage: $0 {up|deploy|all|down|configtx}" >&2
	exit 1
	;;
esac
