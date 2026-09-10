#!/usr/bin/env bash
#
# tier.sh — reset the network to a clean ledger before a measurement tier.
#
#   ./tools/tier.sh <voters> <positions> [--dry-run]
#
# Tears the Fabric network down, brings it back up with a fresh channel, and
# redeploys the chaincode. Every tier therefore starts from an empty ledger, so
# a tier's ledger_bytes_delta and its commit latencies measure that tier rather
# than the accumulated state of the ones before it.
#
# The bring-up itself is tools/up.sh's, sourced rather than copied: a second
# copy of the preflight and deploy steps would drift from the one CI proves.
#
# The tier's arguments are used to report the ledger this tier projects
# (voters x positions x 12,000 bytes), which is the same number the console's
# own disk guard refuses on — so a tier that will not fit says so here, before
# the teardown, rather than after the network is already down.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DRY_RUN=0
ARGS=()
while [ $# -gt 0 ]; do
	case "$1" in
	--dry-run) DRY_RUN=1; shift ;;
	-h | --help)
		sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		ARGS+=("$1")
		shift
		;;
	esac
done

if [ "${#ARGS[@]}" -ne 2 ]; then
	echo "usage: $0 <voters> <positions> [--dry-run]" >&2
	exit 2
fi
VOTERS="${ARGS[0]}"
POSITIONS="${ARGS[1]}"

# Bytes per ballot record, matching LedgerBytesPerBallot in the console.
BYTES_PER_BALLOT=12000
PROJECTED=$((VOTERS * POSITIONS * BYTES_PER_BALLOT))

# shellcheck source=tools/up.sh
. "${ROOT}/tools/up.sh"

printf 'tier: %s voters x %s positions -> ~%s bytes of ledger projected\n' \
	"${VOTERS}" "${POSITIONS}" "${PROJECTED}"

if [ "${DRY_RUN}" = 1 ]; then
	echo "preflight"
	echo "install_fabric"
	echo "cmd_down                 # network.sh down"
	echo "bring_up_network         # network.sh all == up createChannel + deployCC"
	exit 0
fi

preflight
install_fabric
cmd_down          # network.sh down — discards the previous tier's ledger
bring_up_network  # network.sh all — up createChannel, then deployCC
ok "tier reset: empty ledger, chaincode deployed"
