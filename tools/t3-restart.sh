#!/usr/bin/env bash
#
# t3-restart.sh — the T3 fault injection: restart the peer under load, then ask
# the console what the chain actually kept.
#
#   ./tools/t3-restart.sh <run-id> [--base-url URL] [--peer NAME]
#                         [--downtime SECONDS] [--dry-run]
#
# Stops peer0.org1.example.com mid-run, leaves it down for 30 s, brings it back,
# and then POSTs /api/runs/<run-id>/verify-only. That endpoint reconciles the
# chaincode's committed-ballot count against the run's own committed set, walks
# the chain over the blocks the run's receipts name, and stamps the run
# interrupted.
#
# It deliberately does NOT resume: a resume fills the gap, and T3's question is
# what the gap was.
set -euo pipefail

BASE_URL="${SAKSI_BASE_URL:-http://127.0.0.1:8090}"
PEER="${SAKSI_PEER_CONTAINER:-peer0.org1.example.com}"
DOWNTIME=30
DRY_RUN=0
RUN_ID=""

while [ $# -gt 0 ]; do
	case "$1" in
	--base-url) BASE_URL="$2"; shift 2 ;;
	--peer) PEER="$2"; shift 2 ;;
	--downtime) DOWNTIME="$2"; shift 2 ;;
	--dry-run) DRY_RUN=1; shift ;;
	-h | --help)
		sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	-*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	*)
		RUN_ID="$1"
		shift
		;;
	esac
done

if [ -z "${RUN_ID}" ]; then
	echo "usage: $0 <run-id> [--base-url URL] [--peer NAME] [--downtime SECONDS] [--dry-run]" >&2
	exit 2
fi

run() {
	if [ "${DRY_RUN}" = 1 ]; then
		printf '%q ' "$@"
		printf '\n'
	else
		"$@"
	fi
}

run docker stop "${PEER}"
run sleep "${DOWNTIME}"
run docker start "${PEER}"
run curl -fsS -X POST "${BASE_URL}/api/runs/${RUN_ID}/verify-only"
