#!/usr/bin/env bash
#
# ladder.sh — run the validation ladder against a RUNNING console.
#
#   ./tools/ladder.sh [--base-url URL] [--runs DIR] [--dry-run]
#
# The ladder runs the same election at 1, 10, 100 and 1,000 voters (3 positions,
# 4 candidates, realistic) through the console's own HTTP API and requires each
# tier to pass the data-validation gate AND finish with E = 0 on every contest.
# Only then does it write <runs>/ladder.json pinning this build's commit.
#
# That file is what unlocks tiers above 1,000 voters: a large tier costs hours,
# and a build whose four cheap tiers were never shown to be correct is not worth
# spending them on. Re-run this after every change to the console or generator —
# the gate compares ladder.json's commit to the console's own git HEAD, so a new
# build closes the gate again by construction.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONSOLE_DIR="${ROOT}/packages/saksi-campaign"

BASE_URL="${SAKSI_BASE_URL:-http://127.0.0.1:8090}"
RUNS_DIR="${SAKSI_RUNS:-${HOME}/.saksi/campaign/runs}"
DRY_RUN=0

while [ $# -gt 0 ]; do
	case "$1" in
	--base-url) BASE_URL="$2"; shift 2 ;;
	--runs) RUNS_DIR="$2"; shift 2 ;;
	--dry-run) DRY_RUN=1; shift ;;
	-h | --help)
		sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	esac
done

run() {
	if [ "${DRY_RUN}" = 1 ]; then
		printf '%q ' "$@"
		printf '\n'
	else
		"$@"
	fi
}

CONSOLE_BIN="${ROOT}/target/saksi-campaign"
run bash -c "cd '${CONSOLE_DIR}' && go build -o '${CONSOLE_BIN}' ./cmd/saksi-campaign"
run "${CONSOLE_BIN}" --ladder --base-url "${BASE_URL}" --runs "${RUNS_DIR}"
