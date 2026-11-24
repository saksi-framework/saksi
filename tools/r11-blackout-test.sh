#!/usr/bin/env bash
#
# r11-blackout-test.sh — the R11 whole-network blackout and recovery test.
#
# One on-chain election runs through the console executor's own lifecycle.
# When --blackout-at of its ballot records have committed, the orderer, both
# peers and the chaincode containers are SIGKILLed in one `docker kill` while
# ballots are in flight, and the ballot window stops dispatching. After
# --downtime the orderer and the peers are started again (the peers relaunch
# their chaincode containers; any they do not is started and recorded), and
# the test waits for the first successful query. Then:
#
#   - every record is classified C (commit status valid), U (submit or commit
#     status error) or N (never sent), and every C record must still be on the
#     ledger, at a height no lower than before the blackout;
#   - resubmitting one C record is refused by the nullifier gate;
#   - the executor's journal-based resume (ListNullifiers ∩ the run's
#     nullifiers) submits only what the chain lacks, then closes;
#   - after the partial decryptions and the tally: committed count = records,
#     no nullifier twice, E = 0 on every contest over the ledger dump.
#
# Every check, with its expected and observed value and PASS/FAIL, goes into
# <out>/r11-evidence.json; every transaction is in <out>/calls.ndjson, the
# killed containers' docker events in <out>/docker-events.ndjson, the run
# folder (journal, receipts, ledger dump, correctness.csv) under <out>/runs/.
# The commit and the binaries' SHA-256 digests are recorded. Exit status is 0
# only when every check passes.
#
# Usage:
#   tools/r11-blackout-test.sh [--out DIR] [--voters N] [--blackout-at F]
#                              [--downtime D] [--dry-run] [saksi-r11-test flags...]
#
#   --out DIR          output directory (default ~/.saksi/r11/r11-<UTC stamp>)
#   --voters N         voters (default 20; the main run uses 1000)
#   --blackout-at F    fraction of records committed at the kill (default 0.4)
#   --downtime D       how long the network stays down (default 30s)
#   --dry-run          print the plan and the checks; contact nothing
#   other flags go to saksi-r11-test as is: --positions 3 --candidates 4
#   --trustees 5 --threshold 3 --concurrency 32 --compose-project r14
#   --ready-timeout 5m --chaincode-grace 1m --stamp S --distribution D
#   --stop-window with-kill|after-kill (default with-kill: the window stops
#   dispatching at the instant of the kill, as when the console goes down
#   with the network; after-kill keeps dispatching into the dead network
#   until docker kill returns, a network-only outage under a console that
#   keeps running: every remaining record is sent and fails and the window
#   ends with drops). Either way the console's own resume is the only
#   recovery; a refusal fails the run (there is no harness fallback).
#
# Environment:
#   FABRIC_SAMPLES     fabric-samples checkout (default: beside the repo, as network.sh)
#   SAKSI_DEMO_BIN     saksi-demo binary (default target/release/saksi-demo, built if missing)
#   SAKSI_CHANNEL      channel (default saksi)
#   SAKSI_CC_NAME      chaincode name (default saksi-bulletin)
#   COMPOSE_PROJECT_NAME  compose project of the running network (default r14)
#
# The network must already be up (see tools/r14-machine-test.sh for a safe
# bring-up under a compose project of its own). This script never brings a
# network up or down. It also refuses unless every chaincode container is
# on a Docker network of the project's peers. The only docker calls it makes are: ps, inspect,
# logs (the orderer's, for its Raft leader after the restart),
# events, `kill` of exactly orderer.example.com, peer0.org1.example.com,
# peer0.org2.example.com and the running dev-peer0.org{1,2}.example.com-
# <chaincode>_* containers, and `start` of those same containers. It refuses
# to kill anything when the orderer or a peer is not labelled with the
# compose project. Never `network.sh down`, `docker rm -v`, or any volume or
# system prune on a machine holding other ledgers.
#
# Stated limit: the containers are killed, the Docker VM and the host stay
# up, so the host page cache survives; this is a crash fault of every
# container, not a host power loss.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAMPAIGN="${ROOT}/packages/saksi-campaign"
FABRIC_SAMPLES="${FABRIC_SAMPLES:-$(cd "${ROOT}/.." && pwd)/fabric-samples}"
ORG_DIR="${FABRIC_SAMPLES}/test-network/organizations/peerOrganizations/org1.example.com"
CHANNEL="${SAKSI_CHANNEL:-saksi}"
CC_NAME="${SAKSI_CC_NAME:-saksi-bulletin}"
PROJECT="${COMPOSE_PROJECT_NAME:-r14}"
DEMO_BIN="${SAKSI_DEMO_BIN:-${ROOT}/target/release/saksi-demo}"

die() { printf 'r11-blackout-test: %s\n' "$*" >&2; exit 2; }

STAMP="$(date -u +%Y%m%dt%H%M%S)"
OUT=""
DRY=0
PASS=()
while [ $# -gt 0 ]; do
	case "$1" in
	--out) [ $# -ge 2 ] || die "--out needs a directory"; OUT="$2"; shift 2 ;;
	--dry-run) DRY=1; shift ;;
	--stamp) [ $# -ge 2 ] || die "--stamp needs a value"; STAMP="$2"; shift 2 ;;
	-h | --help) sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
	*) PASS+=("$1"); shift ;;
	esac
done
[ -n "${OUT}" ] || OUT="${HOME}/.saksi/r11/r11-${STAMP}"

COMMIT="$(git -C "${ROOT}" rev-parse HEAD)"
if [ -n "$(git -C "${ROOT}" status --porcelain --untracked-files=no)" ]; then
	COMMIT="${COMMIT}-dirty"
fi

# The harness binary is kept with the evidence it produced (its digest is in
# r11-evidence.json). A dry run writes nothing into --out.
if [ "${DRY}" -eq 1 ]; then
	BIN_DIR="$(mktemp -d)"
	trap 'rm -rf "${BIN_DIR}"' EXIT
else
	BIN_DIR="${OUT}/bin"
fi
mkdir -p "${BIN_DIR}"
HARNESS="${BIN_DIR}/saksi-r11-test"
(cd "${CAMPAIGN}" && go build -o "${HARNESS}" ./cmd/saksi-r11-test) || die "build saksi-r11-test failed"

if [ "${DRY}" -eq 0 ] && [ ! -x "${DEMO_BIN}" ]; then
	echo "building saksi-demo (cargo build --release -p saksi-demo)"
	(cd "${ROOT}" && cargo build --release -p saksi-demo) || die "build saksi-demo failed"
fi

# The installed package id, best effort, for the evidence.
CC_PACKAGE_ID=""
if [ "${DRY}" -eq 0 ] && [ -x "${FABRIC_SAMPLES}/bin/peer" ]; then
	CC_PACKAGE_ID="$(
		FABRIC_CFG_PATH="${FABRIC_SAMPLES}/config" \
			CORE_PEER_TLS_ENABLED=true \
			CORE_PEER_LOCALMSPID=Org1MSP \
			CORE_PEER_TLS_ROOTCERT_FILE="${ORG_DIR}/peers/peer0.org1.example.com/tls/ca.crt" \
			CORE_PEER_MSPCONFIGPATH="${ORG_DIR}/users/Admin@org1.example.com/msp" \
			CORE_PEER_ADDRESS=localhost:7051 \
			"${FABRIC_SAMPLES}/bin/peer" lifecycle chaincode queryinstalled 2>/dev/null |
			sed -n "s/^Package ID: \(${CC_NAME}_[^,]*\),.*/\1/p" | tail -n1
	)" || CC_PACKAGE_ID=""
fi

ARGS=(
	--out "${OUT}"
	--stamp "${STAMP}"
	--demo "${DEMO_BIN}"
	--org-dir "${ORG_DIR}"
	--channel "${CHANNEL}"
	--chaincode "${CC_NAME}"
	--compose-project "${PROJECT}"
	--commit "${COMMIT}"
	--chaincode-package-id "${CC_PACKAGE_ID}"
)
if [ "${DRY}" -eq 1 ]; then
	ARGS+=(--dry-run)
fi

echo "commit ${COMMIT}; output ${OUT}"
if [ "${DRY}" -eq 1 ]; then
	"${HARNESS}" "${ARGS[@]}" "${PASS[@]+"${PASS[@]}"}"
	exit $?
fi
set +e
"${HARNESS}" "${ARGS[@]}" "${PASS[@]+"${PASS[@]}"}" 2>&1 | tee "${OUT}/harness.log"
STATUS=${PIPESTATUS[0]}
set -e
exit "${STATUS}"
