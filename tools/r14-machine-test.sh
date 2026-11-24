#!/usr/bin/env bash
#
# r14-machine-test.sh — the R14 precinct-machine test on a live network.
#
# Two precinct elections, r14-<stamp>-p01 (A, bound to User1) and
# r14-<stamp>-p02 (B, bound to User2), then five cases:
#
#   1  User1 (A's registered machine) submits A's ballots           accepted
#   2  User3 (valid Org1 client, registered nowhere) submits an A
#      ballot                                                       refused, gate caller
#   3  User2 (B's machine) submits an A ballot                      refused, gate caller
#   4  User1 calls CreateElection, RegisterPrecinctMachine and
#      CloseElection (B1 retest)                                    refused, gate admin
#      Admin re-registers or swaps A's machine                      refused, machine-duplicate
#                                                                   / machine-window
#   5  Admin closes A, the trustees' partial decryptions and the
#      tally go on chain, the auditor runs over the ledger dump     E = 0, ledger ballots =
#                                                                   case 1 accepted
#
# The ballot offered in cases 2 and 3 is A's last generated ballot; User1
# submits it afterwards and it is accepted, so the refusals are about the
# caller, not the ballot. Every call, its identity (user, role, certificate
# fingerprint), the expected and observed outcome, the chaincode's error and
# gate, and PASS/FAIL go into <out>/r14-evidence.json; every transaction is in
# <out>/calls.ndjson; the generator and auditor output sit beside them. The
# commit and the binaries' SHA-256 digests are recorded. Exit status is 0 only
# when every case passes.
#
# Usage:
#   tools/r14-machine-test.sh [--out DIR] [--voters N] [--dry-run] [saksi-r14-test flags...]
#
#   --out DIR      output directory (default ~/.saksi/r14/r14-<UTC stamp>)
#   --voters N     precinct A's voters (default 20; Task 4 also runs 1000)
#   --dry-run      print the plan of calls and identities; contact nothing
#   other flags go to saksi-r14-test as is: --positions 3 --candidates 4
#   --trustees 5 --threshold 3 --concurrency 32 --stamp S --distribution D
#
# Environment:
#   FABRIC_SAMPLES     fabric-samples checkout (default: beside the repo, as network.sh)
#   SAKSI_DEMO_BIN     saksi-demo binary (default target/release/saksi-demo, built if missing)
#   SAKSI_CHANNEL      channel (default saksi)
#   SAKSI_CC_NAME      chaincode name (default saksi-bulletin)
#
# ---------------------------------------------------------------------------
# Bringing the network up at this branch (Task 4, unattended)
#
# The test needs a FRESH test network: Org1 must issue User1, User2 and User3
# (network.sh sets the cryptogen count from SAKSI_ORG1_USERS, default 3, but
# only a fresh `up` regenerates the crypto), and the deployed chaincode must
# be this branch's (admin gate, RegisterPrecinctMachine, caller gate).
#
# WARNING: do NOT run `network.sh down` on a machine that holds any other
# Fabric ledger. fabric-samples' `down` force-removes EVERY container labelled
# service=hyperledger-fabric (any compose project), runs `compose down
# --volumes` under the default project name `compose` (deleting any
# compose_orderer.example.com / compose_peer0.* ledger volumes), and deletes
# the shared fabric-samples crypto (organizations/peerOrganizations,
# ordererOrganizations). If COMPOSE_PROJECT_NAME is exported, it deletes that
# project's volumes instead. Use a project of its own and bring it up by hand.
#
# The recipe Task 4 used on the Mac (fabric-samples beside the repo, Docker
# running, a space-free checkout of this branch):
#
#   # 0. stop anything holding the Fabric ports (the live demo kit needs the
#   #    user's go); back up the shared crypto first:
#   cp -R "$FABRIC_SAMPLES"/test-network/organizations <backup>/organizations
#   # 1. remove only STOPPED containers whose fixed names collide
#   #    (orderer.example.com, peer0.org1/org2.example.com) -- never `rm -v`,
#   #    never `docker volume rm/prune` or `docker system prune`:
#   docker rm <ids>
#   # 2. move the old crypto and channel artifacts aside so `up` regenerates them:
#   mv "$FABRIC_SAMPLES"/test-network/organizations/{peer,orderer}Organizations <aside>/
#   mv "$FABRIC_SAMPLES"/test-network/channel-artifacts/* <aside>/
#   # 3. bring up under a project of its own (keep it set for every later command):
#   export COMPOSE_PROJECT_NAME=r14 PATH="$FABRIC_SAMPLES/bin:$PATH"
#   cd <repo>; N=packages/saksi-bulletin/network/network.sh
#   SAKSI_ORG1_USERS=3 "$N" up                 # configtx + Org1 users, network, channel 'saksi'
#   docker pull hyperledger/fabric-ccenv:2.5   # chaincode builder images, if missing
#   docker pull hyperledger/fabric-baseos:2.5
#   "$N" deploy                                # this branch's chaincode, policy OR('Org1MSP.peer')
#   ls "$FABRIC_SAMPLES"/test-network/organizations/peerOrganizations/org1.example.com/users
#   #   -> Admin@ User1@ User2@ User3@ org1.example.com
#   cargo build --release -p saksi-demo        # if target/release/saksi-demo is stale
#   tools/r14-machine-test.sh --dry-run        # all four fingerprints resolve
#   tools/r14-machine-test.sh --out <dir>                    # 20 voters x 3 x 4, 3-of-5
#   tools/r14-machine-test.sh --out <dir> --voters 1000      # the 1,000-voter run
#   # 4. when finished: `docker compose -p r14 ... down` WITHOUT --volumes, or
#   #    `docker rm -f` the three r14 containers; then the r14_* volumes are
#   #    this run's alone. Restore the backed-up crypto before restarting any
#   #    other network that used it.
#
# network.sh's default FABRIC_SAMPLES is <repo>/../fabric-samples
# (~/dev/fabric-samples for ~/dev/saksi-r14). On the Mac, if saksi-demo fails
# to load libllhttp, point DYLD_LIBRARY_PATH at a directory holding
# libllhttp.9.3.dylib (Task 2's offline run used a scratchpad symlink).
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAMPAIGN="${ROOT}/packages/saksi-campaign"
FABRIC_SAMPLES="${FABRIC_SAMPLES:-$(cd "${ROOT}/.." && pwd)/fabric-samples}"
ORG_DIR="${FABRIC_SAMPLES}/test-network/organizations/peerOrganizations/org1.example.com"
CHANNEL="${SAKSI_CHANNEL:-saksi}"
CC_NAME="${SAKSI_CC_NAME:-saksi-bulletin}"
DEMO_BIN="${SAKSI_DEMO_BIN:-${ROOT}/target/release/saksi-demo}"

die() { printf 'r14-machine-test: %s\n' "$*" >&2; exit 2; }

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
[ -n "${OUT}" ] || OUT="${HOME}/.saksi/r14/r14-${STAMP}"

COMMIT="$(git -C "${ROOT}" rev-parse HEAD)"
if [ -n "$(git -C "${ROOT}" status --porcelain --untracked-files=no)" ]; then
	COMMIT="${COMMIT}-dirty"
fi

# The harness binary is kept with the evidence it produced (its digest is in
# r14-evidence.json). A dry run writes nothing into --out.
if [ "${DRY}" -eq 1 ]; then
	BIN_DIR="$(mktemp -d)"
	trap 'rm -rf "${BIN_DIR}"' EXIT
else
	BIN_DIR="${OUT}/bin"
fi
mkdir -p "${BIN_DIR}"
HARNESS="${BIN_DIR}/saksi-r14-test"
(cd "${CAMPAIGN}" && go build -o "${HARNESS}" ./cmd/saksi-r14-test) || die "build saksi-r14-test failed"

if [ "${DRY}" -eq 0 ] && [ ! -x "${DEMO_BIN}" ]; then
	echo "building saksi-demo (cargo build --release -p saksi-demo)"
	(cd "${ROOT}" && cargo build --release -p saksi-demo) || die "build saksi-demo failed"
fi

# The installed package id, best effort, for the evidence: which chaincode
# build the peer is running. Needs the peer CLI from fabric-samples/bin.
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
