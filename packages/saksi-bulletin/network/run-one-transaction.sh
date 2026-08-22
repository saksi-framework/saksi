#!/usr/bin/env bash
#
# Runs a single end-to-end bulletin-board transaction against the running
# test-network: stands up the fixture election (CreateElection + DKG), submits
# one ballot and reads it back, using the Org1 user material the test-network
# generated.
#
# The ballot comes from the checked-in REAL bundle fixture
# (saksi-protocol/test-vectors/bundle-v1.json, generated once by
# `saksi-demo gen`): the chaincode verifies CDS proofs on-chain at endorsement
# (ADR-0007), so the wire-format golden vector (ballot-v1.hex, placeholder
# crypto) can never commit — a cryptographically real fixture is required.
#
# Prerequisites: ./network.sh all has succeeded, Go and jq are installed, and
# Docker is running. See README.md.
set -euo pipefail

CHANNEL="${SAKSI_CHANNEL:-saksi}"
CC_NAME="${SAKSI_CC_NAME:-saksi-bulletin}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FABRIC_SAMPLES="${FABRIC_SAMPLES:-$(cd "${SCRIPT_DIR}/../../../.." && pwd)/fabric-samples}"
ORG_DIR="${FABRIC_SAMPLES}/test-network/organizations/peerOrganizations/org1.example.com"
SDK_DIR="$(cd "${SCRIPT_DIR}/../client-sdk" && pwd)"

# Default bundle is the checked-in real fixture (1 voter, 2-of-3 trustees).
BUNDLE="${SAKSI_BUNDLE:-$(cd "${SCRIPT_DIR}/../../saksi-protocol/test-vectors" && pwd)/bundle-v1.json}"

if [ ! -d "${ORG_DIR}" ]; then
	echo "Org1 material not found at ${ORG_DIR}. Run ./network.sh all first." >&2
	exit 1
fi
command -v jq >/dev/null || { echo "jq is required (extracts the fixture ballot)." >&2; exit 1; }

USER_MSP="${ORG_DIR}/users/User1@org1.example.com/msp"
KEY_FILE="$(find "${USER_MSP}/keystore" -type f | head -n1)"
CERT_FILE="$(find "${USER_MSP}/signcerts" -type f | head -n1)"
TLS_CERT="${ORG_DIR}/peers/peer0.org1.example.com/tls/ca.crt"

CONN_ARGS=(
	--peer-endpoint localhost:7051
	--gateway-peer peer0.org1.example.com
	--tls-cert "${TLS_CERT}"
	--cert "${CERT_FILE}"
	--key "${KEY_FILE}"
	--msp-id Org1MSP
	--channel "${CHANNEL}"
	--chaincode "${CC_NAME}"
)

BALLOT_FILE="$(mktemp)"
trap 'rm -f "${BALLOT_FILE}"' EXIT
jq -r '.ballots[0]' "${BUNDLE}" > "${BALLOT_FILE}"

cd "${SDK_DIR}"
# Idempotence note: re-running against the same network re-submits the same
# nullifier and the chaincode rejects it (double-vote protection working as
# designed). Bring the network down/up (or point SAKSI_BUNDLE at a fresh
# `saksi-demo gen` bundle) to run again.
go run ./cmd/saksi-console --bundle "${BUNDLE}" --setup-only "${CONN_ARGS[@]}"
exec go run ./cmd/submit-ballot "${CONN_ARGS[@]}" --ballot "${BALLOT_FILE}"
