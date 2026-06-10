#!/usr/bin/env bash
#
# Runs a single end-to-end bulletin-board transaction against the running
# test-network: submits one ballot and reads it back, using the Org1 admin user
# material the test-network generated.
#
# Prerequisites: ./network.sh all has succeeded, Go is installed, and Docker is
# running. See README.md.
set -euo pipefail

CHANNEL="${SAKSI_CHANNEL:-saksi}"
CC_NAME="${SAKSI_CC_NAME:-saksi-bulletin}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FABRIC_SAMPLES="${FABRIC_SAMPLES:-$(cd "${SCRIPT_DIR}/../../../.." && pwd)/fabric-samples}"
ORG_DIR="${FABRIC_SAMPLES}/test-network/organizations/peerOrganizations/org1.example.com"
SDK_DIR="$(cd "${SCRIPT_DIR}/../client-sdk" && pwd)"

# Default ballot is the protocol golden vector — a valid, well-formed ballot.
BALLOT="${SAKSI_BALLOT:-$(cd "${SCRIPT_DIR}/../../saksi-protocol/test-vectors" && pwd)/ballot-v1.hex}"

if [ ! -d "${ORG_DIR}" ]; then
	echo "Org1 material not found at ${ORG_DIR}. Run ./network.sh all first." >&2
	exit 1
fi

USER_MSP="${ORG_DIR}/users/User1@org1.example.com/msp"
KEY_FILE="$(find "${USER_MSP}/keystore" -type f | head -n1)"
CERT_FILE="$(find "${USER_MSP}/signcerts" -type f | head -n1)"
TLS_CERT="${ORG_DIR}/peers/peer0.org1.example.com/tls/ca.crt"

cd "${SDK_DIR}"
exec go run ./cmd/submit-ballot \
	--peer-endpoint localhost:7051 \
	--gateway-peer peer0.org1.example.com \
	--tls-cert "${TLS_CERT}" \
	--cert "${CERT_FILE}" \
	--key "${KEY_FILE}" \
	--msp-id Org1MSP \
	--channel "${CHANNEL}" \
	--chaincode "${CC_NAME}" \
	--ballot "${BALLOT}"
