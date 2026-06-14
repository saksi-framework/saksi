#!/usr/bin/env bash
#
# saksi-demo — a high-level menu that drives the whole Saksi demo: bring the
# Fabric network up, deploy the chaincode, generate a valid election bundle,
# run the full election cycle against the live bulletin board, and audit it.
#
# It glues together the existing pieces:
#   - packages/saksi-bulletin/network/network.sh   (network up/deploy/down)
#   - cargo run -p saksi-demo -- gen|audit          (bundle generator + auditor)
#   - go run ./cmd/saksi-console                     (live lifecycle driver)
#
# Run from a space-free path on Linux/WSL with Docker running and the Fabric
# binaries available (see packages/saksi-bulletin/network/README.md).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK="${ROOT}/packages/saksi-bulletin/network"
SDK="${ROOT}/packages/saksi-bulletin/client-sdk"

CHANNEL="${SAKSI_CHANNEL:-saksi}"
CC_NAME="${SAKSI_CC_NAME:-saksi-bulletin}"
BUNDLE="${SAKSI_BUNDLE:-/tmp/saksi-bundle.json}"
FABRIC_SAMPLES="${FABRIC_SAMPLES:-$(cd "${ROOT}/.." && pwd)/fabric-samples}"
ORG_DIR="${FABRIC_SAMPLES}/test-network/organizations/peerOrganizations/org1.example.com"

export FABRIC_SAMPLES
export PATH="${FABRIC_SAMPLES}/bin:${PATH}"

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
err() { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

console_args() {
	local msp="${ORG_DIR}/users/User1@org1.example.com/msp"
	if [ ! -d "${msp}" ]; then
		err "Org1 user material not found at ${msp}. Bring the network up first."
		return 1
	fi
	printf '%s\0' \
		--peer-endpoint localhost:7051 \
		--gateway-peer peer0.org1.example.com \
		--tls-cert "${ORG_DIR}/peers/peer0.org1.example.com/tls/ca.crt" \
		--cert "$(find "${msp}/signcerts" -type f | head -n1)" \
		--key "$(find "${msp}/keystore" -type f | head -n1)" \
		--msp-id Org1MSP --channel "${CHANNEL}" --chaincode "${CC_NAME}" \
		--bundle "${BUNDLE}"
}

run_console() {
	# Passes extra args ($@, e.g. --auto) plus the connection config.
	local args=()
	while IFS= read -r -d '' a; do args+=("$a"); done < <(console_args)
	(cd "${SDK}" && go run ./cmd/saksi-console "${args[@]}" "$@")
}

network_up()     { say "Network up + create channel '${CHANNEL}'"; "${NETWORK}/network.sh" up; }
network_deploy() { say "Deploy chaincode '${CC_NAME}'";            "${NETWORK}/network.sh" deploy; }
network_down()   { say "Network down";                            "${NETWORK}/network.sh" down; }

gen_bundle() {
	say "Generate election bundle -> ${BUNDLE}"
	(cd "${ROOT}" && cargo run -q -p saksi-demo -- gen "${BUNDLE}")
}

audit_bundle() {
	say "Audit election bundle"
	(cd "${ROOT}" && cargo run -q -p saksi-demo -- audit "${BUNDLE}")
}

run_tests() {
	say "cargo test --workspace"
	(cd "${ROOT}" && cargo test --workspace)
	say "go test (chaincode + client-sdk)"
	(cd "${ROOT}/packages/saksi-bulletin/chaincode" && go test ./...)
	(cd "${SDK}" && go test ./...)
}

full_demo() {
	network_up
	network_deploy
	gen_bundle
	say "Run FULL election cycle against the live network"
	run_console --auto
	audit_bundle
	say "Demo complete."
}

menu() {
	while true; do
		cat <<MENU

saksi demo console
──────────────────
 1) Network: up + deploy
 2) Generate election bundle
 3) Run FULL election cycle (live)
 4) Open interactive console
 5) Audit the bundle (off-chain)
 6) Run tests (cargo + go)
 7) Network: down
 9) Everything (up → deploy → gen → cycle → audit)
 0) Exit
MENU
		read -r -p "select> " choice
		case "${choice}" in
		1) network_up && network_deploy ;;
		2) gen_bundle ;;
		3) [ -f "${BUNDLE}" ] || gen_bundle; run_console --auto ;;
		4) [ -f "${BUNDLE}" ] || gen_bundle; run_console ;;
		5) audit_bundle ;;
		6) run_tests ;;
		7) network_down ;;
		9) full_demo ;;
		0 | "") return 0 ;;
		*) err "unknown option: ${choice}" ;;
		esac
	done
}

# Non-interactive entry points: `saksi-demo.sh all` runs the whole demo.
case "${1:-menu}" in
menu) menu ;;
all) full_demo ;;
up) network_up && network_deploy ;;
gen) gen_bundle ;;
cycle) run_console --auto ;;
audit) audit_bundle ;;
down) network_down ;;
*)
	err "usage: $0 {menu|all|up|gen|cycle|audit|down}"
	exit 1
	;;
esac
