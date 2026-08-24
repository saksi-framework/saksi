#!/usr/bin/env bash
#
# up.sh — bring up the whole stack with one command.
#
#   ./tools/up.sh          install Fabric if needed, start the network, deploy
#                          the chaincode, build both binaries, run the console
#                          wired to the ledger, and print the URL
#   ./tools/up.sh down     tear the network down
#   ./tools/up.sh status   report what is currently running
#
# Fabric itself runs as Docker containers; this drives the same
# packages/saksi-bulletin/network/network.sh path that CI proves green, so a
# local bring-up and the CI job cannot drift apart.
#
# The console is started in the foreground: Ctrl-C stops it and leaves the
# network up, so a restart is instant. Use `down` to stop the network too.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK_DIR="${ROOT}/packages/saksi-bulletin/network"
CHAINCODE_DIR="${ROOT}/packages/saksi-bulletin/chaincode"
CONSOLE_DIR="${ROOT}/packages/saksi-campaign"

CHANNEL="${SAKSI_CHANNEL:-saksi}"
ADDR="${SAKSI_ADDR:-127.0.0.1:8090}"
RUNS_DIR="${SAKSI_RUNS:-${HOME}/.saksi/campaign/runs}"
FABRIC_VERSION="${FABRIC_VERSION:-2.5.15}"
# Default beside the repo, matching network.sh's own default.
FABRIC_SAMPLES="${FABRIC_SAMPLES:-$(cd "${ROOT}/.." && pwd)/fabric-samples}"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
info() { printf '  \033[2m·\033[0m %s\n' "$*"; }
die()  { printf '\n  \033[31m✗ %s\033[0m\n\n' "$*" >&2; exit 1; }

# --- preflight --------------------------------------------------------------
# Every one of these has cost someone an hour at least once, so each failure
# says what to do rather than what went wrong.

preflight() {
	# fabric-samples resolves paths through shell scripts that do not quote
	# consistently; a space anywhere above the repo breaks the deploy in a way
	# whose error message points nowhere near the cause.
	case "${ROOT}" in
	*\ *) die "the repo path contains a space:
    ${ROOT}
  fabric-samples cannot handle it. Clone somewhere like ~/Code/saksi and retry." ;;
	esac

	command -v docker >/dev/null || die "docker not found. Install Docker Desktop and start it."
	docker info >/dev/null 2>&1 || die "the Docker daemon is not running. Start Docker Desktop and retry."
	command -v go >/dev/null || die "go not found. brew install go (or see docs/research-election-console-runbook.md)."
	command -v cargo >/dev/null || die "cargo not found. Install Rust: https://rustup.rs"
	command -v curl >/dev/null || die "curl not found."
}

# --- fabric -----------------------------------------------------------------

install_fabric() {
	if [ -d "${FABRIC_SAMPLES}/test-network" ] && [ -x "${FABRIC_SAMPLES}/bin/peer" ]; then
		ok "fabric-samples present ($(basename "${FABRIC_SAMPLES}"))"
		return
	fi
	info "installing Fabric ${FABRIC_VERSION} (binaries, docker images, samples)…"
	info "first run pulls ~1GB of images; later runs skip this entirely"
	local parent
	parent="$(dirname "${FABRIC_SAMPLES}")"
	mkdir -p "${parent}"
	(
		cd "${parent}"
		curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh \
			-o install-fabric.sh
		chmod +x install-fabric.sh
		./install-fabric.sh --fabric-version "${FABRIC_VERSION}" binary docker samples
	) || die "Fabric install failed. See https://hyperledger-fabric.readthedocs.io/en/latest/install.html"
	ok "Fabric ${FABRIC_VERSION} installed"
}

network_running() {
	docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^peer0.org1.example.com$'
}

bring_up_network() {
	if network_running; then
		ok "Fabric network already running (channel ${CHANNEL})"
		return
	fi
	# deployCC builds the chaincode inside a container with no network access,
	# so its dependencies must already be vendored.
	info "vendoring chaincode dependencies…"
	(cd "${CHAINCODE_DIR}" && go mod vendor) || die "go mod vendor failed in ${CHAINCODE_DIR}"

	info "starting the network and deploying the chaincode (a few minutes)…"
	export PATH="${FABRIC_SAMPLES}/bin:${PATH}"
	export FABRIC_SAMPLES
	(cd "${NETWORK_DIR}" && ./network.sh all) || die "network bring-up failed. Try: ${0} down, then retry."
	ok "network up, chaincode deployed on channel ${CHANNEL}"
}

# --- crypto material --------------------------------------------------------

# The console needs an identity to sign proposals with. These are the paths the
# test-network's cryptogen produces; CI reads exactly the same ones.
resolve_identity() {
	local org msp
	org="${FABRIC_SAMPLES}/test-network/organizations/peerOrganizations/org1.example.com"
	msp="${org}/users/User1@org1.example.com/msp"

	TLS_CERT="${org}/peers/peer0.org1.example.com/tls/ca.crt"
	CERT="$(find "${msp}/signcerts" -type f 2>/dev/null | head -n1 || true)"
	KEY="$(find "${msp}/keystore" -type f 2>/dev/null | head -n1 || true)"

	[ -f "${TLS_CERT}" ] || die "TLS cert missing: ${TLS_CERT}
  The network may be only partly up. Try: ${0} down, then rerun."
	[ -n "${CERT}" ] || die "no signing certificate under ${msp}/signcerts"
	[ -n "${KEY}" ] || die "no private key under ${msp}/keystore"
	ok "identity resolved (Org1MSP, User1)"
}

# --- binaries ---------------------------------------------------------------

build_binaries() {
	info "building saksi-demo (release)…"
	(cd "${ROOT}" && cargo build --release -p saksi-demo -q) || die "cargo build failed"
	DEMO_BIN="${ROOT}/target/release/saksi-demo"
	[ -x "${DEMO_BIN}" ] || DEMO_BIN="${DEMO_BIN}.exe"
	[ -x "${DEMO_BIN}" ] || die "saksi-demo binary not found after build"

	info "building the console…"
	(cd "${CONSOLE_DIR}" && go build -o "${ROOT}/target/saksi-campaign" ./cmd/saksi-campaign) \
		|| die "go build failed"
	CONSOLE_BIN="${ROOT}/target/saksi-campaign"
	ok "binaries built"
}

# --- commands ---------------------------------------------------------------

cmd_up() {
	bold "Saksi — bringing up the full stack"
	preflight
	install_fabric
	bring_up_network
	resolve_identity
	build_binaries
	mkdir -p "${RUNS_DIR}"

	echo
	bold "Console starting — on-chain mode ENABLED"
	printf '  wizard   http://%s/wizard\n' "${ADDR}"
	printf '  trail    http://%s/trail/\n' "${ADDR}"
	printf '  runs     %s\n' "${RUNS_DIR}"
	echo
	printf '  \033[2mCtrl-C stops the console and leaves the network up.\033[0m\n'
	printf '  \033[2mRun "%s down" to stop Fabric too.\033[0m\n\n' "${0}"

	exec "${CONSOLE_BIN}" serve \
		--addr "${ADDR}" \
		--demo "${DEMO_BIN}" \
		--runs "${RUNS_DIR}" \
		--fabric-channel "${CHANNEL}" \
		--fabric-tls-cert "${TLS_CERT}" \
		--fabric-cert "${CERT}" \
		--fabric-key "${KEY}"
}

cmd_down() {
	bold "Stopping the Fabric network"
	export PATH="${FABRIC_SAMPLES}/bin:${PATH}"
	export FABRIC_SAMPLES
	(cd "${NETWORK_DIR}" && ./network.sh down) || true
	ok "network down"
	info "run folders under ${RUNS_DIR} are kept"
}

cmd_status() {
	bold "Status"
	if docker info >/dev/null 2>&1; then ok "docker running"; else info "docker NOT running"; fi
	if network_running; then ok "Fabric network up"; else info "Fabric network down"; fi
	if curl -fsS "http://${ADDR}/api/capabilities" 2>/dev/null | grep -q '"fabric":true'; then
		ok "console up at http://${ADDR} with on-chain ENABLED"
	elif curl -fsS "http://${ADDR}/api/capabilities" >/dev/null 2>&1; then
		info "console up at http://${ADDR} but on-chain is DISABLED (no Fabric flags)"
	else
		info "console not responding on ${ADDR}"
	fi
}

case "${1:-up}" in
up) cmd_up ;;
down) cmd_down ;;
status) cmd_status ;;
*)
	echo "usage: $0 {up|down|status}" >&2
	exit 1
	;;
esac
