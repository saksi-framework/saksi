#!/usr/bin/env bash
#
# configtx_test.sh — checks network.sh's configtx installation against a fake
# fabric-samples tree. No Docker, no Fabric binaries, no network: it only
# exercises the copy/backup/opt-out branches, which is the part that can
# silently make a measurement run non-reproducible.
#
#   ./configtx_test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK="${SCRIPT_DIR}/network.sh"

bash -n "${NETWORK}"

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

DST="${TMP}/test-network/configtx/configtx.yaml"
BACKUP="${DST}.test-network-default"
mkdir -p "$(dirname "${DST}")"
printf 'PRISTINE test-network configtx\n' >"${DST}"

run() { FABRIC_SAMPLES="${TMP}" "${NETWORK}" configtx >/dev/null; }

fail() { echo "FAIL: $*" >&2; exit 1; }

# 1. First install: ours lands, the pristine file is backed up.
run
grep -q 'MaxMessageCount: 50' "${DST}" || fail "adopted parameters not installed"
grep -q '^PRISTINE' "${BACKUP}" || fail "pristine file not backed up"

# 2. Idempotent: a second install must not overwrite the backup with our file.
run
grep -q '^PRISTINE' "${BACKUP}" || fail "backup clobbered on reinstall"
grep -q 'MaxMessageCount: 50' "${DST}" || fail "reinstall did not keep our file"

# 3. Opt-out restores the pristine file for A/B runs.
SAKSI_CONFIGTX=default FABRIC_SAMPLES="${TMP}" "${NETWORK}" configtx >/dev/null
grep -q '^PRISTINE' "${DST}" || fail "SAKSI_CONFIGTX=default did not restore defaults"

# 4. Back to ours, and a typo is refused rather than silently treated as one.
run
grep -q 'MaxMessageCount: 50' "${DST}" || fail "reinstall after opt-out failed"
if SAKSI_CONFIGTX=deafult FABRIC_SAMPLES="${TMP}" "${NETWORK}" configtx >/dev/null 2>&1; then
	fail "an unknown SAKSI_CONFIGTX value was accepted"
fi

echo "ok: configtx install, backup, idempotency, opt-out"
