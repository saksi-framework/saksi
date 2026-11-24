#!/usr/bin/env bash
#
# users_test.sh — checks network.sh's Org1 cryptogen user count against a fake
# fabric-samples tree (no Docker, no Fabric binaries).
#
#   ./users_test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK="${SCRIPT_DIR}/network.sh"
bash -n "${NETWORK}"

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
F="${TMP}/test-network/organizations/cryptogen/crypto-config-org1.yaml"
mkdir -p "$(dirname "${F}")"
cat >"${F}" <<'YAML'
PeerOrgs:
  - Name: Org1
    Domain: org1.example.com
    EnableNodeOUs: true
    Template:
      Count: 1
      SANS:
        - localhost
    Users:
      Count: 1
YAML

fail() { echo "FAIL: $*" >&2; exit 1; }
run() { FABRIC_SAMPLES="${TMP}" "${NETWORK}" users >/dev/null; }

# 1. Default: three users; the peer Template count is untouched.
run
grep -A1 '^    Users:' "${F}" | grep -q 'Count: 3' || fail "Users.Count not 3"
grep -A1 '^    Template:' "${F}" | grep -q 'Count: 1' || fail "Template.Count changed"
grep -q 'Count: 1' "${F}.test-network-default" || fail "pristine file not backed up"

# 2. Idempotent, and an override is honoured.
run
SAKSI_ORG1_USERS=5 run
grep -A1 '^    Users:' "${F}" | grep -q 'Count: 5' || fail "SAKSI_ORG1_USERS=5 not applied"

# 3. Garbage is refused and leaves the file alone.
before="$(cat "${F}")"
if SAKSI_ORG1_USERS=x FABRIC_SAMPLES="${TMP}" "${NETWORK}" users >/dev/null 2>&1; then
	fail "a non-numeric SAKSI_ORG1_USERS was accepted"
fi
[ "$(cat "${F}")" = "${before}" ] || fail "refused value modified the file"

echo "ok: Org1 cryptogen user count, backup, override, refusal"
