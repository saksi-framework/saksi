#!/usr/bin/env bash
#
# Regenerate the protobuf Go types in a pinned Docker container — works on any
# machine with Docker, no host Go/protoc needed. Run from anywhere:
#   ./scripts/codegen.sh
# Then commit the regenerated files. CI verifies they are up to date.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

docker build -t saksi-codegen "${ROOT}/tools/codegen"
docker run --rm -v "${ROOT}:/work" -w /work saksi-codegen bash tools/codegen/generate.sh
