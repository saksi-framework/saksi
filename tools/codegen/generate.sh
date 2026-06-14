#!/usr/bin/env bash
#
# Regenerates the Go protobuf types for saksi-protocol from the canonical
# wire.proto (ADR-0003). Runs INSIDE the codegen container (see Dockerfile);
# invoke it from the host via scripts/codegen.sh. Working directory is the repo
# root (/work in the container).
set -euo pipefail

cd packages/saksi-protocol

# Output base is the Go module dir; --go_opt=module strips the module path prefix
# from the proto's go_package, so the file lands at go/saksiprotocolv1/wire.pb.go.
protoc \
  -I proto \
  --go_out=go \
  --go_opt=module=github.com/saksi-framework/saksi/packages/saksi-protocol/go \
  proto/saksi/protocol/v1/wire.proto

echo "generated: packages/saksi-protocol/go/saksiprotocolv1/"
