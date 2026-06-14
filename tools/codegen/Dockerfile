# Device-agnostic codegen + Go toolchain for Saksi.
#
# Pins Go, protoc, and protoc-gen-go so protobuf generation and Go builds are
# reproducible on any machine with Docker — no host Go/protoc install required.
# CI runs Go natively on GitHub runners; this image is for local development and
# for regenerating the committed protobuf Go types (ADR-0003).
FROM golang:1.23-bookworm

# protoc (the Protocol Buffers compiler).
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler make \
    && rm -rf /var/lib/apt/lists/*

# protoc-gen-go pinned to match the google.golang.org/protobuf runtime in go.mod.
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2

ENV PATH="/go/bin:${PATH}"
WORKDIR /work
