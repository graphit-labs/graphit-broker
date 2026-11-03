#!/bin/sh
set -eu

# External, loopback-only validation tools; never shipped with the Broker.
: "${GOBIN:?Set GOBIN to an absolute test-tool directory}"
mkdir -p "$GOBIN"
export GOTOOLCHAIN=local
go install github.com/minio/minio@v0.0.0-20251015172955-9e49d5e7a648
go install github.com/minio/mc@v0.0.0-20250313080218-cf909e1063a9
