#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd -- "$root"

: "${SYNAPSE_VERSION:?set SYNAPSE_VERSION}"
: "${SYNAPSE_ARCH:=amd64}"
: "${SYNAPSE_LIBC_FLOOR:=2.34}"
: "${SYNAPSE_PACKAGE_TYPE:=rpm}"

rm -rf dist/worker
install -d -m 0755 dist/worker
for command in synapse-worker synapse-egress-broker synapse-sandbox-check synapse-dast-helper synapse-callgraph synapse-cspm; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$SYNAPSE_ARCH" go build -trimpath -o "dist/worker/$command" "./cmd/$command"
done

if [[ "$(go env GOOS)" != linux || "$(go env GOARCH)" != "$SYNAPSE_ARCH" ]]; then
    printf '%s\n' "synapse-ast requires a native Linux $SYNAPSE_ARCH package build" >&2
    exit 1
fi
CGO_ENABLED=1 go build -trimpath -o dist/worker/synapse-ast ./cmd/synapse-ast

: "${SYNAPSE_SYFT_BIN:?set SYNAPSE_SYFT_BIN to the verified pinned Syft executable}"
: "${SYNAPSE_GRYPE_BIN:?set SYNAPSE_GRYPE_BIN to the verified pinned Grype executable}"
: "${SYNAPSE_SUBFINDER_BIN:?set SYNAPSE_SUBFINDER_BIN to the verified pinned Subfinder executable}"
: "${SYNAPSE_HTTPX_BIN:?set SYNAPSE_HTTPX_BIN to the verified pinned HTTPX executable}"
: "${SYNAPSE_NAABU_BIN:?set SYNAPSE_NAABU_BIN to the verified pinned Naabu executable}"
install -m 0755 "$SYNAPSE_SYFT_BIN" dist/worker/syft
install -m 0755 "$SYNAPSE_GRYPE_BIN" dist/worker/grype
install -m 0755 "$SYNAPSE_SUBFINDER_BIN" dist/worker/subfinder
install -m 0755 "$SYNAPSE_HTTPX_BIN" dist/worker/httpx
install -m 0755 "$SYNAPSE_NAABU_BIN" dist/worker/naabu

export SYNAPSE_VERSION SYNAPSE_ARCH SYNAPSE_LIBC_FLOOR
nfpm package -f packaging/nfpm-worker.yaml -p "$SYNAPSE_PACKAGE_TYPE" -t dist/
