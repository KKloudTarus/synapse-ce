#!/bin/sh
set -eu

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop synapse-worker synapse-egress-broker >/dev/null 2>&1 || true
    systemctl disable synapse-worker synapse-egress-broker >/dev/null 2>&1 || true
fi
