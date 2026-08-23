#!/bin/sh
set -eu

case "${1:-}" in
0 | remove | purge) ;;
*) exit 0 ;;
esac

if [ -d /etc/synapse-worker ] && [ -z "$(ls -A /etc/synapse-worker 2>/dev/null)" ]; then
    rmdir /etc/synapse-worker
fi
