#!/bin/sh
set -eu

if ! getent group synapse-worker >/dev/null 2>&1; then
    groupadd --system synapse-worker
fi
if ! getent passwd synapse-worker >/dev/null 2>&1; then
    useradd --system --gid synapse-worker --no-create-home \
        --home-dir /var/lib/synapse --shell /sbin/nologin synapse-worker
fi

install -d -o root -g synapse-worker -m 0750 /etc/synapse-worker
install -d -o root -g root -m 0755 /run/netns
install -d -o synapse-worker -g synapse-worker -m 0750 \
    /var/lib/synapse/project-uploads \
    /var/lib/synapse/project-source-artifacts \
    /var/cache/synapse/scan
