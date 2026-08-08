#!/bin/sh
# Preinstall hook (#412): the libc floor is enforced TWICE. The package metadata already declares a
# dependency (rpm `Requires: glibc >= X`, deb `Depends: libc6 (>= X)`) so the package manager refuses
# an install below the floor. This script is the SECOND check for the field failure mode where the
# dependency is satisfiable but the actual runtime glibc is older than the build target — the install
# then succeeds and the service crash-loops at first start. We fail HERE, at install time, with a
# readable message and leave nothing behind, instead of letting that happen.
#
# SYNAPSE_LIBC_FLOOR is substituted by the release pipeline (nfpm) from the build's glibc target.
set -eu

LIBC_FLOOR="${SYNAPSE_LIBC_FLOOR:-2.28}" # e.g. RHEL 8 / Debian 10 baseline; overridden at build time

# Create the dedicated, unprivileged service account (idempotent) before files land.
if ! getent group synapse-agent >/dev/null 2>&1; then
    groupadd --system synapse-agent >/dev/null 2>&1 || true
fi
if ! getent passwd synapse-agent >/dev/null 2>&1; then
    useradd --system --gid synapse-agent --no-create-home \
        --home-dir /var/lib/synapse-agent --shell /usr/sbin/nologin synapse-agent >/dev/null 2>&1 || true
fi

# Determine the runtime glibc version. `ldd --version` prints it on the first line on glibc systems.
detected="$(ldd --version 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+' | head -n1 || true)"

if [ -z "$detected" ]; then
    echo "synapse-agent: could not determine the runtime C library version." >&2
    echo "synapse-agent: this build targets glibc >= ${LIBC_FLOOR}; refusing to install on an unverifiable runtime." >&2
    exit 1
fi

# Compare detected vs floor as "major.minor" using sort -V.
older="$(printf '%s\n%s\n' "$LIBC_FLOOR" "$detected" | sort -V | head -n1)"
if [ "$detected" != "$LIBC_FLOOR" ] && [ "$older" = "$detected" ]; then
    echo "synapse-agent: runtime glibc ${detected} is older than the build floor ${LIBC_FLOOR}." >&2
    echo "synapse-agent: this package would install but crash-loop at first start; refusing." >&2
    echo "synapse-agent: install a build for your platform (see the support matrix in docs/guide/fleet-agent-packaging.md)." >&2
    exit 1
fi

exit 0
