#!/usr/bin/env bash
# #412 req 4: a release cannot be published with an unsigned artifact.
#
# The gate is fail-closed in three ways, and each one is a failure mode that has actually shipped
# somewhere:
#
#   1. An artifact with no detached signature fails. Not "warn", not "skip" — the release stops.
#   2. An EMPTY artifact set fails. A run that scanned nothing must never look like a clean pass; that
#      is how a broken build step turns into a green release.
#   3. Any error fails, because `set -euo pipefail` is on and nothing here swallows an exit.
#
# Usage: verify-artifacts-signed.sh <directory>
#
# Every releasable artifact must sit beside a detached signature named "<artifact>.sig". Checksums and
# signatures themselves are not artifacts and are not required to be signed in turn.
set -euo pipefail

dir="${1:-}"
if [ -z "${dir}" ]; then
    echo "usage: $(basename "$0") <artifact-directory>" >&2
    exit 2
fi
if [ ! -d "${dir}" ]; then
    echo "verify-artifacts-signed: ${dir} is not a directory" >&2
    exit 2
fi

# Extensions that are release ARTIFACTS and must carry a signature.
is_artifact() {
    case "$1" in
    # Other JSON files are derived metadata, but the evidence manifest is the root that binds the
    # complete release set. Letting it bypass the detached-signature gate would reduce the whole
    # release to unauthenticated checksums.
    release-evidence.json) return 0 ;;
    *.sig | *.asc | *.pem | *.sha256 | *.txt | *.json | *.sbom | *.intoto.jsonl) return 1 ;;
    *) return 0 ;;
    esac
}

checked=0
unsigned=""

while IFS= read -r path; do
    [ -f "${path}" ] || continue
    name="$(basename "${path}")"
    if ! is_artifact "${name}"; then
        continue
    fi
    checked=$((checked + 1))
    if [ ! -f "${path}.sig" ]; then
        unsigned="${unsigned}${name}"$'\n'
    fi
done <<EOF
$(find "${dir}" -maxdepth 1 -type f | sort)
EOF

if [ -n "${unsigned}" ]; then
    echo "verify-artifacts-signed: these artifacts have no detached signature:" >&2
    printf '%s' "${unsigned}" >&2
    echo "verify-artifacts-signed: refusing to publish a release with an unsigned artifact." >&2
    exit 1
fi

# Vacuous success is the failure this check exists to prevent: a build step that produced nothing must
# not read as "everything is signed".
if [ "${checked}" -eq 0 ]; then
    echo "verify-artifacts-signed: no artifacts were found in ${dir}." >&2
    echo "verify-artifacts-signed: a release with nothing to sign is a broken build, not a clean pass." >&2
    exit 1
fi

echo "verify-artifacts-signed: ${checked} artifact(s), all signed."
