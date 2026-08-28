#!/usr/bin/env bash
#
# Release smoke test: run a real scan from a PACKAGED synapse-cli and require it to complete and produce
# findings. The release scan-gate builds the scanner from source, so it never exercised the shipped
# tarball binary — which is how v0.1.8 shipped a scan that died at "persist scan: validation error:
# tenant context is required" while main was fine. This closes that gap.
#
# Usage: smoke-scan.sh <dir-with-synapse-cli>
#   <dir> is an extracted release tarball (or ./bin for a local `make build`). The sample is
#   self-contained and exercises the IN-PROCESS analyzers, so no syft/grype is required.
#
# The default scan legitimately exits non-zero when it reports a high finding, so this does NOT assert
# a zero exit — it asserts the scan COMPLETED without a hard error (the v0.1.8 class: a persist/validation
# failure or a panic) and that the packaged binary actually produced a finding.
set -euo pipefail

BINDIR="${1:-bin}"
CLI="$BINDIR/synapse-cli"
if [ ! -x "$CLI" ]; then
	echo "release-smoke: $CLI not found or not executable" >&2
	exit 2
fi

SAMPLE="$(mktemp -d)"
trap 'rm -rf "$SAMPLE"' EXIT

# A finding the in-process analyzers detect with no external tools: a well-known AWS example access-key
# id (assembled at runtime so this script is not itself flagged as carrying a live key).
printf 'aws_access_key_id = %s%s\n' "AKIA" "IOSFODNN7EXAMPLE" > "$SAMPLE/config.ini"

fail() {
	echo "release-smoke: FAIL — $1" >&2
	shift || true
	[ "$#" -gt 0 ] && { echo "----- output -----" >&2; head -60 "$@" >&2; }
	exit 1
}

# 1) Default scan (the exact path users run, which PERSISTS the scan — the step that regressed in v0.1.8).
#    A high finding flips the exit code, so we don't check it; we require the scan to have COMPLETED
#    without a hard error rather than aborting like v0.1.8 did.
echo "release-smoke: running default scan (persist path)…"
DEF="$SAMPLE/default.log"
set +e
"$CLI" scan "$SAMPLE" >"$DEF" 2>&1
set -e
if grep -qiE 'persist scan|validation error|panic:|runtime error' "$DEF"; then
	fail "the packaged scan hit a hard error (v0.1.8 class)" "$DEF"
fi
if ! grep -qiE 'finding|sca.scan' "$DEF"; then
	fail "the packaged scan did not complete a scan" "$DEF"
fi

# 2) JSON scan MUST report a finding for the planted key file, proving the packaged binary actually
#    scanned (in-process; no syft/grype), not just exited cleanly on an empty result.
echo "release-smoke: running JSON scan and checking for findings…"
OUT="$SAMPLE/out.json"
set +e
"$CLI" scan "$SAMPLE" --json >"$OUT" 2>"$SAMPLE/json.err"
set -e
if ! grep -q 'config.ini' "$OUT"; then
	fail "the packaged scanner produced no finding for the planted key file" "$OUT"
fi

echo "release-smoke: OK — packaged synapse-cli scanned and reported findings"
