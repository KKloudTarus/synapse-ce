#!/usr/bin/env bash
# #412 req 6: no step in the release path may swallow a non-zero exit (the field failure was a release
# scan wrapped in `|| true` that reported zero findings for every release because the scanner was
# missing). This lint greps the release workflows for exit-swallowing constructs and fails if any is
# found. It is runnable locally and in CI; it does not require GitHub Actions to be enabled.
set -euo pipefail

# Release-path workflows the rule applies to: any workflow whose name contains "release", so a new
# release-path workflow added later is covered automatically (not just a hardcoded pair).
targets=()
for f in .github/workflows/*release*.yml .github/workflows/*release*.yaml; do
    [ -f "$f" ] && targets+=("$f")
done
if [ "${#targets[@]}" -eq 0 ]; then
    echo "OK: no release-path workflows to lint."
    exit 0
fi

# Patterns that swallow a non-zero exit in a shell step.
#   `|| true`, `|| :`, `|| exit 0`, and `continue-on-error: true`
patterns='(\|\|[[:space:]]*true)|(\|\|[[:space:]]*:)|(\|\|[[:space:]]*exit[[:space:]]+0)|(continue-on-error:[[:space:]]*true)'

found=0
for f in "${targets[@]}"; do
    [ -f "$f" ] || continue
    # Number the lines, strip trailing comments (from the first '#') so a comment that MENTIONS the
    # pattern is not a false positive, while a real executable construct (which precedes any '#') is
    # still caught, then match. grep exiting 1 (no match) must not abort the loop under `set -e`.
    hits="$(grep -n '' "$f" | sed -E 's/#.*$//' | grep -Ei "$patterns" || true)"
    if [ -n "$hits" ]; then
        echo "ERROR: $f contains an exit-swallowing construct in the release path (#412 req 6):" >&2
        echo "$hits" >&2
        found=1
    fi
done

if [ "$found" -ne 0 ]; then
    echo "Release steps must fail on a non-zero exit — remove the construct(s) above." >&2
    exit 1
fi
echo "OK: no exit-swallowing constructs in the release path."
