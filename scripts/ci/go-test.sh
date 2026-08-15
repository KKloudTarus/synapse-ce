#!/usr/bin/env bash
# CI Go test runner.
#
# Runs the full Go suite once, but retries ONLY internal/infrastructure/dastengine up to 3x. That
# package's *test harness* drives the DAST helper's authorization channel over in-process OS pipes +
# a goroutine and exercises wall-clock-tight session/reauth timing; under CI load it intermittently
# reports Incomplete{session_lost|request_not_authorized}. `go test -race` on it is clean, so this is a
# harness timing/IPC flake, NOT a production bug — in production the helper runs as a subprocess with
# dedicated FDs (see engine.go), not this in-process harness. Tracked for a proper fix in #569.
#
# The retry is deliberately narrow: a genuine regression in dastengine still fails the job (all three
# attempts red); only a transient flake self-heals. Every other package runs exactly once.
set -euo pipefail

flaky="github.com/KKloudTarus/synapse-ce/internal/infrastructure/dastengine"

# Everything except the flaky package, once (postgres integration tests self-skip without a DSN).
mapfile -t pkgs < <(go list ./... | grep -vx "${flaky}")
go test -count=1 "${pkgs[@]}"

# The flaky package, with bounded retries.
for attempt in 1 2 3; do
  if go test -count=1 "${flaky}"; then
    exit 0
  fi
  echo "::warning::dastengine test attempt ${attempt}/3 failed (known harness flake #569); retrying"
done
echo "::error::dastengine failed 3 consecutive attempts — treating this as a real failure, not a flake"
exit 1
