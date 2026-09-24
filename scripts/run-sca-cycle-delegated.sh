#!/usr/bin/env bash
set -euo pipefail

if (( $# < 1 )) || [[ $1 != run && $1 != candidate ]]; then
  echo "usage: run-sca-cycle-delegated.sh {run|candidate} [ARGS...]" >&2
  exit 2
fi

source_root=$(git rev-parse --show-toplevel)
if [[ $(pwd -P) != "$(cd "$source_root" && pwd -P)" ]]; then
  echo "run the SCA cycle from the source checkout root" >&2
  exit 2
fi

runtime_dir=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
if [[ ! -S $runtime_dir/bus ]]; then
  echo "a running systemd user manager is required" >&2
  exit 1
fi
export XDG_RUNTIME_DIR=$runtime_dir
export DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unix:path=$runtime_dir/bus}

temp_root=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
work_dir=$(mktemp -d "$temp_root/synapse-sca-cycle.XXXXXXXX")
unit="synapse-sca-cycle-$(date -u +%s)-$$.service"
cleanup() {
  status=$?
  trap - EXIT INT TERM
  systemctl --user stop "$unit" >/dev/null 2>&1 || true
  rm -rf -- "$work_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

binary=$work_dir/synapse-sca-cycle
go build -trimpath -o "$binary" ./cmd/synapse-sca-cycle
go_path=$(go env GOPATH)
go_mod_cache=$(go env GOMODCACHE)
service_env=(
  --setenv "PATH=$PATH"
  --setenv "HOME=$HOME"
  --setenv "GOPATH=$go_path"
  --setenv "GOMODCACHE=$go_mod_cache"
)
if [[ -n ${DOCKER_HOST:-} ]]; then
  service_env+=(--setenv "DOCKER_HOST=$DOCKER_HOST")
fi

systemd-run --user --wait --pipe --collect --unit "$unit" \
  --property Delegate=yes --property TasksMax=4096 \
  --property RuntimeMaxSec=2400 --property TimeoutStopSec=30 \
  "${service_env[@]}" \
  /usr/bin/bash "$source_root/scripts/sca-cycle-service.sh" \
  "$source_root" "$binary" "$@"
