#!/usr/bin/env bash
set -euo pipefail

if (( $# < 3 )); then
  echo "usage: sca-cycle-service.sh SOURCE_ROOT BINARY MODE [ARGS...]" >&2
  exit 2
fi

source_root=$1
binary=$2
shift 2
if [[ $source_root != /* || $binary != /* ]]; then
  echo "source root and binary must be absolute paths" >&2
  exit 2
fi

cd -- "$source_root"
relative_cgroup=$(sed -n 's/^0:://p' /proc/self/cgroup)
if [[ $relative_cgroup != /* || $relative_cgroup == / ]]; then
  echo "delegated service cgroup is unavailable" >&2
  exit 1
fi
export SCA_ACCURACY_DELEGATED_CGROUP_ROOT="/sys/fs/cgroup${relative_cgroup}"
exec "$binary" "$@"
