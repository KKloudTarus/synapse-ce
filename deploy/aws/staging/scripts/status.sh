#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"

usage() { printf '%s\n' 'Usage: status.sh --backend-config FILE --var-file FILE'; }
backend_config=''
var_file=''
while (($#)); do
  case "$1" in
    --backend-config) backend_config=${2:?missing backend config path}; shift 2 ;;
    --var-file) var_file=${2:?missing variable file path}; shift 2 ;;
    *) usage >&2; exit 64 ;;
  esac
done
[[ -n "$backend_config" && -f "$backend_config" && -n "$var_file" && -f "$var_file" ]] || { usage >&2; exit 64; }

terraform init -input=false -backend-config="$backend_config"
set +e
terraform plan -input=false -detailed-exitcode -var-file="$var_file"
status=$?
set -e
case "$status" in
  0) printf '%s\n' 'Infrastructure matches configuration.' ;;
  2) printf '%s\n' 'Infrastructure drift or pending configuration changes detected.' ;;
  *) exit "$status" ;;
esac
