#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"

usage() { printf '%s\n' 'Usage: provision.sh --backend-config FILE --var-file FILE --confirm-apply'; }
backend_config=''
var_file=''
confirmed=false
while (($#)); do
  case "$1" in
    --backend-config) backend_config=${2:?missing backend config path}; shift 2 ;;
    --var-file) var_file=${2:?missing variable file path}; shift 2 ;;
    --confirm-apply) confirmed=true; shift ;;
    *) usage >&2; exit 64 ;;
  esac
done
[[ -n "$backend_config" && -f "$backend_config" && -n "$var_file" && -f "$var_file" && "$confirmed" == true ]] || { usage >&2; exit 64; }

terraform init -input=false -backend-config="$backend_config"
terraform plan -input=false -var-file="$var_file" -out=plan.tfplan
terraform apply -input=false plan.tfplan
rm -f -- plan.tfplan
