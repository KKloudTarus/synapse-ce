#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"

usage() { printf '%s\n' 'Usage: teardown.sh --backend-config FILE --var-file FILE --confirm-destroy'; }
backend_config=''
var_file=''
confirmed=false
while (($#)); do
  case "$1" in
    --backend-config) backend_config=${2:?missing backend config path}; shift 2 ;;
    --var-file) var_file=${2:?missing variable file path}; shift 2 ;;
    --confirm-destroy) confirmed=true; shift ;;
    *) usage >&2; exit 64 ;;
  esac
done
[[ -n "$backend_config" && -f "$backend_config" && -n "$var_file" && -f "$var_file" && "$confirmed" == true ]] || { usage >&2; exit 64; }

expires_at=$(perl -ne 'if (/^\s*expires_at\s*=\s*"([^"]+)"\s*$/) { print $1; exit }' -- "$var_file")
[[ -n "$expires_at" ]] || { printf '%s\n' 'expires_at must be set in the supplied variable file.' >&2; exit 64; }
python3 - "$expires_at" <<'PY'
from datetime import datetime, timezone
import sys
try:
    expiry = datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00"))
except ValueError:
    raise SystemExit("expires_at is not a valid RFC3339 timestamp")
if expiry.tzinfo is None or expiry > datetime.now(timezone.utc):
    raise SystemExit("refusing teardown: expires_at has not passed")
PY

terraform init -input=false -backend-config="$backend_config"
terraform plan -input=false -destroy -var-file="$var_file" -out=destroy.tfplan
terraform apply -input=false destroy.tfplan
rm -f -- destroy.tfplan
