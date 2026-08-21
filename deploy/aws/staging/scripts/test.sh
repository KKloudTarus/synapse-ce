#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"

command -v terraform >/dev/null 2>&1 || { printf '%s\n' 'terraform is required' >&2; exit 127; }
terraform fmt -check -recursive
terraform init -backend=false -input=false
terraform validate
./tests/static.sh
