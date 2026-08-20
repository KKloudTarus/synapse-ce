#!/usr/bin/env bash
# Create a paired, quiesced PostgreSQL and object-store backup. Dry-run by default.

set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'USAGE'
Usage:
  backup.sh --backup-dir ABSOLUTE_PATH --pg-dsn-env NAME --object-source MC_SOURCE \
    --quiesced-confirmation BACKUP-QUIESCED [--execute]

The caller must first quiesce every Synapse writer. Without --execute this command
only validates its arguments and prints the planned operations.
USAGE
}

backup_dir=""
pg_dsn_env=""
object_source=""
quiesced_confirmation=""
execute=false

while (($#)); do
  case "$1" in
    --backup-dir) backup_dir="${2:-}"; shift 2 ;;
    --pg-dsn-env) pg_dsn_env="${2:-}"; shift 2 ;;
    --object-source) object_source="${2:-}"; shift 2 ;;
    --quiesced-confirmation) quiesced_confirmation="${2:-}"; shift 2 ;;
    --execute) execute=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

require_value "--backup-dir" "$backup_dir"
require_absolute_path "--backup-dir" "$backup_dir"
require_value "--pg-dsn-env" "$pg_dsn_env"
require_environment_name "$pg_dsn_env"
require_value "--object-source" "$object_source"
require_safe_operand "--object-source" "$object_source"
[[ ! -e "$backup_dir" ]] || fail "backup directory already exists: $backup_dir"

if ! "$execute"; then
  printf '%s\n' "dry run: would create a paired backup at $backup_dir"
  printf '%s\n' 'dry run: would run pg_dump in custom archive format and mc mirror without --remove or --overwrite'
  printf '%s\n' 'dry run: add --execute and --quiesced-confirmation BACKUP-QUIESCED after stopping all writers'
  exit 0
fi

[[ "$quiesced_confirmation" == "BACKUP-QUIESCED" ]] || fail "--quiesced-confirmation must be BACKUP-QUIESCED"
require_command pg_dump
require_command mc
require_command sha256sum

parent_dir="$(dirname -- "$backup_dir")"
[[ -d "$parent_dir" ]] || fail "backup parent directory does not exist: $parent_dir"
umask 077
mkdir -- "$backup_dir"
mkdir -- "$backup_dir/objects"

pg_dump --dbname="${!pg_dsn_env}" --format=custom --file="$backup_dir/database.dump"
mc mirror "$object_source" "$backup_dir/objects"

{
  printf 'backup-format=postgres-custom-plus-object-mirror\n'
  printf 'created-at-utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  pg_dump --version
  mc --version | sed -n '1p'
} >"$backup_dir/BACKUP-METADATA.txt"

(
  cd -- "$backup_dir"
  {
    sha256sum -b database.dump
    LC_ALL=C find objects -type f -print0 | LC_ALL=C sort -z | xargs -r -0 sha256sum -b --
  } >MANIFEST.sha256
  sha256sum --check --strict MANIFEST.sha256
)

printf '%s\n' "backup complete: $backup_dir"
printf '%s\n' 'record the immutable backup location and MANIFEST.sha256 with the change evidence'
