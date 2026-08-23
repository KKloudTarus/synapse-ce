#!/usr/bin/env bash
# Restore a verified paired backup to a fresh isolated target. Dry-run by default.

set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'USAGE'
Usage:
  restore.sh --backup-dir ABSOLUTE_PATH --target-pg-dsn-env NAME --object-target MC_TARGET \
    --verifier ABSOLUTE_PATH --expected-state ABSOLUTE_PATH \
    --fresh-target-confirmation RESTORE-TO-FRESH-ISOLATED-TARGET [--execute]

The target database must already exist, be isolated from production, and have no
user tables. The target object-store location must already exist and be empty.

A restore is only reported successful when synapse-verify-restore confirms the
evidence chains, object identities, global audit chain, and migration state against
the independently captured expected-state manifest.
USAGE
}

backup_dir=""
target_pg_dsn_env=""
object_target=""
verifier=""
expected_state=""
fresh_target_confirmation=""
execute=false

while (($#)); do
  case "$1" in
    --backup-dir) backup_dir="${2:-}"; shift 2 ;;
    --target-pg-dsn-env) target_pg_dsn_env="${2:-}"; shift 2 ;;
    --object-target) object_target="${2:-}"; shift 2 ;;
    --verifier) verifier="${2:-}"; shift 2 ;;
    --expected-state) expected_state="${2:-}"; shift 2 ;;
    --fresh-target-confirmation) fresh_target_confirmation="${2:-}"; shift 2 ;;
    --execute) execute=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

require_value "--backup-dir" "$backup_dir"
require_absolute_path "--backup-dir" "$backup_dir"
require_value "--target-pg-dsn-env" "$target_pg_dsn_env"
require_environment_name "$target_pg_dsn_env"
require_value "--object-target" "$object_target"
require_safe_operand "--object-target" "$object_target"
require_value "--verifier" "$verifier"
require_absolute_path "--verifier" "$verifier"
require_value "--expected-state" "$expected_state"
require_absolute_path "--expected-state" "$expected_state"

if ! "$execute"; then
  printf '%s\n' "dry run: would verify $backup_dir/MANIFEST.sha256"
  printf '%s\n' 'dry run: would restore only into a fresh isolated database and empty object-store target'
  printf '%s\n' 'dry run: no --clean, object deletion, or overwrite option will be used'
  printf '%s\n' "dry run: would then require synapse-verify-restore at $verifier to pass against --expected-state $expected_state"
  exit 0
fi

[[ "$fresh_target_confirmation" == "RESTORE-TO-FRESH-ISOLATED-TARGET" ]] || fail "--fresh-target-confirmation must be RESTORE-TO-FRESH-ISOLATED-TARGET"
require_command sha256sum
require_command psql
require_command pg_restore
require_command mc
verify_manifest "$backup_dir"

user_table_count="$(psql --dbname="${!target_pg_dsn_env}" --tuples-only --no-align --quiet --command="SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog', 'information_schema') AND table_type = 'BASE TABLE';")"
[[ "$user_table_count" == "0" ]] || fail "target database is not fresh: it has $user_table_count user table(s)"
object_listing="$(mc ls "$object_target")"
[[ -z "${object_listing//[[:space:]]/}" ]] || fail 'target object-store location is not empty'

[[ -x "$verifier" ]] || fail "restore verifier is not executable: $verifier"
[[ -f "$expected_state" ]] || fail "expected-state manifest does not exist: $expected_state"

pg_restore --dbname="${!target_pg_dsn_env}" --exit-on-error --single-transaction --no-owner --no-privileges "$backup_dir/database.dump"
mc mirror "$backup_dir/objects" "$object_target"

# Matching files are not a restored system. Evidence chains, content-addressed object
# identities, the global audit chain, and migration state must all verify against an
# independently captured expected state before this reports success.
SYNAPSE_DB_DSN="${!target_pg_dsn_env}" \
"$verifier" --expected-state "$expected_state" \
  || fail 'restore verification failed: the restored copy is not usable and must not be promoted'

printf '%s\n' 'restore complete and verified: validate the isolated application with its own non-production configuration'
