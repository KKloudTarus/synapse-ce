#!/usr/bin/env bash
# Verify a v0.1.8 baseline artifact and apply current embedded forward migrations. Dry-run by default.

set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'USAGE'
Usage:
  forward-upgrade.sh --backup-dir ABSOLUTE_PATH     --baseline-migrator ABSOLUTE_PATH --baseline-expected-sha256 SHA256     --current-migrator ABSOLUTE_PATH --current-expected-sha256 SHA256     --runtime-pg-dsn-env NAME --migration-pg-dsn-env NAME     --quiesced-confirmation UPGRADE-QUIESCED     --baseline-confirmation BASELINE-V0.1.8-VERIFIED     --forward-upgrade-confirmation UPGRADE-FROM-V0.1.8-TO-CURRENT [--execute]

The baseline migrator is verified only to attest the v0.1.8 state represented by this paired backup. The current migrator is the only binary this wrapper runs. It runs no down migration and does not deploy, stop, or delete any service.
USAGE
}

backup_dir=""
baseline_migrator=""
baseline_expected_sha256=""
current_migrator=""
current_expected_sha256=""
runtime_pg_dsn_env=""
migration_pg_dsn_env=""
quiesced_confirmation=""
baseline_confirmation=""
forward_upgrade_confirmation=""
execute=false

while (($#)); do
  case "$1" in
    --backup-dir) backup_dir="${2:-}"; shift 2 ;;
    --baseline-migrator) baseline_migrator="${2:-}"; shift 2 ;;
    --baseline-expected-sha256) baseline_expected_sha256="${2:-}"; shift 2 ;;
    --current-migrator) current_migrator="${2:-}"; shift 2 ;;
    --current-expected-sha256) current_expected_sha256="${2:-}"; shift 2 ;;
    --runtime-pg-dsn-env) runtime_pg_dsn_env="${2:-}"; shift 2 ;;
    --migration-pg-dsn-env) migration_pg_dsn_env="${2:-}"; shift 2 ;;
    --quiesced-confirmation) quiesced_confirmation="${2:-}"; shift 2 ;;
    --baseline-confirmation) baseline_confirmation="${2:-}"; shift 2 ;;
    --forward-upgrade-confirmation) forward_upgrade_confirmation="${2:-}"; shift 2 ;;
    --execute) execute=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

require_value "--backup-dir" "$backup_dir"
require_absolute_path "--backup-dir" "$backup_dir"
require_value "--baseline-migrator" "$baseline_migrator"
require_absolute_path "--baseline-migrator" "$baseline_migrator"
require_value "--baseline-expected-sha256" "$baseline_expected_sha256"
[[ "$baseline_expected_sha256" =~ ^[[:xdigit:]]{64}$ ]] || fail "--baseline-expected-sha256 must be a SHA-256 digest"
require_value "--current-migrator" "$current_migrator"
require_absolute_path "--current-migrator" "$current_migrator"
require_value "--current-expected-sha256" "$current_expected_sha256"
[[ "$current_expected_sha256" =~ ^[[:xdigit:]]{64}$ ]] || fail "--current-expected-sha256 must be a SHA-256 digest"
require_value "--runtime-pg-dsn-env" "$runtime_pg_dsn_env"
require_environment_name "$runtime_pg_dsn_env"
require_value "--migration-pg-dsn-env" "$migration_pg_dsn_env"
require_environment_name "$migration_pg_dsn_env"

if ! "$execute"; then
  printf '%s\n' "dry run: would verify separate v0.1.8 baseline and current migrator digests, the paired baseline backup, and run only the current migrator at $current_migrator"
  printf '%s\n' 'dry run: would execute only synapse-migrate; it does not run down migrations or deploy services'
  printf '%s\n' 'dry run: add --execute and all explicit confirmations after quiescing writers'
  exit 0
fi

[[ "$quiesced_confirmation" == "UPGRADE-QUIESCED" ]] || fail "--quiesced-confirmation must be UPGRADE-QUIESCED"
[[ "$baseline_confirmation" == "BASELINE-V0.1.8-VERIFIED" ]] || fail "--baseline-confirmation must be BASELINE-V0.1.8-VERIFIED"
[[ "$forward_upgrade_confirmation" == "UPGRADE-FROM-V0.1.8-TO-CURRENT" ]] || fail "--forward-upgrade-confirmation must be UPGRADE-FROM-V0.1.8-TO-CURRENT"
[[ -x "$baseline_migrator" ]] || fail "baseline migrator is not executable: $baseline_migrator"
[[ -x "$current_migrator" ]] || fail "current migrator is not executable: $current_migrator"
require_command sha256sum
verify_manifest "$backup_dir"
verify_artifact_sha256() {
  local label="$1" artifact="$2" expected_sha256="$3" actual_sha256
  actual_sha256="$(sha256sum -- "$artifact")"
  actual_sha256="${actual_sha256%% *}"
  [[ "${actual_sha256,,}" == "${expected_sha256,,}" ]] || fail "$label SHA-256 does not match its approved artifact"
}
verify_artifact_sha256 'v0.1.8 baseline migrator' "$baseline_migrator" "$baseline_expected_sha256"
verify_artifact_sha256 'current migrator' "$current_migrator" "$current_expected_sha256"

# SYNAPSE_ENV must be production. The migrator only requires a distinct migration DSN and
# validates migration/runtime role separation under a production posture; omitting it defaults
# to development and silently disables the gate this wrapper exists to enforce.
SYNAPSE_ENV=production \
SYNAPSE_DB_DSN="${!runtime_pg_dsn_env}" \
SYNAPSE_DB_MIGRATION_DSN="${!migration_pg_dsn_env}" \
SYNAPSE_DB_AUTO_MIGRATE=false \
"$current_migrator"

printf '%s\n' 'current forward migrations complete: deploy only the separately verified current services, then run readiness checks'
