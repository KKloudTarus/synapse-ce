#!/usr/bin/env bash
# Static and dry-run checks for the conservative operational wrappers.

set -euo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  local file="$1" text="$2"
  local content
  content="$(<"$file")"
  [[ "$content" == *"$text"* ]] || fail "$file must contain: $text"
}

assert_not_contains() {
  local file="$1" text="$2"
  local content
  content="$(<"$file")"
  [[ "$content" != *"$text"* ]] || fail "$file must not contain: $text"
}

for script in lib.sh backup.sh restore.sh forward-upgrade.sh; do
  bash -n "$SCRIPT_DIR/$script"
done

backup_dry_run="$(SYNAPSE_TEST_DSN=placeholder "$SCRIPT_DIR/backup.sh" --backup-dir /tmp/synapse-backup-static-test --pg-dsn-env SYNAPSE_TEST_DSN --object-source test-alias/test-bucket)"
[[ "$backup_dry_run" == *'dry run:'* ]] || fail 'backup default must be a dry run'
restore_dry_run="$(SYNAPSE_TEST_DSN=placeholder "$SCRIPT_DIR/restore.sh" --backup-dir /tmp/synapse-backup-static-test --target-pg-dsn-env SYNAPSE_TEST_DSN --object-target test-alias/test-bucket --verifier /tmp/synapse-verify-restore --expected-state /tmp/synapse-expected-state.json)"
[[ "$restore_dry_run" == *'synapse-verify-restore'* ]] || fail 'restore dry run must state that verification is required'
[[ "$restore_dry_run" == *'dry run:'* ]] || fail 'restore default must be a dry run'
upgrade_dry_run="$(SYNAPSE_TEST_DSN=placeholder "$SCRIPT_DIR/forward-upgrade.sh" --backup-dir /tmp/synapse-backup-static-test --baseline-migrator /tmp/synapse-migrate-v0.1.8 --baseline-expected-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --current-migrator /tmp/synapse-migrate-current --current-expected-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --runtime-pg-dsn-env SYNAPSE_TEST_DSN --migration-pg-dsn-env SYNAPSE_TEST_DSN)"
[[ "$upgrade_dry_run" == *'dry run:'* ]] || fail 'upgrade default must be a dry run'

for script in backup.sh restore.sh forward-upgrade.sh; do
  assert_contains "$SCRIPT_DIR/$script" '--execute'
done
assert_contains "$SCRIPT_DIR/backup.sh" 'BACKUP-QUIESCED'
assert_contains "$SCRIPT_DIR/restore.sh" 'RESTORE-TO-FRESH-ISOLATED-TARGET'
assert_contains "$SCRIPT_DIR/forward-upgrade.sh" 'UPGRADE-QUIESCED'
assert_contains "$SCRIPT_DIR/forward-upgrade.sh" 'BASELINE-V0.1.8-VERIFIED'
assert_contains "$SCRIPT_DIR/forward-upgrade.sh" 'UPGRADE-FROM-V0.1.8-TO-CURRENT'
assert_contains "$SCRIPT_DIR/forward-upgrade.sh" 'verify_artifact_sha256'
assert_contains "$SCRIPT_DIR/forward-upgrade.sh" 'SYNAPSE_ENV=production'
assert_contains "$SCRIPT_DIR/restore.sh" 'synapse-verify-restore'
assert_contains "$SCRIPT_DIR/restore.sh" '--expected-state'
assert_contains "$SCRIPT_DIR/forward-upgrade.sh" '"$current_migrator"'
assert_not_contains "$SCRIPT_DIR/forward-upgrade.sh" 'UPGRADE-TO-0.1.8'
assert_contains "$SCRIPT_DIR/lib.sh" 'sha256sum --check --strict MANIFEST.sha256'
assert_not_contains "$SCRIPT_DIR/backup.sh" 'mc mirror --remove'
assert_not_contains "$SCRIPT_DIR/backup.sh" 'mc mirror --overwrite'
assert_not_contains "$SCRIPT_DIR/restore.sh" 'mc mirror --remove'
assert_not_contains "$SCRIPT_DIR/restore.sh" 'mc mirror --overwrite'
assert_not_contains "$SCRIPT_DIR/restore.sh" 'pg_restore --clean'
assert_not_contains "$SCRIPT_DIR/restore.sh" 'pg_restore --create'
assert_not_contains "$SCRIPT_DIR/forward-upgrade.sh" ' --down'

printf '%s\n' 'operational script static tests passed'
