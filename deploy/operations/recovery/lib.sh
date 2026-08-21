#!/usr/bin/env bash
# Shared guardrails for the EPIC #587 operational wrappers. Source only.

set -euo pipefail

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

require_absolute_path() {
  [[ "$2" == /* ]] || fail "$1 must be an absolute path"
}

require_value() {
  [[ -n "$2" ]] || fail "$1 is required"
}

require_safe_operand() {
  [[ "$2" != -* ]] || fail "$1 must not begin with a dash"
}

require_environment_name() {
  [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || fail "invalid environment-variable name: $1"
  [[ -n "${!1:-}" ]] || fail "environment variable $1 is unset or empty"
}

verify_manifest() {
  local backup_dir="$1"
  require_absolute_path "backup directory" "$backup_dir"
  [[ -d "$backup_dir" ]] || fail "backup directory does not exist: $backup_dir"
  [[ -f "$backup_dir/database.dump" ]] || fail "database.dump is missing from backup directory"
  [[ -d "$backup_dir/objects" ]] || fail "objects directory is missing from backup directory"
  [[ -f "$backup_dir/MANIFEST.sha256" ]] || fail "MANIFEST.sha256 is missing from backup directory"
  (
    cd -- "$backup_dir"
    sha256sum --check --strict MANIFEST.sha256
  )
}
