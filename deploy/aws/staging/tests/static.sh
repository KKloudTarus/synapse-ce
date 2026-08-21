#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"

fail() {
  printf 'static check failed: %s\n' "$1" >&2
  exit 1
}

# Detect credential-like literals without inspecting ignored operator variable files.
if perl -ne 'exit 1 if /AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|(?i:aws_secret_access_key)\s*=\s*"[^"]/' -- ./*.tf; then :; else
  fail "AWS credential-like literal found in Terraform source"
fi

if perl -ne 'exit 1 if /^\s*(?:password|master_password)\s*=\s*"/' -- ./*.tf; then :; else
  fail "hard-coded password found in Terraform source"
fi

if perl -0777 -ne 'while (/output\s+"[^"]*(?:secret|password)[^"]*"\s*\{(.*?)\}/sg) { exit 1 unless $1 =~ /sensitive\s*=\s*true/ } exit 0' -- outputs.tf; then :; else
  fail "secret or password outputs must be explicitly sensitive"
fi

for required in 'manage_master_user_password\s*=\s*true' 'storage_encrypted\s*=\s*true' 'publicly_accessible\s*=\s*false' 'endpoint_public_access\s*=\s*false' 'enable_key_rotation\s*=\s*true' 'block_public_policy\s*=\s*true' 'status\s*=\s*"Enabled"'; do
  perl -0777 -ne "BEGIN { \$found = 0 } \$found = 1 if /$required/; END { exit !\$found }" -- ./*.tf || fail "missing required security control: $required"
done

printf '%s\n' 'static security checks passed'
