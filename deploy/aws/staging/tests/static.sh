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

for required in 'http_tokens\s*=\s*"required"' 'associate_public_ip_address\s*=\s*false' 'encrypted\s*=\s*true' 'AmazonSSMManagedInstanceCore' 'aws_autoscaling_group" "worker' 'aws_imagebuilder_image" "worker' 'referenced_security_group_id\s*=\s*aws_security_group.worker.id' 'aws_security_group" "grant_authority_nlb' 'aws_subnet" "worker' 'AWSServiceRoleForAutoScaling' 'kms:GrantIsForAWSResource'; do
  perl -0777 -ne "BEGIN { \$found = 0 } \$found = 1 if /$required/; END { exit !\$found }" -- ./*.tf || fail "missing native worker control: $required"
done

perl -0777 -ne 'if (/resource\s+"aws_launch_template"\s+"worker"\s*\{(.*?)\n\}/s) { exit 1 if $1 =~ /\bkey_name\s*=/; exit 0 } exit 1' -- worker.tf || fail "worker launch template must exist without an SSH key"
perl -0777 -ne 'if (/resource\s+"aws_security_group"\s+"worker"\s*\{(.*?)\n\}/s) { exit 1 if $1 =~ /\bingress\s*\{/; exit 0 } exit 1' -- worker.tf || fail "worker security group must not declare inbound rules"

grep -Fq 'vpc_zone_identifier       = [for subnet in aws_subnet.worker : subnet.id]' worker.tf || fail "worker ASG must use dedicated private subnets"
grep -Fq 'CapabilityBoundingSet=' worker.tf || fail "AMI conformance must preserve the empty capability set"
grep -Fq 'update-ca-trust extract' worker.tf || fail "AMI must install the pinned private trust anchor"
grep -Fq 'worker_trust_anchor_sha256' worker.tf || fail "AMI must verify the private trust anchor digest"
grep -Fq 'cidrhost(cidr, 4)' locals.tf || fail "grant NLB output must match the fixed private addresses assigned by Helm"

printf '%s\n' 'static security checks passed'
