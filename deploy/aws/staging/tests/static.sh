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

# #635 data-governance posture: all durable AWS data planes and native worker disks
# use the same rotating customer-managed KMS key. Do not accept provider-default
# encryption here because it would make key ownership and rotation unverifiable.
for required in \
  'resource\s+"aws_ecr_repository"\s+"app".*?encryption_type\s*=\s*"KMS".*?kms_key\s*=\s*aws_kms_key\.staging\.arn' \
  'resource\s+"aws_s3_bucket_server_side_encryption_configuration"\s+"evidence".*?kms_master_key_id\s*=\s*aws_kms_key\.staging\.arn.*?sse_algorithm\s*=\s*"aws:kms"' \
  'resource\s+"aws_db_instance"\s+"postgres".*?storage_encrypted\s*=\s*true.*?kms_key_id\s*=\s*aws_kms_key\.staging\.arn' \
  'resource\s+"aws_launch_template"\s+"worker".*?encrypted\s*=\s*true.*?kms_key_id\s*=\s*aws_kms_key\.staging\.arn'; do
  perl -0777 -ne "BEGIN { \$found = 0 } \$found = 1 if /$required/s; END { exit !\$found }" -- ./*.tf || fail "missing governed KMS wiring: $required"
done

# This reference stack is deliberately single-region. The provider consumes one validated
# aws_region value and every configured AZ must belong to that same region. Cross-region
# replication is therefore an explicit separate deployment, never an accidental default.
grep -Fq 'region = var.aws_region' versions.tf || fail "AWS provider must use the governed aws_region variable"
perl -0777 -ne 'exit !(/variable\s+"aws_region"\s*\{.*?condition\s*=\s*var\.aws_region\s*==\s*"us-east-1"/s)' variables.tf || fail "staging aws_region must remain explicitly constrained"
perl -0777 -ne 'exit !(/variable\s+"availability_zones"\s*\{.*?startswith\(az,\s*"us-east-1"\)/s)' variables.tf || fail "availability zones must remain inside the governed region"

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

printf '%s\n' 'static security and data-governance checks passed'
