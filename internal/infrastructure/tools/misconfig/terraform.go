package misconfig

import (
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Terraform (HCL) misconfiguration checks. Rather than a full HCL evaluator, this tracks the enclosing
// `resource "TYPE" "NAME"` block by brace depth and matches insecure LITERAL attribute values inside it
// – the common, high-signal cloud misconfigurations (public storage, world-open security groups,
// disabled encryption, public databases, wildcard IAM, plaintext secrets). Values that come from a
// variable / interpolation (${...}) are not flagged, keeping false positives low.
var (
	tfResourceOpen = regexp.MustCompile(`^\s*resource\s+"([^"]+)"\s+"([^"]*)"\s*\{`)
	tfPublicACL    = regexp.MustCompile(`(?i)\bacl\s*=\s*"(public-read|public-read-write|authenticated-read)"`)
	tfEncFalse     = regexp.MustCompile(`(?i)\b(encrypted|storage_encrypted|encryption)\s*=\s*false\b`)
	tfPublicRDS    = regexp.MustCompile(`(?i)\bpublicly_accessible\s*=\s*true\b`)
	tfPabDisabled  = regexp.MustCompile(`(?i)\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b`)
	tfOpenCIDR     = regexp.MustCompile(`"0\.0\.0\.0/0"|"::/0"`)
	tfSubBlockOpen = regexp.MustCompile(`^(ingress|egress)\b`)
	tfIAMWildcard  = regexp.MustCompile(`(?i)("Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\])`)
	tfSecretAttr   = regexp.MustCompile(`(?i)\b(password|secret|secret_key|access_key|private_key|api_key|token)\s*=\s*"([^"]+)"`)
)

// scanTerraform runs the owned Terraform checks over one .tf file.
func scanTerraform(rel string, data []byte) []ports.MisconfigRawFinding {
	lines := strings.Split(string(data), "\n")
	var out []ports.MisconfigRawFinding

	type frame struct {
		typ, name string
		depth     int
		start     int
		body      strings.Builder
	}
	var stack []*frame
	depth := 0
	sawEnabledVersioning := false
	// subBlock tracks the innermost ingress/egress sub-block so an open CIDR can be attributed to the
	// right direction; subOpenDepth is the brace depth at which it opened, used to clear it on close.
	subBlock := ""
	subOpenDepth := 0

	for i, raw := range lines {
		line := stripHCLComment(raw)
		trimmed := strings.TrimSpace(line)
		if m := tfResourceOpen.FindStringSubmatch(trimmed); m != nil {
			stack = append(stack, &frame{typ: m[1], name: m[2], depth: depth, start: i + 1})
		}
		// The brace is expected on the same line as ingress/egress (the near-universal HCL style); a
		// brace on the following line would miss attribution, acceptable for this depth heuristic.
		if m := tfSubBlockOpen.FindStringSubmatch(trimmed); m != nil && strings.Contains(trimmed, "{") {
			subBlock, subOpenDepth = m[1], depth
		}
		curType := ""
		if len(stack) > 0 {
			curType = stack[len(stack)-1].typ
			stack[len(stack)-1].body.WriteString(trimmed)
			stack[len(stack)-1].body.WriteByte('\n')
		}
		out = append(out, tfLineRules(rel, i+1, trimmed, curType, subBlock)...)

		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth < 0 {
			depth = 0
		}
		if subBlock != "" && depth <= subOpenDepth {
			subBlock = "" // the ingress/egress sub-block closed
		}
		for len(stack) > 0 && depth <= stack[len(stack)-1].depth {
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			out = append(out, tfBlockRules(rel, f.typ, f.start, f.body.String())...) // block-level missing-setting rules
			if f.typ == "aws_s3_bucket_versioning" && strings.Contains(f.body.String(), `"Enabled"`) {
				sawEnabledVersioning = true
			}
		}
	}
	// Provider v4+ manages versioning in a separate aws_s3_bucket_versioning resource, so an aws_s3_bucket
	// block legitimately omits an inline versioning block. When the file has an Enabled versioning resource,
	// drop the bucket-origin "no versioning" finding to avoid a false positive on the modern split style.
	if sawEnabledVersioning {
		out = filterOutBucketVersioning(out)
	}
	return out
}

// filterOutBucketVersioning removes terraform-s3-no-versioning findings that originate from an
// aws_s3_bucket block (as opposed to an aws_s3_bucket_versioning resource).
func filterOutBucketVersioning(in []ports.MisconfigRawFinding) []ports.MisconfigRawFinding {
	out := in[:0]
	for _, f := range in {
		if f.RuleID == "terraform-s3-no-versioning" && f.Resource == "Terraform aws_s3_bucket" {
			continue
		}
		out = append(out, f)
	}
	return out
}

// tfBlockRules applies whole-block "recommended secure setting is missing" rules to a resource block –
// the posture comprehensive scanners (tfsec/Trivy) use for cloud hardening. A rule fires when a resource
// of a given type does not contain the attribute that enables the secure behavior.
func tfBlockRules(rel, resType string, line int, body string) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	has := func(attr string) bool { return strings.Contains(body, attr) }
	add := func(rule, title string, sev shared.Severity, desc string) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: rule, Title: title, Severity: sev, Resource: "Terraform " + clip(resType), Description: desc,
		})
	}
	switch resType {
	case "aws_ecr_repository":
		if !has("image_tag_mutability") || strings.Contains(body, `image_tag_mutability = "MUTABLE"`) {
			add("terraform-ecr-mutable-tags", "ECR image tags are mutable", shared.SeverityLow,
				"The ECR repository does not set image_tag_mutability = \"IMMUTABLE\", so a pushed tag can be overwritten, breaking image provenance. Set it to IMMUTABLE.")
		}
		if !has("encryption_configuration") {
			add("terraform-ecr-no-cmk", "ECR repository not encrypted with a customer-managed key", shared.SeverityLow,
				"The ECR repository sets no encryption_configuration, so images use the default AWS-managed key. Configure a customer-managed KMS key for stronger key control.")
		}
	case "aws_cloudwatch_log_group":
		if !has("kms_key_id") {
			add("terraform-cloudwatch-unencrypted", "CloudWatch log group not encrypted with KMS", shared.SeverityLow,
				"The log group sets no kms_key_id, so logs are not encrypted with a customer-managed key. Set kms_key_id to a KMS key ARN.")
		}
	case "aws_dynamodb_table":
		if !has("server_side_encryption") {
			add("terraform-dynamodb-unencrypted", "DynamoDB table not encrypted with a CMK", shared.SeverityMedium,
				"The table declares no server_side_encryption block, so it uses the default AWS-owned key. Add server_side_encryption { enabled = true, kms_key_arn = ... }.")
		}
		if !has("point_in_time_recovery") {
			add("terraform-dynamodb-no-pitr", "DynamoDB point-in-time recovery disabled", shared.SeverityLow,
				"The table enables no point_in_time_recovery, so there is no continuous backup to restore from. Add point_in_time_recovery { enabled = true }.")
		}
	case "aws_sns_topic":
		if !has("kms_master_key_id") {
			add("terraform-sns-unencrypted", "SNS topic not encrypted", shared.SeverityMedium,
				"The SNS topic sets no kms_master_key_id, so messages are not encrypted at rest. Set kms_master_key_id to a KMS key.")
		}
	case "aws_ebs_volume":
		// A missing `encrypted` leaves the volume unencrypted at rest (the AWS default). An explicit
		// `encrypted = false` is already caught by the line-level terraform-encryption-disabled rule, so
		// only the absent-attribute case is handled here to avoid a duplicate finding.
		if !has("encrypted") {
			add("terraform-ebs-unencrypted", "EBS volume not encrypted at rest", shared.SeverityMedium,
				"The aws_ebs_volume sets no encrypted = true, so the volume is unencrypted at rest. Set encrypted = true (and kms_key_id for a customer-managed key).")
		}
	case "aws_s3_bucket":
		if !has("logging") {
			add("terraform-s3-no-logging", "S3 bucket access logging disabled", shared.SeverityLow,
				"The bucket configures no access logging, so object access is not audited. Enable server access logging (a logging block or an aws_s3_bucket_logging resource).")
		}
		if !has("versioning") {
			add("terraform-s3-no-versioning", "S3 bucket versioning not enabled", shared.SeverityLow,
				"The bucket enables no versioning, so an overwritten or deleted object cannot be recovered, weakening resilience against accidental loss and ransomware. Add a versioning block (or an aws_s3_bucket_versioning resource) with status = \"Enabled\".")
		}
	case "aws_s3_bucket_versioning":
		// The modern split resource. Anything other than an Enabled status (Suspended, Disabled, or an
		// unset status) leaves versioning off.
		if !strings.Contains(body, `"Enabled"`) {
			add("terraform-s3-no-versioning", "S3 bucket versioning not enabled", shared.SeverityLow,
				"The aws_s3_bucket_versioning resource does not set status = \"Enabled\" (it is Suspended, Disabled, or unset), so object versions are not retained. Set versioning_configuration { status = \"Enabled\" }.")
		}
	case "aws_instance", "aws_launch_template":
		if !has("metadata_options") || (has("metadata_options") && !strings.Contains(body, "required")) {
			add("terraform-imdsv2-not-required", "IMDSv2 not enforced", shared.SeverityMedium,
				"The instance does not require IMDSv2 (metadata_options { http_tokens = \"required\" }), leaving the metadata service reachable via the SSRF-prone IMDSv1. Require IMDSv2.")
		}
	}
	return out
}

// tfLineRules applies the per-line attribute checks, scoping by the enclosing resource type (and, for an
// open CIDR, the ingress/egress sub-block) where it matters.
func tfLineRules(rel string, line int, text, resType, subBlock string) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	add := func(rule, title string, sev shared.Severity, desc string) {
		res := "Terraform"
		if resType != "" {
			res = "Terraform " + clip(resType)
		}
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: rule, Title: title, Severity: sev, Resource: res, Description: desc,
		})
	}
	lower := strings.ToLower(resType)

	if tfPublicACL.MatchString(text) && (strings.Contains(lower, "s3") || strings.Contains(lower, "bucket") || resType == "") {
		add("terraform-public-bucket-acl", "Object storage granted a public ACL", shared.SeverityHigh,
			"A storage-bucket ACL is set to a public value (public-read / public-read-write / authenticated-read), exposing the bucket contents. Use a private ACL and grant access via IAM or a bucket policy.")
	}
	if tfEncFalse.MatchString(text) {
		add("terraform-encryption-disabled", "Encryption explicitly disabled", shared.SeverityHigh,
			"An encryption attribute is set to false, so data is stored unencrypted at rest. Enable encryption (and, where supported, a customer-managed key).")
	}
	if tfPublicRDS.MatchString(text) {
		add("terraform-db-publicly-accessible", "Database is publicly accessible", shared.SeverityHigh,
			"publicly_accessible = true puts the database on a public endpoint reachable from the internet. Set it to false and reach the database through a private subnet / VPC.")
	}
	if tfPabDisabled.MatchString(text) {
		add("terraform-public-access-block-disabled", "Public-access block disabled", shared.SeverityMedium,
			"An S3 public-access-block guard is set to false, weakening the account/bucket protection against accidental public exposure. Keep all four block settings true.")
	}
	if tfOpenCIDR.MatchString(text) && (strings.Contains(lower, "security_group") || strings.Contains(lower, "firewall") || strings.Contains(lower, "ingress") || resType == "") {
		if subBlock == "egress" {
			add("terraform-open-egress", "Security group egress open to the whole internet", shared.SeverityMedium,
				"An egress rule allows 0.0.0.0/0 (or ::/0), letting the workload reach any host on the internet and easing data exfiltration if it is compromised. Restrict egress to the destinations it actually needs.")
		} else {
			add("terraform-open-cidr", "Network rule open to the whole internet", shared.SeverityHigh,
				"A security-group / firewall rule allows 0.0.0.0/0 (or ::/0), exposing the port to the entire internet. Restrict the CIDR to the specific ranges that need access.")
		}
	}
	if tfIAMWildcard.MatchString(text) {
		add("terraform-iam-wildcard", "IAM policy grants a wildcard action", shared.SeverityMedium,
			"An IAM policy statement uses a wildcard action (\"*\"), granting far more than the workload needs. Scope the policy to the specific actions required.")
	}
	if m := tfSecretAttr.FindStringSubmatch(text); m != nil {
		v := strings.TrimSpace(m[2])
		if v != "" && !strings.Contains(v, "${") && !strings.HasPrefix(v, "var.") && !strings.HasPrefix(v, "data.") {
			add("terraform-plaintext-secret", "Secret hardcoded in Terraform", shared.SeverityHigh,
				"A secret-named attribute is assigned a literal value in the Terraform source, so the credential is committed to version control. Reference a variable, a secret manager, or a data source instead.")
		}
	}
	return out
}

// stripHCLComment removes a trailing line comment (# or //) that starts outside a quoted string, so
// braces/values inside comments do not affect depth tracking or rule matching.
func stripHCLComment(line string) string {
	inQ := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' && (i == 0 || line[i-1] != '\\') {
			inQ = !inQ
			continue
		}
		if inQ {
			continue
		}
		if c == '#' || (c == '/' && i+1 < len(line) && line[i+1] == '/') {
			return line[:i]
		}
	}
	return line
}
