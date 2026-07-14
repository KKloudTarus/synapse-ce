package misconfig

import (
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Terraform (HCL) misconfiguration checks. Rather than a full HCL
// evaluator, this tracks the enclosing `resource "TYPE" "NAME"` block
// by brace depth and matches high-confidence insecure literal values or
// missing secure settings.
//
// Dynamic values from variables, locals, data sources, modules, and
// expressions are not evaluated, keeping false positives low.
var (
	tfResourceOpen = regexp.MustCompile(`^\s*resource\s+"([^"]+)"\s+"([^"]*)"\s*\{`)
	tfModuleOpen   = regexp.MustCompile(`^\s*module\s+"([^"]+)"\s*\{`)
	tfPublicACL    = regexp.MustCompile(`(?i)\bacl\s*=\s*"(public-read|public-read-write|authenticated-read)"`)
	tfEncFalse     = regexp.MustCompile(`(?i)\b(encrypted|storage_encrypted|encryption)\s*=\s*false\b`)
	tfPublicRDS    = regexp.MustCompile(`(?i)\bpublicly_accessible\s*=\s*true\b`)
	tfPabDisabled  = regexp.MustCompile(`(?i)\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b`)
	tfOpenCIDR     = regexp.MustCompile(`"0\.0\.0\.0/0"|"::/0"`)
	tfSubBlockOpen = regexp.MustCompile(`^(ingress|egress)\b`)
	tfIAMWildcard  = regexp.MustCompile(`(?i)("Action"\s*:\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\])`)
	tfSecretAttr   = regexp.MustCompile(`(?i)\b(password|secret|secret_key|access_key|private_key|api_key|token)\s*=\s*"([^"]+)"`)

	// authz — public access / over-broad grants (some case-sensitive to separate IAM "Principal" from
	// the lower-case `principal` attribute on aws_lambda_permission).
	tfResourceWildcard  = regexp.MustCompile(`("Resource"\s*:\s*"\*"|\bResource\s*=\s*"\*"|\bresources\s*=\s*\[\s*"\*"\s*\])`)
	tfWildcardPrincipal = regexp.MustCompile(`("Principal"\s*:\s*"?\*|\bPrincipal\s*=\s*"\*"|\bPrincipal"?\s*[:=]\s*\{[^}]*\*|\bidentifiers\s*=\s*\[\s*"\*"\s*\])`)
	tfLambdaPublic      = regexp.MustCompile(`\bprincipal\s*=\s*"\*"`)
	tfApiNoAuth         = regexp.MustCompile(`\bauthorization\s*=\s*"NONE"`)
	tfAzureContainerPub = regexp.MustCompile(`\bcontainer_access_type\s*=\s*"(blob|container)"`)
	tfAzurePublicNet    = regexp.MustCompile(`\bpublic_network_access_enabled\s*=\s*true\b`)
	tfGcpPublicMember   = regexp.MustCompile(`"(allUsers|allAuthenticatedUsers)"`)
	tfEksPublic         = regexp.MustCompile(`\bendpoint_public_access\s*=\s*true\b`)
	tfAzureNsgOpen      = regexp.MustCompile(`\bsource_address_prefix\s*=\s*"(\*|0\.0\.0\.0/0)"`)
	tfAdminPolicy       = regexp.MustCompile(`AdministratorAccess`)

	// crypto — in-transit / at-rest weaknesses expressed as explicit insecure values.
	tfCloudfrontHTTP  = regexp.MustCompile(`\bviewer_protocol_policy\s*=\s*"allow-all"`)
	tfAzureHTTPSFalse = regexp.MustCompile(`\b(enable_https_traffic_only|https_traffic_only_enabled)\s*=\s*false\b`)
	tfAzureMinTLS     = regexp.MustCompile(`\bmin_tls_version\s*=\s*"TLS1_[01]"`)

	// hotspot / bugs — explicit weak values.
	tfRdsNoBackup    = regexp.MustCompile(`\bbackup_retention_period\s*=\s*0\b`)
	tfRdsSingleAz    = regexp.MustCompile(`\bmulti_az\s*=\s*false\b`)
	tfInstancePublic = regexp.MustCompile(`\bassociate_public_ip_address\s*=\s*true\b`)

	// maint — provisioners, drift suppression, module sourcing.
	tfLocalExec    = regexp.MustCompile(`\bprovisioner\s+"local-exec"`)
	tfRemoteExec   = regexp.MustCompile(`\bprovisioner\s+"remote-exec"`)
	tfIgnoreAll    = regexp.MustCompile(`\bignore_changes\s*=\s*all\b`)
	tfModuleSource = regexp.MustCompile(`\bsource\s*=\s*"([^"]+)"`)
	tfModuleRef    = regexp.MustCompile(`\bversion\s*=`)
	// tfRegistryModule matches a Terraform-registry source shape (NAMESPACE/NAME/PROVIDER, optionally
	// with a //submodule), which is the only source kind that takes a version constraint.
	tfRegistryModule = regexp.MustCompile(`^[0-9A-Za-z._-]+/[0-9A-Za-z._-]+/[0-9A-Za-z._-]+(//.+)?$`)
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
		if m := tfModuleOpen.FindStringSubmatch(trimmed); m != nil {
			stack = append(stack, &frame{typ: "module:" + m[1], name: m[1], depth: depth, start: i + 1})
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
			if strings.HasPrefix(f.typ, "module:") {
				out = append(out, tfModuleRules(rel, f.start, f.body.String())...)
			} else {
				out = append(out, tfBlockRules(rel, f.typ, f.start, f.body.String())...) // block-level missing-setting rules
			}
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
	case "aws_db_instance":
		value, present := tfDirectAttribute(
			body,
			"deletion_protection",
		)

		if !present || value == "false" {
			add(
				"terraform-rds-deletion-protection-disabled",
				"RDS deletion protection is not enabled",
				shared.SeverityLow,
				"The RDS DB instance does not enable deletion protection, so it can be deleted without first removing an explicit protection control. Set deletion_protection = true to reduce the risk of accidental or unauthorized deletion.",
			)
		}
		if !has("storage_encrypted") {
			add("terraform-rds-no-encryption", "RDS storage not encrypted at rest", shared.SeverityHigh,
				"The RDS DB instance sets no storage_encrypted = true, so the underlying storage and backups are unencrypted at rest. Set storage_encrypted = true (and kms_key_id for a customer-managed key).")
		}
		if !has("iam_database_authentication_enabled") {
			add("terraform-rds-iam-auth-disabled", "RDS IAM database authentication disabled", shared.SeverityLow,
				"The RDS DB instance does not enable IAM database authentication, so access relies solely on static database passwords. Set iam_database_authentication_enabled = true to use short-lived IAM credentials.")
		}
	case "aws_ecr_repository":
		if !has("image_tag_mutability") || strings.Contains(body, `image_tag_mutability = "MUTABLE"`) {
			add("terraform-ecr-mutable-tags", "ECR image tags are mutable", shared.SeverityLow,
				"The ECR repository does not set image_tag_mutability = \"IMMUTABLE\", so a pushed tag can be overwritten, breaking image provenance. Set it to IMMUTABLE.")
		}
		if !has("encryption_configuration") {
			add("terraform-ecr-no-cmk", "ECR repository not encrypted with a customer-managed key", shared.SeverityLow,
				"The ECR repository sets no encryption_configuration, so images use the default AWS-managed key. Configure a customer-managed KMS key for stronger key control.")
		}
		if !has("image_scanning_configuration") {
			add("terraform-ecr-no-scan", "ECR image scanning not enabled", shared.SeverityLow,
				"The ECR repository declares no image_scanning_configuration, so pushed images are not scanned for known vulnerabilities. Add image_scanning_configuration { scan_on_push = true }.")
		}
	case "aws_cloudwatch_log_group":
		if !has("kms_key_id") {
			add("terraform-cloudwatch-unencrypted", "CloudWatch log group not encrypted with KMS", shared.SeverityLow,
				"The log group sets no kms_key_id, so logs are not encrypted with a customer-managed key. Set kms_key_id to a KMS key ARN.")
		}
		if !has("retention_in_days") {
			add("terraform-cloudwatch-no-retention", "CloudWatch log group has no retention", shared.SeverityLow,
				"The log group sets no retention_in_days, so logs are kept forever, growing cost and audit surface indefinitely. Set retention_in_days to a bounded value.")
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
	case "aws_kms_key":
		if !has("enable_key_rotation") {
			add("terraform-kms-no-rotation", "KMS key rotation not enabled", shared.SeverityLow,
				"The KMS key sets no enable_key_rotation = true, so the key material is never rotated automatically, lengthening the window in which a compromised key stays valid. Set enable_key_rotation = true.")
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
	case "aws_efs_file_system":
		if !has("encrypted") {
			add("terraform-efs-unencrypted", "EFS file system not encrypted at rest", shared.SeverityMedium,
				"The aws_efs_file_system sets no encrypted = true, so the file system is unencrypted at rest. Set encrypted = true (and kms_key_id for a customer-managed key).")
		}
	case "aws_sqs_queue":
		if !has("kms_master_key_id") && !has("sqs_managed_sse_enabled") {
			add("terraform-sqs-unencrypted", "SQS queue not encrypted at rest", shared.SeverityLow,
				"The SQS queue enables no server-side encryption (neither kms_master_key_id nor sqs_managed_sse_enabled), so messages are not encrypted at rest. Enable SSE.")
		}
		if !has("redrive_policy") {
			add("terraform-sqs-no-dlq", "SQS queue has no dead-letter queue", shared.SeverityLow,
				"The SQS queue sets no redrive_policy, so messages that repeatedly fail processing are lost rather than moved to a dead-letter queue. Configure a redrive_policy pointing at a DLQ.")
		}
	case "aws_elasticache_replication_group":
		if !has("at_rest_encryption_enabled") {
			add("terraform-elasticache-unencrypted", "ElastiCache not encrypted at rest", shared.SeverityMedium,
				"The ElastiCache replication group sets no at_rest_encryption_enabled = true, so cached data is unencrypted at rest. Set at_rest_encryption_enabled = true.")
		}
	case "aws_redshift_cluster":
		if !has("encrypted") {
			add("terraform-redshift-unencrypted", "Redshift cluster not encrypted at rest", shared.SeverityHigh,
				"The Redshift cluster sets no encrypted = true, so the warehouse data is unencrypted at rest. Set encrypted = true (and a kms_key_id for a customer-managed key).")
		}
	case "aws_kinesis_stream":
		if !has("encryption_type") {
			add("terraform-kinesis-unencrypted", "Kinesis stream not encrypted at rest", shared.SeverityMedium,
				"The Kinesis stream sets no encryption_type, so records are not encrypted at rest with a KMS key. Set encryption_type = \"KMS\" and a kms_key_id.")
		}
	case "aws_cloudtrail":
		if !has("enable_log_file_validation") {
			add("terraform-cloudtrail-no-log-validation", "CloudTrail log file validation disabled", shared.SeverityLow,
				"The trail sets no enable_log_file_validation = true, so tampering with delivered log files cannot be detected. Set enable_log_file_validation = true.")
		}
		if !has("is_multi_region_trail") {
			add("terraform-cloudtrail-not-multi-region", "CloudTrail is not multi-region", shared.SeverityLow,
				"The trail sets no is_multi_region_trail = true, so activity in other regions is not captured, leaving audit gaps. Set is_multi_region_trail = true.")
		}
	case "aws_lb", "aws_alb":
		if !has("access_logs") {
			add("terraform-lb-no-access-logs", "Load balancer access logging disabled", shared.SeverityLow,
				"The load balancer declares no access_logs block, so request-level access is not recorded for audit or incident response. Add an access_logs block writing to an S3 bucket.")
		}
	case "aws_api_gateway_stage":
		if !has("access_log_settings") {
			add("terraform-apigw-no-logging", "API Gateway stage access logging disabled", shared.SeverityLow,
				"The API Gateway stage declares no access_log_settings, so requests are not logged for audit or troubleshooting. Add access_log_settings with a destination_arn and format.")
		}
	case "aws_eks_cluster":
		if !has("enabled_cluster_log_types") {
			add("terraform-eks-no-logging", "EKS control-plane logging disabled", shared.SeverityLow,
				"The EKS cluster sets no enabled_cluster_log_types, so control-plane logs (api, audit, authenticator, ...) are not exported to CloudWatch. Enable the relevant log types.")
		}
	case "aws_lambda_function":
		if !has("dead_letter_config") {
			add("terraform-lambda-no-dlq", "Lambda function has no dead-letter queue", shared.SeverityLow,
				"The Lambda function sets no dead_letter_config, so asynchronous invocations that exhaust retries are dropped silently. Configure a dead_letter_config target (SQS or SNS).")
		}
	case "aws_autoscaling_group":
		if !has("health_check_type") {
			add("terraform-asg-no-health-check", "Auto Scaling group has no health check type", shared.SeverityLow,
				"The Auto Scaling group sets no health_check_type, so it defaults to EC2 status checks and will not replace instances whose application has failed but whose VM is still running. Set health_check_type = \"ELB\" where a load balancer is attached.")
		}
	case "aws_cloudfront_distribution":
		if !has("default_root_object") {
			add("terraform-cloudfront-no-default-root", "CloudFront has no default root object", shared.SeverityLow,
				"The CloudFront distribution sets no default_root_object, so a request to the root path can list or expose unintended content. Set default_root_object (for example \"index.html\").")
		}
	case "google_compute_instance":
		if has("access_config") {
			add("terraform-gcp-compute-public-ip", "Compute instance has a public IP", shared.SeverityMedium,
				"The Compute Engine instance declares an access_config block, which assigns an external (public) IP, widening its network exposure. Remove access_config and reach the instance through a bastion, IAP, or Cloud NAT.")
		}
	case "aws_security_group":
		if !has("description") {
			add("terraform-sg-no-description", "Security group has no description", shared.SeverityInfo,
				"The security group sets no description, making its intent unclear and audits harder. Add a description explaining what the group is for.")
		}
	case "aws_default_vpc", "aws_default_security_group", "aws_default_subnet", "aws_default_route_table":
		add("terraform-default-resource-managed", "Default AWS resource managed by Terraform", shared.SeverityLow,
			"Terraform manages a default AWS resource ("+clip(resType)+"), which adopts a pre-existing, shared default rather than creating a purpose-built resource. Create explicit resources instead of adopting account defaults.")
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

	// authz — over-broad grants / public exposure expressed as explicit values.
	if tfResourceWildcard.MatchString(text) {
		add("terraform-iam-wildcard-resource", "IAM policy grants a wildcard resource", shared.SeverityHigh,
			"An IAM policy statement targets every resource (\"*\"), so the granted actions apply account-wide rather than to specific ARNs. Scope Resource to the specific ARNs the workload needs.")
	}
	if tfWildcardPrincipal.MatchString(text) {
		add("terraform-wildcard-principal", "Policy grants access to any principal", shared.SeverityHigh,
			"A resource policy grants access to any principal (\"*\"), effectively making the resource public. Scope the principal to specific accounts, roles, or services, and add conditions.")
	}
	if resType == "aws_lambda_permission" && tfLambdaPublic.MatchString(text) {
		add("terraform-lambda-public", "Lambda permission open to any principal", shared.SeverityHigh,
			"The aws_lambda_permission sets principal = \"*\", allowing any principal to invoke the function. Restrict principal to the specific service or account, and set source_arn/source_account.")
	}
	if tfApiNoAuth.MatchString(text) {
		add("terraform-api-gateway-no-auth", "API Gateway method has no authorization", shared.SeverityMedium,
			"An API Gateway method sets authorization = \"NONE\", so the endpoint is callable without authentication. Use an authorizer (IAM, Cognito, or a Lambda authorizer) unless the route is intentionally public.")
	}
	if tfAzureContainerPub.MatchString(text) {
		add("terraform-azure-storage-public-container", "Storage container allows public access", shared.SeverityHigh,
			"An Azure storage container sets container_access_type to blob or container, exposing its contents anonymously over the internet. Use \"private\" and grant access via SAS tokens or Azure AD.")
	}
	if tfAzurePublicNet.MatchString(text) {
		add("terraform-azure-public-network-access", "Public network access enabled", shared.SeverityMedium,
			"An Azure resource sets public_network_access_enabled = true, exposing its endpoint to the public internet. Set it to false and reach the resource through a private endpoint or service endpoint.")
	}
	if tfGcpPublicMember.MatchString(text) {
		add("terraform-gcp-public-iam-member", "IAM binding grants access to all users", shared.SeverityHigh,
			"A GCP IAM binding grants a role to allUsers or allAuthenticatedUsers, making the resource public. Grant the role to specific principals (users, groups, or service accounts) instead.")
	}
	if tfEksPublic.MatchString(text) {
		add("terraform-eks-public-endpoint", "EKS API endpoint publicly accessible", shared.SeverityMedium,
			"The EKS cluster sets endpoint_public_access = true, so the Kubernetes API server is reachable from the internet. Disable public access, or restrict it with public_access_cidrs and enable private access.")
	}
	if tfAzureNsgOpen.MatchString(text) {
		add("terraform-azure-nsg-open", "Network security rule open to the whole internet", shared.SeverityHigh,
			"An Azure network security rule sets source_address_prefix to \"*\" or 0.0.0.0/0, exposing the port to the entire internet. Restrict the source to the specific address ranges that need access.")
	}
	if tfAdminPolicy.MatchString(text) && (strings.Contains(text, "policy_arn") || strings.Contains(text, "managed_policy_arns")) {
		add("terraform-iam-admin-policy", "Full administrator policy attached", shared.SeverityHigh,
			"A principal is granted the AdministratorAccess managed policy, which permits every action on every resource, violating least privilege. Attach a policy scoped to the actions the principal actually needs.")
	}

	// crypto — in-transit / at-rest weaknesses expressed as explicit values.
	if tfCloudfrontHTTP.MatchString(text) {
		add("terraform-cloudfront-allow-http", "CloudFront allows plaintext HTTP", shared.SeverityMedium,
			"A CloudFront cache behavior sets viewer_protocol_policy = \"allow-all\", so viewers can connect over plaintext HTTP, exposing traffic to interception. Use \"redirect-to-https\" or \"https-only\".")
	}
	if tfAzureHTTPSFalse.MatchString(text) {
		add("terraform-azure-storage-no-https", "Storage account allows plaintext HTTP", shared.SeverityMedium,
			"An Azure storage account disables HTTPS-only traffic (enable_https_traffic_only / https_traffic_only_enabled = false), so data can be transferred over plaintext HTTP. Require HTTPS-only traffic.")
	}
	if tfAzureMinTLS.MatchString(text) {
		add("terraform-azure-storage-min-tls", "Storage account allows an outdated TLS version", shared.SeverityMedium,
			"An Azure storage account sets min_tls_version to TLS1_0 or TLS1_1, both deprecated and vulnerable. Set min_tls_version = \"TLS1_2\" (or later).")
	}

	// hotspot / bugs — explicit weak values.
	if tfRdsNoBackup.MatchString(text) {
		add("terraform-rds-no-backup", "Database automated backups disabled", shared.SeverityMedium,
			"backup_retention_period = 0 disables automated RDS backups, so there is no point-in-time recovery after data loss. Set a non-zero retention period (for example 7).")
	}
	if tfRdsSingleAz.MatchString(text) {
		add("terraform-rds-no-multi-az", "RDS instance is single-AZ", shared.SeverityLow,
			"multi_az = false leaves the RDS instance in a single availability zone, so a zone outage takes the database down with no automatic failover. Set multi_az = true for production databases.")
	}
	if tfInstancePublic.MatchString(text) {
		add("terraform-instance-public-ip", "Instance assigned a public IP", shared.SeverityMedium,
			"associate_public_ip_address = true gives the instance a public IP, exposing it directly to the internet. Place it in a private subnet and reach it through a load balancer, bastion, or NAT.")
	}

	// maint — provisioners and drift suppression.
	if tfLocalExec.MatchString(text) {
		add("terraform-local-exec-provisioner", "local-exec provisioner used", shared.SeverityLow,
			"A local-exec provisioner runs an imperative command on the machine applying Terraform, which is non-idempotent, unversioned, and outside Terraform's dependency graph. Prefer a native resource or a data source; use provisioners only as a last resort.")
	}
	if tfRemoteExec.MatchString(text) {
		add("terraform-remote-exec-provisioner", "remote-exec provisioner used", shared.SeverityLow,
			"A remote-exec provisioner runs imperative commands over SSH/WinRM on the created resource, which is non-idempotent and outside Terraform's model. Bake configuration into the image or use a configuration-management tool instead.")
	}
	if tfIgnoreAll.MatchString(text) {
		add("terraform-lifecycle-ignore-all", "lifecycle ignores all changes", shared.SeverityLow,
			"A lifecycle block sets ignore_changes = all, so Terraform stops reconciling the resource entirely and silently hides configuration drift. Ignore only the specific attributes that are managed elsewhere.")
	}
	return out
}

// tfModuleRules applies module-block hygiene rules: a module sourced from a registry should pin a
// version, and a module sourced from a git URL should pin a ref.
func tfModuleRules(rel string, line int, body string) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	m := tfModuleSource.FindStringSubmatch(body)
	if m == nil {
		return out
	}
	src := m[1]
	add := func(rule, title string, sev shared.Severity, desc string) {
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: line, RuleID: rule, Title: title, Severity: sev, Resource: "Terraform module", Description: desc,
		})
	}
	isLocal := strings.HasPrefix(src, "./") || strings.HasPrefix(src, "../")
	isGit := strings.Contains(src, "git::") || strings.HasPrefix(src, "git@") || strings.Contains(src, "github.com/") || strings.Contains(src, "bitbucket.org/") || strings.HasSuffix(src, ".git") || strings.Contains(src, ".git//")
	// A remote archive / VCS-other source (http(s), s3::, gcs::, hg::). version is not valid for these,
	// so nothing is pinned here. Checked after isGit so git::https URLs still go through the git branch.
	isRemote := strings.Contains(src, "://") || strings.HasPrefix(src, "s3::") || strings.HasPrefix(src, "gcs::") || strings.HasPrefix(src, "hg::")
	switch {
	case isLocal:
		// A local path module is versioned with the repository itself; nothing to pin.
	case isGit:
		if !strings.Contains(src, "?ref=") {
			add("terraform-module-unpinned-git", "Git-sourced module is not pinned to a ref", shared.SeverityLow,
				"The module is sourced from a git URL with no ?ref= revision, so a future apply can pull a different commit and change infrastructure unexpectedly. Pin the source to a tag or commit with ?ref=.")
		}
	case isRemote:
		// A remote archive source (http/s3/gcs/hg); version is not applicable, nothing to pin.
	case tfRegistryModule.MatchString(src):
		// A registry source (NAMESPACE/NAME/PROVIDER). It should pin a version constraint.
		if !tfModuleRef.MatchString(body) {
			add("terraform-module-no-version", "Registry module has no version constraint", shared.SeverityLow,
				"The module is sourced from a registry but sets no version, so a future apply can resolve a different, untested module release. Add a version constraint (for example version = \"~> 5.0\").")
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

func tfDirectAttribute(
	body string,
	attr string,
) (string, bool) {
	body = stripHCLBlockComments(body)
	depth := 0

	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)

		if depth == 1 {
			key, value, ok := strings.Cut(line, "=")
			if ok && strings.TrimSpace(key) == attr {
				return strings.TrimSpace(value), true
			}
		}

		depth += strings.Count(line, "{")
		depth -= strings.Count(line, "}")

		if depth < 0 {
			depth = 0
		}
	}

	return "", false
}

// stripHCLBlockComments removes /* ... */ block comments from the given string,
// except when inside a quoted string. It preserves newline characters to maintain
// line counting and structure.
func stripHCLBlockComments(body string) string {
	var out strings.Builder
	out.Grow(len(body))
	inQ := false
	inC := false
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !inC && c == '"' && (i == 0 || body[i-1] != '\\') {
			inQ = !inQ
			out.WriteByte(c)
			continue
		}
		if !inQ && !inC && c == '/' && i+1 < len(body) && body[i+1] == '*' {
			inC = true
			i++ // skip '*'
			continue
		}
		if inC {
			if c == '*' && i+1 < len(body) && body[i+1] == '/' {
				inC = false
				i++ // skip '/'
			} else if c == '\n' {
				out.WriteByte('\n')
			}
			continue
		}
		out.WriteByte(c)
	}
	return out.String()
}
