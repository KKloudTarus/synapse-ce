package misconfig

import (
	"bytes"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// cfnSecretKeyRe matches property names that conventionally hold a secret. Only the KEY is ever emitted
// in a finding, never the value (golden-rule-3: a scanner must not copy a secret into its output).
var cfnSecretKeyRe = regexp.MustCompile(`(?i)(password|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)`)

// scanCloudFormation parses an AWS CloudFormation template (YAML or JSON, both of which are valid YAML)
// and flags insecure resource settings. It walks the resource tree via yaml.Node so CloudFormation
// short-form intrinsics (!Ref, !Sub, !GetAtt, ...) are tolerated: a tagged scalar keeps its value and
// simply does not match a literal check. Best-effort: a parse error or an unexpected shape is a per-file
// skip, never a scan failure.
func scanCloudFormation(rel string, data []byte) []ports.MisconfigRawFinding {
	// Refuse pathologically deep documents before decoding, matching the Kubernetes path: yaml.v3 recurses
	// per nesting level with no depth cap, so a crafted deep document (flow or compact block) would overflow
	// the goroutine stack. tooDeepYAML makes that a per-file skip.
	if tooDeepYAML(data) {
		return nil
	}
	var root yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&root); err != nil {
		return nil // empty or malformed: skip this file
	}
	doc := documentRoot(&root)
	resources := mapValue(doc, "Resources")
	if resources == nil || resources.Kind != yaml.MappingNode {
		return nil
	}

	var out []ports.MisconfigRawFinding
	for i := 0; i+1 < len(resources.Content); i += 2 {
		logicalID := resources.Content[i].Value
		res := resources.Content[i+1]
		if res.Kind != yaml.MappingNode {
			continue
		}
		typeNode := mapValue(res, "Type")
		if typeNode == nil || typeNode.Kind != yaml.ScalarNode {
			continue
		}
		out = append(out, cfnResourceRules(rel, res.Line, logicalID, typeNode.Value, mapValue(res, "Properties"))...)
	}
	return out
}

func cfnResourceRules(rel string, resLine int, logicalID, resType string, props *yaml.Node) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding
	resource := "CloudFormation " + clip(resType) + " " + clip(logicalID)
	add := func(rule, title string, sev shared.Severity, atLine int, desc string) {
		if atLine <= 0 {
			atLine = resLine
		}
		out = append(out, ports.MisconfigRawFinding{
			File: rel, Line: atLine, RuleID: rule, Title: title, Severity: sev, Resource: resource, Description: desc,
		})
	}

	// secureBoolNotTrue reports whether a boolean security property is missing or explicitly not "true".
	// A dynamic value (intrinsic/parameter) is treated as present (not flagged) to keep false positives low.
	secureBoolNotTrue := func(key string) bool {
		n := mapValue(props, key)
		if n == nil {
			return true
		}
		v, ok := literalScalar(n)
		return ok && !strings.EqualFold(v, "true")
	}
	// litTrue reports whether a property is the literal boolean true.
	litTrue := func(n *yaml.Node) bool {
		v, ok := literalScalar(n)
		return ok && strings.EqualFold(v, "true")
	}

	switch resType {
	case "AWS::S3::Bucket":
		if acl := mapValue(props, "AccessControl"); acl != nil {
			if v, ok := literalScalar(acl); ok && (v == "PublicRead" || v == "PublicReadWrite") {
				add("cloudformation-public-bucket-acl", "S3 bucket granted a public ACL", shared.SeverityHigh, acl.Line,
					"AccessControl is "+clip(v)+", which exposes the bucket publicly. Remove the public ACL, block public access, and use a bucket policy scoped to specific principals.")
			}
		}
		if mapValue(props, "BucketEncryption") == nil {
			add("cloudformation-s3-no-encryption", "S3 bucket without default encryption", shared.SeverityMedium, resLine,
				"No BucketEncryption is configured, so objects are not encrypted at rest by default. Add a BucketEncryption block (SSE-S3 or SSE-KMS).")
		}
		if mapValue(props, "PublicAccessBlockConfiguration") == nil {
			add("cloudformation-s3-no-public-access-block", "S3 bucket without a public-access block", shared.SeverityMedium, resLine,
				"No PublicAccessBlockConfiguration is set, so a later ACL or policy can expose the bucket publicly. Add a PublicAccessBlockConfiguration with all four settings true.")
		}
		if mapValue(props, "LoggingConfiguration") == nil {
			add("cloudformation-s3-no-logging", "S3 bucket access logging disabled", shared.SeverityLow, resLine,
				"No LoggingConfiguration is set, so object access is not audited. Enable server access logging to a dedicated log bucket.")
		}
		if vc := mapValue(props, "VersioningConfiguration"); vc == nil {
			add("cloudformation-s3-no-versioning", "S3 bucket versioning not enabled", shared.SeverityLow, resLine,
				"No VersioningConfiguration is set, so an overwritten or deleted object cannot be recovered. Add VersioningConfiguration with Status: Enabled.")
		} else if s, ok := literalScalar(mapValue(vc, "Status")); ok && s != "Enabled" {
			add("cloudformation-s3-no-versioning", "S3 bucket versioning not enabled", shared.SeverityLow, vc.Line,
				"VersioningConfiguration Status is not Enabled, so an overwritten or deleted object cannot be recovered. Set Status: Enabled.")
		}
	case "AWS::RDS::DBInstance":
		enc := mapValue(props, "StorageEncrypted")
		if v, ok := literalScalar(enc); enc == nil || (ok && v != "true") {
			add("cloudformation-rds-unencrypted", "RDS instance storage not encrypted", shared.SeverityMedium, resLine,
				"StorageEncrypted is not true, so the database volume is unencrypted at rest. Set StorageEncrypted: true (and a KMS key where policy requires one).")
		}
		if pub := mapValue(props, "PubliclyAccessible"); litTrue(pub) {
			add("cloudformation-rds-public", "RDS instance is publicly accessible", shared.SeverityHigh, pub.Line,
				"PubliclyAccessible is true, putting the database on a public endpoint reachable from the internet. Set it to false and reach it through a private subnet/VPC.")
		}
		if secureBoolNotTrue("DeletionProtection") {
			add("cloudformation-rds-no-deletion-protection", "RDS deletion protection disabled", shared.SeverityLow, resLine,
				"DeletionProtection is not true, so the instance can be deleted without removing an explicit guard. Set DeletionProtection: true.")
		}
		if br := mapValue(props, "BackupRetentionPeriod"); br != nil {
			if v, ok := literalScalar(br); ok && v == "0" {
				add("cloudformation-rds-no-backup", "RDS automated backups disabled", shared.SeverityLow, br.Line,
					"BackupRetentionPeriod is 0, disabling automated backups, so there is no point-in-time recovery after data loss. Set a non-zero retention period (for example 7).")
			}
		}
	case "AWS::EC2::SecurityGroup":
		for _, ing := range seqItems(mapValue(props, "SecurityGroupIngress")) {
			cidr, ok := literalScalar(mapValue(ing, "CidrIp"))
			cidr6, ok6 := literalScalar(mapValue(ing, "CidrIpv6"))
			if (ok && cidr == "0.0.0.0/0") || (ok6 && cidr6 == "::/0") {
				add("cloudformation-open-security-group", "Security group open to the entire internet", shared.SeverityMedium, ing.Line,
					"An ingress rule allows 0.0.0.0/0 (or ::/0), exposing the port to the whole internet. Restrict CidrIp to the specific ranges that need access.")
				break // one finding per group is enough
			}
		}
		for _, eg := range seqItems(mapValue(props, "SecurityGroupEgress")) {
			cidr, ok := literalScalar(mapValue(eg, "CidrIp"))
			cidr6, ok6 := literalScalar(mapValue(eg, "CidrIpv6"))
			if (ok && cidr == "0.0.0.0/0") || (ok6 && cidr6 == "::/0") {
				add("cloudformation-sg-open-egress", "Security group egress open to the whole internet", shared.SeverityLow, eg.Line,
					"An egress rule allows 0.0.0.0/0 (or ::/0), letting the workload reach any host and easing data exfiltration if it is compromised. Restrict egress to the destinations it needs.")
				break
			}
		}
	case "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role":
		for _, pd := range cfnPolicyDocuments(props) {
			flagged := false
			for _, st := range seqItems(mapValue(pd, "Statement")) {
				if eff, ok := literalScalar(mapValue(st, "Effect")); ok && !strings.EqualFold(eff, "Allow") {
					continue
				}
				if hasWildcard(mapValue(st, "Action"), true) || hasWildcard(mapValue(st, "Resource"), false) {
					add("cloudformation-iam-wildcard", "IAM policy grants a wildcard action or resource", shared.SeverityMedium, st.Line,
						"An Allow statement uses \"*\" for Action or Resource, granting overly broad permissions. Scope both to the minimum required.")
					flagged = true
					break
				}
			}
			if flagged {
				break
			}
		}
	case "AWS::EC2::Volume":
		if secureBoolNotTrue("Encrypted") {
			add("cloudformation-ebs-unencrypted", "EBS volume not encrypted at rest", shared.SeverityMedium, resLine,
				"Encrypted is not true, so the volume is unencrypted at rest. Set Encrypted: true (and a KmsKeyId for a customer-managed key).")
		}
	case "AWS::SQS::Queue":
		if mapValue(props, "KmsMasterKeyId") == nil && secureBoolNotTrue("SqsManagedSseEnabled") {
			add("cloudformation-sqs-no-encryption", "SQS queue not encrypted at rest", shared.SeverityLow, resLine,
				"The queue enables no server-side encryption (neither KmsMasterKeyId nor SqsManagedSseEnabled), so messages are not encrypted at rest. Enable SSE.")
		}
		if mapValue(props, "RedrivePolicy") == nil {
			add("cloudformation-sqs-no-dlq", "SQS queue has no dead-letter queue", shared.SeverityLow, resLine,
				"No RedrivePolicy is set, so messages that repeatedly fail processing are lost instead of moved to a dead-letter queue. Configure a RedrivePolicy.")
		}
	case "AWS::SNS::Topic":
		if mapValue(props, "KmsMasterKeyId") == nil {
			add("cloudformation-sns-no-encryption", "SNS topic not encrypted at rest", shared.SeverityLow, resLine,
				"No KmsMasterKeyId is set, so topic messages are not encrypted at rest. Set KmsMasterKeyId to a KMS key.")
		}
	case "AWS::DynamoDB::Table":
		if mapValue(props, "SSESpecification") == nil {
			add("cloudformation-dynamodb-unencrypted", "DynamoDB table not encrypted with a CMK", shared.SeverityLow, resLine,
				"No SSESpecification is set, so the table uses the default AWS-owned key. Add SSESpecification with SSEEnabled: true and a KMS key.")
		}
	case "AWS::EFS::FileSystem":
		if secureBoolNotTrue("Encrypted") {
			add("cloudformation-efs-unencrypted", "EFS file system not encrypted at rest", shared.SeverityMedium, resLine,
				"Encrypted is not true, so the file system is unencrypted at rest. Set Encrypted: true.")
		}
	case "AWS::Redshift::Cluster":
		if secureBoolNotTrue("Encrypted") {
			add("cloudformation-redshift-unencrypted", "Redshift cluster not encrypted at rest", shared.SeverityHigh, resLine,
				"Encrypted is not true, so the data warehouse is unencrypted at rest. Set Encrypted: true (and a KmsKeyId for a customer-managed key).")
		}
	case "AWS::Lambda::Permission":
		if p := mapValue(props, "Principal"); p != nil {
			if v, ok := literalScalar(p); ok && v == "*" {
				add("cloudformation-lambda-public", "Lambda permission open to any principal", shared.SeverityHigh, p.Line,
					"Principal is \"*\", allowing any principal to invoke the function. Restrict Principal to the specific service or account and set SourceArn/SourceAccount.")
			}
		}
	case "AWS::Lambda::Function":
		if mapValue(props, "DeadLetterConfig") == nil {
			add("cloudformation-lambda-no-dlq", "Lambda function has no dead-letter queue", shared.SeverityLow, resLine,
				"No DeadLetterConfig is set, so asynchronous invocations that exhaust retries are dropped silently. Configure a DeadLetterConfig target (SQS or SNS).")
		}
	case "AWS::EKS::Cluster":
		// EndpointPublicAccess defaults to true, so a missing key is the same insecure state as an explicit
		// true. Fire unless it is explicitly false (a dynamic !Ref value is left alone to avoid a false positive).
		ep := mapValue(mapValue(props, "ResourcesVpcConfig"), "EndpointPublicAccess")
		if epv, ok := literalScalar(ep); ep == nil || (ok && !strings.EqualFold(epv, "false")) {
			add("cloudformation-eks-public-endpoint", "EKS API endpoint publicly accessible", shared.SeverityMedium, resLine,
				"EndpointPublicAccess is not disabled (it defaults to true), so the Kubernetes API server is reachable from the internet. Set EndpointPublicAccess: false, or restrict it with PublicAccessCidrs and enable private access.")
		}
	case "AWS::CloudTrail::Trail":
		if secureBoolNotTrue("EnableLogFileValidation") {
			add("cloudformation-cloudtrail-no-log-validation", "CloudTrail log file validation disabled", shared.SeverityLow, resLine,
				"EnableLogFileValidation is not true, so tampering with delivered log files cannot be detected. Set EnableLogFileValidation: true.")
		}
		if secureBoolNotTrue("IsMultiRegionTrail") {
			add("cloudformation-cloudtrail-not-multi-region", "CloudTrail is not multi-region", shared.SeverityLow, resLine,
				"IsMultiRegionTrail is not true, so activity in other regions is not captured, leaving audit gaps. Set IsMultiRegionTrail: true.")
		}
	case "AWS::ApiGateway::Stage":
		if mapValue(props, "AccessLogSetting") == nil {
			add("cloudformation-apigw-no-logging", "API Gateway stage access logging disabled", shared.SeverityLow, resLine,
				"No AccessLogSetting is configured, so API requests are not logged for audit or troubleshooting. Add AccessLogSetting with a DestinationArn and Format.")
		}
	case "AWS::ApiGateway::Method":
		if at := mapValue(props, "AuthorizationType"); at != nil {
			if v, ok := literalScalar(at); ok && v == "NONE" {
				add("cloudformation-api-no-auth", "API Gateway method has no authorization", shared.SeverityMedium, at.Line,
					"AuthorizationType is NONE, so the endpoint is callable without authentication. Use an authorizer (IAM, Cognito, or a Lambda authorizer) unless the route is intentionally public.")
			}
		}
	case "AWS::EC2::Instance":
		// HttpTokens defaults to "optional" (IMDSv1 allowed), so both a missing MetadataOptions block and a
		// present block without HttpTokens are insecure. A dynamic !Ref HttpTokens is left alone.
		mo := mapValue(props, "MetadataOptions")
		ht := mapValue(mo, "HttpTokens")
		htv, htok := literalScalar(ht)
		if mo == nil || ht == nil || (htok && htv != "required") {
			add("cloudformation-ec2-imdsv2", "IMDSv2 not enforced", shared.SeverityMedium, resLine,
				"MetadataOptions does not require IMDSv2 (HttpTokens: required), leaving the metadata service reachable via the SSRF-prone IMDSv1. Set HttpTokens: required.")
		}
	case "AWS::Logs::LogGroup":
		if mapValue(props, "RetentionInDays") == nil {
			add("cloudformation-log-retention-missing", "Log group has no retention policy", shared.SeverityLow, resLine,
				"No RetentionInDays is set, so logs are kept forever, growing cost and audit surface indefinitely. Set RetentionInDays to a bounded value.")
		}
	case "AWS::CloudFront::Distribution":
		dc := mapValue(props, "DistributionConfig")
		if dc != nil && mapValue(dc, "Logging") == nil {
			add("cloudformation-cloudfront-no-logging", "CloudFront access logging disabled", shared.SeverityLow, resLine,
				"The DistributionConfig has no Logging block, so viewer requests are not logged for audit. Add a Logging block writing to an S3 bucket.")
		}
		if dc != nil && mapValue(dc, "DefaultRootObject") == nil {
			add("cloudformation-cloudfront-no-default-root", "CloudFront has no default root object", shared.SeverityLow, resLine,
				"The DistributionConfig sets no DefaultRootObject, so a request to the root path can list or expose unintended content. Set DefaultRootObject (for example index.html).")
		}
	case "AWS::KMS::Key":
		if secureBoolNotTrue("EnableKeyRotation") {
			add("cloudformation-kms-no-rotation", "KMS key rotation not enabled", shared.SeverityLow, resLine,
				"EnableKeyRotation is not true, so the key material is never rotated automatically, lengthening the window in which a compromised key stays valid. Set EnableKeyRotation: true.")
		}
	case "AWS::ECR::Repository":
		if mapValue(props, "ImageScanningConfiguration") == nil {
			add("cloudformation-ecr-no-scan", "ECR image scanning not enabled", shared.SeverityLow, resLine,
				"No ImageScanningConfiguration is set, so pushed images are not scanned for known vulnerabilities. Add ImageScanningConfiguration with ScanOnPush: true.")
		}
	case "AWS::S3::BucketPolicy", "AWS::SQS::QueuePolicy", "AWS::SNS::TopicPolicy":
		pd := mapValue(props, "PolicyDocument")
		for _, st := range cfnStatements(mapValue(pd, "Statement")) {
			if eff, ok := literalScalar(mapValue(st, "Effect")); ok && !strings.EqualFold(eff, "Allow") {
				continue
			}
			if cfnPrincipalWildcard(mapValue(st, "Principal")) {
				add("cloudformation-wildcard-principal", "Resource policy grants access to any principal", shared.SeverityHigh, st.Line,
					"A resource policy statement grants access to Principal \"*\", making the resource effectively public. Scope the principal to specific accounts, roles, or services and add conditions.")
				break
			}
		}
	}

	// A plaintext secret can appear on any resource; scan the top-level Properties keys.
	if props != nil && props.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(props.Content); i += 2 {
			key := props.Content[i].Value
			val := props.Content[i+1]
			if !cfnSecretKeyRe.MatchString(key) {
				continue
			}
			v, ok := literalScalar(val)
			if !ok || v == "" || strings.HasPrefix(v, "{{resolve:") {
				continue // an intrinsic, a parameter, or a dynamic reference: not a hardcoded secret
			}
			add("cloudformation-plaintext-secret", "Hardcoded secret in a resource property", shared.SeverityHigh, val.Line,
				"Property "+clip(key)+" holds a plaintext literal. Use a dynamic reference to Secrets Manager or SSM Parameter Store, or a NoEcho parameter, instead of an inline secret.")
		}
	}
	return out
}

// documentRoot unwraps a yaml document node to its single content node.
func documentRoot(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		return n.Content[0]
	}
	return n
}

// mapValue returns the value node for key in a mapping node, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// seqItems returns the items of a sequence node, or nil for anything else.
func seqItems(n *yaml.Node) []*yaml.Node {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

// literalScalar returns the value of a plain scalar node. It returns ("", false) for a missing node, a
// non-scalar, or a CloudFormation short-form intrinsic (!Ref, !Sub, !GetAtt, ...): those carry a single
// "!"-prefixed tag, unlike the core "!!" tags, so they are not treated as literals.
func literalScalar(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	if strings.HasPrefix(n.Tag, "!") && !strings.HasPrefix(n.Tag, "!!") {
		return "", false
	}
	return n.Value, true
}

// cfnPolicyDocuments gathers the inline policy documents on an IAM resource: a direct PolicyDocument
// (AWS::IAM::Policy / ManagedPolicy) and each PolicyDocument under Policies (AWS::IAM::Role). The role's
// AssumeRolePolicyDocument is intentionally skipped: trust policies routinely use broad principals.
func cfnPolicyDocuments(props *yaml.Node) []*yaml.Node {
	var docs []*yaml.Node
	if pd := mapValue(props, "PolicyDocument"); pd != nil {
		docs = append(docs, pd)
	}
	for _, p := range seqItems(mapValue(props, "Policies")) {
		if pd := mapValue(p, "PolicyDocument"); pd != nil {
			docs = append(docs, pd)
		}
	}
	return docs
}

// cfnStatements returns a policy's Statement entries, tolerating both the list form (Statement: [ ... ])
// and the single-object form (Statement: { ... }), which is valid IAM/resource-policy JSON.
func cfnStatements(n *yaml.Node) []*yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.MappingNode {
		return []*yaml.Node{n}
	}
	return seqItems(n)
}

// cfnPrincipalWildcard reports whether a policy statement's Principal grants access to any principal:
// the scalar "*", or a map (e.g. {AWS: "*"} / {AWS: ["*"]}) whose value is or contains "*".
func cfnPrincipalWildcard(n *yaml.Node) bool {
	if n == nil {
		return false
	}
	if v, ok := literalScalar(n); ok {
		return v == "*"
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			val := n.Content[i+1]
			if v, ok := literalScalar(val); ok && v == "*" {
				return true
			}
			for _, it := range seqItems(val) {
				if v, ok := literalScalar(it); ok && v == "*" {
					return true
				}
			}
		}
	}
	return false
}

// hasWildcard reports whether a policy leaf (a scalar or a sequence of scalars) is a wildcard. For an
// action, a service-scoped wildcard like "s3:*" also counts; for a resource only a bare "*" does, since a
// resource ARN ending in "*" (e.g. "arn:aws:s3:::bucket/*") is common, legitimate scoping.
func hasWildcard(n *yaml.Node, serviceScope bool) bool {
	match := func(v string) bool {
		return v == "*" || (serviceScope && strings.HasSuffix(v, ":*"))
	}
	if v, ok := literalScalar(n); ok {
		return match(v)
	}
	for _, it := range seqItems(n) {
		if v, ok := literalScalar(it); ok && match(v) {
			return true
		}
	}
	return false
}
