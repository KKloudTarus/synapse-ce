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
	case "AWS::RDS::DBInstance":
		enc := mapValue(props, "StorageEncrypted")
		if v, ok := literalScalar(enc); enc == nil || (ok && v != "true") {
			add("cloudformation-rds-unencrypted", "RDS instance storage not encrypted", shared.SeverityMedium, resLine,
				"StorageEncrypted is not true, so the database volume is unencrypted at rest. Set StorageEncrypted: true (and a KMS key where policy requires one).")
		}
	case "AWS::EC2::SecurityGroup":
		// Covers the inline ingress list. Standalone AWS::EC2::SecurityGroupIngress resources and egress
		// rules are not yet checked.
		for _, ing := range seqItems(mapValue(props, "SecurityGroupIngress")) {
			cidr, ok := literalScalar(mapValue(ing, "CidrIp"))
			cidr6, ok6 := literalScalar(mapValue(ing, "CidrIpv6"))
			if (ok && cidr == "0.0.0.0/0") || (ok6 && cidr6 == "::/0") {
				add("cloudformation-open-security-group", "Security group open to the entire internet", shared.SeverityMedium, ing.Line,
					"An ingress rule allows 0.0.0.0/0 (or ::/0), exposing the port to the whole internet. Restrict CidrIp to the specific ranges that need access.")
				break // one finding per group is enough
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
