package misconfig

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// A rule that DENIES a range is the opposite of a rule that opens it. The predicate used to read the CIDR
// without the decision beside it, so a deny-all NACL entry was reported as internet exposure.
func TestTerraformNetworkRuleActionDecidesExposure(t *testing.T) {
	cases := []struct {
		name string
		tf   string
		want bool
	}{
		{
			name: "network ACL rule that denies the internet",
			tf: `resource "aws_network_acl_rule" "deny_ssh" {
  network_acl_id = "acl-1"
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}
`,
			want: false,
		},
		{
			name: "network ACL rule that allows the internet",
			tf: `resource "aws_network_acl_rule" "allow_ssh" {
  network_acl_id = "acl-1"
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}
`,
			want: true,
		},
		{
			name: "network ACL ingress sub-block that denies",
			tf: `resource "aws_network_acl" "acl" {
  vpc_id = "vpc-1"
  ingress {
    rule_no    = 100
    action     = "deny"
    protocol   = "tcp"
    from_port  = 22
    to_port    = 22
    cidr_block = "0.0.0.0/0"
  }
}
`,
			want: false,
		},
		{
			name: "google firewall deny block",
			tf: `resource "google_compute_firewall" "deny_ssh" {
  name          = "deny-ssh"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  deny {
    protocol = "tcp"
    ports    = ["22"]
  }
}
`,
			want: false,
		},
		{
			name: "google firewall allow block",
			tf: `resource "google_compute_firewall" "allow_ssh" {
  name          = "allow-ssh"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
`,
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleIDs(scan(t, map[string]string{"main.tf": tc.tf}))
			if _, ok := got["terraform-open-cidr"]; ok != tc.want {
				t.Fatalf("open-cidr reported=%v, want %v (rules %v)", ok, tc.want, keys(got))
			}
		})
	}
}

// An Azure network security rule carries its decision in `access`.
func TestTerraformAzureNsgDenyIsNotExposure(t *testing.T) {
	for _, tc := range []struct {
		access string
		want   bool
	}{{"Deny", false}, {"Allow", true}} {
		t.Run(tc.access, func(t *testing.T) {
			got := ruleIDs(scan(t, map[string]string{"main.tf": `resource "azurerm_network_security_rule" "r" {
  name                  = "ssh"
  direction             = "Inbound"
  access                = "` + tc.access + `"
  protocol              = "Tcp"
  source_address_prefix = "*"
}
`}))
			if _, ok := got["terraform-azure-nsg-open"]; ok != tc.want {
				t.Fatalf("azure-nsg-open reported=%v, want %v (rules %v)", ok, tc.want, keys(got))
			}
		})
	}
}

// An Enabled versioning resource protects the bucket it names. It used to suppress the finding for every
// bucket in the file, so a genuinely unversioned bucket beside a versioned one disappeared.
func TestTerraformVersioningBindsToItsBucket(t *testing.T) {
	findings := scan(t, map[string]string{"main.tf": `resource "aws_s3_bucket" "versioned" {
  bucket = "versioned-bucket"
}

resource "aws_s3_bucket" "unversioned" {
  bucket = "unversioned-bucket"
}

resource "aws_s3_bucket_versioning" "v" {
  bucket = aws_s3_bucket.versioned.id
  versioning_configuration {
    status = "Enabled"
  }
}
`})
	var lines []int
	for _, f := range findings {
		if f.RuleID == "terraform-s3-no-versioning" {
			lines = append(lines, f.Line)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("want exactly one no-versioning finding, for the unversioned bucket; got %v", lines)
	}
	if lines[0] != 5 {
		t.Fatalf("the finding must point at the unversioned bucket on line 5, got line %d", lines[0])
	}
}

// The association also holds across files in the same module, and a literal bucket name resolves as well
// as a reference does.
func TestTerraformVersioningBindsAcrossFilesAndByName(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{
		"buckets.tf": `resource "aws_s3_bucket" "b" {
  bucket = "data-bucket"
}
`,
		"versioning.tf": `resource "aws_s3_bucket_versioning" "v" {
  bucket = "data-bucket"
  versioning_configuration {
    status = "Enabled"
  }
}
`,
	}))
	if _, ok := got["terraform-s3-no-versioning"]; ok {
		t.Fatalf("a versioning resource naming the bucket must bind to it, got %v", keys(got))
	}
}

// A versioning resource whose bucket reference does not resolve suppresses nothing when the module holds
// more than one bucket: suppressing across unrelated buckets is how a real finding is lost.
func TestTerraformUnresolvedVersioningReferenceSuppressesNothing(t *testing.T) {
	findings := scan(t, map[string]string{"main.tf": `resource "aws_s3_bucket" "a" {
  bucket = "a"
}

resource "aws_s3_bucket" "b" {
  bucket = "b"
}

resource "aws_s3_bucket_versioning" "v" {
  bucket = data.external.pick.result.bucket
  versioning_configuration {
    status = "Enabled"
  }
}
`})
	n := 0
	for _, f := range findings {
		if f.RuleID == "terraform-s3-no-versioning" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("an unresolved versioning reference must suppress nothing across two buckets, got %d findings", n)
	}
}

// policyFinding returns the finding for ruleID, or fails.
func policyFinding(t *testing.T, fs []ports.MisconfigRawFinding, ruleID string) ports.MisconfigRawFinding {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == ruleID {
			return f
		}
	}
	t.Fatalf("expected %q, got %v", ruleID, ruleIDs(fs))
	return ports.MisconfigRawFinding{}
}

func noRule(t *testing.T, fs []ports.MisconfigRawFinding, ruleID string) {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == ruleID {
			t.Fatalf("must not report %q: %s", ruleID, f.Description)
		}
	}
}

// bucketPolicy wraps a statement body in a bucket policy resource.
func bucketPolicy(statement string) string {
	return `resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [` + statement + `]
  })
}
`
}

// A wildcard token is assessed with the Effect, the condition, and the policy kind beside it, never alone.
func TestTerraformPolicyStatementsAreAssessedTogether(t *testing.T) {
	cases := []struct {
		name       string
		tf         string
		wantRule   string
		wantSev    shared.Severity
		wantAbsent []string
		wantText   string
	}{
		{
			name:     "unconstrained wildcard principal on a bucket policy",
			tf:       bucketPolicy(`{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "arn:aws:s3:::b/*" }`),
			wantRule: "terraform-wildcard-principal",
			wantSev:  shared.SeverityHigh,
		},
		{
			name:       "organization condition restricts the caller set",
			tf:         bucketPolicy(`{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "arn:aws:s3:::b/*", Condition = { StringEquals = { "aws:PrincipalOrgID" = "o-abc123" } } }`),
			wantAbsent: []string{"terraform-wildcard-principal"},
		},
		{
			name:     "a condition on an unrelated key restricts nothing about the caller",
			tf:       bucketPolicy(`{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "arn:aws:s3:::b/*", Condition = { StringEquals = { "s3:prefix" = "public/" } } }`),
			wantRule: "terraform-wildcard-principal",
			wantSev:  shared.SeverityHigh,
		},
		{
			name: "an unresolved organization value is unknown, not safe",
			tf: `variable "org" {}
resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "arn:aws:s3:::b/*", Condition = { StringEquals = { "aws:PrincipalOrgID" = var.org } } }]
  })
}
`,
			wantRule: "terraform-wildcard-principal",
			wantSev:  shared.SeverityMedium,
			wantText: "UNKNOWN",
		},
		{
			name:       "a Deny statement never exposes",
			tf:         bucketPolicy(`{ Effect = "Deny", Principal = "*", Action = "s3:*", Resource = "*" }`),
			wantAbsent: []string{"terraform-wildcard-principal", "terraform-iam-wildcard-resource", "terraform-iam-wildcard"},
		},
		{
			name: "an identity policy has no principal to assess",
			tf: `resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "*" }] })
}
`,
			wantRule:   "terraform-iam-wildcard-resource",
			wantSev:    shared.SeverityHigh,
			wantAbsent: []string{"terraform-wildcard-principal"},
		},
		{
			name: "a scoped principal ARN is not every principal",
			tf: `resource "aws_kms_key" "k" {
  enable_key_rotation = true
  policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = { AWS = "arn:aws:iam::123456789012:role/app-*" }, Action = "kms:Decrypt", Resource = "arn:aws:kms:::key/x" }] })
}
`,
			wantAbsent: []string{"terraform-wildcard-principal"},
		},
		{
			name: "a VPC endpoint policy is a boundary, not a grant",
			tf: `resource "aws_vpc_endpoint" "e" {
  vpc_id       = "vpc-1"
  service_name = "com.amazonaws.ap-southeast-1.s3"
  policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = "*", Action = "*", Resource = "*" }] })
}
`,
			wantRule: "terraform-wildcard-principal",
			wantSev:  shared.SeverityMedium,
			wantText: "does not by itself grant access",
		},
		{
			name: "a federated AssumeRole statement is not restricted by a principal org",
			tf: `resource "aws_vpc_endpoint" "sts" {
  vpc_id       = "vpc-1"
  service_name = "com.amazonaws.ap-southeast-1.sts"
  policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = "*", Action = ["sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML"], Resource = "*" }] })
}
`,
			wantRule: "terraform-iam-wildcard-resource",
			wantSev:  shared.SeverityMedium,
			wantText: "aws:ResourceOrgID",
		},
		{
			name: "a federated statement scoped by the destination organization is restricted",
			tf: `resource "aws_vpc_endpoint" "sts" {
  vpc_id       = "vpc-1"
  service_name = "com.amazonaws.ap-southeast-1.sts"
  policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = "*", Action = ["sts:AssumeRoleWithWebIdentity"], Resource = "*", Condition = { StringEquals = { "aws:ResourceOrgID" = "o-abc123" } } }] })
}
`,
			wantAbsent: []string{"terraform-iam-wildcard-resource"},
		},
		{
			name: "a role trust policy assesses the principal and not the resource",
			tf: `resource "aws_iam_role" "r" {
  name = "app"
  assume_role_policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = "*", Action = "sts:AssumeRole" }] })
}
`,
			wantRule:   "terraform-wildcard-principal",
			wantSev:    shared.SeverityHigh,
			wantAbsent: []string{"terraform-iam-wildcard-resource"},
		},
		{
			name: "the HCL wildcard action form is recognised",
			tf: `resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "arn:aws:s3:::b/*" }] })
}
`,
			wantRule: "terraform-iam-wildcard",
			wantSev:  shared.SeverityMedium,
		},
		{
			name: "the JSON array wildcard forms are recognised",
			tf: `resource "aws_iam_policy" "p" {
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}]
}
EOF
}
`,
			wantRule: "terraform-iam-wildcard",
			wantSev:  shared.SeverityMedium,
		},
		{
			name: "a policy document data source is assessed as the document it produces",
			tf: `data "aws_iam_policy_document" "open" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = data.aws_iam_policy_document.open.json
}
`,
			wantRule: "terraform-wildcard-principal",
			wantSev:  shared.SeverityHigh,
		},
		{
			name: "a policy document data source restricted by the organization is not public",
			tf: `data "aws_iam_policy_document" "org" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::b/*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = ["o-abc123"]
    }
  }
}

resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = data.aws_iam_policy_document.org.json
}
`,
			wantAbsent: []string{"terraform-wildcard-principal"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := scan(t, map[string]string{"main.tf": tc.tf})
			for _, absent := range tc.wantAbsent {
				noRule(t, fs, absent)
			}
			if tc.wantRule == "" {
				return
			}
			got := policyFinding(t, fs, tc.wantRule)
			if got.Severity != tc.wantSev {
				t.Fatalf("%s severity = %v, want %v (%s)", tc.wantRule, got.Severity, tc.wantSev, got.Description)
			}
			if tc.wantText != "" && !strings.Contains(got.Description, tc.wantText) {
				t.Fatalf("description must explain %q, got %q", tc.wantText, got.Description)
			}
		})
	}
}

// A policy the evaluator could not read keeps its literal detection and is reported as unresolved, so an
// unreadable document never passes as a clean one.
func TestTerraformUnreadablePolicyKeepsLiteralDetection(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{"main.tf": `resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = data.external.generated.result.policy
}

resource "aws_iam_policy" "p2" {
  policy = <<EOF
{
  "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "${local.unknown_suffix}"}]
}
EOF
}
`}))
	if _, ok := got["terraform-iam-wildcard"]; !ok {
		t.Fatalf("a policy that did not evaluate must keep its literal detection, got %v", keys(got))
	}
}
