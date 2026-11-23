package misconfig

import (
	"fmt"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestTerraformPolicyDenyWithUnresolvedResources(t *testing.T) {
	for _, attached := range []bool{false, true} {
		t.Run(fmt.Sprintf("attached-%t", attached), func(t *testing.T) {
			source := `resource "aws_s3_bucket" "example" {
  bucket = "example-bucket"
}
data "aws_iam_policy_document" "bucket" {
  statement {
    sid = "DenyInsecureTransport"
    effect = "Deny"
    actions = ["s3:*"]
    resources = [aws_s3_bucket.example.arn, "${aws_s3_bucket.example.arn}/*"]
    principals {
      type = "*"
      identifiers = ["*"]
    }
    condition {
      test = "Bool"
      variable = "aws:SecureTransport"
      values = ["false"]
    }
  }
  statement {
    effect = "Allow"
    actions = ["s3:GetObject"]
    resources = ["*"]
    principals {
      type = "AWS"
      identifiers = ["*"]
    }
  }
}
`
			if attached {
				source += `resource "aws_s3_bucket_policy" "example" {
  bucket = aws_s3_bucket.example.id
  policy = data.aws_iam_policy_document.bucket.json
}
`
			}
			findings := scan(t, map[string]string{"main.tf": source})
			for _, rule := range []string{"terraform-wildcard-principal", "terraform-iam-wildcard-resource"} {
				count := 0
				for _, f := range findings {
					if f.RuleID == rule {
						count++
						if f.Line < 22 || f.Severity != shared.SeverityHigh {
							t.Errorf("expected only the Allow statement to report %s, got %+v", rule, f)
						}
					}
				}
				if count != 1 {
					t.Errorf("%s findings = %d, want 1", rule, count)
				}
			}
		})
	}
}

func TestTerraformWildcardResourceRequiresScopableAction(t *testing.T) {
	for _, tc := range []struct {
		name, actions string
		want          bool
	}{
		{"required wildcard", `["ec2:DescribeInstances", "ec2:DescribeImages"]`, false},
		{"case insensitive", `["EC2:describeinstances"]`, false},
		{"mixed scope", `["ec2:DescribeInstances", "s3:GetObject"]`, true},
		{"scopable describe", `["ec2:DescribeInstanceAttribute"]`, true},
		{"unknown action", `["ec2:DescribeFutureResources"]`, true},
		{"pattern", `["ec2:Describe*"]`, true},
		{"service wildcard", `["ec2:*"]`, true},
		{"global wildcard", `["*"]`, true},
		{"empty", `[]`, true},
		{"null", `null`, true},
		{"non-string member", `["ec2:DescribeInstances", true]`, true},
		{"unresolved", `["ec2:DescribeInstances", var.action]`, true},
	} {
		for _, form := range []string{"data", "attached", "json"} {
			t.Run(tc.name+"/"+form, func(t *testing.T) {
				source := `variable "action" {}
data "aws_iam_policy_document" "describe" {
  statement {
    actions = ` + tc.actions + `
    resources = ["*"]
  }
}
`
				if form == "attached" {
					source += `resource "aws_iam_policy" "describe" {
  policy = data.aws_iam_policy_document.describe.json
}
`
				} else if form == "json" {
					source = `variable "action" {}
resource "aws_iam_policy" "describe" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = ` + tc.actions + `, Resource = "*" }] })
}
`
				}
				got := ruleIDs(scan(t, map[string]string{"main.tf": source}))
				finding, ok := got["terraform-iam-wildcard-resource"]
				if ok != tc.want {
					t.Fatalf("wildcard resource reported = %t, want %t: %+v", ok, tc.want, got)
				}
				if ok && finding.Severity != shared.SeverityHigh {
					t.Fatalf("severity = %s, want high", finding.Severity)
				}
			})
		}
	}
}

func TestTerraformRequiredWildcardResourceDoesNotHidePublicPrincipal(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{"main.tf": `data "aws_iam_policy_document" "public" {
  statement {
    actions = ["ec2:DescribeInstances"]
    resources = ["*"]
    principals {
      type = "AWS"
      identifiers = ["*"]
    }
  }
}
`}))
	if _, ok := got["terraform-iam-wildcard-resource"]; ok {
		t.Fatal("required wildcard resource should not report")
	}
	if f, ok := got["terraform-wildcard-principal"]; !ok || f.Severity != shared.SeverityHigh {
		t.Fatalf("public principal must still report high: %+v", got)
	}
}

func TestTerraformJSONSingleStatement(t *testing.T) {
	for _, tc := range []struct {
		name, statement string
		want            bool
	}{
		{"deny", `{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}`, false},
		{"required wildcard", `{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}`, false},
		{"allow", `{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleIDs(scan(t, map[string]string{"main.tf": `resource "aws_s3_bucket_policy" "example" {
  policy = <<POLICY
{"Statement":` + tc.statement + `}
POLICY
}
`}))
			if _, ok := got["terraform-iam-wildcard-resource"]; ok != tc.want {
				t.Fatalf("wildcard resource reported = %t, want %t: %+v", ok, tc.want, got)
			}
			if _, ok := got["terraform-wildcard-principal"]; ok {
				t.Fatalf("Deny must not report a public principal: %+v", got)
			}
		})
	}
}

func TestTerraformJSONDenyDoesNotHideAllow(t *testing.T) {
	got := scan(t, map[string]string{"main.tf": `resource "aws_s3_bucket_policy" "example" {
  policy = <<POLICY
{"Statement":[
  {"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"},
  {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}
]}
POLICY
}

`})
	for _, rule := range []string{"terraform-wildcard-principal", "terraform-iam-wildcard-resource"} {
		count := 0
		for _, f := range got {
			if f.RuleID == rule {
				count++
			}
		}
		if count != 1 {
			t.Errorf("%s findings = %d, want 1", rule, count)
		}
	}
}

func TestTerraformUnassessedSingleStatementKeepsLiteralFindings(t *testing.T) {
	for _, tc := range []struct {
		name, statement string
		want            []string
	}{
		{"unknown effect", `{ Effect = var.effect, Principal = "*", Action = "s3:GetObject", Resource = "*" }`, []string{"terraform-wildcard-principal", "terraform-iam-wildcard-resource"}},
		{"inverted action", `{ Effect = "Allow", Principal = "*", NotAction = "s3:DeleteObject", Resource = "*" }`, []string{"terraform-wildcard-principal", "terraform-iam-wildcard-resource"}},
		{"inverted resource", `{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", NotResource = "arn:aws:s3:::private/*" }`, []string{"terraform-wildcard-principal"}},
		{"inverted principal", `{ Effect = "Allow", NotPrincipal = { AWS = "arn:aws:iam::123456789012:role/app" }, Action = "s3:GetObject", Resource = "*" }`, []string{"terraform-iam-wildcard-resource"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleIDs(scan(t, map[string]string{"main.tf": `variable "effect" {}
resource "aws_s3_bucket_policy" "example" {
  policy = jsonencode({ Statement = ` + tc.statement + ` })
}
`}))
			for _, rule := range tc.want {
				if f, ok := got[rule]; !ok || f.Severity != shared.SeverityHigh {
					t.Errorf("unassessed statement must retain high %s: %+v", rule, got)
				}
			}
		})
	}
}
