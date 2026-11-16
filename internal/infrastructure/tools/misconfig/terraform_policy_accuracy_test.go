package misconfig

import (
	"encoding/json"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

func TestTerraformIAMPolicyAccuracy(t *testing.T) {
	const resourceRule = "terraform-iam-wildcard-resource"
	const principalRule = "terraform-wildcard-principal"
	dataPolicy := func(body string) string {
		return `variable "action" {}
variable "effect" {}
data "aws_iam_policy_document" "policy" {
  statement {
` + body + `
  }
}
`
	}
	jsonPolicy := func(statement string, array bool) string {
		if array {
			statement = "[" + statement + "]"
		}
		return `variable "action" {}
variable "effect" {}
resource "aws_s3_bucket_policy" "policy" {
  policy = jsonencode({ Statement = ` + statement + ` })
}
`
	}
	type policyCase struct {
		name, group, source string
		expected            []string
	}
	var cases []policyCase
	for _, c := range []struct {
		name, actions    string
		wildcardRequired bool
	}{
		{"describe-instances", `["ec2:DescribeInstances"]`, true},
		{"describe-images", `["ec2:DescribeImages"]`, true},
		{"required-actions", `["ec2:DescribeInstances", "ec2:DescribeImages"]`, true},
		{"case-insensitive", `["EC2:describeinstances"]`, true},
		{"mixed-permissions", `["ec2:DescribeInstances", "s3:GetObject"]`, false},
		{"scopable-describe", `["ec2:DescribeInstanceAttribute"]`, false},
		{"unknown-action", `["ec2:DescribeFutureResources"]`, false},
		{"action-pattern", `["ec2:Describe*"]`, false},
		{"service-wildcard", `["ec2:*"]`, false},
		{"all-actions", `["*"]`, false},
		{"empty-actions", `[]`, false},
		{"null-actions", `null`, false},
		{"malformed-actions", `["ec2:DescribeInstances", true]`, false},
		{"unresolved-action", `["ec2:DescribeInstances", var.action]`, false},
	} {
		expected := []string{}
		if !c.wildcardRequired {
			expected = []string{resourceRule}
		}
		cases = append(cases, policyCase{c.name + "/data", "data", dataPolicy("    actions = " + c.actions + "\n    resources = [\"*\"]"), expected})
		statement := `{ Effect = "Allow", Action = ` + c.actions + `, Resource = "*" }`
		cases = append(cases,
			policyCase{c.name + "/json-array", "json-array", jsonPolicy(statement, true), expected},
			policyCase{c.name + "/json-singleton", "json-singleton", jsonPolicy(statement, false), expected},
		)
	}
	for _, effect := range []string{"Deny", "Allow"} {
		expected := []string{}
		if effect == "Allow" {
			expected = []string{principalRule, resourceRule}
		}
		cases = append(cases, policyCase{effect + "/data", "data", dataPolicy(`    effect = "` + effect + `"
    actions = ["s3:GetObject"]
    resources = ["*"]
    principals {
      type = "AWS"
      identifiers = ["*"]
    }`), expected})
		statement := `{ Effect = "` + effect + `", Principal = "*", Action = "s3:GetObject", Resource = "*" }`
		cases = append(cases,
			policyCase{effect + "/json-array", "json-array", jsonPolicy(statement, true), expected},
			policyCase{effect + "/json-singleton", "json-singleton", jsonPolicy(statement, false), expected},
		)
	}
	cases = append(cases,
		policyCase{"deny-unresolved-resource", "data", dataPolicy(`    effect = "Deny"
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
    }`), []string{}},
		policyCase{"unknown-effect", "json-singleton", jsonPolicy(`{ Effect = var.effect, Principal = "*", Action = "s3:GetObject", Resource = "*" }`, false), []string{principalRule, resourceRule}},
		policyCase{"inverted-action", "json-singleton", jsonPolicy(`{ Effect = "Allow", Principal = "*", NotAction = "s3:DeleteObject", Resource = "*" }`, false), []string{principalRule, resourceRule}},
		policyCase{"public-principal-required-resource", "data", dataPolicy(`    actions = ["ec2:DescribeInstances"]
    resources = ["*"]
    principals {
      type = "AWS"
      identifiers = ["*"]
    }`), []string{principalRule}},
	)
	input := benchmark.AccuracyInput{SchemaVersion: benchmark.AccuracyInputSchemaVersion}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			produced := []string{}
			for _, f := range scan(t, map[string]string{"main.tf": c.source}) {
				if f.RuleID == resourceRule || f.RuleID == principalRule {
					produced = append(produced, f.RuleID)
				}
			}
			input.Observations = append(input.Observations, benchmark.AccuracyObservation{Case: c.name, Group: c.group, Expected: c.expected, Produced: produced})
		})
	}
	report, err := benchmark.EvaluateAccuracy(input)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := json.Marshal(struct {
		Input  benchmark.AccuracyInput  `json:"input"`
		Report benchmark.AccuracyReport `json:"report"`
	}{input, report})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("terraform IAM accuracy: %s", evidence)
	if report.Cases != int64(len(cases)) || report.Overall.FalsePositives != 0 || report.Overall.FalseNegatives != 0 {
		t.Errorf("Terraform IAM accuracy regression: %+v", report.Overall)
	}
}
