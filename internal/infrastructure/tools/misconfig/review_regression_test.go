package misconfig

import (
	"context"

	"github.com/zclconf/go-cty/cty"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An ARM deployment template carries apiVersion and kind INSIDE its resources. A substring sniff claimed
// every such template as a Kubernetes manifest and handed it to a parser that found no top-level kind, so
// the template was scanned by nothing at all while coverage still read complete.
func TestARMTemplateIsNotClaimedAsKubernetes(t *testing.T) {
	arm := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2021-04-01",
      "name": "store",
      "kind": "StorageV2",
      "location": "southeastasia",
      "properties": {
        "allowBlobPublicAccess": true,
        "supportsHttpsTrafficOnly": false,
        "minimumTlsVersion": "TLS1_0"
      }
    }
  ]
}
`
	if looksKubernetes([]byte(arm)) {
		t.Fatal("an ARM template must not be classified as a Kubernetes manifest")
	}
	got := ruleIDs(scan(t, map[string]string{"azuredeploy.json": arm}))
	for _, want := range []string{"arm-storage-public-blob", "arm-storage-https-only-off", "arm-storage-min-tls-below-12"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected %q from the ARM template, got %v", want, keys(got))
		}
	}
}

// A Kubernetes manifest authored as JSON is still recognised at its root.
func TestKubernetesJSONRootIsStillRecognised(t *testing.T) {
	pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":"prod"},
"spec":{"containers":[{"name":"app","image":"app@sha256:0000000000000000000000000000000000000000000000000000000000000000","securityContext":{"privileged":true}}]}}`
	if !looksKubernetes([]byte(pod)) {
		t.Fatal("a JSON Kubernetes manifest must still be recognised")
	}
	if _, ok := ruleIDs(scan(t, map[string]string{"pod.json": pod}))["kubernetes-privileged"]; !ok {
		t.Fatal("the privileged JSON Pod must still be reported")
	}
}

// A width-driven formatter lets a one-line configuration ask for an arbitrarily large allocation inside
// the scanner, and that allocation happens while the function runs, before any limit on the rendered
// result could reject it. The property that has to hold is that such a function is never called, so the
// table is asserted directly: a findings-based check cannot observe an allocation that already happened.
func TestExpandingFunctionsAreNotAvailable(t *testing.T) {
	fns := tfFunctions()
	for _, name := range []string{"format", "formatlist", "indent"} {
		if _, present := fns[name]; present {
			t.Errorf("%s expands on a width or count argument and must not be callable during evaluation", name)
		}
	}
	// The bounded transformations the evaluation contract documents must still be present.
	for _, name := range []string{"concat", "slice", "merge", "jsonencode", "lookup", "try", "strcontains", "tolist"} {
		if _, present := fns[name]; !present {
			t.Errorf("%s is part of the documented contract and must stay available", name)
		}
	}
}

// An expression calling an absent function does not evaluate, so the attribute keeps its source text.
func TestUnavailableFunctionLeavesTheAttributeUnresolved(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{"main.tf": `locals {
  big = format("%8388608s", "")
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = local.big
}
`}))
	if _, ok := got["terraform-encryption-disabled"]; ok {
		t.Fatalf("an unevaluated expansion must not resolve to a value, got %v", keys(got))
	}
}

// A resolved value larger than the per-value budget is not stored, so a chain of transformations cannot
// grow a value without limit inside the scanner. The budget is asserted directly, because an oversized
// value is refused before it can reach a rule.
func TestOversizedValueIsRefusedByTheBudget(t *testing.T) {
	small := cty.StringVal(strings.Repeat("a", 16))
	if !tfValueWithinBudget(small, tfMaxValueBytes) {
		t.Fatal("an ordinary value must fit the budget")
	}
	big := cty.StringVal(strings.Repeat("a", tfMaxValueBytes+1))
	if tfValueWithinBudget(big, tfMaxValueBytes) {
		t.Fatal("a value over the budget must be refused")
	}
	list := cty.TupleVal([]cty.Value{big, big})
	if tfValueWithinBudget(list, tfMaxValueBytes) {
		t.Fatal("a collection over the budget must be refused")
	}
}

// An ...IfExists operator evaluates true when the key is absent, so a fixed value does not prove the grant
// is restricted for a caller that never carries the key.
func TestIfExistsDoesNotProveARestriction(t *testing.T) {
	fs := scan(t, map[string]string{"main.tf": `resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::b/*"
      Condition = { StringEqualsIfExists = { "aws:SourceAccount" = "123456789012" } }
    }]
  })
}
`})
	f := policyFinding(t, fs, "terraform-wildcard-principal")
	if f.Severity != shared.SeverityHigh {
		t.Fatalf("a caller lacking the key is allowed outright, so the grant is public: got %v (%s)", f.Severity, f.Description)
	}
}

// Alongside a requirement that the key be present, the same operator does restrict.
func TestIfExistsWithAPresenceRequirementRestricts(t *testing.T) {
	fs := scan(t, map[string]string{"main.tf": `resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::b/*"
      Condition = {
        StringEqualsIfExists = { "aws:SourceAccount" = "123456789012" }
        Null                 = { "aws:SourceAccount" = "false" }
      }
    }]
  })
}
`})
	noRule(t, fs, "terraform-wildcard-principal")
}

// Alternatives are ORed, so one "*" pattern matches every principal and the specific ARN beside it
// establishes nothing.
func TestWildcardAlternativeDoesNotRestrict(t *testing.T) {
	fs := scan(t, map[string]string{"main.tf": `resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::b/*"
      Condition = { StringLike = { "aws:PrincipalArn" = ["arn:aws:iam::123456789012:role/app", "*"] } }
    }]
  })
}
`})
	policyFinding(t, fs, "terraform-wildcard-principal")
}

// A single specific ARN with no wildcard alternative still restricts, so the fix does not report every
// pattern condition.
func TestSpecificPatternAlternativeStillRestricts(t *testing.T) {
	fs := scan(t, map[string]string{"main.tf": `resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::b/*"
      Condition = { StringLike = { "aws:PrincipalArn" = ["arn:aws:iam::123456789012:role/app-*"] } }
    }]
  })
}
`})
	noRule(t, fs, "terraform-wildcard-principal")
}

// The provider merges source and override documents into the rendered .json. Reading only the direct
// statements would publish a partial document as the resolved one and drop the merged public grant from
// both the structural assessment and the literal fallback.
func TestComposedPolicyDocumentStaysUnresolved(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{"main.tf": `data "aws_iam_policy_document" "combined" {
  override_policy_documents = [jsonencode({
    Statement = [{
      Sid       = "Public"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::b/*"
    }]
  })]
  statement {
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::b"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }
  }
}

resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = data.aws_iam_policy_document.combined.json
}
`}))
	if _, ok := got["terraform-wildcard-principal"]; !ok {
		t.Fatalf("a composed document must keep its literal detection, got %v", keys(got))
	}
}

// A variable-file scenario is a whole-workspace configuration. Resolving only the directory that owns the
// file left every descendant module on its default binding.
func TestScenarioPropagatesIntoChildModules(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{
		"main.tf": `variable "enc" {
  default = true
}
module "vol" {
  source = "./modules/vol"
  enc    = var.enc
}
`,
		"prod.tfvars": "enc = false\n",
		"modules/vol/main.tf": `variable "enc" {
  default = false
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = var.enc
}
`,
	}))
	if _, ok := got["terraform-encryption-disabled"]; !ok {
		t.Fatalf("the scenario must reach the child module, got %v", keys(got))
	}
}

// One call site refining its value as the parent's own variables settle is the same binding becoming
// accurate, not two call sites disagreeing.
func TestSingleCallChainIsNotAConflict(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{
		"main.tf": `module "z" {
  source = "./modules/z"
  enc    = false
}
`,
		"modules/z/main.tf": `variable "enc" {}
module "a" {
  source = "./../a"
  enc    = var.enc
}
`,
		"modules/a/main.tf": `variable "enc" {
  default = true
}
module "leaf" {
  source = "./../leaf"
  enc    = var.enc
}
`,
		"modules/leaf/main.tf": `variable "enc" {
  default = false
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = var.enc
}
`,
	}))
	if _, ok := got["terraform-encryption-disabled"]; !ok {
		t.Fatalf("a single call chain must resolve to its bound value, got %v", keys(got))
	}
}

// Two DIFFERENT call sites that disagree still leave the input without one effective value.
func TestDistinctCallSitesStillConflict(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{
		"main.tf": `module "a" {
  source = "./modules/vol"
  enc    = false
}
module "b" {
  source = "./modules/vol"
  enc    = true
}
`,
		"modules/vol/main.tf": `variable "enc" {}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = var.enc
}
`,
	}))
	if _, ok := got["terraform-encryption-disabled"]; ok {
		t.Fatalf("disagreeing call sites must not resolve to one instance's value, got %v", keys(got))
	}
}

// A local declared later in the file is unknown, not missing, so try() does not freeze a fallback that
// Terraform never takes.
func TestTryDoesNotFreezeAFallbackForALaterLocal(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{"main.tf": `locals {
  secure = try(local.base, false)
  base   = true
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = local.secure
}
`}))
	if _, ok := got["terraform-encryption-disabled"]; ok {
		t.Fatalf("the effective value is true; no encryption finding may be reported, got %v", keys(got))
	}
}

// strcontains is a substring test and tolist is a genuine conversion. Bound to collection membership and
// to coalesce-list they errored, and a try() around them took fallbacks Terraform does not take.
func TestStringAndListFunctionsUseTerraformSemantics(t *testing.T) {
	for name, expr := range map[string]string{
		"strcontains": `try(strcontains("secure", "sec"), false)`,
		"tolist":      `length(try(tolist([]), [false])) == 0`,
	} {
		t.Run(name, func(t *testing.T) {
			got := ruleIDs(scan(t, map[string]string{"main.tf": `resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = ` + expr + `
}
`}))
			if _, ok := got["terraform-encryption-disabled"]; ok {
				t.Fatalf("the expression is true; no encryption finding may be reported, got %v", keys(got))
			}
		})
	}
}

// scanReport is scan() with the report, for the capability assertions.
func scanReport(t *testing.T, files map[string]string) (findings []string, unresolved []string) {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	report, err := New().ScanConfigsReport(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range report.Findings {
		findings = append(findings, f.RuleID)
	}
	return findings, report.UnresolvedInputs
}

// An attribute whose expansion was refused is reported as unresolved rather than passing as evaluated.
func TestRefusedExpansionIsReportedUnresolved(t *testing.T) {
	_, unresolved := scanReport(t, map[string]string{"main.tf": `locals {
  big = format("%8388608s", "")
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = local.big
}
`})
	var found bool
	for _, u := range unresolved {
		if strings.Contains(u, "encrypted") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the unevaluated attribute must be reported, got %v", unresolved)
	}
}
