package misconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"

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
	f := policyFinding(t, fs, "terraform-wildcard-principal")
	if f.Severity != shared.SeverityHigh {
		t.Fatalf("a known match-everything alternative leaves the grant unrestricted, so it is high: got %v (%s)", f.Severity, f.Description)
	}
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
	findings, unresolved, _, _ = scanReportFull(t, files)
	return findings, unresolved
}

func scanReportFull(t *testing.T, files map[string]string) (findings []string, unresolved []string, unassessed int, reasons []string) {
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
	return findings, report.UnresolvedInputs, report.UnassessedInputs, report.UnassessedReasons
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

// join repeats its separator between every pair, so a separator and a list that each fit the stored-value
// budget still multiply into a far larger string. The bound has to be enforced BEFORE the call runs: a
// predicate on the completed result arrives after the allocation it exists to prevent, and wrapping the
// call in length() hides the intermediate entirely. This measures the allocation rather than the finding.
func TestJoinIsRefusedBeforeItAllocates(t *testing.T) {
	join := tfFunctions()["join"]
	separator := cty.StringVal(strings.Repeat("s", 16<<10))
	pieces := make([]cty.Value, 512)
	for i := range pieces {
		pieces[i] = cty.StringVal("y")
	}
	args := []cty.Value{separator, cty.ListVal(pieces)}
	projected := 512 * (16 << 10)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	refused, err := join.Call(args)
	runtime.ReadMemStats(&after)
	if err == nil && refused.IsKnown() {
		t.Fatal("a call whose projected result exceeds the budget must not produce a value")
	}

	if err != nil {
		t.Fatalf("a refusal must be an unknown value, not an error try can catch: %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > uint64(projected/8) {
		t.Fatalf("the refusal allocated %d bytes; the unbounded call would build about %d", allocated, projected)
	}
	// The same arguments below the budget still work, so the bound refuses size rather than the function.
	small, err := join.Call([]cty.Value{cty.StringVal("-"), cty.ListVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")})})
	if err != nil {
		t.Fatalf("an ordinary join must still evaluate: %v", err)
	}
	if small.AsString() != "a-b" {
		t.Fatalf("join produced %q", small.AsString())
	}
}

// An expression reading more references than the bound allows is not evaluated, so a template cannot
// chain an unbounded number of budget-sized operands in one go.
func TestExpressionReferenceBoundIsEnforced(t *testing.T) {
	var b strings.Builder
	b.WriteString("locals {\n  seed = \"abc\"\n  joined = \"")
	for i := 0; i <= tfMaxExprRefs; i++ {
		b.WriteString("${local.seed}")
	}
	b.WriteString("\"\n}\n")
	b.WriteString(`resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = local.joined == ""
}
`)
	got := ruleIDs(scan(t, map[string]string{"main.tf": b.String()}))
	if _, ok := got["terraform-encryption-disabled"]; ok {
		t.Fatalf("an expression past the reference bound must not resolve, got %v", keys(got))
	}
}

// A Null guard whose alternatives permit the key to be ABSENT does not require presence, and the absent
// state is exactly the one in which the IfExists operator succeeds anyway.
func TestNullAlternativesPermittingAbsenceDoNotRestrict(t *testing.T) {
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
        Null                 = { "aws:SourceAccount" = ["false", "true"] }
      }
    }]
  })
}
`})
	f := policyFinding(t, fs, "terraform-wildcard-principal")
	if f.Severity != shared.SeverityHigh {
		t.Fatalf("alternatives permitting absence establish no presence requirement: got %v (%s)", f.Severity, f.Description)
	}
}

// A document this scanner cannot render is DECLARED, not missing. Leaving the name unbound let a try()
// around it resolve to a fallback the provider never produces, and that fallback then consumed the data
// block's literal coverage.
func TestComposedDocumentThroughTryKeepsItsLiteralFinding(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{"main.tf": `data "aws_iam_policy_document" "combined" {
  override_policy_documents = [jsonencode({
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::b/*"
    }]
  })]
  statement {
    sid       = "InternalRead"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::b/*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/app"]
    }
  }
}

resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = try(data.aws_iam_policy_document.combined.json, jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:role/app" }
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::b/*"
    }]
  }))
}
`}))
	if _, ok := got["terraform-wildcard-principal"]; !ok {
		t.Fatalf("the public override must keep its literal finding, got %v", keys(got))
	}
}

// A scenario the cap refuses is work that was not done, so it is reported as a coverage gap rather than
// passing silently.
func TestSkippedScenariosAreReportedAsACoverageGap(t *testing.T) {
	files := map[string]string{}
	for _, dir := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} {
		files[dir+"/main.tf"] = `variable "enc" {
  default = true
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = var.enc
}
`
		value := "true"
		if dir == "i" {
			value = "false"
		}
		files[dir+"/prod.tfvars"] = "enc = " + value + "\n"
	}
	_, _, unassessed, reasons := scanReportFull(t, files)
	if unassessed == 0 {
		t.Fatal("a scenario the budget refused must be reported as unassessed")
	}
	var named bool
	for _, r := range reasons {
		if strings.Contains(r, "scenario budget") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the reason must name the budget, got %v", reasons)
	}
}

// A declared variable with no value is unknown during LOCAL resolution too. Handing locals the raw map
// let try() see it as absent and store a resolved false, which no later context could undo.
func TestUnresolvedVariableDoesNotBecomeAFallbackValue(t *testing.T) {
	findings, unresolved := scanReport(t, map[string]string{"main.tf": `variable "enc" {}
locals {
  secure = try(var.enc, false)
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = local.secure
}
`})
	for _, id := range findings {
		if id == "terraform-encryption-disabled" {
			t.Fatal("an unresolved variable must not be invented as false")
		}
	}
	var reported bool
	for _, u := range unresolved {
		if strings.Contains(u, "encrypted") {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("the dependent attribute must be reported unresolved, got %v", unresolved)
	}
}

// Terraform's conversion preserves null, so tolist(null) is null rather than a function error that sends
// try() to a fallback.
func TestToListPreservesNull(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{"main.tf": `resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = try(tolist(null) == null, false)
}
`}))
	if _, ok := got["terraform-encryption-disabled"]; ok {
		t.Fatalf("tolist(null) is null, so the expression is true, got %v", keys(got))
	}
}

// join is variadic. Projecting only the first list omitted the separator repeating across the COMBINED
// elements of every list that follows.
func TestVariadicJoinIsProjectedOverEveryList(t *testing.T) {
	join := tfFunctions()["join"]
	separator := cty.StringVal(strings.Repeat("s", 16<<10))
	pieces := make([]cty.Value, 512)
	for i := range pieces {
		pieces[i] = cty.StringVal("y")
	}
	list := cty.ListVal(pieces)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	refused, err := join.Call([]cty.Value{separator, list, list})
	runtime.ReadMemStats(&after)

	if err == nil && refused.IsKnown() {
		t.Fatal("two lists multiply the separator just as one does; the call must be refused")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 2<<20 {
		t.Fatalf("the refusal allocated %d bytes", allocated)
	}
}

// A comprehension repeats its body once per element at RUNTIME, so its cost is not knowable from the
// source. Such an expression is refused rather than evaluated.
func TestComprehensionsAreRefusedBeforeEvaluation(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{"main.tf": `locals {
  seed = "` + strings.Repeat("a", 32) + `"
  big  = join("", [for a in range(64) : join("", [for b in range(64) : local.seed])])
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = length(local.big) == 0
}
`}))
	if _, ok := got["terraform-encryption-disabled"]; ok {
		t.Fatalf("a comprehension must not be evaluated, got %v", keys(got))
	}
}

// A scanner refusal is not a configuration failure. Surfacing it as an expression error let try() choose
// a fallback and present the scanner's own limit as a confident answer.
func TestRefusalIsNotCatchableByTry(t *testing.T) {
	for name, fallback := range map[string]string{"true fallback": "true", "false fallback": "false"} {
		t.Run(name, func(t *testing.T) {
			findings, unresolved := scanReport(t, map[string]string{"main.tf": `locals {
  s = join("", [for a in range(100) : "` + strings.Repeat("a", 32) + `"])
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = try(length(split(",", local.s)) > 1, ` + fallback + `)
}
`})
			for _, id := range findings {
				if id == "terraform-encryption-disabled" {
					t.Fatal("a refusal must not be normalized to the fallback and reported as resolved")
				}
			}
			var reported bool
			for _, u := range unresolved {
				if strings.Contains(u, "encrypted") {
					reported = true
				}
			}
			if !reported {
				t.Fatalf("the refused attribute must be reported unresolved, got %v", unresolved)
			}
		})
	}
}

// An ordinary split on a long string with no separator is not refused: the projection counts the
// separator occurrences rather than assuming every character becomes an element.
func TestOrdinarySplitIsNotRefused(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{"main.tf": `locals {
  s = "` + strings.Repeat("a", 3200) + `"
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = length(split(",", local.s)) > 1
}
`}))
	if _, ok := got["terraform-encryption-disabled"]; !ok {
		t.Fatalf("the split resolves to one element, so the expression is false and must report, got %v", keys(got))
	}
}

// Variable files beyond the LOAD bound are work that was not done, and reach the same coverage gap as
// those the evaluation budget skips.
func TestScenariosDroppedAtLoadTimeAreCounted(t *testing.T) {
	files := map[string]string{"main.tf": `variable "enc" {
  default = true
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = var.enc
}
`}
	for i := 1; i <= 9; i++ {
		value := "true"
		if i == 9 {
			value = "false"
		}
		files[fmt.Sprintf("%02d.tfvars", i)] = "enc = " + value + "\n"
	}
	_, _, unassessed, reasons := scanReportFull(t, files)
	if unassessed == 0 {
		t.Fatalf("scenarios past the budget must be reported, reasons %v", reasons)
	}
}

// An unknown input establishes no element type, so a comparison against a list of another type stays
// unknown rather than becoming definitely false.
func TestToListKeepsAnUnknownElementTypeDynamic(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{"main.tf": `variable "items" {}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = tolist(var.items) == tolist([true])
}
`}))
	if _, ok := got["terraform-encryption-disabled"]; ok {
		t.Fatalf("an unknown input must not produce a definite comparison, got %v", keys(got))
	}
}

// Binding policy-document data must EXTEND the supplied context. Rebuilding it from the resolved maps
// discarded the unknown-aware bindings, so an unknown variable looked absent in any module that happened
// to contain a policy document.
func TestPolicyDataBindingKeepsUnknownVariables(t *testing.T) {
	findings, unresolved := scanReport(t, map[string]string{"main.tf": `variable "enc" {}
data "aws_iam_policy_document" "combined" {
  source_policy_documents = []
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = try(var.enc, false)
}
`})
	for _, id := range findings {
		if id == "terraform-encryption-disabled" {
			t.Fatal("an unknown variable must stay unknown when policy data is bound")
		}
	}
	var reported bool
	for _, u := range unresolved {
		if strings.Contains(u, "encrypted") {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("the dependent attribute must be reported unresolved, got %v", unresolved)
	}
}

// jsonLoopFixture writes a .tf.json workspace whose attribute value is the expression under test. The
// loop is 16 x 16 over a 512-byte seed: small enough that no bound on individual function calls sees
// anything unusual, large enough that running it materializes 128 KiB per evaluation.
func jsonLoopFixture(t *testing.T, attrs map[string]any) map[string]string {
	t.Helper()
	items := make([]string, 16)
	for i := range items {
		items[i] = fmt.Sprint(i)
	}
	body := map[string]any{"availability_zone": "us-east-1a", "size": 1}
	for k, v := range attrs {
		body[k] = v
	}
	doc, err := json.Marshal(map[string]any{
		"resource": map[string]any{"aws_ebs_volume": map[string]any{"v": body}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"locals.tf":    "locals {\n seed = \"" + strings.Repeat("a", 512) + "\"\n items = [" + strings.Join(items, ",") + "]\n}\n",
		"main.tf.json": string(doc),
	}
}

const jsonTemplateLoop = `%{ for i in local.items }%{ for j in local.items }${local.seed}%{ endfor }%{ endfor }`

// A .tf.json attribute carries no AST of its own: hcl/json parses the string as a native template at
// Value() time. Admitting it because its type is not hclsyntax.Expression ran every loop a JSON
// configuration could write, on the one file format the native guard could not see.
func TestJSONTemplateLoopIsRefused(t *testing.T) {
	cases := map[string]any{
		"scalar attribute": `${"` + jsonTemplateLoop + `" != ""}`,
		"array element":    []any{`${"` + jsonTemplateLoop + `" != ""}`},
		"object value":     map[string]any{"note": jsonTemplateLoop},
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			findings, unresolved := scanReport(t, jsonLoopFixture(t, map[string]any{"encrypted": value}))
			runtime.ReadMemStats(&after)

			var reported bool
			for _, u := range unresolved {
				if strings.Contains(u, "encrypted") {
					reported = true
				}
			}
			if !reported {
				t.Fatalf("a refused JSON expression must be reported unresolved, got %v", unresolved)
			}
			for _, id := range findings {
				if id == "terraform-encryption-disabled" {
					t.Fatal("a refused expression must not resolve to a value")
				}
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8<<20 {
				t.Fatalf("the scan allocated %d bytes, so the loop body ran", allocated)
			}
		})
	}
}

// An object key is an expression too in JSON configurations, and hcl/json evaluates it in interpolation
// mode. Walking only values left that surface evaluating whatever the target wrote.
func TestJSONInterpolatedObjectKeyIsRefused(t *testing.T) {
	files := jsonLoopFixture(t, map[string]any{
		"tags": map[string]any{`${"` + jsonTemplateLoop + `" != "" ? "a" : "b"}`: "x"},
	})
	_, unresolved := scanReport(t, files)
	var reported bool
	for _, u := range unresolved {
		if strings.Contains(u, "tags") {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("a loop in an object key must refuse the attribute, got %v", unresolved)
	}
}

// Dropping an unresolved attribute from the rendered HCL changes the claim. The rules read an absent
// attribute as a value the operator never set, which is a finding about the target rather than about
// what this scanner resolved.
func TestUnresolvedJSONAttributeStaysPresent(t *testing.T) {
	got := ruleIDs(scan(t, jsonLoopFixture(t, map[string]any{
		"encrypted": `${"` + jsonTemplateLoop + `" != ""}`,
	})))
	if _, ok := got["terraform-ebs-unencrypted"]; ok {
		t.Fatalf("an unresolved attribute must not be reported as an absent one, got %v", keys(got))
	}
}

// The admission must not refuse ordinary JSON configurations, which carry no loop at all.
func TestOrdinaryJSONAttributesStillResolve(t *testing.T) {
	files := jsonLoopFixture(t, map[string]any{"encrypted": "${local.on}"})
	files["locals.tf"] = "locals {\n on = false\n}\n"
	got := ruleIDs(scan(t, files))
	if _, ok := got["terraform-encryption-disabled"]; !ok {
		t.Fatalf("a JSON attribute resolving through a local must still report, got %v", keys(got))
	}
}

// Admission at one call site is not admission. A loop reaches the evaluator through a variable default,
// a variable file and a policy document just as it does through a resource attribute.
func TestLoopIsRefusedAtEveryEvaluationSurface(t *testing.T) {
	seed := strings.Repeat("a", 512)
	loop := `join("", [for i in range(16) : join("", [for j in range(16) : "` + seed + `"])])`

	t.Run("variable default", func(t *testing.T) {
		got := ruleIDs(scan(t, map[string]string{"main.tf": `variable "pad" {
  default = ` + loop + `
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = length(var.pad) == 0
}
`}))
		if _, ok := got["terraform-encryption-disabled"]; ok {
			t.Fatalf("a loop in a variable default must be refused, got %v", keys(got))
		}
	})

	t.Run("json variable default", func(t *testing.T) {
		doc, err := json.Marshal(map[string]any{
			"variable": map[string]any{"pad": map[string]any{"default": jsonTemplateLoop}},
		})
		if err != nil {
			t.Fatal(err)
		}
		files := jsonLoopFixture(t, map[string]any{"encrypted": "${length(var.pad) == 0}"})
		files["vars.tf.json"] = string(doc)
		_, unresolved := scanReport(t, files)
		var reported bool
		for _, u := range unresolved {
			if strings.Contains(u, "encrypted") {
				reported = true
			}
		}
		if !reported {
			t.Fatalf("a default nobody resolved must leave the attribute unresolved, got %v", unresolved)
		}
	})

	t.Run("variable file", func(t *testing.T) {
		got := ruleIDs(scan(t, map[string]string{
			"main.tf": `variable "pad" {
  default = "off"
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = var.pad == "on"
}
`,
			"terraform.tfvars": "pad = " + loop + "\n",
		}))
		if _, ok := got["terraform-encryption-disabled"]; !ok {
			t.Fatalf("a refused variable file leaves the declared default in force, got %v", keys(got))
		}
	})

	t.Run("policy document", func(t *testing.T) {
		findings, _ := scanReport(t, map[string]string{"main.tf": `locals {
  items = [0, 1]
}
data "aws_iam_policy_document" "d" {
  statement {
    effect    = "Allow"
    actions   = [for i in local.items : "s3:GetObject"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}
`})
		for _, id := range findings {
			if id == "terraform-encryption-disabled" {
				t.Fatalf("unexpected finding %s", id)
			}
		}
	})
}
