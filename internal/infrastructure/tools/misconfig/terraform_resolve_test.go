package misconfig

import (
	"context"
	"fmt"
	"testing"
)

// A variable default resolves so a misconfiguration expressed through the variable is caught where a
// literal-only match would miss it.
func TestTerraformResolvesVariableDefault(t *testing.T) {
	fs := scan(t, map[string]string{
		"main.tf": `
variable "enc" {
  default = false
}
resource "aws_db_instance" "db" {
  storage_encrypted = var.enc
}
`,
	})
	if _, ok := ruleIDs(fs)["terraform-encryption-disabled"]; !ok {
		t.Fatalf("a variable default of false must resolve to flag encryption-disabled, got %v", ruleIDs(fs))
	}
}

// A value from a separate .tfvars file resolves across the workspace.
func TestTerraformResolvesCrossFileTFVars(t *testing.T) {
	fs := scan(t, map[string]string{
		"main.tf": `
variable "pub" {}
resource "aws_db_instance" "db" {
  publicly_accessible = var.pub
}
`,
		"terraform.tfvars": `pub = true` + "\n",
	})
	if _, ok := ruleIDs(fs)["terraform-db-publicly-accessible"]; !ok {
		t.Fatalf("a tfvars value of true must resolve to flag publicly-accessible, got %v", ruleIDs(fs))
	}
}

// A locals literal resolves.
func TestTerraformResolvesLocals(t *testing.T) {
	fs := scan(t, map[string]string{
		"main.tf": `
locals {
  open = "0.0.0.0/0"
}
resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = [local.open]
  }
}
`,
	})
	if _, ok := ruleIDs(fs)["terraform-open-cidr"]; !ok {
		t.Fatalf("a locals CIDR of 0.0.0.0/0 must resolve to flag the open rule, got %v", ruleIDs(fs))
	}
}

// Conflicting sources (a default and a tfvars that disagree) are AMBIGUOUS and must not be substituted, so
// no false positive is produced. Here the effective value is true (secure), so encryption-disabled must NOT
// fire.
func TestTerraformAmbiguousValueNotSubstituted(t *testing.T) {
	fs := scan(t, map[string]string{
		"main.tf": `
variable "enc" {
  default = false
}
resource "aws_db_instance" "db" {
  storage_encrypted = var.enc
}
`,
		"terraform.tfvars": `enc = true` + "\n",
	})
	if _, ok := ruleIDs(fs)["terraform-encryption-disabled"]; ok {
		t.Fatalf("a variable with disagreeing sources must not resolve (no false positive), got %v", ruleIDs(fs))
	}
}

// When every source agrees, resolution proceeds even across files.
func TestTerraformAgreeingSourcesResolve(t *testing.T) {
	fs := scan(t, map[string]string{
		"main.tf": `
variable "enc" {
  default = false
}
resource "aws_db_instance" "db" {
  storage_encrypted = var.enc
}
`,
		"terraform.tfvars": `enc = false` + "\n",
	})
	if _, ok := ruleIDs(fs)["terraform-encryption-disabled"]; !ok {
		t.Fatalf("agreeing default and tfvars must resolve, got %v", ruleIDs(fs))
	}
}

// An unresolved variable (no default, no tfvars) is left untouched, so nothing is flagged: exactly the
// pre-resolution behavior, with no false positive from a guessed value.
func TestTerraformUnresolvedVariableNotFlagged(t *testing.T) {
	fs := scan(t, map[string]string{
		"main.tf": `
resource "aws_db_instance" "db" {
  storage_encrypted = var.unknown
}
`,
	})
	if _, ok := ruleIDs(fs)["terraform-encryption-disabled"]; ok {
		t.Fatalf("an unresolved variable must not be flagged, got %v", ruleIDs(fs))
	}
}

// A root variable default must NOT be substituted into a same-named variable of a CHILD module (a module
// is a directory; the child receives its value from the module block, not the root default).
func TestTerraformResolutionIsModuleScoped(t *testing.T) {
	fs := scan(t, map[string]string{
		"main.tf": `
variable "enc" {
  default = false
}
module "db" {
  source = "./modules/db"
  enc    = true
}
`,
		"modules/db/main.tf": `
variable "enc" {}
resource "aws_db_instance" "db" {
  storage_encrypted = var.enc
}
`,
	})
	if _, ok := ruleIDs(fs)["terraform-encryption-disabled"]; ok {
		t.Fatalf("a root default must not leak into a child module's variable, got %v", ruleIDs(fs))
	}
}

func TestTerraformModuleOmittedInputsUseTheirOwnEffectiveBinding(t *testing.T) {
	tests := []struct {
		name           string
		defaultVar     string
		first          string
		second         string
		fileVars       string
		wantFinding    bool
		wantUnresolved bool
	}{
		{name: "safe override versus unsafe default", defaultVar: "default = false", first: "enc = true", wantUnresolved: true},
		{name: "unsafe override versus safe default", defaultVar: "default = true", first: "enc = false", wantUnresolved: true},
		{name: "omitted required input", first: "enc = false", wantUnresolved: true},
		{name: "matching unsafe default", defaultVar: "default = false", first: "enc = false", wantFinding: true},
		{name: "matching safe default", defaultVar: "default = true", first: "enc = true"},
		{name: "explicit disagreement", defaultVar: "default = true", first: "enc = true", second: "enc = false", wantUnresolved: true},
		{name: "automatic file overrides default", defaultVar: "default = true", first: "enc = false", fileVars: "enc = false\n", wantFinding: true},
		{name: "automatic file disagrees with override", defaultVar: "default = false", first: "enc = false", fileVars: "enc = true\n", wantUnresolved: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{
				"main.tf": `module "first" {
  source = "./modules/vol"
  ` + tt.first + `
}
module "second" {
  source = "./modules/vol"
  ` + tt.second + `
}
`,
				"modules/vol/main.tf": `variable "enc" {
  ` + tt.defaultVar + `
}
resource "aws_ebs_volume" "vol" {
  encrypted = var.enc
}
`,
			}
			if tt.fileVars != "" {
				files["modules/vol/terraform.tfvars"] = tt.fileVars
			}
			findings, unresolved := scanReport(t, files)
			found := false
			for _, id := range findings {
				if id == "terraform-encryption-disabled" {
					found = true
				}
			}
			if found != tt.wantFinding {
				t.Errorf("encryption finding = %v, want %v; findings: %v", found, tt.wantFinding, findings)
			}
			if got := hasUnresolved(unresolved, "modules/vol/main.tf", "encrypted"); got != tt.wantUnresolved {
				t.Errorf("encrypted unresolved = %v, want %v; unresolved: %v", got, tt.wantUnresolved, unresolved)
			}
		})
	}
}

func TestTerraformModuleChainedInputsPreserveUnknownAndRefinement(t *testing.T) {
	for _, expression := range []string{"var.enc", "try(var.enc, true)"} {
		for _, defaultValue := range []string{"true", "false"} {
			for _, bindings := range []struct {
				name           string
				second         string
				wantFinding    bool
				wantUnresolved bool
			}{
				{name: "conflicting", second: "false", wantUnresolved: true},
				{name: "resolved safe", second: "true"},
				{name: "resolved unsafe", second: "false", wantFinding: true},
			} {
				t.Run(expression+"/"+defaultValue+"/"+bindings.name, func(t *testing.T) {
					first := "true"
					if bindings.name == "resolved unsafe" {
						first = "false"
					}
					findings, unresolved := scanReport(t, map[string]string{
						"main.tf": `module "first" {
  source = "./wrapper"
  enc = ` + first + `
}
module "second" {
  source = "./wrapper"
  enc = ` + bindings.second + `
}
`,
						"wrapper/main.tf": `variable "enc" {}
module "leaf" {
  source = "../leaf"
  enc = ` + expression + `
}
`,
						"leaf/main.tf": `variable "enc" {
  default = ` + defaultValue + `
}
resource "aws_ebs_volume" "vol" {
  encrypted = var.enc
}
`,
					})
					found := false
					for _, id := range findings {
						if id == "terraform-encryption-disabled" {
							found = true
						}
					}
					if found != bindings.wantFinding {
						t.Errorf("finding = %v, want %v; findings: %v", found, bindings.wantFinding, findings)
					}
					if got := hasUnresolved(unresolved, "leaf/main.tf", "encrypted"); got != bindings.wantUnresolved {
						t.Errorf("unresolved = %v, want %v; unresolved: %v", got, bindings.wantUnresolved, unresolved)
					}
				})
			}
		}
	}
}

func TestTerraformReverseOrderedModuleChainRespectsPropagationBound(t *testing.T) {
	for _, tc := range []struct {
		name           string
		depth          int
		defaultValue   string
		override       string
		wantFinding    bool
		wantUnresolved bool
	}{
		{name: "beyond bound unsafe override", depth: 10, defaultValue: "true", override: "false", wantUnresolved: true},
		{name: "beyond bound safe override", depth: 10, defaultValue: "false", override: "true", wantUnresolved: true},
		{name: "within bound unsafe override", depth: 4, defaultValue: "true", override: "false", wantFinding: true},
		{name: "within bound safe override", depth: 4, defaultValue: "false", override: "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				"main.tf":             fmt.Sprintf("module \"top\" {\n  source = \"./modules/m%02d\"\n  enc = %s\n}\n", tc.depth-1, tc.override),
				"modules/m00/main.tf": fmt.Sprintf("variable \"enc\" {\n  default = %s\n}\nresource \"aws_ebs_volume\" \"vol\" {\n  encrypted = var.enc\n}\n", tc.defaultValue),
			}
			for i := 1; i < tc.depth; i++ {
				files[fmt.Sprintf("modules/m%02d/main.tf", i)] = fmt.Sprintf(
					"variable \"enc\" {\n  default = %s\n}\nmodule \"next\" {\n  source = \"../m%02d\"\n  enc = var.enc\n}\n",
					tc.defaultValue, i-1,
				)
			}
			findings, unresolved := scanReport(t, files)
			found := false
			for _, id := range findings {
				if id == "terraform-encryption-disabled" {
					found = true
				}
			}
			if found != tc.wantFinding {
				t.Errorf("finding = %v, want %v; findings: %v", found, tc.wantFinding, findings)
			}
			leafUnresolved := false
			for _, diagnostic := range unresolved {
				if diagnostic == "modules/m00/main.tf:5: encrypted" {
					leafUnresolved = true
				}
			}
			if leafUnresolved != tc.wantUnresolved {
				t.Errorf("leaf unresolved = %v, want %v; unresolved: %v", leafUnresolved, tc.wantUnresolved, unresolved)
			}
		})
	}
}

func TestTerraformModuleOmittedInputRespectsSelectedFileScenario(t *testing.T) {
	findings, unresolved := scanReport(t, map[string]string{
		"main.tf": `module "first" {
  source = "./modules/vol"
  enc = false
}
module "second" {
  source = "./modules/vol"
}
`,
		"modules/vol/main.tf": `variable "enc" {
  default = false
}
resource "aws_ebs_volume" "vol" {
  encrypted = var.enc
}
`,
		"modules/vol/other.tfvars": "enc = true\n",
	})
	found := false
	for _, id := range findings {
		if id == "terraform-encryption-disabled" {
			found = true
		}
	}
	if !found {
		t.Errorf("matching default bindings must report encryption disabled, got %v", findings)
	}
	if !hasUnresolved(unresolved, "modules/vol/main.tf", "encrypted") {
		t.Errorf("selected file must make the omitted binding disagree, got %v", unresolved)
	}
}

// A resource attribute named like `locals_map = { ... }` is not a top-level locals block, so its keys must
// not be collected as local.* values. The bool `pub = true` fires no rule directly, so a finding here would
// come only from a wrongly-collected local.pub being substituted.
func TestTerraformLocalsBlockNotConfusedWithAttribute(t *testing.T) {
	fs := scan(t, map[string]string{
		"main.tf": `
resource "aws_db_instance" "db" {
  locals_map = {
    pub = true
  }
  publicly_accessible = local.pub
}
`,
	})
	if _, ok := ruleIDs(fs)["terraform-db-publicly-accessible"]; ok {
		t.Fatalf("a locals_map resource attribute must not define local.pub, got %v", ruleIDs(fs))
	}
}

// A `default` key nested inside an object default is not the variable's scalar default.
func TestTerraformNestedDefaultNotCollected(t *testing.T) {
	fs := scan(t, map[string]string{
		"main.tf": `
variable "enc" {
  default = {
    default = false
  }
}
resource "aws_db_instance" "db" {
  storage_encrypted = var.enc
}
`,
	})
	if _, ok := ruleIDs(fs)["terraform-encryption-disabled"]; ok {
		t.Fatalf("a nested object key named default must not be read as the variable's value, got %v", ruleIDs(fs))
	}
}

// A reference-looking token inside a plain string literal ("var.cidr") is not a reference and must not be
// substituted; a real ${...} interpolation of the same variable is. The CIDR value lives in a .tfvars file
// (never scanned for rules), so any open-cidr finding comes only from substitution into main.tf.
func TestTerraformSubstitutionRespectsStringLiterals(t *testing.T) {
	tfvars := `cidr = "0.0.0.0/0"` + "\n"
	// A quoted literal string that merely looks like a reference: no substitution, no finding.
	quoted := scan(t, map[string]string{
		"terraform.tfvars": tfvars,
		"main.tf": `
variable "cidr" {}
resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = ["var.cidr"]
  }
}
`,
	})
	if _, ok := ruleIDs(quoted)["terraform-open-cidr"]; ok {
		t.Fatalf("a reference inside a plain string literal must not be substituted, got %v", ruleIDs(quoted))
	}
	// A genuine interpolation still resolves.
	interp := scan(t, map[string]string{
		"terraform.tfvars": tfvars,
		"main.tf": `
variable "cidr" {}
resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = ["${var.cidr}"]
  }
}
`,
	})
	if _, ok := ruleIDs(interp)["terraform-open-cidr"]; !ok {
		t.Fatalf("a ${...} interpolation of an open CIDR must resolve and flag, got %v", ruleIDs(interp))
	}
}

// A string ending in an escaped backslash (\\) closes correctly, so a real reference on a later line is
// still substituted (regression: a naive escaped-quote check left the parser stuck inside the string).
func TestTerraformSubstitutionHandlesEscapedBackslash(t *testing.T) {
	fs := scan(t, map[string]string{
		"main.tf": `
variable "enc" {
  default = false
}
resource "aws_db_instance" "db" {
  description       = "ends with slash\\"
  storage_encrypted = var.enc
}
`,
	})
	if _, ok := ruleIDs(fs)["terraform-encryption-disabled"]; !ok {
		t.Fatalf("a string ending in \\\\ must close so the next line's var resolves, got %v", ruleIDs(fs))
	}
}

// A module-output traversal whose middle segment happens to be named `var` (module.var.cidr) is NOT a
// variable reference and must not be substituted; likewise a nested attribute access on a variable.
func TestTerraformTraversalNotMistakenForVarRef(t *testing.T) {
	fs := scan(t, map[string]string{
		"terraform.tfvars": `cidr = "0.0.0.0/0"` + "\n",
		"main.tf": `
variable "cidr" {}
module "var" {
  source = "./m"
}
resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = [module.var.cidr]
  }
}
`,
	})
	if _, ok := ruleIDs(fs)["terraform-open-cidr"]; ok {
		t.Fatalf("module.var.cidr is a module output, not var.cidr, and must not be substituted, got %v", ruleIDs(fs))
	}
}

// A hyphenated variable name (var.cidr-block) must not be matched by its prefix (var.cidr): the whole name
// is consumed, so a same-prefixed but distinct variable does not leak its value.
func TestTerraformHyphenatedNameNotPrefixMatched(t *testing.T) {
	fs := scan(t, map[string]string{
		"terraform.tfvars": "cidr = \"0.0.0.0/0\"\ncidr-block = \"10.0.0.0/8\"\n",
		"main.tf": `
variable "cidr" {}
variable "cidr-block" {}
resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = [var.cidr-block]
  }
}
`,
	})
	// var.cidr-block resolves to the private 10.0.0.0/8, not the public var.cidr; no open-cidr finding.
	if _, ok := ruleIDs(fs)["terraform-open-cidr"]; ok {
		t.Fatalf("var.cidr-block must not be prefix-matched as var.cidr, got %v", ruleIDs(fs))
	}
}

func TestTerraformModuleUnsupportedResourceInputRemainsUnknown(t *testing.T) {
	for _, expression := range []string{"aws_ebs_volume.source.encrypted", "try(aws_ebs_volume.source.encrypted, true)", "try(aws_ebs_volume.source.encrypted, false)"} {
		for _, fallback := range []bool{false, true} {
			for _, encrypted := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/default-%t/source-%t", expression, fallback, encrypted), func(t *testing.T) {
					configs := []tfInputFile{
						{rel: "main.tf", data: []byte(fmt.Sprintf(`resource "aws_ebs_volume" "source" {
  availability_zone = "us-east-1a"
  size = 20
  encrypted = %t
}
module "child" {
  source = "./child"
  enc = %s
}
`, encrypted, expression))},
						{rel: "child/main.tf", data: []byte(fmt.Sprintf(`variable "enc" {
  default = %t
}
resource "aws_ebs_volume" "destination" {
  availability_zone = "us-east-1a"
  size = 20
  encrypted = var.enc
}
`, fallback))},
					}
					workspace, err := buildTFWorkspace(context.Background(), configs, nil)
					if err != nil {
						t.Fatal(err)
					}
					findings, unresolved, _, err := workspace.scanWorkspace(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					if !hasUnresolved(unresolved, "child/main.tf", "encrypted") {
						t.Fatalf("unsupported explicit reference must remain unknown: %v", unresolved)
					}
					parentFinding := false
					for _, finding := range findings {
						if finding.RuleID != "terraform-encryption-disabled" {
							continue
						}
						if finding.File == "child/main.tf" {
							t.Fatalf("unsupported reference selected the child's default: %+v", finding)
						}
						parentFinding = parentFinding || finding.File == "main.tf"
					}
					if parentFinding == encrypted {
						t.Fatalf("known parent encryption finding = %t, encrypted = %t", parentFinding, encrypted)
					}
				})
			}
		}
	}
}

func TestTerraformModuleTryRetainsValidAttributeFallback(t *testing.T) {
	for _, root := range []string{"var", "local"} {
		for _, fallback := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/fallback-%t", root, fallback), func(t *testing.T) {
				declaration := "variable \"settings\" {\n default = {}\n}\n"
				if root == "local" {
					declaration = "locals {\n settings = {}\n}\n"
				}
				findings, unresolved := scanReport(t, map[string]string{
					"main.tf": declaration + fmt.Sprintf(`module "child" {
  source = "./child"
  enc = try(%s.settings.encrypted, %t)
}
`, root, fallback),
					"child/main.tf": fmt.Sprintf(`variable "enc" {
  default = %t
}
resource "aws_ebs_volume" "destination" {
  encrypted = var.enc
}
`, !fallback),
				})
				encryptionFinding := false
				for _, rule := range findings {
					encryptionFinding = encryptionFinding || rule == "terraform-encryption-disabled"
				}
				if encryptionFinding == fallback {
					t.Fatalf("valid try fallback=%t produced encryption finding=%t", fallback, encryptionFinding)
				}
				if hasUnresolved(unresolved, "child/main.tf", "encrypted") {
					t.Fatalf("valid attribute fallback must resolve: %v", unresolved)
				}
			})
		}
	}
}

func TestTerraformPolicyDocumentInstancesRemainUnknown(t *testing.T) {
	for _, instance := range []struct {
		name        string
		variable    string
		declaration string
		index       string
	}{
		{"count", "variable \"i\" {\n default = 0\n}\n", "count = 1", "var.i"},
		{"for_each", "variable \"key\" {\n default = \"read\"\n}\n", "for_each = { read = true }", "var.key"},
	} {
		for _, fallback := range []bool{false, true} {
			for _, childDefault := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/fallback-%t/default-%t", instance.name, fallback, childDefault), func(t *testing.T) {
					comparison := "> 0"
					if fallback {
						comparison = "== 0"
					}
					findings, unresolved := scanReport(t, map[string]string{
						"main.tf": instance.variable + fmt.Sprintf(`data "aws_iam_policy_document" "doc" {
  %s
  statement {
    effect = "Allow"
    actions = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example/*"]
    principals {
      type = "AWS"
      identifiers = ["*"]
    }
  }
}
module "child" {
  source = "./child"
  enc = try(length(data.aws_iam_policy_document.doc[%s].json) %s, %t)
}
`, instance.declaration, instance.index, comparison, fallback),
						"child/main.tf": fmt.Sprintf(`variable "enc" {
  default = %t
}
resource "aws_ebs_volume" "destination" {
  encrypted = var.enc
}
`, childDefault),
					})
					literalPrincipalFinding := false
					for _, rule := range findings {
						if rule == "terraform-encryption-disabled" {
							t.Fatal("unsupported document collection must not produce a concrete child encryption value")
						}
						literalPrincipalFinding = literalPrincipalFinding || rule == "terraform-wildcard-principal"
					}
					if !literalPrincipalFinding {
						t.Fatal("unknown document collection must retain its literal wildcard-principal finding")
					}
					if !hasUnresolved(unresolved, "child/main.tf", "encrypted") {
						t.Fatalf("unsupported document collection must leave the child unresolved: %v", unresolved)
					}
				})
			}
		}
	}
}

func TestTerraformPolicyDocumentValueBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expression string
		unresolved bool
		encrypted  bool
	}{
		{"provider identifier equality", `data.aws_iam_policy_document.doc.id == "doc"`, true, false},
		{"provider identifier inequality", `data.aws_iam_policy_document.doc.id != "doc"`, true, false},
		{"whole object attributes", `contains(keys(data.aws_iam_policy_document.doc), "statement")`, true, false},
		{"whole object attribute absence", `!contains(keys(data.aws_iam_policy_document.doc), "statement")`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, unresolved := scanReport(t, map[string]string{
				"main.tf": `data "aws_iam_policy_document" "doc" {
  statement {
    actions = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example/*"]
  }
}
module "child" {
  source = "./child"
  enc = ` + tc.expression + `
}
`,
				"child/main.tf": `variable "enc" {
  default = false
}
resource "aws_ebs_volume" "destination" {
  encrypted = var.enc
}
`,
			})
			encryptionFinding := false
			for _, rule := range findings {
				encryptionFinding = encryptionFinding || rule == "terraform-encryption-disabled"
			}
			wantFinding := !tc.unresolved && !tc.encrypted
			if encryptionFinding != wantFinding {
				t.Fatalf("encryption finding = %t, want %t", encryptionFinding, wantFinding)
			}
			if found := hasUnresolved(unresolved, "child/main.tf", "encrypted"); found != tc.unresolved {
				t.Fatalf("child uncertainty = %t, want %t: %v", found, tc.unresolved, unresolved)
			}
		})
	}
}

func TestTerraformPolicyStringListTypes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		actions    string
		unresolved bool
	}{
		{"primitive", "true", true},
		{"object", `{ read = "s3:GetObject" }`, true},
		{"non-string member", `["s3:GetObject", true]`, true},
		{"string tuple", `["s3:GetObject"]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, unresolved := scanReport(t, map[string]string{
				"main.tf": `data "aws_iam_policy_document" "doc" {
  statement {
    actions = ` + tc.actions + `
    resources = ["arn:aws:s3:::example/*"]
    principals {
      type = "AWS"
      identifiers = ["*"]
    }
  }
}
module "child" {
  source = "./child"
  enc = jsondecode(data.aws_iam_policy_document.doc.json).Version == "2012-10-17"
}
`,
				"child/main.tf": `variable "enc" {
  default = false
}
resource "aws_ebs_volume" "destination" {
  encrypted = var.enc
}
`,
			})
			literalFinding := false
			for _, rule := range findings {
				if rule == "terraform-encryption-disabled" {
					t.Fatal("policy type handling must not invent a child encryption value")
				}
				literalFinding = literalFinding || rule == "terraform-wildcard-principal"
			}
			if !literalFinding {
				t.Fatal("policy type handling must retain literal wildcard-principal inspection")
			}
			if found := hasUnresolved(unresolved, "child/main.tf", "encrypted"); found != tc.unresolved {
				t.Fatalf("child uncertainty = %t, want %t: %v", found, tc.unresolved, unresolved)
			}
		})
	}
}

func TestTerraformPolicyVersionAndUnsupportedAttributes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		attributes string
		expression string
		unresolved bool
		finding    bool
	}{
		{"default version", "", `jsondecode(data.aws_iam_policy_document.doc.json).Version == "2012-10-17"`, false, false},
		{"unsupported explicit version", `version = "2008-10-17"`, `try(jsondecode(data.aws_iam_policy_document.doc.json).Version == "2012-10-17", false)`, true, false},
		{"unsupported policy identity", `policy_id = "AssessmentPolicy"`, `try(jsondecode(data.aws_iam_policy_document.doc.json).Id == "AssessmentPolicy", false)`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, unresolved := scanReport(t, map[string]string{
				"main.tf": `data "aws_iam_policy_document" "doc" {
  ` + tc.attributes + `
  statement {
    actions = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example/*"]
  }
}
module "child" {
  source = "./child"
  enc = ` + tc.expression + `
}
`,
				"child/main.tf": `variable "enc" {
  default = true
}
resource "aws_ebs_volume" "destination" {
  encrypted = var.enc
}
`,
			})
			encryptionFinding := false
			for _, rule := range findings {
				encryptionFinding = encryptionFinding || rule == "terraform-encryption-disabled"
			}
			if encryptionFinding != tc.finding {
				t.Fatalf("encryption finding = %t, want %t", encryptionFinding, tc.finding)
			}
			if found := hasUnresolved(unresolved, "child/main.tf", "encrypted"); found != tc.unresolved {
				t.Fatalf("child uncertainty = %t, want %t: %v", found, tc.unresolved, unresolved)
			}
		})
	}
}

func TestTerraformDynamicPolicyBlocksPreserveUncertaintyAndLiteralFindings(t *testing.T) {
	publicStatement := `
    actions = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example/*"]
    principals {
      type = "AWS"
      identifiers = ["*"]
    }
`
	for _, tc := range []struct {
		name string
		body string
	}{
		{"dynamic statement", `statement {
  actions = ["s3:ListBucket"]
  resources = ["arn:aws:s3:::example"]
}
dynamic "statement" {
  for_each = [1]
  content {` + publicStatement + `}
}
`},
		{"dynamic principals", `statement {` + publicStatement + `
  dynamic "principals" {
    for_each = [1]
    content {
      type = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/app"]
    }
  }
}
`},
		{"dynamic condition", `statement {` + publicStatement + `
  dynamic "condition" {
    for_each = [1]
    content {
      test = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values = ["o-example"]
    }
  }
}
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, unresolved := scanReport(t, map[string]string{
				"main.tf": `data "aws_iam_policy_document" "doc" {
` + tc.body + `}
resource "aws_s3_bucket_policy" "p" {
  bucket = "example"
  policy = data.aws_iam_policy_document.doc.json
}
module "child" {
  source = "./child"
  enc = length(jsondecode(data.aws_iam_policy_document.doc.json).Statement) == 2
}
`,
				"child/main.tf": `variable "enc" {
  default = true
}
resource "aws_ebs_volume" "destination" {
  encrypted = var.enc
}
`,
			})
			literalFinding := false
			for _, rule := range findings {
				if rule == "terraform-encryption-disabled" {
					t.Fatal("dynamic policy content must not become a partial concrete child value")
				}
				literalFinding = literalFinding || rule == "terraform-wildcard-principal"
			}
			if !literalFinding {
				t.Fatal("dynamic policy content must not suppress literal wildcard-principal findings")
			}
			if !hasUnresolved(unresolved, "child/main.tf", "encrypted") {
				t.Fatalf("dynamic policy must leave child encryption unknown: %v", unresolved)
			}
		})
	}
}

func TestTerraformLengthUsesStringAndCollectionSemantics(t *testing.T) {
	for _, tc := range []struct {
		name       string
		expression string
		finding    bool
		unresolved bool
	}{
		{"graphemes through try", `try(length("x\u0301z\u0308"), 0) == 2`, false, false},
		{"opposite grapheme predicate", `try(length("x\u0301z\u0308"), 0) != 2`, true, false},
		{"empty string", `length("") == 0`, false, false},
		{"object attributes", `length({ a = 1, b = 2 }) == 2`, false, false},
		{"tuple elements", `length(["a", "b"]) == 2`, false, false},
		{"real type error fallback", `try(length(true), 3) == 3`, false, false},
		{"unknown input", `try(length(var.value) > 0, false)`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, unresolved := scanReport(t, map[string]string{
				"main.tf": `variable "value" {}
module "child" {
  source = "./child"
  enc = ` + tc.expression + `
}
`,
				"child/main.tf": `variable "enc" {
  default = true
}
resource "aws_ebs_volume" "destination" {
  encrypted = var.enc
}
`,
			})
			encryptionFinding := false
			for _, rule := range findings {
				encryptionFinding = encryptionFinding || rule == "terraform-encryption-disabled"
			}
			if encryptionFinding != tc.finding {
				t.Fatalf("encryption finding = %t, want %t", encryptionFinding, tc.finding)
			}
			if found := hasUnresolved(unresolved, "child/main.tf", "encrypted"); found != tc.unresolved {
				t.Fatalf("child uncertainty = %t, want %t: %v", found, tc.unresolved, unresolved)
			}
		})
	}
}

func TestTerraformUnsupportedFunctionsInsideTryRemainUnknown(t *testing.T) {
	for _, shape := range []string{"native", "json", "module"} {
		for _, expression := range []string{
			`try(format("%s", "false") == "true", true)`,
			`try(format("%s", "true") == "true", false)`,
		} {
			t.Run(shape+"/"+expression, func(t *testing.T) {
				file := "main.tf"
				files := map[string]string{
					file: "resource \"aws_ebs_volume\" \"volume\" {\n  encrypted = " + expression + "\n}\n",
				}
				switch shape {
				case "json":
					file = "main.tf.json"
					files = map[string]string{
						file: fmt.Sprintf(`{"resource":{"aws_ebs_volume":{"volume":{"encrypted":%q}}}}`, "${"+expression+"}"),
					}
				case "module":
					file = "child/main.tf"
					files = map[string]string{
						"main.tf": "module \"child\" {\n  source = \"./child\"\n  enc = " + expression + "\n}\n",
						file: "variable \"enc\" {\n  type = bool\n  default = true\n}\n" +
							"resource \"aws_ebs_volume\" \"volume\" {\n  encrypted = var.enc\n}\n",
					}
				}
				findings, unresolved := scanReport(t, files)
				for _, rule := range findings {
					if rule == "terraform-encryption-disabled" {
						t.Fatal("an unsupported function must not invent an effective encryption value through try")
					}
				}
				if !hasUnresolved(unresolved, file, "encrypted") {
					t.Fatalf("unsupported function did not retain consumer uncertainty: %v", unresolved)
				}
			})
		}
	}
}
