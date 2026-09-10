package misconfig

import "testing"

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
