package misconfig

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sg renders a security group whose SSH ingress takes its CIDR list from expr.
func sg(expr string) string {
	return `resource "aws_security_group" "sg" {
  description = "ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ` + expr + `
  }
}
`
}

// The audit reported the same internet CIDR as HIGH when written literally and as nothing at all when it
// arrived through a variable, a local, or a list. The effective value decides, not the spelling.
func TestTerraformEvaluatesListForms(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{
			name:  "literal list",
			files: map[string]string{"main.tf": sg(`["0.0.0.0/0"]`)},
			want:  true,
		},
		{
			name: "list variable default",
			files: map[string]string{"main.tf": `variable "ssh" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}
` + sg("var.ssh")},
			want: true,
		},
		{
			name: "local list",
			files: map[string]string{"main.tf": `locals {
  ssh = ["10.0.0.0/16", "0.0.0.0/0"]
}
` + sg("local.ssh")},
			want: true,
		},
		{
			name: "ipv6 list variable",
			files: map[string]string{"main.tf": `variable "ssh6" {
  type    = list(string)
  default = ["::/0"]
}
resource "aws_security_group" "sg" {
  description = "ssh"
  ingress {
    from_port        = 22
    to_port          = 22
    ipv6_cidr_blocks = var.ssh6
  }
}
`},
			want: true,
		},
		{
			name: "concat of a private and a public list",
			files: map[string]string{"main.tf": `locals {
  office = ["10.0.0.0/16"]
}
` + sg(`concat(local.office, ["0.0.0.0/0"])`)},
			want: true,
		},
		{
			name:  "slice that drops the public entry",
			files: map[string]string{"main.tf": sg(`slice(["0.0.0.0/0", "10.0.0.0/16"], 1, 2)`)},
			want:  false,
		},
		{
			name: "conditional that resolves to the private list",
			files: map[string]string{"main.tf": `variable "public" {
  default = false
}
` + sg(`var.public ? ["0.0.0.0/0"] : ["10.0.0.0/16"]`)},
			want: false,
		},
		{
			name: "conditional that resolves to the public list",
			files: map[string]string{"main.tf": `variable "public" {
  default = true
}
` + sg(`var.public ? ["0.0.0.0/0"] : ["10.0.0.0/16"]`)},
			want: true,
		},
		{
			name:  "unresolved reference stays unevaluated",
			files: map[string]string{"main.tf": sg("data.external.ranges.result")},
			want:  false,
		},
		{
			name: "tfvars override supplies the public list",
			files: map[string]string{
				"main.tf": `variable "ssh" {
  type    = list(string)
  default = ["10.0.0.0/16"]
}
` + sg("var.ssh"),
				"terraform.tfvars": `ssh = ["0.0.0.0/0"]` + "\n",
			},
			want: true,
		},
		{
			name: "auto tfvars overrides terraform.tfvars",
			files: map[string]string{
				"main.tf": `variable "ssh" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}
` + sg("var.ssh"),
				"terraform.tfvars": `ssh = ["0.0.0.0/0"]` + "\n",
				"zz.auto.tfvars":   `ssh = ["10.0.0.0/16"]` + "\n",
			},
			want: false,
		},
		{
			name: "json variable file supplies the public list",
			files: map[string]string{
				"main.tf": `variable "ssh" {
  type    = list(string)
  default = ["10.0.0.0/16"]
}
` + sg("var.ssh"),
				"terraform.tfvars.json": `{"ssh": ["0.0.0.0/0"]}` + "\n",
			},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleIDs(scan(t, tc.files))
			if _, ok := got["terraform-open-cidr"]; ok != tc.want {
				t.Fatalf("open-cidr reported=%v, want %v (rules %v)", ok, tc.want, keys(got))
			}
		})
	}
}

// A conditional on an encryption attribute is evaluated, so an effective false is reported and an effective
// true is not.
func TestTerraformEvaluatesEncryptionConditional(t *testing.T) {
	for _, tc := range []struct {
		name string
		prod string
		want bool
	}{
		{name: "effective false", prod: "false", want: true},
		{name: "effective true", prod: "true", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleIDs(scan(t, map[string]string{"main.tf": `variable "prod" {
  default = ` + tc.prod + `
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = var.prod ? true : false
}
`}))
			if _, ok := got["terraform-encryption-disabled"]; ok != tc.want {
				t.Fatalf("encryption-disabled reported=%v, want %v (rules %v)", ok, tc.want, keys(got))
			}
		})
	}
}

// A .tf.json configuration carries the same resources as its HCL form and must produce the same findings.
func TestTerraformJSONSyntax(t *testing.T) {
	got := ruleIDs(scan(t, map[string]string{"main.tf.json": `{
  "resource": {
    "aws_ebs_volume": {
      "v": {
        "availability_zone": "us-east-1a",
        "size": 20,
        "encrypted": false
      }
    },
    "aws_security_group": {
      "sg": {
        "description": "ssh",
        "ingress": {
          "from_port": 22,
          "to_port": 22,
          "cidr_blocks": ["0.0.0.0/0"]
        }
      }
    }
  }
}
`}))
	for _, want := range []string{"terraform-encryption-disabled", "terraform-open-cidr"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected %q from a .tf.json configuration, got %v", want, keys(got))
		}
	}
}

// A child module is evaluated with the inputs its parent binds, in both directions: the parent's value
// wins over the child's default whether it is the safe or the unsafe one.
func TestTerraformModuleInputsBindFromTheCall(t *testing.T) {
	child := `variable "encrypted" {
  default = %s
}
resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = var.encrypted
}
`
	root := `module "vol" {
  source    = "./modules/vol"
  encrypted = %s
}
`
	for _, tc := range []struct {
		name            string
		childDefault    string
		parentBinds     string
		wantEncDisabled bool
	}{
		{name: "parent overrides a safe default with false", childDefault: "true", parentBinds: "false", wantEncDisabled: true},
		{name: "parent overrides an unsafe default with true", childDefault: "false", parentBinds: "true", wantEncDisabled: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleIDs(scan(t, map[string]string{
				"main.tf":             fmtf(root, tc.parentBinds),
				"modules/vol/main.tf": fmtf(child, tc.childDefault),
			}))
			if _, ok := got["terraform-encryption-disabled"]; ok != tc.wantEncDisabled {
				t.Fatalf("encryption-disabled reported=%v, want %v (rules %v)", ok, tc.wantEncDisabled, keys(got))
			}
		})
	}
}

// Two call sites that bind the same input differently leave the child's value without a single effective
// answer, so the module is reported as unresolved rather than evaluated against one instance's value.
func TestTerraformConflictingModuleInputsStayUnresolved(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"main.tf": `module "a" {
  source = "./modules/sg"
  ssh    = ["0.0.0.0/0"]
}
module "b" {
  source = "./modules/sg"
  ssh    = ["10.0.0.0/16"]
}
`,
		"modules/sg/main.tf": `variable "ssh" {}
` + sg("var.ssh"),
	}
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
	if _, ok := ruleIDs(report.Findings)["terraform-open-cidr"]; ok {
		t.Fatalf("a module bound differently by two call sites must not resolve to one instance's value")
	}
	if !hasUnresolved(report.UnresolvedInputs, "modules/sg/main.tf", "cidr_blocks") {
		t.Fatalf("the unresolved attribute must be reported, got %v", report.UnresolvedInputs)
	}
}

func hasUnresolved(in []string, file, attr string) bool {
	for _, s := range in {
		if strings.HasPrefix(s, file+":") && strings.HasSuffix(s, " "+attr) {
			return true
		}
	}
	return false
}

func fmtf(tmpl string, v string) string { return strings.Replace(tmpl, "%s", v, 1) }
