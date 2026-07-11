package misconfig

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTerraformInsecure(t *testing.T) {
	tf := `resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
  password            = "hunter2super"
}

resource "aws_ecr_repository" "r" {
  name = "app"
}

resource "aws_dynamodb_table" "t" {
  name = "items"
}

resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 20
}

resource "aws_s3_bucket_versioning" "v" {
  bucket = aws_s3_bucket.b.id
  versioning_configuration {
    status = "Suspended"
  }
}
`
	got := ruleIDs(scan(t, map[string]string{"main.tf": tf}))
	for _, want := range []string{
		"terraform-public-bucket-acl", "terraform-open-cidr", "terraform-db-publicly-accessible",
		"terraform-encryption-disabled", "terraform-plaintext-secret",
		"terraform-ecr-mutable-tags", "terraform-ecr-no-cmk",
		"terraform-dynamodb-unencrypted", "terraform-dynamodb-no-pitr",
		"terraform-ebs-unencrypted", "terraform-s3-no-versioning", "terraform-open-egress",
		"terraform-rds-deletion-protection-disabled",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected Terraform rule %q, got %v", want, keys(got))
		}
	}
}

func TestTerraformSecureNoFindings(t *testing.T) {
	// A hardened resource set: private ACL, scoped CIDR, encryption on, secret from a variable,
	// immutable+encrypted ECR, encrypted DynamoDB with PITR, deletion protection on.
	tf := `resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
  acl    = "private"
  logging {
    target_bucket = "logs"
  }
  versioning {
    enabled = true
  }
}

resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
}

resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = ["10.0.0.0/8"]
  }
  egress {
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "db" {
  publicly_accessible = false
  storage_encrypted   = true
  password            = var.db_password
  deletion_protection = true
}

resource "aws_ecr_repository" "r" {
  name                 = "app"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
    encryption_type = "KMS"
  }
}
`
	if got := scan(t, map[string]string{"main.tf": tf}); len(got) != 0 {
		t.Errorf("hardened Terraform should yield no findings, got %+v", got)
	}
}

func TestTerraformS3VersioningSplitStyle(t *testing.T) {
	// Provider v4+ style: the bucket omits an inline versioning block and versioning is set on a
	// separate aws_s3_bucket_versioning resource. An Enabled split resource must suppress the
	// bucket-origin "no versioning" false positive.
	tf := `resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
  acl    = "private"
  logging {
    target_bucket = "logs"
  }
}

resource "aws_s3_bucket_versioning" "v" {
  bucket = aws_s3_bucket.b.id
  versioning_configuration {
    status = "Enabled"
  }
}
`
	got := ruleIDs(scan(t, map[string]string{"main.tf": tf}))
	if _, ok := got["terraform-s3-no-versioning"]; ok {
		t.Errorf("split-style Enabled versioning must not flag terraform-s3-no-versioning, got %v", keys(got))
	}
}

func TestHelmRenderedIfAvailable(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed; Helm rendering is best-effort and skipped")
	}
	files := map[string]string{
		"chart/Chart.yaml":                "apiVersion: v2\nname: demo\nversion: 0.1.0\n",
		"chart/values.yaml":               "image: demo:1.0\n",
		"chart/templates/deployment.yaml": helmDeployment,
	}
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
	// Helm rendering is off by default; the trusted-local CLI path (WithHelmDirect) enables it.
	out, err := New().WithHelmDirect().ScanConfigs(context.Background(), root)
	if err != nil {
		t.Fatalf("ScanConfigs: %v", err)
	}
	got := ruleIDs(out)
	// The rendered pod sets no hardening, so the missing-hardening rules must fire via the Helm path.
	for _, want := range []string{"kubernetes-no-run-as-non-root", "kubernetes-no-seccomp"} {
		if _, ok := got[want]; !ok {
			t.Errorf("Helm-rendered manifest must be scanned with the K8s rules; missing %q, got %v", want, keys(got))
		}
	}
}

const helmDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-web
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: {{ .Values.image }}
`

func terraformFindingsByRule(
	in []ports.MisconfigRawFinding,
	ruleID string,
) []ports.MisconfigRawFinding {
	var out []ports.MisconfigRawFinding

	for _, finding := range in {
		if finding.RuleID == ruleID {
			out = append(out, finding)
		}
	}

	return out
}

func TestTerraformRDSDeletionProtectionMissing(t *testing.T) {
	tf := `resource "aws_db_instance" "primary" {
  identifier     = "primary"
  engine         = "postgres"
  instance_class = "db.t3.micro"
}`
	all := scanTerraform(
		"infra/main.tf",
		[]byte(tf),
	)

	got := terraformFindingsByRule(
		all,
		"terraform-rds-deletion-protection-disabled",
	)

	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}

	want := ports.MisconfigRawFinding{
		File:        "infra/main.tf",
		Line:        1,
		RuleID:      "terraform-rds-deletion-protection-disabled",
		Title:       "RDS deletion protection is not enabled",
		Severity:    shared.SeverityLow,
		Resource:    "Terraform aws_db_instance",
		Description: "The RDS DB instance does not enable deletion protection, so it can be deleted without first removing an explicit protection control. Set deletion_protection = true to reduce the risk of accidental or unauthorized deletion.",
	}

	if got[0] != want {
		t.Errorf("finding mismatch:\nwant: %+v\n got: %+v", want, got[0])
	}
}

func TestTerraformRDSDeletionProtectionFalse(t *testing.T) {
	tf := `resource "aws_db_instance" "primary" {
  deletion_protection = false
}`
	all := scanTerraform("main.tf", []byte(tf))
	got := terraformFindingsByRule(all, "terraform-rds-deletion-protection-disabled")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Line != 1 {
		t.Errorf("want line 1, got %d", got[0].Line)
	}
	if got[0].Severity != shared.SeverityLow {
		t.Errorf("want Low severity, got %v", got[0].Severity)
	}
}

func TestTerraformRDSDeletionProtectionTrue(t *testing.T) {
	tf := `resource "aws_db_instance" "primary" {
  deletion_protection = true
}`
	all := scanTerraform("main.tf", []byte(tf))
	got := terraformFindingsByRule(all, "terraform-rds-deletion-protection-disabled")
	if len(got) != 0 {
		t.Fatalf("want 0 findings, got %d: %+v", len(got), got)
	}
}

func TestTerraformRDSDeletionProtectionLiteralSyntax(t *testing.T) {
	tests := []struct {
		name string
		line string
		want int
	}{
		{
			name: "false with spaces",
			line: `  deletion_protection = false`,
			want: 1,
		},
		{
			name: "false without spaces",
			line: `deletion_protection=false`,
			want: 1,
		},
		{
			name: "false with tab",
			line: "deletion_protection\t=\tfalse",
			want: 1,
		},
		{
			name: "true with spaces",
			line: `  deletion_protection = true`,
			want: 0,
		},
		{
			name: "true with inline comment",
			line: `  deletion_protection = true # protected`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tf := "resource \"aws_db_instance\" \"primary\" {\n" + tt.line + "\n}"
			all := scanTerraform("main.tf", []byte(tf))
			got := terraformFindingsByRule(all, "terraform-rds-deletion-protection-disabled")
			if len(got) != tt.want {
				t.Fatalf("want %d findings, got %d: %+v", tt.want, len(got), got)
			}
		})
	}
}

func TestTerraformRDSDeletionProtectionDynamicValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{
			name:  "variable",
			value: `var.enable_deletion_protection`,
		},
		{
			name:  "local",
			value: `local.enable_deletion_protection`,
		},
		{
			name:  "data source",
			value: `data.aws_ssm_parameter.deletion_protection.value`,
		},
		{
			name:  "module output",
			value: `module.database_policy.deletion_protection`,
		},
		{
			name:  "workspace expression",
			value: `terraform.workspace == "prod"`,
		},
		{
			name:  "conditional expression",
			value: `var.production ? true : false`,
		},
		{
			name:  "function expression",
			value: `try(var.enable_deletion_protection, true)`,
		},
		{
			name:  "interpolation string",
			value: `"${var.enable_deletion_protection}"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tf := "resource \"aws_db_instance\" \"primary\" {\n  deletion_protection = " + tt.value + "\n}"
			all := scanTerraform("main.tf", []byte(tf))
			got := terraformFindingsByRule(all, "terraform-rds-deletion-protection-disabled")
			if len(got) != 0 {
				t.Fatalf("want 0 findings, got %d: %+v", len(got), got)
			}
		})
	}
}

func TestTerraformRDSDeletionProtectionCommentsDoNotSuppress(t *testing.T) {
	tfs := []string{
		`resource "aws_db_instance" "primary" {
  # deletion_protection = true
  engine = "postgres"
}`,
		`resource "aws_db_instance" "primary" {
  // deletion_protection = true
  engine = "postgres"
}`,
		`resource "aws_db_instance" "primary" {
  engine = "postgres" # deletion_protection = true
}`,
		`resource "aws_db_instance" "primary" {
  /* deletion_protection = true */
  engine = "postgres"
}`,
		`resource "aws_db_instance" "primary" {
  /*
  deletion_protection = true
  */
  engine = "postgres"
}`,
		`resource "aws_db_instance" "primary" {
  deletion_protection = false /* disabled */
}`,
	}
	for i, tf := range tfs {
		t.Run("comment_case_"+string(rune('0'+i)), func(t *testing.T) {
			all := scanTerraform("main.tf", []byte(tf))
			got := terraformFindingsByRule(all, "terraform-rds-deletion-protection-disabled")
			if len(got) != 1 {
				t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
			}
		})
	}
}

func TestTerraformRDSDeletionProtectionExactAttribute(t *testing.T) {
	tf := `resource "aws_db_instance" "primary" {
  deletion_protection_backup = true
  enable_deletion_protection = true
  rds_deletion_protection    = true
}`
	all := scanTerraform("main.tf", []byte(tf))
	got := terraformFindingsByRule(all, "terraform-rds-deletion-protection-disabled")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
}

func TestTerraformRDSDeletionProtectionNestedAttribute(t *testing.T) {
	tf := `resource "aws_db_instance" "primary" {
  timeouts {
    deletion_protection = true
  }
}`
	all := scanTerraform("main.tf", []byte(tf))
	got := terraformFindingsByRule(all, "terraform-rds-deletion-protection-disabled")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
}

func TestTerraformRDSDeletionProtectionAfterNestedBlock(t *testing.T) {
	tf := `resource "aws_db_instance" "primary" {
  timeouts {
    create = "60m"
  }

  deletion_protection = true
}`
	all := scanTerraform("main.tf", []byte(tf))
	got := terraformFindingsByRule(all, "terraform-rds-deletion-protection-disabled")
	if len(got) != 0 {
		t.Fatalf("want 0 findings, got %d: %+v", len(got), got)
	}
}

func TestTerraformRDSDeletionProtectionDirectFalse(t *testing.T) {
	tf := `resource "aws_db_instance" "primary" {
  timeouts {
    deletion_protection = true
  }

  deletion_protection = false
}`
	all := scanTerraform("main.tf", []byte(tf))
	got := terraformFindingsByRule(all, "terraform-rds-deletion-protection-disabled")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
}

func TestTerraformRDSDeletionProtectionResourceScope(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
	}{
		{
			name:         "RDS cluster",
			resourceType: "aws_rds_cluster",
		},
		{
			name:         "DocumentDB cluster",
			resourceType: "aws_docdb_cluster",
		},
		{
			name:         "Neptune cluster",
			resourceType: "aws_neptune_cluster",
		},
		{
			name:         "EC2 instance",
			resourceType: "aws_instance",
		},
		{
			name:         "random resource",
			resourceType: "random_id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tf := "resource \"" + tt.resourceType + "\" \"example\" {\n  deletion_protection = false\n}"
			all := scanTerraform("main.tf", []byte(tf))
			got := terraformFindingsByRule(all, "terraform-rds-deletion-protection-disabled")
			if len(got) != 0 {
				t.Fatalf("want 0 findings, got %d: %+v", len(got), got)
			}
		})
	}
}

func TestTerraformRDSDeletionProtectionMultipleResources(t *testing.T) {
	tf := `resource "aws_db_instance" "missing" {
  engine = "postgres"
}
resource "aws_db_instance" "disabled" {
  deletion_protection = false
}
resource "aws_db_instance" "enabled" {
  deletion_protection = true
}
resource "aws_db_instance" "dynamic" {
  deletion_protection = var.enabled
}`
	all := scanTerraform("main.tf", []byte(tf))
	got := terraformFindingsByRule(all, "terraform-rds-deletion-protection-disabled")
	if len(got) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(got), got)
	}
	if got[0].Line != 1 {
		t.Errorf("want start line 1, got %d", got[0].Line)
	}
	if got[1].Line != 4 {
		t.Errorf("want start line 4, got %d", got[1].Line)
	}
}

func TestTerraformRDSDeletionProtectionDeterministic(t *testing.T) {
	tf := `resource "aws_db_instance" "missing" {
  engine = "postgres"
}
resource "aws_db_instance" "disabled" {
  deletion_protection = false
}
resource "aws_db_instance" "enabled" {
  deletion_protection = true
}
resource "aws_ebs_volume" "v" {
  size = 20
}`
	first := scanTerraform("main.tf", []byte(tf))
	for i := 0; i < 20; i++ {
		got := scanTerraform("main.tf", []byte(tf))
		if len(first) != len(got) {
			t.Fatalf("iteration %d: length mismatch %d != %d", i, len(first), len(got))
		}
		for j := range first {
			if first[j] != got[j] {
				t.Fatalf("iteration %d: finding %d mismatch: %+v != %+v", i, j, first[j], got[j])
			}
		}
	}
}

func TestTerraformRDSDeletionProtectionOneFindingPerResource(t *testing.T) {
	tf := `resource "aws_db_instance" "primary" {
  deletion_protection = false
}`
	all := scanTerraform("main.tf", []byte(tf))
	got := terraformFindingsByRule(all, "terraform-rds-deletion-protection-disabled")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
}
