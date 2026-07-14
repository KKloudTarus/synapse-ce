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
  description = "App tier ingress from the load balancer"
  ingress {
    cidr_blocks = ["10.0.0.0/8"]
  }
  egress {
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "db" {
  publicly_accessible                 = false
  storage_encrypted                   = true
  iam_database_authentication_enabled = true
  password                            = var.db_password
  deletion_protection                 = true
}

resource "aws_ecr_repository" "r" {
  name                 = "app"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
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

func TestTerraformGapPackTriggers(t *testing.T) {
	// Each new rule must fire on a genuine violation across AWS/Azure/GCP.
	cases := []struct {
		name, tf, want string
	}{
		{"iam resource wildcard", "resource \"aws_iam_policy\" \"p\" {\n  policy = jsonencode({ Statement = [{ Effect = \"Allow\", Action = \"s3:GetObject\", Resource = \"*\" }] })\n}\n", "terraform-iam-wildcard-resource"},
		{"wildcard principal", "resource \"aws_sqs_queue_policy\" \"p\" {\n  policy = jsonencode({ Statement = [{ Effect = \"Allow\", Principal = \"*\", Action = \"sqs:SendMessage\" }] })\n}\n", "terraform-wildcard-principal"},
		{"wildcard principal nested", "resource \"aws_kms_key\" \"k\" {\n  policy = jsonencode({ Statement = [{ Principal = { AWS = \"*\" }, Action = \"kms:Decrypt\" }] })\n}\n", "terraform-wildcard-principal"},
		{"lambda public", "resource \"aws_lambda_permission\" \"p\" {\n  action        = \"lambda:InvokeFunction\"\n  function_name = \"f\"\n  principal     = \"*\"\n}\n", "terraform-lambda-public"},
		{"api no auth", "resource \"aws_api_gateway_method\" \"m\" {\n  authorization = \"NONE\"\n}\n", "terraform-api-gateway-no-auth"},
		{"azure public container", "resource \"azurerm_storage_container\" \"c\" {\n  container_access_type = \"blob\"\n}\n", "terraform-azure-storage-public-container"},
		{"azure public net", "resource \"azurerm_storage_account\" \"sa\" {\n  public_network_access_enabled = true\n}\n", "terraform-azure-public-network-access"},
		{"gcp public member", "resource \"google_storage_bucket_iam_member\" \"m\" {\n  member = \"allUsers\"\n}\n", "terraform-gcp-public-iam-member"},
		{"eks public endpoint", "resource \"aws_eks_cluster\" \"c\" {\n  enabled_cluster_log_types = [\"api\"]\n  vpc_config {\n    endpoint_public_access = true\n  }\n}\n", "terraform-eks-public-endpoint"},
		{"azure nsg open", "resource \"azurerm_network_security_rule\" \"r\" {\n  source_address_prefix = \"*\"\n}\n", "terraform-azure-nsg-open"},
		{"iam admin policy", "resource \"aws_iam_role_policy_attachment\" \"a\" {\n  policy_arn = \"arn:aws:iam::aws:policy/AdministratorAccess\"\n}\n", "terraform-iam-admin-policy"},
		{"rds iam auth", "resource \"aws_db_instance\" \"db\" {\n  storage_encrypted = true\n}\n", "terraform-rds-iam-auth-disabled"},
		{"gcp public ip", "resource \"google_compute_instance\" \"vm\" {\n  network_interface {\n    access_config {\n    }\n  }\n}\n", "terraform-gcp-compute-public-ip"},
		{"rds no encryption", "resource \"aws_db_instance\" \"db\" {\n  engine = \"postgres\"\n}\n", "terraform-rds-no-encryption"},
		{"efs unencrypted", "resource \"aws_efs_file_system\" \"fs\" {\n  creation_token = \"app\"\n}\n", "terraform-efs-unencrypted"},
		{"sqs unencrypted", "resource \"aws_sqs_queue\" \"q\" {\n  name = \"jobs\"\n}\n", "terraform-sqs-unencrypted"},
		{"elasticache unencrypted", "resource \"aws_elasticache_replication_group\" \"r\" {\n  replication_group_id = \"c\"\n}\n", "terraform-elasticache-unencrypted"},
		{"redshift unencrypted", "resource \"aws_redshift_cluster\" \"c\" {\n  cluster_identifier = \"dw\"\n}\n", "terraform-redshift-unencrypted"},
		{"kinesis unencrypted", "resource \"aws_kinesis_stream\" \"s\" {\n  name = \"e\"\n}\n", "terraform-kinesis-unencrypted"},
		{"cloudfront http", "resource \"aws_cloudfront_distribution\" \"d\" {\n  default_root_object = \"index.html\"\n  default_cache_behavior {\n    viewer_protocol_policy = \"allow-all\"\n  }\n}\n", "terraform-cloudfront-allow-http"},
		{"azure no https", "resource \"azurerm_storage_account\" \"sa\" {\n  https_traffic_only_enabled = false\n}\n", "terraform-azure-storage-no-https"},
		{"azure min tls", "resource \"azurerm_storage_account\" \"sa\" {\n  min_tls_version = \"TLS1_1\"\n}\n", "terraform-azure-storage-min-tls"},
		{"ecr no scan", "resource \"aws_ecr_repository\" \"r\" {\n  name = \"app\"\n}\n", "terraform-ecr-no-scan"},
		{"cloudtrail no validation", "resource \"aws_cloudtrail\" \"t\" {\n  is_multi_region_trail = true\n}\n", "terraform-cloudtrail-no-log-validation"},
		{"cloudtrail not multi region", "resource \"aws_cloudtrail\" \"t\" {\n  enable_log_file_validation = true\n}\n", "terraform-cloudtrail-not-multi-region"},
		{"lb no access logs", "resource \"aws_lb\" \"lb\" {\n  name = \"app\"\n}\n", "terraform-lb-no-access-logs"},
		{"apigw no logging", "resource \"aws_api_gateway_stage\" \"s\" {\n  stage_name = \"prod\"\n}\n", "terraform-apigw-no-logging"},
		{"eks no logging", "resource \"aws_eks_cluster\" \"c\" {\n  name = \"app\"\n}\n", "terraform-eks-no-logging"},
		{"cloudwatch no retention", "resource \"aws_cloudwatch_log_group\" \"lg\" {\n  kms_key_id = \"k\"\n}\n", "terraform-cloudwatch-no-retention"},
		{"sg no description", "resource \"aws_security_group\" \"sg\" {\n  name = \"app\"\n}\n", "terraform-sg-no-description"},
		{"rds no backup", "resource \"aws_db_instance\" \"db\" {\n  storage_encrypted       = true\n  backup_retention_period = 0\n}\n", "terraform-rds-no-backup"},
		{"sqs no dlq", "resource \"aws_sqs_queue\" \"q\" {\n  sqs_managed_sse_enabled = true\n}\n", "terraform-sqs-no-dlq"},
		{"lambda no dlq", "resource \"aws_lambda_function\" \"f\" {\n  function_name = \"w\"\n}\n", "terraform-lambda-no-dlq"},
		{"asg no health check", "resource \"aws_autoscaling_group\" \"asg\" {\n  max_size = 3\n}\n", "terraform-asg-no-health-check"},
		{"cloudfront no root", "resource \"aws_cloudfront_distribution\" \"d\" {\n  enabled = true\n}\n", "terraform-cloudfront-no-default-root"},
		{"rds single az", "resource \"aws_db_instance\" \"db\" {\n  storage_encrypted = true\n  multi_az          = false\n}\n", "terraform-rds-no-multi-az"},
		{"default resource", "resource \"aws_default_vpc\" \"d\" {\n}\n", "terraform-default-resource-managed"},
		{"local exec", "resource \"null_resource\" \"r\" {\n  provisioner \"local-exec\" {\n    command = \"echo hi\"\n  }\n}\n", "terraform-local-exec-provisioner"},
		{"remote exec", "resource \"null_resource\" \"r\" {\n  provisioner \"remote-exec\" {\n    inline = [\"ls\"]\n  }\n}\n", "terraform-remote-exec-provisioner"},
		{"ignore all", "resource \"null_resource\" \"r\" {\n  lifecycle {\n    ignore_changes = all\n  }\n}\n", "terraform-lifecycle-ignore-all"},
		{"module no version", "module \"vpc\" {\n  source = \"terraform-aws-modules/vpc/aws\"\n}\n", "terraform-module-no-version"},
		{"module unpinned git", "module \"vpc\" {\n  source = \"git::https://github.com/org/repo.git\"\n}\n", "terraform-module-unpinned-git"},
		{"kms no rotation", "resource \"aws_kms_key\" \"k\" {\n  description = \"app\"\n}\n", "terraform-kms-no-rotation"},
		{"instance public ip", "resource \"aws_instance\" \"i\" {\n  associate_public_ip_address = true\n}\n", "terraform-instance-public-ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleIDs(scan(t, map[string]string{"main.tf": tc.tf}))
			if _, ok := got[tc.want]; !ok {
				t.Errorf("expected %s, got %v", tc.want, keys(got))
			}
		})
	}
}

func TestTerraformGapPackNoFalsePositives(t *testing.T) {
	// Compliant snippets must NOT trigger the paired rule (low-false-positive guard).
	cases := []struct {
		name, tf, notRule string
	}{
		{"scoped resource", "resource \"aws_iam_policy\" \"p\" {\n  policy = jsonencode({ Statement = [{ Effect = \"Allow\", Action = \"s3:GetObject\", Resource = \"arn:aws:s3:::b/*\" }] })\n}\n", "terraform-iam-wildcard-resource"},
		{"lambda scoped principal", "resource \"aws_lambda_permission\" \"p\" {\n  principal = \"s3.amazonaws.com\"\n}\n", "terraform-lambda-public"},
		{"lambda principal is not iam principal", "resource \"aws_lambda_permission\" \"p\" {\n  principal = \"s3.amazonaws.com\"\n}\n", "terraform-wildcard-principal"},
		{"module with version", "module \"vpc\" {\n  source  = \"terraform-aws-modules/vpc/aws\"\n  version = \"~> 5.0\"\n}\n", "terraform-module-no-version"},
		{"git module with ref", "module \"vpc\" {\n  source = \"git::https://github.com/org/repo.git?ref=v1.2.0\"\n}\n", "terraform-module-unpinned-git"},
		{"local module is fine", "module \"vpc\" {\n  source = \"./modules/vpc\"\n}\n", "terraform-module-no-version"},
		{"kms rotation on", "resource \"aws_kms_key\" \"k\" {\n  enable_key_rotation = true\n}\n", "terraform-kms-no-rotation"},
		{"tls 1.2 is fine", "resource \"azurerm_storage_account\" \"sa\" {\n  min_tls_version = \"TLS1_2\"\n}\n", "terraform-azure-storage-min-tls"},
		{"cloudfront https is fine", "resource \"aws_cloudfront_distribution\" \"d\" {\n  default_root_object = \"index.html\"\n  default_cache_behavior {\n    viewer_protocol_policy = \"redirect-to-https\"\n  }\n}\n", "terraform-cloudfront-allow-http"},
		{"scoped nsg is fine", "resource \"azurerm_network_security_rule\" \"r\" {\n  source_address_prefix = \"10.0.0.0/16\"\n}\n", "terraform-azure-nsg-open"},
		{"specific member is fine", "resource \"google_storage_bucket_iam_member\" \"m\" {\n  member = \"user:alice@example.com\"\n}\n", "terraform-gcp-public-iam-member"},
		{"private instance is fine", "resource \"aws_instance\" \"i\" {\n  associate_public_ip_address = false\n  metadata_options {\n    http_tokens = \"required\"\n  }\n}\n", "terraform-instance-public-ip"},
		{"apt-target-release style safe pin", "resource \"aws_db_instance\" \"db\" {\n  storage_encrypted       = true\n  backup_retention_period = 7\n}\n", "terraform-rds-no-backup"},
		{"admin policy data-source ref is not an attachment", "data \"aws_iam_policy\" \"admin\" {\n  arn = \"arn:aws:iam::aws:policy/AdministratorAccess\"\n}\n", "terraform-iam-admin-policy"},
		{"remote archive module takes no version", "module \"vpc\" {\n  source = \"https://example.com/vpc.zip\"\n}\n", "terraform-module-no-version"},
		{"s3 archive module takes no version", "module \"vpc\" {\n  source = \"s3::https://s3.amazonaws.com/b/vpc.zip\"\n}\n", "terraform-module-no-version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleIDs(scan(t, map[string]string{"main.tf": tc.tf}))
			if _, bad := got[tc.notRule]; bad {
				t.Errorf("%s: must not trigger %q; got %v", tc.name, tc.notRule, keys(got))
			}
		})
	}
}
