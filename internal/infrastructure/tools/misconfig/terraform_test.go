package misconfig

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
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
`
	got := ruleIDs(scan(t, map[string]string{"main.tf": tf}))
	for _, want := range []string{
		"terraform-public-bucket-acl", "terraform-open-cidr", "terraform-db-publicly-accessible",
		"terraform-encryption-disabled", "terraform-plaintext-secret",
		"terraform-ecr-mutable-tags", "terraform-ecr-no-cmk",
		"terraform-dynamodb-unencrypted", "terraform-dynamodb-no-pitr",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected Terraform rule %q, got %v", want, keys(got))
		}
	}
}

func TestTerraformSecureNoFindings(t *testing.T) {
	// A hardened resource set: private ACL, scoped CIDR, encryption on, secret from a variable,
	// immutable+encrypted ECR, encrypted DynamoDB with PITR.
	tf := `resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
  acl    = "private"
  logging {
    target_bucket = "logs"
  }
}

resource "aws_security_group" "sg" {
  ingress {
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "db" {
  publicly_accessible = false
  storage_encrypted   = true
  password            = var.db_password
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
