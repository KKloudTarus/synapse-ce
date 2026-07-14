package misconfig

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	domainrule "github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

var explicitInventory = []string{
	"cloudformation-iam-wildcard", "cloudformation-open-security-group", "cloudformation-plaintext-secret", "cloudformation-public-bucket-acl", "cloudformation-rds-unencrypted", "cloudformation-s3-no-encryption",
	"compose-dangerous-capability", "compose-docker-socket-mount", "compose-host-ipc", "compose-host-network", "compose-host-pid", "compose-image-unpinned", "compose-privileged", "compose-secret-in-env", "compose-unconfined-security-opt", "compose-userns-host",
	"dockerfile-add-instead-of-copy", "dockerfile-add-remote-url", "dockerfile-apt-no-clean", "dockerfile-apt-no-norecommends", "dockerfile-apt-upgrade", "dockerfile-expose-ssh", "dockerfile-image-no-tag", "dockerfile-insecure-download", "dockerfile-maintainer-deprecated", "dockerfile-multiple-cmd", "dockerfile-no-healthcheck", "dockerfile-run-as-root", "dockerfile-run-pipe-shell", "dockerfile-run-sudo", "dockerfile-secret-in-arg", "dockerfile-secret-in-env", "dockerfile-workdir-relative", "dockerfile-multiple-entrypoint", "dockerfile-shell-form-entrypoint", "dockerfile-from-platform-pinned", "dockerfile-copy-to-root", "dockerfile-private-key-copy", "dockerfile-world-writable", "dockerfile-setuid-chmod", "dockerfile-secret-in-run", "dockerfile-apt-no-yes", "dockerfile-apk-no-cache", "dockerfile-yum-no-clean", "dockerfile-pip-no-cache-dir", "dockerfile-cd-in-run", "dockerfile-plaintext-download", "dockerfile-apt-cli", "dockerfile-yum-no-yes", "dockerfile-apt-version-pin", "dockerfile-apk-version-pin",
	"gha-permissions-write-all", "gha-pull-request-target", "gha-script-injection", "gha-unpinned-action",
	"kubernetes-allow-priv-escalation", "kubernetes-automount-sa-token", "kubernetes-caps-not-dropped", "kubernetes-dangerous-capability", "kubernetes-default-namespace", "kubernetes-default-service-account", "kubernetes-host-ipc", "kubernetes-host-network", "kubernetes-host-path", "kubernetes-host-pid", "kubernetes-host-port", "kubernetes-image-no-tag", "kubernetes-ingress-no-tls", "kubernetes-ingress-tls-no-secret", "kubernetes-namespace-no-network-policy", "kubernetes-no-cpu-limit", "kubernetes-no-memory-limit", "kubernetes-no-priv-escalation-disabled", "kubernetes-no-read-only-root-fs", "kubernetes-no-run-as-group", "kubernetes-no-run-as-non-root", "kubernetes-no-run-as-user", "kubernetes-no-seccomp", "kubernetes-privileged", "kubernetes-rbac-cluster-admin-binding", "kubernetes-rbac-escalation-verbs", "kubernetes-rbac-wildcard-permissions", "kubernetes-run-as-root", "kubernetes-secret-in-env", "kubernetes-secret-in-manifest",
	"terraform-api-gateway-no-auth", "terraform-apigw-no-logging", "terraform-asg-no-health-check", "terraform-azure-nsg-open", "terraform-azure-public-network-access", "terraform-azure-storage-min-tls", "terraform-azure-storage-no-https", "terraform-azure-storage-public-container", "terraform-cloudfront-allow-http", "terraform-cloudfront-no-default-root", "terraform-cloudtrail-no-log-validation", "terraform-cloudtrail-not-multi-region", "terraform-cloudwatch-no-retention", "terraform-cloudwatch-unencrypted", "terraform-db-publicly-accessible", "terraform-default-resource-managed", "terraform-dynamodb-no-pitr", "terraform-dynamodb-unencrypted", "terraform-ebs-unencrypted", "terraform-ecr-mutable-tags", "terraform-ecr-no-cmk", "terraform-ecr-no-scan", "terraform-efs-unencrypted", "terraform-eks-no-logging", "terraform-eks-public-endpoint", "terraform-elasticache-unencrypted", "terraform-encryption-disabled", "terraform-gcp-compute-public-ip", "terraform-gcp-public-iam-member", "terraform-iam-admin-policy", "terraform-iam-wildcard", "terraform-iam-wildcard-resource", "terraform-imdsv2-not-required", "terraform-instance-public-ip", "terraform-kinesis-unencrypted", "terraform-kms-no-rotation", "terraform-lambda-no-dlq", "terraform-lambda-public", "terraform-lb-no-access-logs", "terraform-lifecycle-ignore-all", "terraform-local-exec-provisioner", "terraform-module-no-version", "terraform-module-unpinned-git", "terraform-open-cidr", "terraform-open-egress", "terraform-plaintext-secret", "terraform-public-access-block-disabled", "terraform-public-bucket-acl", "terraform-rds-deletion-protection-disabled", "terraform-rds-iam-auth-disabled", "terraform-rds-no-backup", "terraform-rds-no-encryption", "terraform-rds-no-multi-az", "terraform-redshift-unencrypted", "terraform-remote-exec-provisioner", "terraform-s3-no-logging", "terraform-s3-no-versioning", "terraform-sg-no-description", "terraform-sns-unencrypted", "terraform-sqs-no-dlq", "terraform-sqs-unencrypted", "terraform-wildcard-principal",
}

func TestCatalogParity(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Failed to load catalog: %v", err)
	}

	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("Failed to list catalog: %v", err)
	}

	catalogMap := make(map[string]domainrule.Rule)
	for _, r := range rules {
		catalogMap[string(r.Key)] = r
	}

	expectedDetection := map[string]domainrule.Detection{
		"CloudFormation": domainrule.DetectionAST,
		"Docker Compose": domainrule.DetectionPattern,
		"Dockerfile":     domainrule.DetectionPattern,
		"GitHub Actions": domainrule.DetectionPattern,
		"Kubernetes":     domainrule.DetectionAST,
		"Terraform":      domainrule.DetectionPattern,
	}

	if len(explicitInventory) == 0 {
		t.Fatal("explicit misconfiguration inventory is empty")
	}

	inventory := make(map[string]struct{}, len(explicitInventory))
	for _, id := range explicitInventory {
		inventory[id] = struct{}{}
	}

	misconfigLanguages := map[string]bool{
		"CloudFormation": true,
		"Docker Compose": true,
		"Dockerfile":     true,
		"GitHub Actions": true,
		"Kubernetes":     true,
		"Terraform":      true,
	}

	for _, catalogRule := range rules {
		if !misconfigLanguages[catalogRule.Language] {
			continue
		}

		if _, ok := inventory[string(catalogRule.Key)]; !ok {
			t.Errorf(
				"extra stale misconfiguration rule in catalog: %s",
				catalogRule.Key,
			)
		}
	}

	// 1. Explicit Inventory Verification
	for _, expectedID := range explicitInventory {
		if r, ok := catalogMap[expectedID]; !ok {
			t.Errorf("Rule %s found in explicit inventory but missing from catalog", expectedID)
		} else {
			if exp, ok2 := expectedDetection[r.Language]; ok2 {
				if r.Detection != exp {
					t.Errorf("Rule %s detection mode mismatch: got %v, expected %v", expectedID, r.Detection, exp)
				}
			}
		}
	}

	// 2. Table-Driven Example Verification
	// Validate key, name, severity, and example-behavior for all 147 misconfiguration rules.
	for _, id := range explicitInventory {
		catRule, ok := catalogMap[id]
		if !ok {
			continue // Checked above
		}

		filename := ""
		if strings.HasPrefix(id, "cloudformation-") {
			filename = "template.yaml"
		} else if strings.HasPrefix(id, "compose-") {
			filename = "docker-compose.yml"
		} else if strings.HasPrefix(id, "dockerfile-") {
			filename = "Dockerfile"
		} else if strings.HasPrefix(id, "gha-") {
			filename = ".github/workflows/workflow.yaml"
		} else if strings.HasPrefix(id, "kubernetes-") {
			filename = "pod.yaml"
		} else if strings.HasPrefix(id, "terraform-") {
			filename = "main.tf"
		}

		if filename == "" {
			t.Errorf("Unknown filename mapping for rule %s", id)
			continue
		}

		// Test NoncompliantExample
		rootNC := t.TempDir()
		pathNC := filepath.Join(rootNC, filename)
		if filename == ".github/workflows/workflow.yaml" {
			if err := os.MkdirAll(filepath.Dir(pathNC), 0755); err != nil {
				t.Fatalf("MkdirAll failed for %s: %v", id, err)
			}
		}
		if err := os.WriteFile(pathNC, []byte(catRule.NoncompliantExample), 0644); err != nil {
			t.Fatalf("WriteFile failed for %s: %v", id, err)
		}

		findingsNC, err := New().ScanConfigs(context.Background(), rootNC)
		if err != nil {
			t.Fatalf("Failed to scan noncompliant configs for %s: %v", id, err)
		}

		foundNC := false
		for _, f := range findingsNC {
			if f.RuleID == id {
				foundNC = true
				if f.Title != catRule.Name {
					t.Errorf("Rule %s Name mismatch: catalog=%q engine=%q", id, catRule.Name, f.Title)
				}
				if f.Severity != catRule.DefaultSeverity {
					t.Errorf("Rule %s Severity mismatch: catalog=%v engine=%v", id, catRule.DefaultSeverity, f.Severity)
				}
			}
		}

		if !foundNC {
			t.Errorf("Rule %s: Noncompliant example does not trigger the detector", id)
		}

		// Test CompliantExample
		rootC := t.TempDir()
		pathC := filepath.Join(rootC, filename)
		if filename == ".github/workflows/workflow.yaml" {
			if err := os.MkdirAll(filepath.Dir(pathC), 0755); err != nil {
				t.Fatalf("MkdirAll failed for %s: %v", id, err)
			}
		}
		if err := os.WriteFile(pathC, []byte(catRule.CompliantExample), 0644); err != nil {
			t.Fatalf("WriteFile failed for %s: %v", id, err)
		}

		findingsC, err := New().ScanConfigs(context.Background(), rootC)
		if err != nil {
			t.Fatalf("Failed to scan compliant configs for %s: %v", id, err)
		}

		for _, f := range findingsC {
			if f.RuleID == id {
				t.Errorf("Rule %s: Compliant example incorrectly triggers the detector", id)
			}
		}
	}
}
