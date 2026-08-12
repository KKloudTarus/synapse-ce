package cspm

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
)

func TestTerraformExpectations(t *testing.T) {
	content := `resource "aws_s3_bucket" "logs" {
  bucket = "prod-logs"
  acl = "private"
  server_side_encryption_configuration {
    rule {}
  }
}
resource "aws_s3_bucket" "public" {
  bucket = "public-assets"
  acl = "public-read"
}
resource "azurerm_storage_container" "public" {
  name = "assets"
  storage_account_name = "prod"
  subscription_id = "sub-1"
  resource_group_name = "rg-prod"
  container_access_type = "blob"
}
resource "google_storage_bucket" "private" {
  name = "logs"
  project = "project-a"
  public_access_prevention = "enforced"
}`
	got, gaps := terraformExpectations("main.tf", content)
	if len(gaps) != 0 {
		t.Fatalf("gaps = %#v", gaps)
	}
	want := map[string]cloudposture.State{
		"arn:aws:s3:::prod-logs\x00public":     cloudposture.StateDisabled,
		"arn:aws:s3:::prod-logs\x00encrypted":  cloudposture.StateEnabled,
		"arn:aws:s3:::public-assets\x00public": cloudposture.StateEnabled,
		"/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/prod/blobServices/default/containers/assets\x00public": cloudposture.StateEnabled,
		"projects/project-a/buckets/logs\x00public": cloudposture.StateDisabled,
	}
	for _, expectation := range got {
		key := expectation.ResourceID + "\x00" + expectation.Control
		if want[key] != expectation.State {
			t.Fatalf("expectation %#v", expectation)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("missing expectations: %v", want)
	}
}

func TestTerraformExpectationsReportsDynamicIdentity(t *testing.T) {
	_, gaps := terraformExpectations("dynamic.tf", `resource "google_storage_bucket" "dynamic" {
  name = var.bucket_name
  project = var.project_id
}`)
	if len(gaps) != 1 || gaps[0].Code != "iac_scope_unresolved" {
		t.Fatalf("gaps = %#v", gaps)
	}
}
