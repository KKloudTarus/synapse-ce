package cspm

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestCloudOperationReadOnlyAllowlist(t *testing.T) {
	tests := []struct {
		name      string
		operation ports.CloudOperation
		allowed   bool
	}{
		{name: "AWS read", operation: ports.CloudOperation{Provider: cloudposture.ProviderAWS, Name: "ListBuckets"}, allowed: true},
		{name: "AWS mutation", operation: ports.CloudOperation{Provider: cloudposture.ProviderAWS, Name: "DeleteBucket"}},
		{name: "Azure token", operation: ports.CloudOperation{Provider: cloudposture.ProviderAzure, Name: "POST login.microsoftonline.com/tenant/oauth2/v2.0/token"}, allowed: true},
		{name: "Azure Resource Graph", operation: ports.CloudOperation{Provider: cloudposture.ProviderAzure, Name: "POST management.azure.com/providers/Microsoft.ResourceGraph/resources"}, allowed: true},
		{name: "Azure lookalike Resource Graph", operation: ports.CloudOperation{Provider: cloudposture.ProviderAzure, Name: "POST management.azure.com/evil/providers/Microsoft.ResourceGraph/resources"}},
		{name: "Azure arbitrary POST", operation: ports.CloudOperation{Provider: cloudposture.ProviderAzure, Name: "POST management.azure.com/subscriptions/sub/providers/Microsoft.Storage/storageAccounts"}},
		{name: "GCP token", operation: ports.CloudOperation{Provider: cloudposture.ProviderGCP, Name: "POST oauth2.googleapis.com/token"}, allowed: true},
		{name: "GCP list", operation: ports.CloudOperation{Provider: cloudposture.ProviderGCP, Name: "GET compute.googleapis.com/compute/v1/projects/p/aggregated/instances"}, allowed: true},
		{name: "GCP IAM read", operation: ports.CloudOperation{Provider: cloudposture.ProviderGCP, Name: "POST cloudresourcemanager.googleapis.com/v1/projects/p:getIamPolicy"}, allowed: true},
		{name: "GCP arbitrary GET", operation: ports.CloudOperation{Provider: cloudposture.ProviderGCP, Name: "GET compute.googleapis.com/compute/v1/projects/p/zones/z/instances/vm/serialPort"}},
		{name: "GCP malicious host", operation: ports.CloudOperation{Provider: cloudposture.ProviderGCP, Name: "GET evil.example/compute/v1/projects/p/aggregated/instances"}},
		{name: "GCP lookalike IAM read", operation: ports.CloudOperation{Provider: cloudposture.ProviderGCP, Name: "POST evil.example/v1/projects/p:getIamPolicy"}},
		{name: "GCP arbitrary POST", operation: ports.CloudOperation{Provider: cloudposture.ProviderGCP, Name: "POST compute.googleapis.com/compute/v1/projects/p/zones/z/instances"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := cloudOperationIsReadOnly(test.operation); got != test.allowed {
				t.Fatalf("allowed = %t, want %t", got, test.allowed)
			}
		})
	}
}
