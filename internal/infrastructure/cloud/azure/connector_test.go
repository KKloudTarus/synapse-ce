package azure

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type graphClientStub struct {
	responses []armresourcegraph.ClientResourcesResponse
	errs      []error
	requests  []armresourcegraph.QueryRequest
}

func (s *graphClientStub) Resources(_ context.Context, request armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
	s.requests = append(s.requests, request)
	index := len(s.requests) - 1
	if index < len(s.errs) && s.errs[index] != nil {
		return armresourcegraph.ClientResourcesResponse{}, s.errs[index]
	}
	return s.responses[index], nil
}

func allowAzureOperation(context.Context, ports.CloudOperation) error { return nil }

func TestEnumeratePagesAndNormalizesExplicitAzureFacts(t *testing.T) {
	next := "next"
	authorizationCalls := 0
	client := &graphClientStub{responses: []armresourcegraph.ClientResourcesResponse{
		{QueryResponse: armresourcegraph.QueryResponse{Data: []any{map[string]any{
			"id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/publicstore", "name": "publicstore", "type": "Microsoft.Storage/storageAccounts", "location": "eastus", "subscriptionId": "sub-1",
			"properties": map[string]any{"allowBlobPublicAccess": true, "publicNetworkAccess": "Enabled", "encryption": map[string]any{"services": map[string]any{"blob": map[string]any{"enabled": false}}}},
		}}, SkipToken: &next}},
		{QueryResponse: armresourcegraph.QueryResponse{Data: []any{map[string]any{
			"id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/secret-vault", "name": "secret-vault", "type": "Microsoft.KeyVault/vaults", "location": "westus", "subscriptionId": "sub-1",
			"properties": map[string]any{"publicNetworkAccess": "Enabled"},
		}}}},
	}}
	connector, err := newConnector(nil, client, nil, Config{PageSize: 10, MaxPages: 2})
	if err != nil {
		t.Fatal(err)
	}
	inventory, gaps, err := connector.Enumerate(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAzure, CredentialRef: "azure", Authorize: func(context.Context, ports.CloudOperation) error { authorizationCalls++; return nil }, Root: "subscriptions/sub-1"})
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Complete || len(gaps) != 2 || len(inventory.Resources) != 3 {
		t.Fatalf("inventory = %#v, gaps = %#v", inventory, gaps)
	}
	storage := inventory.Resources[2]
	if storage.Kind != asset.KindStorage || storage.Public != cloudposture.StateUnknown || storage.Encrypted != cloudposture.StateDisabled || storage.PublicNetwork != cloudposture.StateUnknown {
		t.Fatalf("storage = %#v", storage)
	}
	vault := inventory.Resources[1]
	if !vault.Sensitive || vault.PublicNetwork != cloudposture.StateUnknown || vault.Public != cloudposture.StateUnknown {
		t.Fatalf("vault = %#v", vault)
	}
	if got := *client.requests[1].Options.SkipToken; got != next {
		t.Fatalf("skip token = %q, want %q", got, next)
	}
	if authorizationCalls != 2 {
		t.Fatalf("authorization calls = %d, want 2", authorizationCalls)
	}
}

func TestManagementGroupUsesMultiSubscriptionScope(t *testing.T) {
	client := &graphClientStub{responses: []armresourcegraph.ClientResourcesResponse{{QueryResponse: armresourcegraph.QueryResponse{Data: []any{map[string]any{"id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm", "name": "vm", "type": "Microsoft.Compute/virtualMachines", "subscriptionId": "sub-1"}}}}}}
	connector, err := newConnector(nil, client, nil, Config{})
	if err != nil {
		t.Fatal(err)
	}
	inventory, gaps, err := connector.Enumerate(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAzure, CredentialRef: "azure", Authorize: allowAzureOperation, Root: "managementGroups/group-a"})
	if err != nil {
		t.Fatal(err)
	}
	if inventory.ScopeKey != "azure:managementGroups/group-a" || len(inventory.Resources) != 2 || len(gaps) != 3 {
		t.Fatalf("inventory = %#v, gaps = %#v", inventory, gaps)
	}
	if client.requests[0].ManagementGroups == nil || *client.requests[0].ManagementGroups[0] != "group-a" || client.requests[0].Subscriptions != nil || client.requests[0].Options.AllowPartialScopes == nil || !*client.requests[0].Options.AllowPartialScopes {
		t.Fatalf("request = %#v", client.requests[0])
	}
}

func TestNetworkAndRoleFactsRequireCompleteEvidence(t *testing.T) {
	vmID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
	pipID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip"
	nicID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic"
	nsgID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg"
	subnetID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/default"
	definitionID := "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/role"
	resources := []graphResource{
		{ID: vmID, Name: "vm", Type: "Microsoft.Compute/virtualMachines", SubscriptionID: "sub"},
		{ID: pipID, Name: "pip", Type: "Microsoft.Network/publicIPAddresses", SubscriptionID: "sub", Properties: json.RawMessage(`{"ipAddress":"203.0.113.1"}`)},
		{ID: nicID, Name: "nic", Type: "Microsoft.Network/networkInterfaces", SubscriptionID: "sub", Properties: json.RawMessage(`{"virtualMachine":{"id":"` + vmID + `"},"networkSecurityGroup":{"id":"` + nsgID + `"},"ipConfigurations":[{"subnet":{"id":"` + subnetID + `"},"publicIPAddress":{"id":"` + pipID + `"}}]}`)},
		{ID: nsgID, Name: "nsg", Type: "Microsoft.Network/networkSecurityGroups", SubscriptionID: "sub", Properties: json.RawMessage(`{"securityRules":[{"properties":{"direction":"Inbound","access":"Allow","priority":100,"sourceAddressPrefix":"Internet","destinationAddressPrefix":"*"}}]}`)},
		{ID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet", Name: "vnet", Type: "Microsoft.Network/virtualNetworks", SubscriptionID: "sub", Properties: json.RawMessage(`{"subnets":[{"id":"` + subnetID + `"}]}`)},
		{ID: definitionID, Name: "Owner", Type: "Microsoft.Authorization/roleDefinitions", SubscriptionID: "sub", Properties: json.RawMessage(`{"roleName":"Owner","permissions":[{"actions":["*"]}]}`)},
		{ID: "/subscriptions/sub/providers/Microsoft.Authorization/roleAssignments/assignment", Name: "assignment", Type: "Microsoft.Authorization/roleAssignments", SubscriptionID: "sub", Properties: json.RawMessage(`{"roleDefinitionId":"` + definitionID + `"}`)},
	}
	inventory := cloudposture.Inventory{Provider: cloudposture.ProviderAzure}
	for _, resource := range resources {
		normalized, ok := normalizeResource(resource)
		if ok {
			inventory.Resources = append(inventory.Resources, normalized)
		}
	}
	applyNetworkFacts(&inventory, resources)
	applyRoleFacts(&inventory, resources)
	for _, resource := range inventory.Resources {
		if resource.ID == vmID && (resource.Public != cloudposture.StateEnabled || resource.PublicNetwork != cloudposture.StateEnabled) {
			t.Fatalf("vm = %#v", resource)
		}
		if strings.Contains(resource.ResourceType, "roleassignments") && (!resource.PolicyKnown || !resource.WildcardAction || !resource.HighPrivilege) {
			t.Fatalf("assignment = %#v", resource)
		}
	}
}

func TestEnumerateReportsQueryFailureAsCoverageGap(t *testing.T) {
	connector, err := newConnector(nil, &graphClientStub{errs: []error{errors.New("forbidden")}}, nil, Config{})
	if err != nil {
		t.Fatal(err)
	}
	inventory, gaps, err := connector.Enumerate(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAzure, CredentialRef: "azure", Authorize: allowAzureOperation, Root: "sub-1"})
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Complete || len(gaps) != 1 || gaps[0].Code != "resource_graph_query_denied" {
		t.Fatalf("inventory = %#v, gaps = %#v", inventory, gaps)
	}
}

func TestEnumerateRejectsNonAzureAndInvalidScopes(t *testing.T) {
	connector, err := newConnector(nil, &graphClientStub{}, nil, Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []ports.CloudScope{{Provider: cloudposture.ProviderAWS, Root: "sub-1"}, {Provider: cloudposture.ProviderAzure, Root: "subscriptions/sub/child"}} {
		_, _, err := connector.Enumerate(context.Background(), scope)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("Enumerate(%#v) error = %v, want validation error", scope, err)
		}
	}
}

func TestEvaluateUsesVendorNeutralRules(t *testing.T) {
	connector, err := newConnector(nil, &graphClientStub{}, nil, Config{})
	if err != nil {
		t.Fatal(err)
	}
	matches, err := connector.Evaluate(context.Background(), cloudposture.Inventory{Provider: cloudposture.ProviderAzure, Resources: []cloudposture.Resource{{Provider: cloudposture.ProviderAzure, ID: "storage", Kind: asset.KindStorage, Public: cloudposture.StateEnabled}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].RuleKey != cloudposture.RuleStoragePublic {
		t.Fatalf("matches = %#v", matches)
	}
}

func TestContainerPublicAccessIsAnActualExposure(t *testing.T) {
	account, ok := normalizeResource(graphResource{ID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/store", Name: "store", Type: "Microsoft.Storage/storageAccounts", SubscriptionID: "sub", Properties: json.RawMessage(`{"allowBlobPublicAccess":true}`)})
	if !ok || account.Public != cloudposture.StateUnknown {
		t.Fatalf("account = %#v", account)
	}
	container, ok := normalizeResource(graphResource{ID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/store/blobServices/default/containers/public", Name: "public", Type: "Microsoft.Storage/storageAccounts/blobServices/containers", SubscriptionID: "sub", Properties: json.RawMessage(`{"publicAccess":"Blob"}`)})
	if !ok || container.Public != cloudposture.StateEnabled {
		t.Fatalf("container = %#v", container)
	}
}

type vaultStub struct {
	secret   []byte
	resolved []byte
	err      error
}

func (v vaultStub) Put(context.Context, shared.ID, string, []byte) error { return nil }
func (v *vaultStub) Resolve(context.Context, shared.ID, string) ([]byte, error) {
	v.resolved = append([]byte(nil), v.secret...)
	return v.resolved, v.err
}
func (v vaultStub) List(context.Context, shared.ID) ([]ports.CredentialMeta, error) { return nil, nil }
func (v vaultStub) Delete(context.Context, shared.ID, string) error                 { return nil }

func TestEnumerateResolvesVaultCredentialOnlyDuringRun(t *testing.T) {
	secret := []byte(`{"tenant_id":"tenant","client_id":"client","client_secret":"secret"}`)
	client := &graphClientStub{responses: []armresourcegraph.ClientResourcesResponse{{QueryResponse: armresourcegraph.QueryResponse{Data: []any{}}}}}
	vault := &vaultStub{secret: secret}
	connector, err := newConnector(vault, nil, func(got []byte, _ ports.CloudScope) (resourceGraphClient, error) {
		if string(got) != string(secret) {
			t.Fatalf("credential = %q", got)
		}
		return client, nil
	}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = connector.Enumerate(context.Background(), ports.CloudScope{EngagementID: "eng", Provider: cloudposture.ProviderAzure, Root: "sub-1", CredentialRef: "azure", Authorize: allowAzureOperation})
	if err != nil {
		t.Fatal(err)
	}
	if vault.resolved[0] != 0 {
		t.Fatal("credential material was not cleared")
	}
}
