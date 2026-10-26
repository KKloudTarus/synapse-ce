package api_test

import (
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

func TestInitialProvisioningWireSchemas(t *testing.T) {
	raw, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	const location = "https://synapse.example/openapi.json"
	if err := compiler.AddResource(location, document); err != nil {
		t.Fatal(err)
	}
	provisioning := map[string]any{"id": "reservation", "tenant_id": "secondary", "recipient": "admin@example.test", "state": "open", "version": 1, "connection": nil, "invitation": nil}
	draft := map[string]any{}
	for key, value := range provisioning {
		draft[key] = value
	}
	draft["connection"] = map[string]any{"id": "connection", "display_name": "Identity", "issuer": "https://issuer.example/", "client_id": "public-client", "enabled": false, "revision": 0, "draft_revision": 1, "version": 1, "test_passed": false, "auth0_organization_id": ""}
	for _, tc := range []struct {
		name, schema string
		body         map[string]any
	}{
		{"status", "InitialIdentityProvisioningResponse", map[string]any{"provisioning": provisioning}},
		{"draft metadata", "InitialIdentityProvisioningResponse", map[string]any{"provisioning": draft}},
		{"begin", "InitialIdentityProvisioningBeginResponse", map[string]any{"provisioning": provisioning, "capability": "scoped-proof"}},
		{"closed begin", "InitialIdentityProvisioningBeginResponse", map[string]any{"provisioning": map[string]any{"id": "reservation", "tenant_id": "secondary", "recipient": "admin@example.test", "state": "closed", "version": 6}}},
		{"invitation", "InitialIdentityProvisioningInvitationResponse", map[string]any{"provisioning": provisioning, "code": "one-use-invitation"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			schema, err := compiler.Compile(location + "#/components/schemas/" + tc.schema)
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(tc.body); err != nil {
				t.Fatalf("valid wire response refused: %v", err)
			}
			tc.body["invitation_code_sealed"] = "must-not-be-exposed"
			if err := schema.Validate(tc.body); err == nil {
				t.Fatal("response schema accepts a private store field")
			}
		})
	}
	schema, err := compiler.Compile(location + "#/paths/~1api~1v1~1identity~1provisioning~1begin/post/requestBody/content/application~1json/schema")
	if err != nil {
		t.Fatal(err)
	}
	for _, recipient := range []string{"admin@example.test", ""} {
		if err := schema.Validate(map[string]any{"tenant_id": "secondary", "recipient": recipient}); err != nil {
			t.Fatalf("valid initial/resume request refused: %v", err)
		}
	}
}
