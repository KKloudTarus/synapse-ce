package api_test

import (
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

func TestIdentityConnectionLegacyConfigurationProjection(t *testing.T) {
	raw, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	const location = "https://synapse.example/openapi.json"
	if err := compiler.AddResource(location, document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(location + "#/components/schemas/IdentityConnection")
	if err != nil {
		t.Fatal(err)
	}
	base := map[string]any{
		"id": "connection", "display_name": "Identity", "issuer": "https://issuer.example/",
		"enabled": false, "revision": 1, "draft_revision": 1, "version": 1, "test_passed": false,
	}
	if err := schema.Validate(base); err != nil {
		t.Fatalf("normal secret-free connection projection refused: %v", err)
	}
	pending := make(map[string]any, len(base)+2)
	for key, value := range base {
		pending[key] = value
	}
	pending["configuration_pending"] = true
	pending["client_id"] = ""
	if err := schema.Validate(pending); err != nil {
		t.Fatalf("pending legacy connection projection refused: %v", err)
	}
	nativeWithClientID := make(map[string]any, len(base)+1)
	for key, value := range base {
		nativeWithClientID[key] = value
	}
	nativeWithClientID["client_id"] = "must-not-project"
	if err := schema.Validate(nativeWithClientID); err == nil {
		t.Fatal("normal connection projection accepts client_id")
	}
	pending["client_secret"] = "must-not-project"
	if err := schema.Validate(pending); err == nil {
		t.Fatal("legacy connection projection accepts a client secret")
	}
}
