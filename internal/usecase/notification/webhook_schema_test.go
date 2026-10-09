package notification

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/notificationbuiltin"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestDefaultWebhookMatchesPublishedSchema(t *testing.T) {
	path := filepath.Join("..", "..", "..", "docs", "guide", "schemas", "notification-webhook.v1.schema.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	const location = "https://synapse.kkloudtarus.net/docs/schemas/notification-webhook.v1.schema.json"
	if err := compiler.AddResource(location, document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(location)
	if err != nil {
		t.Fatal(err)
	}
	h := newRenderHarness(t)
	h.svc.SetBuiltinTemplates(notificationbuiltin.New())
	for _, event := range builtinMatrixEvents() {
		for _, class := range builtinMatrixClasses() {
			output, _ := renderBuiltinMatrix(t, h, event, domain.FamilyWebhook, class, tenancy.LocaleEnglish)
			var wire map[string]any
			if err := json.Unmarshal(output.Webhook, &wire); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(wire); err != nil {
				t.Fatalf("%s/%s violates webhook schema: %v", event, class, err)
			}
			wire["links"] = []any{map[string]any{"label": "Open scan", "url": "https://console.example/engagements/e1/scanruns"}}
			if err := schema.Validate(wire); err != nil {
				t.Fatalf("trusted links violate webhook schema: %v", err)
			}
			wire["tenant_id"] = "private-tenant"
			if err := schema.Validate(wire); err == nil {
				t.Fatal("webhook schema permits an undeclared tenant field")
			}
		}
	}
}
