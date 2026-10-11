package postgres

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/testutil/eventschema"
)

// Inspect the JSON actually emitted by production, not a schema-derived fixture.
func assertPublishedEventSchema(t *testing.T, event notification.Event) {
	t.Helper()
	if err := event.Validate(); err != nil {
		t.Fatalf("invalid %s event: %v", event.Type, err)
	}
	root := filepath.Join("..", "..", "..", "..", "docs", "guide", "schemas", "events")
	path := filepath.Join(root, fmt.Sprintf("%s.v%d.schema.json", event.Type, event.SchemaVersion))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := eventschema.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := eventschema.Check(schema); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := eventschema.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := eventschema.Match(schema, wire); err != nil {
		t.Fatalf("emitted %s wire envelope violates published schema: %v", event.Type, err)
	}
	props := schema["properties"].(map[string]any)
	for key := range wire {
		if _, ok := props[key]; !ok {
			t.Errorf("undocumented emitted envelope field %q", key)
		}
	}
	if _, ok := wire["tenant_id"]; ok {
		t.Error("tenant ID leaked into public wire payload")
	}
	dataSchema := props["data"].(map[string]any)
	data, err := eventschema.Decode(event.Data)
	if err != nil {
		t.Fatal(err)
	}
	if err := eventschema.Match(dataSchema, data); err != nil {
		t.Fatalf("emitted %s data violates published schema: %v", event.Type, err)
	}
	declared := dataSchema["properties"].(map[string]any)
	for key := range data {
		if _, ok := declared[key]; !ok {
			t.Errorf("undocumented emitted data field %q", key)
		}
	}
}
