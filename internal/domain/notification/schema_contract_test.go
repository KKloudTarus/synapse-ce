package notification

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEventSchemaCatalogDrift(t *testing.T) {
	root := filepath.Join("..", "..", "..", "docs", "guide", "schemas", "events")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{}
	for _, spec := range EventCatalog() {
		prefix := fmt.Sprintf("%s.v%d", spec.Type, spec.SchemaVersion)
		schemaFile, fixtureFile := prefix+".schema.json", prefix+".fixture.json"
		expected[schemaFile], expected[fixtureFile] = true, true
		t.Run(string(spec.Type), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, schemaFile))
			if err != nil {
				t.Fatalf("missing catalog schema: %v", err)
			}
			schema, err := decodeEventJSON(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkEventSchema(schema); err != nil {
				t.Fatalf("invalid schema: %v", err)
			}
			if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
				t.Fatalf("incorrect JSON Schema dialect: %v", schema["$schema"])
			}
			wantID := "https://synapse.kkloudtarus.net/docs/schemas/events/" + schemaFile
			if schema["$id"] != wantID {
				t.Fatalf("schema $id = %v; want %s", schema["$id"], wantID)
			}
			title, titleOK := schema["title"].(string)
			if schema["type"] != "object" || !titleOK || strings.TrimSpace(title) == "" {
				t.Fatal("schema envelope metadata missing")
			}
			properties := schema["properties"].(map[string]any)
			eventType := properties["type"].(map[string]any)
			version := properties["schema_version"].(map[string]any)
			if eventType["const"] != string(spec.Type) || version["const"] != float64(spec.SchemaVersion) {
				t.Fatal("type or schema_version does not match EventSpec")
			}
			required := schema["required"].([]any)
			for _, field := range []string{"id", "type", "source_kind", "source_id", "schema_version", "occurred_at", "data"} {
				found := false
				for _, item := range required {
					if item == field {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("missing required envelope field %s", field)
				}
			}
			if spec.HasEngagement && properties["engagement_id"] == nil {
				t.Fatal("EventSpec engagement missing in schema")
			}
			if spec.HasSeverity && properties["severity"] == nil {
				t.Fatal("EventSpec severity missing in schema")
			}
			data := properties["data"].(map[string]any)
			dataProps := data["properties"].(map[string]any)
			if spec.HasLeadTime && dataProps["lead_time_seconds"] == nil {
				t.Fatal("EventSpec lead time missing in data schema")
			}
			if spec.HasTeam && (dataProps["old_team_id"] == nil || dataProps["new_team_id"] == nil) {
				t.Fatal("EventSpec team identifiers missing in data schema")
			}
			fixtureRaw, err := os.ReadFile(filepath.Join(root, fixtureFile))
			if err != nil {
				t.Fatalf("missing catalog fixture: %v", err)
			}
			fixture, err := decodeEventJSON(fixtureRaw)
			if err != nil {
				t.Fatalf("invalid fixture JSON: %v", err)
			}
			if err := matchEventSchema(schema, fixture); err != nil {
				t.Fatalf("fixture does not validate: %v", err)
			}
			if fixture["type"] != string(spec.Type) || fixture["schema_version"] != float64(spec.SchemaVersion) {
				t.Fatal("fixture does not match EventSpec")
			}
			dataRaw, _ := json.Marshal(fixture["data"])
			if len(dataRaw) > 16384 {
				t.Fatalf("fixture data exceeds 16 KiB: %d", len(dataRaw))
			}
		})
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".schema.json") || strings.HasSuffix(name, ".fixture.json") {
			if !expected[name] && !validHistoricalEventPair(name, root) {
				t.Errorf("unregistered or stale schema/fixture: %s", name)
			}
			if entry.IsDir() {
				t.Errorf("schema/fixture is a directory: %s", name)
			}
		}
	}
}

func TestEventSchemaRejectsBrokenFixture(t *testing.T) {
	root := filepath.Join("..", "..", "..", "docs", "guide", "schemas", "events")
	schemaRaw, err := os.ReadFile(filepath.Join(root, "sla.approaching_deadline.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := decodeEventJSON(schemaRaw)
	if err != nil {
		t.Fatal(err)
	}
	fixtureRaw, err := os.ReadFile(filepath.Join(root, "sla.approaching_deadline.v1.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(map[string]any){
		"wrong type":             func(v map[string]any) { v["type"] = "scan.completed" },
		"wrong version":          func(v map[string]any) { v["schema_version"] = float64(2) },
		"missing envelope field": func(v map[string]any) { delete(v, "occurred_at") },
		"invalid timestamp":      func(v map[string]any) { v["occurred_at"] = "yesterday" },
		"invalid data":           func(v map[string]any) { v["data"] = "text" },
		"missing lead time":      func(v map[string]any) { delete(v["data"].(map[string]any), "lead_time_seconds") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fixture, err := decodeEventJSON(fixtureRaw)
			if err != nil {
				t.Fatal(err)
			}
			mutate(fixture)
			if err := matchEventSchema(schema, fixture); err == nil {
				t.Fatal("corrupt fixture passed validation")
			}
		})
	}
	if err := checkEventSchema(map[string]any{"type": "object", "mystery_keyword": true}); err == nil {
		t.Fatal("unknown JSON Schema keyword ignored")
	}
}
