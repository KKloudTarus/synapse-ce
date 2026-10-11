package notification

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func publishedEventSchema(t *testing.T, typ EventType, version int) map[string]any {
	t.Helper()
	file := fmt.Sprintf("%s.v%d.schema.json", typ, version)
	root := filepath.Join("..", "..", "..", "docs", "guide", "schemas", "events")
	raw, err := os.ReadFile(filepath.Join(root, file))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := decodeEventJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkEventSchema(schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

// This round-trip is sourced from the actual Go Event JSON tags, not schema
// transcriptions. Renaming occurred_at or silently emitting a new field must
// fail even when the schema and fixture are untouched.
func TestEventGoWireMatchesPublishedSchemas(t *testing.T) {
	root := filepath.Join("..", "..", "..", "docs", "guide", "schemas", "events")
	for _, spec := range EventCatalog() {
		t.Run(string(spec.Type), func(t *testing.T) {
			file := fmt.Sprintf("%s.v%d.fixture.json", spec.Type, spec.SchemaVersion)
			fixtureRaw, err := os.ReadFile(filepath.Join(root, file))
			if err != nil {
				t.Fatal(err)
			}
			fixture, err := decodeEventJSON(fixtureRaw)
			if err != nil {
				t.Fatal(err)
			}
			var event Event
			if err := json.Unmarshal(fixtureRaw, &event); err != nil {
				t.Fatalf("unmarshal event through actual Go tags: %v", err)
			}
			event.TenantID = "schema-test-tenant"
			if event.Type != spec.Type || event.SchemaVersion != spec.SchemaVersion {
				t.Fatalf("Go event type/version do not match catalog: %s v%d", event.Type, event.SchemaVersion)
			}
			if err := event.Validate(); err != nil {
				t.Fatalf("Go event rejected schema fixture: %v", err)
			}
			raw, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := decodeEventJSON(raw)
			if err != nil {
				t.Fatal(err)
			}
			schema := publishedEventSchema(t, spec.Type, spec.SchemaVersion)
			if err := matchEventSchema(schema, wire); err != nil {
				t.Fatalf("actual Go wire event differs from published schema: %v", err)
			}
			properties := schema["properties"].(map[string]any)
			for key := range wire {
				if _, ok := properties[key]; !ok {
					t.Errorf("Go emits undocumented envelope key %q", key)
				}
				if _, ok := fixture[key]; !ok {
					t.Errorf("Go emits envelope key %q missing from fixture", key)
				}
			}
			for key := range fixture {
				if _, ok := wire[key]; !ok {
					t.Errorf("Go wire dropped fixture envelope key %q", key)
				}
			}
			for _, name := range schemaRequired(schema) {
				if _, ok := wire[name]; !ok {
					t.Errorf("Go wire dropped required key %q", name)
				}
			}
			if _, leaked := wire["tenant_id"]; leaked {
				t.Fatal("internal tenant ID leaked into webhook event")
			}
		})
	}
}

func checkGoProducedData(t *testing.T, typ EventType, data json.RawMessage) {
	t.Helper()
	schema := publishedEventSchema(t, typ, 1)
	dataSchema := schema["properties"].(map[string]any)["data"].(map[string]any)
	body, err := decodeEventJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := matchEventSchema(dataSchema, body); err != nil {
		t.Fatalf("actual Go producer data violates published schema: %v", err)
	}
	properties := dataSchema["properties"].(map[string]any)
	for key := range body {
		if _, ok := properties[key]; !ok {
			t.Errorf("producer emits undocumented data key %q", key)
		}
	}
	for _, key := range schemaRequired(dataSchema) {
		if _, ok := body[key]; !ok {
			t.Errorf("producer omitted required data key %q", key)
		}
	}
}

func TestOwnershipGoPayloadMatchesPublishedSchema(t *testing.T) {
	// Construct the exact struct the PostgreSQL ownership poller serializes.
	payload := OwnershipChanged{
		Title: "Finding ownership changed", Summary: "A finding's team or assignee changed.",
		DecisionID: "decision", FindingID: "finding", EngagementID: "engagement",
		OldTeamID: "old-team", NewTeamID: "new-team",
		OldAssigneeID: "old-user", NewAssigneeID: "new-user",
		Actor: "operator", Reason: "reassigned",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	checkGoProducedData(t, EventOwnershipChanged, data)
}

func TestDestinationGoPayloadMatchesPublishedSchema(t *testing.T) {
	at := time.Date(2026, time.September, 27, 8, 0, 0, 0, time.UTC)
	for _, channel := range []ChannelType{ChannelWebhook, ChannelSlack} {
		for _, action := range []string{"created", "host_changed"} {
			t.Run(string(channel)+"/"+action, func(t *testing.T) {
				event, err := NewDestinationEvent(
					shared.ID("tenant"), shared.ID("channel"), channel,
					"https://user:secret@hooks.example:443/path?token=hidden",
					action, "operator", at,
				)
				if err != nil {
					t.Fatal(err)
				}
				event.ID = "destination-event"
				if err := event.Validate(); err != nil {
					t.Fatal(err)
				}
				checkGoProducedData(t, EventDestinationChanged, event.Data)
				raw, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				wire, err := decodeEventJSON(raw)
				if err != nil {
					t.Fatal(err)
				}
				if err := matchEventSchema(publishedEventSchema(t, EventDestinationChanged, 1), wire); err != nil {
					t.Fatalf("destination event envelope mismatch: %v", err)
				}
			})
		}
	}
}
