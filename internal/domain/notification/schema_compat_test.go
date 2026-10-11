package notification

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// This independent baseline prevents changing a published v1 schema and its
// fixture together without bumping the version. Additional optional fields
// are allowed; removing, renaming, retyping or requiring new fields is not.
var v1DataFields = map[EventType]string{
	"vulnerability_action.created":     "title summary action_type outbox_id",
	"scan.completed":                   "title summary scan_id scan_kind",
	"quality_gate.failed":              "title summary analysis_id project_id",
	"sla.approaching_deadline":         "title summary assessment_id engagement_id finding_id deadline lead_time_seconds",
	"fleet.agent.offline":              "title summary agent_id last_seen_at",
	"incident.created":                 "title summary incident_id asset_id",
	"finding.ownership_changed":        "title summary decision_id finding_id engagement_id old_team_id new_team_id old_assignee_id new_assignee_id actor reason",
	"notification.destination_changed": "title summary actor action class scheme host",
	"notification.channel_paused":      "title summary channel_id class reason failure_code",
	"notification.test":                "title",
}

func equalFieldSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func schemaRequired(s map[string]any) []string {
	items, _ := s["required"].([]any)
	names := make([]string, 0, len(items))
	for _, v := range items {
		if name, ok := v.(string); ok {
			names = append(names, name)
		}
	}
	return names
}

func TestPublishedV1ContractCompatibility(t *testing.T) {
	root := filepath.Join("..", "..", "..", "docs", "guide", "schemas", "events")
	seen := map[EventType]bool{}
	for _, spec := range EventCatalog() {
		required, known := v1DataFields[spec.Type]
		if spec.SchemaVersion == 1 && !known {
			t.Errorf("new v1 event %s needs a compatibility baseline", spec.Type)
		}
		if !known {
			continue
		}
		seen[spec.Type] = true
		t.Run(string(spec.Type), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, string(spec.Type)+".v1.schema.json"))
			if err != nil {
				t.Fatalf("published v1 schema must be retained: %v", err)
			}
			s, err := decodeEventJSON(raw)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkEventSchema(s); err != nil {
				t.Fatal(err)
			}
			p := s["properties"].(map[string]any)
			d := p["data"].(map[string]any)
			if p["type"].(map[string]any)["const"] != string(spec.Type) || p["schema_version"].(map[string]any)["const"] != float64(1) {
				t.Error("v1 event type/version changed")
			}
			if !equalFieldSet(schemaRequired(s), []string{"id", "type", "source_kind", "source_id", "schema_version", "occurred_at", "data"}) {
				t.Error("breaking change to required v1 envelope")
			}
			if !equalFieldSet(schemaRequired(d), strings.Fields(required)) {
				t.Errorf("breaking change to v1 data required fields: got %v, want %q", schemaRequired(d), required)
			}
			if s["additionalProperties"] != true || d["additionalProperties"] != true {
				t.Error("v1 no longer accepts additive optional fields")
			}
			if p["occurred_at"].(map[string]any)["format"] != "date-time" {
				t.Error("occurred_at lost date-time format")
			}
			props := d["properties"].(map[string]any)
			for _, field := range strings.Fields(required) {
				item, ok := props[field].(map[string]any)
				if !ok {
					t.Errorf("v1 data field %s removed", field)
					continue
				}
				types, err := schemaTypes(item["type"])
				if err != nil {
					t.Errorf("%s: %v", field, err)
					continue
				}
				sort.Strings(types)
				wantType := "string"
				if field == "lead_time_seconds" {
					wantType = "integer"
				}
				if strings.Join(types, "|") != wantType {
					t.Errorf("v1 field %s changed type: %v, expected %s", field, types, wantType)
				}
				if field == "deadline" || field == "last_seen_at" {
					if item["format"] != "date-time" {
						t.Errorf("v1 %s lost date-time format", field)
					}
				}
			}
		})
	}
	for typ := range v1DataFields {
		if !seen[typ] {
			t.Errorf("published event %s removed from catalog", typ)
		}
	}
}

// Once a catalog version advances, old public schemas must remain published
// with a matching fixture. Neither an orphan nor a future version is allowed.
func validHistoricalEventPair(name, root string) bool {
	suffix := ".schema.json"
	if strings.HasSuffix(name, ".fixture.json") {
		suffix = ".fixture.json"
	}
	stem := strings.TrimSuffix(name, suffix)
	pos := strings.LastIndex(stem, ".v")
	if pos < 1 {
		return false
	}
	typ := EventType(stem[:pos])
	version, err := strconv.Atoi(stem[pos+2:])
	spec, known := LookupEvent(typ)
	if err != nil || !known || version < 1 || version >= spec.SchemaVersion {
		return false
	}
	prefix := fmt.Sprintf("%s.v%d", typ, version)
	a, err := os.ReadFile(filepath.Join(root, prefix+".schema.json"))
	if err != nil {
		return false
	}
	b, err := os.ReadFile(filepath.Join(root, prefix+".fixture.json"))
	if err != nil {
		return false
	}
	schema, err := decodeEventJSON(a)
	if err != nil || checkEventSchema(schema) != nil {
		return false
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" ||
		schema["$id"] != "https://synapse.kkloudtarus.net/docs/schemas/events/"+prefix+".schema.json" {
		return false
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return false
	}
	typeProp, ok := props["type"].(map[string]any)
	if !ok || typeProp["const"] != string(typ) {
		return false
	}
	versionProp, ok := props["schema_version"].(map[string]any)
	if !ok || versionProp["const"] != float64(version) {
		return false
	}
	fixture, err := decodeEventJSON(b)
	return err == nil && matchEventSchema(schema, fixture) == nil
}

func TestPublishedEventSchemaIndex(t *testing.T) {
	root := filepath.Join("..", "..", "..", "docs", "guide", "schemas", "events")
	index, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	nav, err := os.ReadFile(filepath.Join("..", "..", "..", "mkdocs.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(nav), "schemas/events/README.md") {
		t.Error("MkDocs nav omits schema index")
	}
	for _, spec := range EventCatalog() {
		prefix := fmt.Sprintf("%s.v%d", spec.Type, spec.SchemaVersion)
		for _, suffix := range []string{".schema.json", ".fixture.json"} {
			filename := prefix + suffix
			if !strings.Contains(string(index), "]("+filename+")") {
				t.Errorf("schema index omits %s", filename)
			}
		}
	}
	// Previously published v1 contracts must remain discoverable after a v2 bump.
	for typ := range v1DataFields {
		for _, suffix := range []string{".schema.json", ".fixture.json"} {
			name := string(typ) + ".v1" + suffix
			if !strings.Contains(string(index), "]("+name+")") {
				t.Errorf("schema index no longer links historical %s", name)
			}
		}
	}
}

// These independently recorded v1 constraints include optional envelope fields
// and closed enums. The fixture cannot prove a field is compatible if it omits
// the field, nor can it detect removal of an enum when its sample still passes.
func TestPublishedV1FieldConstraints(t *testing.T) {
	root := filepath.Join("..", "..", "..", "docs", "guide", "schemas", "events")
	optionalEnvelope := map[EventType]string{
		"vulnerability_action.created":     "engagement_id severity",
		"scan.completed":                   "engagement_id",
		"quality_gate.failed":              "",
		"sla.approaching_deadline":         "engagement_id",
		"fleet.agent.offline":              "",
		"incident.created":                 "engagement_id severity",
		"finding.ownership_changed":        "engagement_id",
		"notification.destination_changed": "",
		"notification.channel_paused":      "",
		"notification.test":                "",
	}
	closedEnums := map[EventType]map[string]string{
		"vulnerability_action.created":     {"action_type": strings.Join(ActionTypes(), " ")},
		"notification.destination_changed": {"action": "created host_changed", "class": "webhook slack", "scheme": "http https"},
		"notification.channel_paused":      {"reason": "consecutive_permanent_failures"},
	}
	idFields := map[EventType]string{
		"vulnerability_action.created":     "outbox_id",
		"scan.completed":                   "scan_id scan_kind",
		"quality_gate.failed":              "analysis_id project_id",
		"sla.approaching_deadline":         "assessment_id engagement_id finding_id",
		"fleet.agent.offline":              "agent_id",
		"incident.created":                 "incident_id",
		"finding.ownership_changed":        "decision_id finding_id engagement_id",
		"notification.destination_changed": "host",
		"notification.channel_paused":      "channel_id class failure_code",
	}
	for _, spec := range EventCatalog() {
		fields, ok := optionalEnvelope[spec.Type]
		if !ok {
			t.Errorf("published optional envelope baseline missing for %s", spec.Type)
			continue
		}
		t.Run(string(spec.Type), func(t *testing.T) {
			name := string(spec.Type) + ".v1.schema.json"
			raw, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			schema, err := decodeEventJSON(raw)
			if err != nil {
				t.Fatal(err)
			}
			if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" ||
				schema["$id"] != "https://synapse.kkloudtarus.net/docs/schemas/events/"+name {
				t.Error("published v1 schema dialect or identifier changed")
			}
			props := schema["properties"].(map[string]any)
			// All v1 envelope value types are fixed independently of a fixture.
			for field, want := range map[string]string{
				"type": "string", "schema_version": "integer", "occurred_at": "string", "data": "object",
			} {
				p, exists := props[field].(map[string]any)
				if !exists || p["type"] != want {
					t.Errorf("v1 envelope field %s changed type", field)
				}
			}
			for _, field := range []string{"id", "source_kind", "source_id"} {
				p := props[field].(map[string]any)
				if p["type"] != "string" || p["minLength"] != float64(1) {
					t.Errorf("v1 envelope field %s changed type or minimum length", field)
				}
			}
			for _, field := range strings.Fields(fields) {
				p, exists := props[field].(map[string]any)
				if !exists || p["type"] != "string" {
					t.Errorf("v1 optional envelope field %s changed type or disappeared", field)
					continue
				}
				if field == "severity" {
					if !equalEnum(p["enum"], strings.Join(schemaSeverityNames(), " ")) {
						t.Error("severity enum differs from Go vocabulary")
					}
					if !equalEnum(p["enum"], "critical high medium low info unknown") {
						t.Error("breaking change to published v1 severity enum")
					}
				}
			}
			data := props["data"].(map[string]any)["properties"].(map[string]any)
			if spec.Type == EventVulnerabilityAction {
				action, exists := data["action_type"].(map[string]any)
				if !exists || !equalEnum(action["enum"], "new_exposure escalation withdrawal reexposure retest_required risk_review") {
					t.Error("breaking change to published v1 action_type enum")
				}
			}
			for field, values := range closedEnums[spec.Type] {
				p, exists := data[field].(map[string]any)
				if !exists || !equalEnum(p["enum"], values) {
					t.Errorf("v1 closed enum for %s changed", field)
				}
			}
			for _, field := range strings.Fields(idFields[spec.Type]) {
				p, exists := data[field].(map[string]any)
				if !exists || p["minLength"] != float64(1) {
					t.Errorf("v1 required identifier %s lost minimum length", field)
				}
			}
			if spec.Type == "sla.approaching_deadline" {
				p := data["lead_time_seconds"].(map[string]any)
				if p["minimum"] != float64(1) {
					t.Error("v1 lead time minimum changed")
				}
			}
		})
	}
}

func equalEnum(value any, wanted string) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	got := make([]string, 0, len(items))
	for _, item := range items {
		name, ok := item.(string)
		if !ok {
			return false
		}
		got = append(got, name)
	}
	return equalFieldSet(got, strings.Fields(wanted))
}

// Schema checks use the same accepted severity vocabulary as the domain.
func schemaSeverityNames() []string {
	values := shared.AllSeverities()
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = string(value)
	}
	return out
}
