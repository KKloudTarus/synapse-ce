package ticketing

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTicketMarkerRoundTripPreservesNativeWire(t *testing.T) {
	marker := "synapse-intent-intent-1"
	tests := []struct {
		name string
		wire string
		desc ports.TicketMarkerDescriptor
	}{
		{"array", `{"labels":["security"]}`, ports.TicketMarkerDescriptor{Version: 1, Strategy: ports.TicketMarkerJSONArray, Path: []string{"labels"}}},
		{"empty tag", `{"labels":""}`, ports.TicketMarkerDescriptor{Version: 1, Strategy: ports.TicketMarkerTag, Path: []string{"labels"}}},
		{"scalar", `{"correlation_id":""}`, ports.TicketMarkerDescriptor{Version: 1, Strategy: ports.TicketMarkerScalar, Path: []string{"correlation_id"}}},
		{"text suffix", `{"input":{"description":"finding"}}`, ports.TicketMarkerDescriptor{Version: 1, Strategy: ports.TicketMarkerTextSuffix, Path: []string{"input", "description"}}},
		{"json patch", `[{"op":"add","path":"/fields/System.Title","value":"finding"}]`, ports.TicketMarkerDescriptor{Version: 1, Strategy: ports.TicketMarkerJSONPatchAdd, Path: []string{"fields", "System.Tags"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			marked, err := addTicketMarker(json.RawMessage(tt.wire), tt.desc, marker)
			if err != nil {
				t.Fatal(err)
			}
			unsigned, err := removeTicketMarker(marked, tt.desc, marker)
			if err != nil {
				t.Fatal(err)
			}
			if ticketDigest(unsigned) != ticketDigest([]byte(tt.wire)) {
				t.Fatalf("round trip changed native wire: got %s want %s", unsigned, tt.wire)
			}
		})
	}
}

func TestTicketMarkerRejectsReservedTextAndTampering(t *testing.T) {
	desc := ports.TicketMarkerDescriptor{Version: 1, Strategy: ports.TicketMarkerTextSuffix, Path: []string{"input", "description"}}
	if _, err := addTicketMarker(json.RawMessage(`{"input":{"description":"contains synapse-intent-foreign"}}`), desc, "synapse-intent-intent-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("reserved text err=%v", err)
	}
	if _, err := removeTicketMarker(json.RawMessage(`{"input":{"description":"finding\n\n[synapse-intent-other]"}}`), desc, "synapse-intent-intent-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tampered marker err=%v", err)
	}
}

func TestReadTicketSnapshotNativeWireStripsMarkerAndChecksDigest(t *testing.T) {
	marker := "synapse-intent-intent-1"
	desc := ports.TicketMarkerDescriptor{Version: 1, Strategy: ports.TicketMarkerJSONArray, Path: []string{"labels"}}
	unsignedWire := json.RawMessage(`{"title":"finding","labels":["security"]}`)
	markedWire, err := addTicketMarker(unsignedWire, desc, marker)
	if err != nil {
		t.Fatal(err)
	}
	facts := snapshotFacts{Provider: "github-issues", Endpoint: "https://api.github.test", DataClass: notification.DataClassSummary, MappingVersion: 1, ConnectionRevision: 1, CredentialRevision: 1, Marker: &desc}
	unsignedEnvelope, _ := json.Marshal(map[string]any{"fields": map[string]any{"project": map[string]string{"key": "org/repo"}, "issuetype": map[string]string{"id": "issue"}}, "wire": unsignedWire, "_synapse": facts})
	markedEnvelope, _ := json.Marshal(map[string]any{"fields": map[string]any{"project": map[string]string{"key": "org/repo"}, "issuetype": map[string]string{"id": "issue"}}, "wire": markedWire, "_synapse": facts})
	intent := domain.Intent{ID: "intent-1", TenantID: "tenant-1", IntegrationID: "github", MappingID: "mapping-1", FindingID: "finding-1", EngagementID: "engagement-1", Action: domain.Create, RequestKey: "request-1", PayloadDigest: ticketDigest(unsignedEnvelope), Marker: marker, State: writeintent.Pending, Version: 1, Snapshot: markedEnvelope, MappingVersion: 1, ConnectionRevision: 1, CredentialRevision: 1, CreatedAt: testTicketTime, UpdatedAt: testTicketTime}
	_, got, err := readTicketSnapshot(intent)
	if err != nil {
		t.Fatal(err)
	}
	if ticketDigest(got) != ticketDigest(markedWire) {
		t.Fatalf("dispatch wire = %s, want marked %s", got, markedWire)
	}
	intent.Snapshot = append([]byte(nil), markedEnvelope...)
	intent.Snapshot = []byte(string(intent.Snapshot[:len(intent.Snapshot)-1]) + `,"tampered":true}`)
	if _, _, err = readTicketSnapshot(intent); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("tampered envelope err=%v", err)
	}
}

var testTicketTime = mustTicketTime()

func mustTicketTime() (at time.Time) { return time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC) }
