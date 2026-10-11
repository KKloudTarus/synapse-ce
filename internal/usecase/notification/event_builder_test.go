package notification

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var updateGolden = flag.Bool("update", false, "rewrite the golden template contexts")

// builderFixtures are the published event fixtures (#1411), so each builder is pinned against the
// same payload the webhook contract documents.
var builderFixtures = []domain.EventType{
	domain.EventVulnerabilityAction, domain.EventScanCompleted, domain.EventQualityGateFailed, domain.EventSLAApproaching,
	domain.EventFleetAgentOffline, domain.EventIncidentCreated, domain.EventOwnershipChanged,
	domain.EventChannelPaused, domain.EventDestinationChanged, domain.EventTest,
}

func fixtureEvent(t *testing.T, eventType domain.EventType) domain.Event {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "guide", "schemas", "events", string(eventType)+".v1.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var e domain.Event
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("decode fixture %s: %v", eventType, err)
	}
	e.TenantID = "tenant-1"
	return e
}

// TestBuilderContextGolden pins the subject and template context every builder takes from its
// published fixture. Run with -update to rewrite the golden files after a deliberate change.
func TestBuilderContextGolden(t *testing.T) {
	builders := NewEventBuilders()
	for _, eventType := range builderFixtures {
		t.Run(string(eventType), func(t *testing.T) {
			projected, err := builders.Project(context.Background(), fixtureEvent(t, eventType))
			if err != nil {
				t.Fatalf("project: %v", err)
			}
			if err := projected.Validate(); err != nil {
				t.Fatalf("projected event is invalid: %v", err)
			}
			got := goldenContext(t, projected)
			path := filepath.Join("testdata", "event_context", string(eventType)+".json")
			if *updateGolden {
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run with -update to create it): %v", err)
			}
			if string(got) != strings.ReplaceAll(string(want), "\r\n", "\n") {
				t.Fatalf("context of %s changed:\n got %s\nwant %s", eventType, got, want)
			}
		})
	}
}

func goldenContext(t *testing.T, e domain.Event) []byte {
	t.Helper()
	snapshot, err := domain.DecodeTemplateContext(e.Context)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.MarshalIndent(struct {
		SubjectKind string            `json:"subject_kind"`
		SubjectID   string            `json:"subject_id"`
		Vars        map[string]string `json:"vars"`
	}{e.SubjectKind, e.SubjectID, snapshot.Vars}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// TestEveryCatalogEventHasABuilder keeps the builder table and the catalog in step.
func TestEveryCatalogEventHasABuilder(t *testing.T) {
	builders := eventBuilders()
	for _, spec := range domain.EventCatalog() {
		if _, ok := builders[spec.Type]; !ok {
			t.Errorf("%s has no builder", spec.Type)
		}
	}
	if len(builders) != len(domain.EventCatalog()) {
		t.Errorf("builders = %d, catalog = %d", len(builders), len(domain.EventCatalog()))
	}
	if len(builderFixtures) != len(domain.EventCatalog()) {
		t.Errorf("golden fixtures cover %d of %d event types", len(builderFixtures), len(domain.EventCatalog()))
	}
}

// TestProjectKeepsWhatTheProducerRead checks that variables a poller seeded (values the event data
// does not carry) survive, and that an undeclared variable is dropped.
func TestProjectKeepsWhatTheProducerRead(t *testing.T) {
	e := fixtureEvent(t, domain.EventSLAApproaching)
	e.Context = json.RawMessage(`{"vars":{"tier":"high","webhook_secret":"s3cr3t","title":""}}`)
	projected, err := NewEventBuilders().Project(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ := domain.DecodeTemplateContext(projected.Context)
	if snapshot.Vars["tier"] != "high" {
		t.Fatalf("seeded tier = %q", snapshot.Vars["tier"])
	}
	if _, leaked := snapshot.Vars["webhook_secret"]; leaked {
		t.Fatal("an undeclared variable reached the snapshot")
	}
	if snapshot.Vars["title"] != "Remediation SLA approaching" {
		t.Fatalf("an empty seed replaced the derived title: %q", snapshot.Vars["title"])
	}
}

// TestProjectSanitizesValuesAndHonoursTheClass checks the two rules the snapshot applies to every
// value: characters that could hide or reorder text are removed, and nothing above the event
// type's maximum data class is kept.
func TestProjectSanitizesValuesAndHonoursTheClass(t *testing.T) {
	scan := fixtureEvent(t, domain.EventScanCompleted)
	scan.Data, _ = json.Marshal(map[string]string{"title": "Scan" + string(rune(0x202e)) + " done\nnow", "scan_kind": "sast"})
	projected, err := NewEventBuilders().Project(context.Background(), scan)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ := domain.DecodeTemplateContext(projected.Context)
	if got := snapshot.Vars["title"]; got != "Scan done now" {
		t.Fatalf("title = %q, want the bidi override removed and the line break flattened", got)
	}

	test := fixtureEvent(t, domain.EventTest)
	projected, err = NewEventBuilders().Project(context.Background(), test)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ = domain.DecodeTemplateContext(projected.Context)
	if _, ok := snapshot.Vars["title"]; ok {
		t.Fatal("notification.test is signal class, so its summary-class title must not be kept")
	}
}

// TestProjectKeepsAProducerSubject checks that a subject the producer named wins over the data key.
func TestProjectKeepsAProducerSubject(t *testing.T) {
	e := fixtureEvent(t, domain.EventScanCompleted)
	e.SubjectKind, e.SubjectID = "scan_job", "scan-from-producer"
	projected, err := NewEventBuilders().Project(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if projected.SubjectID != "scan-from-producer" {
		t.Fatalf("subject = %q", projected.SubjectID)
	}
}

type recordedFacts struct {
	answer   bool
	scan     string
	reminder ports.SLAReminder
	agent    string
	lastSeen time.Time
}

func (f *recordedFacts) ScanJobSucceeded(_ context.Context, _ shared.ID, scan string) (bool, error) {
	f.scan = scan
	return f.answer, nil
}

func (f *recordedFacts) SLAReminderDue(_ context.Context, _ shared.ID, r ports.SLAReminder) (bool, error) {
	f.reminder = r
	return f.answer, nil
}

func (f *recordedFacts) FleetAgentLastSeen(_ context.Context, _ shared.ID, agent string, lastSeen time.Time) (bool, error) {
	f.agent, f.lastSeen = agent, lastSeen
	return f.answer, nil
}

// TestStillRelevantAsksTheSourceFact checks that each re-check asks the fact the removed repository
// switch asked, with the same identifiers, and that other events are always relevant.
func TestStillRelevantAsksTheSourceFact(t *testing.T) {
	builders := NewEventBuilders()
	ask := func(e domain.Event) (*recordedFacts, bool) {
		t.Helper()
		facts := &recordedFacts{}
		relevant, err := builders.StillRelevant(context.Background(), facts, ports.NotificationWork{Event: e})
		if err != nil {
			t.Fatalf("%s: %v", e.Type, err)
		}
		return facts, relevant
	}

	scan := fixtureEvent(t, domain.EventScanCompleted)
	scan.SourceKind, scan.SourceID = "scan_job", "scan-42"
	if facts, relevant := ask(scan); relevant || facts.scan != "scan-42" {
		t.Fatalf("scan asked %q, relevant %v", facts.scan, relevant)
	}
	scan.SourceKind = "ci_import"
	if _, relevant := ask(scan); !relevant {
		t.Fatal("a scan event not captured from scan_jobs must stay relevant")
	}

	facts, _ := ask(fixtureEvent(t, domain.EventSLAApproaching))
	want := ports.SLAReminder{AssessmentID: "assessment-42", EngagementID: "eng-42", FindingID: "finding-42", Deadline: time.Date(2026, 9, 28, 8, 0, 0, 0, time.UTC)}
	if facts.reminder != want {
		t.Fatalf("SLA asked %+v, want %+v", facts.reminder, want)
	}

	facts, _ = ask(fixtureEvent(t, domain.EventFleetAgentOffline))
	if facts.agent != "agent-42" || !facts.lastSeen.Equal(time.Date(2026, 9, 27, 7, 45, 0, 0, time.UTC)) {
		t.Fatalf("fleet asked %q at %s", facts.agent, facts.lastSeen)
	}

	if _, relevant := ask(fixtureEvent(t, domain.EventIncidentCreated)); !relevant {
		t.Fatal("incident.created has no re-check and must stay relevant")
	}

	broken := fixtureEvent(t, domain.EventSLAApproaching)
	broken.Data = json.RawMessage(`{"title":"x"}`)
	if _, err := builders.StillRelevant(context.Background(), &recordedFacts{}, ports.NotificationWork{Event: broken}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an SLA event without a deadline = %v, want ErrValidation", err)
	}
}
