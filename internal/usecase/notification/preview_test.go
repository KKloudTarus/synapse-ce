package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	eventschemas "github.com/KKloudTarus/synapse-ce/docs/guide/schemas/events"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// previewEvents is a NotificationEventReader over a fixed list, scoped by tenant like RLS.
type previewEvents struct {
	events []domain.Event
	limits []int
}

func (r *previewEvents) ListRecentNotificationEvents(_ context.Context, tenant shared.ID, eventType domain.EventType, limit int) ([]domain.Event, error) {
	r.limits = append(r.limits, limit)
	var out []domain.Event
	for _, e := range r.events {
		if e.TenantID == tenant && e.Type == eventType && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

func (r *previewEvents) GetNotificationEvent(_ context.Context, tenant, id shared.ID) (domain.Event, error) {
	for _, e := range r.events {
		if e.TenantID == tenant && e.ID == id {
			return e, nil
		}
	}
	return domain.Event{}, fmt.Errorf("notification event %s: %w", id, shared.ErrNotFound)
}

func storedIncident(tenant, id shared.ID, at time.Time) domain.Event {
	return domain.Event{
		TenantID: tenant, ID: id, Type: domain.EventIncidentCreated, SourceKind: "incident", SourceID: "src-" + id.String(),
		EngagementID: "eng-1", Severity: shared.SeverityHigh, SchemaVersion: 1, OccurredAt: at, SubjectKind: "incident",
		Data: json.RawMessage(`{"title":"Real incident","summary":"From the tenant","incident_id":"inc-1","asset_id":""}`),
	}
}

func newPreviewFixture(t *testing.T) (bindingFixture, *previewEvents) {
	t.Helper()
	f := newBindingFixture(t)
	f.svc.SetEventFixtures(eventschemas.Fixtures)
	at := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	reader := &previewEvents{events: []domain.Event{
		storedIncident("tenant", "ev-new", at),
		storedIncident("tenant", "ev-old", at.Add(-time.Hour)),
		storedIncident("other", "ev-other", at),
	}}
	f.svc.SetEventReader(reader)
	return f, reader
}

// Every catalog event type has an embedded fixture the preview can read, so a new event type
// cannot ship without one.
func TestEveryCatalogEventHasAnEmbeddedFixture(t *testing.T) {
	f, _ := newPreviewFixture(t)
	for _, spec := range domain.EventCatalog() {
		event, err := f.svc.fixtureEvent("tenant", spec.Type)
		if err != nil {
			t.Errorf("%s: %v", spec.Type, err)
			continue
		}
		if event.TenantID != "tenant" || event.EngagementID != "" || event.Type != spec.Type {
			t.Errorf("%s fixture = tenant %q engagement %q type %q", spec.Type, event.TenantID, event.EngagementID, event.Type)
		}
	}
}

func TestPreviewAgainstTheFixtureResolvesTheTemplate(t *testing.T) {
	f, _ := newPreviewFixture(t)
	channel := f.slackChannel(t)
	bound := f.template(t, domain.EventIncidentCreated, domain.FamilyChat, "en", true)

	preview, err := f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: channel.ID, EventType: domain.EventIncidentCreated})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Sample.Source != PreviewFromFixture || preview.Sample.ID != "event-incident-created" || preview.Sample.EngagementID != "" {
		t.Fatalf("sample = %+v", preview.Sample)
	}
	if preview.Channel.ID != channel.ID || preview.Channel.Family != domain.FamilyChat {
		t.Fatalf("channel = %+v", preview.Channel)
	}
	if preview.Draft != nil || preview.Resolution == nil || preview.Resolution.Tier != TierTenantEvent || preview.Resolution.Template.ID != bound.ID {
		t.Fatalf("resolution = %+v draft = %+v", preview.Resolution, preview.Draft)
	}
	if preview.Rendered {
		t.Fatal("nothing renders before #1365")
	}
	// The prepared input carries the projected template context for the renderer.
	var context domain.TemplateContext
	if err := json.Unmarshal(preview.prepared.event.Context, &context); err != nil || context.Vars["title"] == "" {
		t.Fatalf("prepared context = %s (%v)", preview.prepared.event.Context, err)
	}
	if preview.prepared.channel.ID != channel.ID || preview.prepared.draft != nil {
		t.Fatalf("prepared = %+v", preview.prepared)
	}
}

func TestPreviewAgainstAStoredEvent(t *testing.T) {
	f, _ := newPreviewFixture(t)
	channel := f.slackChannel(t)

	preview, err := f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: channel.ID, EventType: domain.EventIncidentCreated, EventID: "ev-old"})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Sample.Source != PreviewFromEvent || preview.Sample.ID != "ev-old" || preview.Sample.EngagementID != "eng-1" {
		t.Fatalf("sample = %+v", preview.Sample)
	}
	if preview.Resolution == nil || preview.Resolution.Tier != TierFallback {
		t.Fatalf("resolution = %+v", preview.Resolution)
	}
	// A stored event is projected again, so its context is filled even if it was captured empty.
	if !strings.Contains(string(preview.prepared.event.Context), "Real incident") {
		t.Fatalf("prepared context = %s", preview.prepared.event.Context)
	}

	for name, in := range map[string]PreviewInput{
		"another tenant's event": {ChannelID: channel.ID, EventType: domain.EventIncidentCreated, EventID: "ev-other"},
		"a missing event":        {ChannelID: channel.ID, EventType: domain.EventIncidentCreated, EventID: "ev-missing"},
	} {
		if _, err := f.svc.PreviewTemplate(f.ctx, in); !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("%s: %v, want not found", name, err)
		}
	}
	if _, err := f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: channel.ID, EventType: domain.EventScanCompleted, EventID: "ev-old"}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("event of another type: %v", err)
	}
}

func TestPreviewOfAStoredEventNeedsTheReader(t *testing.T) {
	f := newBindingFixture(t)
	f.svc.SetEventFixtures(eventschemas.Fixtures)
	channel := f.slackChannel(t)
	if _, err := f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: channel.ID, EventType: domain.EventIncidentCreated, EventID: "ev-1"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("event preview without a reader: %v", err)
	}
	if _, err := f.svc.ListPreviewEvents(f.ctx, domain.EventIncidentCreated); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("listing without a reader: %v", err)
	}
	f.svc.SetEventFixtures(nil)
	if _, err := f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: channel.ID, EventType: domain.EventIncidentCreated}); !errors.Is(err, errPreviewFixturesUnavailable) {
		t.Fatalf("fixture preview without fixtures: %v", err)
	}
}

func TestPreviewOfASavedTemplateVersion(t *testing.T) {
	f, _ := newPreviewFixture(t)
	channel := f.slackChannel(t)
	draft := f.template(t, domain.EventIncidentCreated, domain.FamilyChat, "vi", false)
	if _, err := f.svc.UpdateTemplate(f.ctx, "ada", draft.ID, TemplateUpdateInput{Fields: map[string]string{"title": "v2", "body": "B2"}, Revision: draft.Revision}); err != nil {
		t.Fatal(err)
	}

	latest, err := f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: channel.ID, EventType: domain.EventIncidentCreated, TemplateID: draft.ID})
	if err != nil {
		t.Fatal(err)
	}
	if latest.Resolution != nil || latest.Draft == nil || *latest.Draft != (PreviewDraft{TemplateID: draft.ID, Version: 2}) || latest.prepared.draft.Fields["title"] != "v2" {
		t.Fatalf("latest draft = %+v prepared %+v", latest.Draft, latest.prepared.draft)
	}
	first, err := f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: channel.ID, EventType: domain.EventIncidentCreated, TemplateID: draft.ID, Version: 1})
	if err != nil || first.Draft.Version != 1 || first.prepared.draft.Fields["title"] != "T" {
		t.Fatalf("version 1 = %+v (%v)", first.Draft, err)
	}
	if _, err := f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: channel.ID, EventType: domain.EventIncidentCreated, TemplateID: draft.ID, Version: 9}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing version: %v", err)
	}
}

func TestPreviewRefusesATemplateTheChannelCannotUse(t *testing.T) {
	f, _ := newPreviewFixture(t)
	channel := f.slackChannel(t)
	email := f.template(t, domain.EventIncidentCreated, domain.FamilyEmail, "en", false)
	scan := f.template(t, domain.EventScanCompleted, domain.FamilyChat, "en", false)

	for name, in := range map[string]PreviewInput{
		"another family":             {ChannelID: channel.ID, EventType: domain.EventIncidentCreated, TemplateID: email.ID},
		"another event":              {ChannelID: channel.ID, EventType: domain.EventIncidentCreated, TemplateID: scan.ID},
		"a version without template": {ChannelID: channel.ID, EventType: domain.EventIncidentCreated, Version: 1},
		"a version with fields":      {ChannelID: channel.ID, EventType: domain.EventIncidentCreated, TemplateID: scan.ID, Version: 1, Fields: map[string]string{"title": "x"}},
		"a negative version":         {ChannelID: channel.ID, EventType: domain.EventIncidentCreated, TemplateID: scan.ID, Version: -1},
		"no event type":              {ChannelID: channel.ID},
		"the wildcard event type":    {ChannelID: channel.ID, EventType: domain.AnyEventType},
	} {
		if _, err := f.svc.PreviewTemplate(f.ctx, in); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v, want a validation error", name, err)
		}
	}
	if _, err := f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: "missing", EventType: domain.EventIncidentCreated}); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("missing channel: %v", err)
	}
}

func TestPreviewOfUnsavedTextIsCheckedLikeASave(t *testing.T) {
	f, _ := newPreviewFixture(t)
	channel := f.slackChannel(t)

	preview, err := f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: channel.ID, EventType: domain.EventIncidentCreated, Fields: map[string]string{"title": "{{.title}}", "body": "New"}})
	if err != nil {
		t.Fatal(err)
	}
	if preview.Draft == nil || !preview.Draft.Unsaved || !preview.Draft.TemplateID.IsZero() || preview.prepared.draft.Fields["title"] != "{{.title}}" {
		t.Fatalf("unsaved draft = %+v prepared %+v", preview.Draft, preview.prepared.draft)
	}

	_, err = f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: channel.ID, EventType: domain.EventIncidentCreated, Fields: map[string]string{"title": "{{.not_declared}}"}})
	var rejection *TemplateValidationError
	if !errors.As(err, &rejection) || rejection.Field != "title" || rejection.Line != 1 {
		t.Fatalf("undeclared variable: %v", err)
	}
	if _, err := f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: channel.ID, EventType: domain.EventIncidentCreated, Fields: map[string]string{"subject": "not a chat field"}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a field of another family: %v", err)
	}

	// An unsaved edit of a "*" template is checked against every event, as a save would be.
	wildcard := f.template(t, domain.AnyEventType, domain.FamilyChat, "en", false)
	edit, err := f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: channel.ID, EventType: domain.EventIncidentCreated, TemplateID: wildcard.ID, Fields: map[string]string{"title": "{{.title}}"}})
	if err != nil || edit.Draft.TemplateID != wildcard.ID || !edit.Draft.Unsaved || edit.Draft.Version != 0 {
		t.Fatalf("unsaved edit = %+v (%v)", edit.Draft, err)
	}
	if _, err := f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: channel.ID, EventType: domain.EventIncidentCreated, TemplateID: wildcard.ID, Fields: map[string]string{"title": "{{.severity}}"}}); !errors.As(err, &rejection) {
		t.Fatalf("a variable only incident.created declares, in a * template: %v", err)
	}
}

func TestListPreviewEventsIsTenantScopedAndCapped(t *testing.T) {
	f, reader := newPreviewFixture(t)
	items, err := f.svc.ListPreviewEvents(f.ctx, domain.EventIncidentCreated)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].ID != "ev-new" || items[1].ID != "ev-old" || items[0].Severity != shared.SeverityHigh || items[0].SubjectKind != "incident" {
		t.Fatalf("items = %+v", items)
	}
	if reader.limits[len(reader.limits)-1] != PreviewEventLimit {
		t.Fatalf("limit = %v", reader.limits)
	}
	// The summary names the event; its data and context stay on the server.
	raw, _ := json.Marshal(items[0])
	if strings.Contains(string(raw), "Real incident") || strings.Contains(string(raw), "data") {
		t.Fatalf("summary leaks event content: %s", raw)
	}
	if _, err := f.svc.ListPreviewEvents(f.ctx, "nope"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown type: %v", err)
	}
	if _, err := f.svc.ListPreviewEvents(context.Background(), domain.EventIncidentCreated); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no tenant: %v", err)
	}
}

// The JSON form never carries the prepared render input: no template context, no draft text.
func TestPreviewResponseCarriesNoContextOrSource(t *testing.T) {
	f, _ := newPreviewFixture(t)
	channel := f.slackChannel(t)
	preview, err := f.svc.PreviewTemplate(f.ctx, PreviewInput{ChannelID: channel.ID, EventType: domain.EventIncidentCreated, EventID: "ev-new", Fields: map[string]string{"title": "SECRET-DRAFT-TEXT {{.title}}"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"SECRET-DRAFT-TEXT", "Real incident", "prepared", "context"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("response contains %q: %s", leak, raw)
		}
	}
}
