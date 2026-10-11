package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	eventschemas "github.com/KKloudTarus/synapse-ce/docs/guide/schemas/events"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

// previewEventReader serves one stored incident for the tenant "tenant".
type previewEventReader struct{}

func (previewEventReader) event() domain.Event {
	return domain.Event{TenantID: "tenant", ID: "ev-1", Type: domain.EventIncidentCreated, SourceKind: "incident", SourceID: "inc-1",
		SchemaVersion: 1, OccurredAt: time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC), SubjectKind: "incident",
		Data: json.RawMessage(`{"title":"STORED-TITLE","summary":"s","incident_id":"inc-1","asset_id":""}`)}
}

func (r previewEventReader) ListRecentNotificationEvents(_ context.Context, tenant shared.ID, eventType domain.EventType, _ int) ([]domain.Event, error) {
	if tenant != "tenant" || eventType != domain.EventIncidentCreated {
		return nil, nil
	}
	return []domain.Event{r.event()}, nil
}

func (r previewEventReader) GetNotificationEvent(_ context.Context, tenant, id shared.ID) (domain.Event, error) {
	if tenant != "tenant" || id != "ev-1" {
		return domain.Event{}, fmt.Errorf("notification event %s: %w", id, shared.ErrNotFound)
	}
	return r.event(), nil
}

func previewRouter(t *testing.T) *Router {
	t.Helper()
	repo := &channelPatchRepo{channel: domain.Channel{TenantID: "tenant", ID: "c1", Name: "ops", Type: domain.ChannelSlack, Enabled: true,
		Destination: "https://hooks.slack.com/services/…", Revision: 1, SecretVersion: 1}}
	svc, err := notificationuc.NewService(repo, handlerProtector{}, nil, &templateHandlerAudit{}, handlerClock{}, &templateHandlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTemplateStore(memory.NewNotificationTemplateStore())
	svc.SetEventFixtures(eventschemas.Fixtures)
	svc.SetEventReader(previewEventReader{})
	rt := &Router{log: discardLog()}
	rt.SetNotifications(svc)
	return rt
}

type previewResponse struct {
	Channel struct {
		ID     string `json:"id"`
		Family string `json:"family"`
	} `json:"channel"`
	Sample struct {
		Source string `json:"source"`
		ID     string `json:"id"`
	} `json:"sample"`
	Resolution *struct {
		Tier string `json:"tier"`
	} `json:"resolution"`
	Draft *struct {
		Unsaved bool `json:"unsaved"`
	} `json:"draft"`
	Rendered *bool `json:"rendered"`
}

func decodePreview(t *testing.T, response interface {
	Result() *http.Response
}, body string, code int) previewResponse {
	t.Helper()
	if got := response.Result().StatusCode; got != code {
		t.Fatalf("status = %d, want %d: %s", got, code, body)
	}
	var out previewResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return out
}

func TestPreviewTemplateRoute(t *testing.T) {
	rt := previewRouter(t)

	response := templateCall(rt, "integration_admin", "tenant", http.MethodPost, "/api/v1/notifications/templates/preview", `{"channel_id":"c1","event_type":"incident.created"}`)
	fixture := decodePreview(t, response, response.Body.String(), http.StatusOK)
	if fixture.Sample.Source != "fixture" || fixture.Channel.Family != "chat" || fixture.Resolution == nil || fixture.Resolution.Tier != "fallback" || fixture.Rendered == nil || *fixture.Rendered {
		t.Fatalf("fixture preview = %s", response.Body.String())
	}

	response = templateCall(rt, "admin", "tenant", http.MethodPost, "/api/v1/notifications/templates/preview",
		`{"channel_id":"c1","event_type":"incident.created","event_id":"ev-1","fields":{"title":"{{.title}}","body":"DRAFT-BODY"}}`)
	stored := decodePreview(t, response, response.Body.String(), http.StatusOK)
	if stored.Sample.Source != "event" || stored.Sample.ID != "ev-1" || stored.Draft == nil || !stored.Draft.Unsaved || stored.Resolution != nil {
		t.Fatalf("stored preview = %s", response.Body.String())
	}
	// Neither the event's content nor the draft text comes back before rendering exists.
	for _, leak := range []string{"STORED-TITLE", "DRAFT-BODY"} {
		if strings.Contains(response.Body.String(), leak) {
			t.Fatalf("response leaks %q: %s", leak, response.Body.String())
		}
	}
}

func TestPreviewTemplateRouteRejections(t *testing.T) {
	rt := previewRouter(t)
	post := func(role, body string) (int, string) {
		response := templateCall(rt, role, "tenant", http.MethodPost, "/api/v1/notifications/templates/preview", body)
		return response.Code, response.Body.String()
	}

	// Unsaved text the engine rejects is a 400 naming the field and line, like a save.
	code, body := post("integration_admin", `{"channel_id":"c1","event_type":"incident.created","fields":{"title":"{{.not_declared}}"}}`)
	var rejection templateValidationBody
	if code != http.StatusBadRequest || json.Unmarshal([]byte(body), &rejection) != nil || rejection.Field != "title" || rejection.Line != 1 || rejection.Code == "" {
		t.Fatalf("engine rejection = %d %s", code, body)
	}
	for name, request := range map[string]string{
		"an unknown field":           `{"channel_id":"c1","event_type":"incident.created","sample":"x"}`,
		"no event type":              `{"channel_id":"c1"}`,
		"version without a template": `{"channel_id":"c1","event_type":"incident.created","version":2}`,
		"another type's event":       `{"channel_id":"c1","event_type":"scan.completed","event_id":"ev-1"}`,
	} {
		if code, body := post("integration_admin", request); code != http.StatusBadRequest {
			t.Errorf("%s = %d %s, want 400", name, code, body)
		}
	}
	if code, body := post("integration_admin", `{"channel_id":"c1","event_type":"incident.created","event_id":"ev-missing"}`); code != http.StatusNotFound {
		t.Errorf("missing event = %d %s", code, body)
	}
	// Another tenant's event is not found, not forbidden: its existence is not revealed.
	response := templateCall(rt, "integration_admin", "other", http.MethodPost, "/api/v1/notifications/templates/preview", `{"channel_id":"c1","event_type":"incident.created","event_id":"ev-1"}`)
	if response.Code != http.StatusNotFound {
		t.Errorf("cross-tenant event = %d %s", response.Code, response.Body.String())
	}
	for _, role := range []string{"reviewer", "consultant", "readonly", "member"} {
		if code, _ := post(role, `{"channel_id":"c1","event_type":"incident.created"}`); code != http.StatusForbidden {
			t.Errorf("%s preview = %d, want 403", role, code)
		}
	}
}

func TestPreviewEventsRoute(t *testing.T) {
	rt := previewRouter(t)
	response := templateCall(rt, "integration_admin", "tenant", http.MethodGet, "/api/v1/notifications/templates/preview/events?event_type=incident.created", "")
	if response.Code != http.StatusOK {
		t.Fatalf("list = %d %s", response.Code, response.Body.String())
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil || len(list.Items) != 1 || list.Items[0]["id"] != "ev-1" || list.Items[0]["subject_kind"] != "incident" {
		t.Fatalf("list = %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "STORED-TITLE") || strings.Contains(response.Body.String(), `"data"`) {
		t.Fatalf("list leaks event content: %s", response.Body.String())
	}
	if response := templateCall(rt, "integration_admin", "tenant", http.MethodGet, "/api/v1/notifications/templates/preview/events", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("no event type = %d", response.Code)
	}
	if response := templateCall(rt, "reviewer", "tenant", http.MethodGet, "/api/v1/notifications/templates/preview/events?event_type=incident.created", ""); response.Code != http.StatusForbidden {
		t.Fatalf("reviewer = %d", response.Code)
	}
}
