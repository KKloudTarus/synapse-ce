package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

// bindingPatchRepo is channelPatchRepo with a rule listing, which a binding change reads.
type bindingPatchRepo struct{ channelPatchRepo }

func (r *bindingPatchRepo) ListRules(context.Context, shared.ID) ([]domain.Rule, error) {
	return nil, nil
}

// An integration_admin binds a template over the channel PATCH (#1371): it is not a destination
// change. The channel view returns the binding, and the resolution preview names the tier.
func TestPatchChannelBindsATemplateAndPreviewsResolution(t *testing.T) {
	repo := &bindingPatchRepo{channelPatchRepo{channel: domain.Channel{TenantID: "tenant", ID: "c1", Name: "ops", Type: domain.ChannelSlack, Enabled: true,
		Destination: "https://hooks.slack.com/services/…", Revision: 1, SecretVersion: 1}}}
	audit := &templateHandlerAudit{}
	svc, err := notificationuc.NewService(repo, handlerProtector{}, nil, audit, handlerClock{}, &templateHandlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTemplateStore(memory.NewNotificationTemplateStore())
	rt := &Router{log: discardLog()}
	rt.SetNotifications(svc)

	created := decodeTemplate(t, templateCall(rt, "integration_admin", "tenant", http.MethodPost, "/api/v1/notifications/templates",
		`{"name":"Any chat","event_type":"*","family":"chat","locale":"*","fields":{"title":"Synapse","body":"Open Synapse."}}`), http.StatusCreated)
	decodeTemplate(t, templateCall(rt, "integration_admin", "tenant", http.MethodPost, "/api/v1/notifications/templates/"+created.ID+"/activate",
		`{"revision":1}`), http.StatusOK)

	response := templateCall(rt, "integration_admin", "tenant", http.MethodPatch, "/api/v1/notifications/channels/c1",
		`{"name":"ops","enabled":true,"revision":1,"template_id":"`+created.ID+`","locale":"vi"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("bind = %d %s", response.Code, response.Body.String())
	}
	var channel map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &channel); err != nil || channel["template_id"] != created.ID || channel["locale"] != "vi" {
		t.Fatalf("channel view = %s", response.Body.String())
	}

	response = templateCall(rt, "integration_admin", "tenant", http.MethodGet, "/api/v1/notifications/channels/c1/template-resolution?event_type=scan.completed", "")
	if response.Code != http.StatusOK {
		t.Fatalf("preview = %d %s", response.Code, response.Body.String())
	}
	var resolution map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &resolution); err != nil {
		t.Fatal(err)
	}
	template, _ := resolution["template"].(map[string]any)
	if resolution["tier"] != "channel" || resolution["locale"] != "vi" || resolution["locale_source"] != "channel" || resolution["matched_locale"] != "*" ||
		resolution["version"] != float64(1) || template["id"] != created.ID {
		t.Fatalf("resolution = %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "Open Synapse") {
		t.Fatalf("preview carries template source: %s", response.Body.String())
	}
	if response := templateCall(rt, "integration_admin", "tenant", http.MethodGet, "/api/v1/notifications/channels/c1/template-resolution", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("preview without event type = %d", response.Code)
	}
	if response := templateCall(rt, "member", "tenant", http.MethodGet, "/api/v1/notifications/channels/c1/template-resolution?event_type=scan.completed", ""); response.Code != http.StatusForbidden {
		t.Fatalf("preview as member = %d", response.Code)
	}
}

// A webhook template whose body puts an expression in a key answers 400 with the path of the
// offending value (#1376), and a channel PATCH opts a webhook channel into the custom body.
func TestWebhookCustomBodyRoutes(t *testing.T) {
	repo := &bindingPatchRepo{channelPatchRepo{channel: domain.Channel{TenantID: "tenant", ID: "c1", Name: "hook", Type: domain.ChannelWebhook, Enabled: true,
		Destination: "https://hooks.example.com/", Revision: 1, SecretVersion: 1}}}
	svc, err := notificationuc.NewService(repo, handlerProtector{}, nil, &templateHandlerAudit{}, handlerClock{}, &templateHandlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTemplateStore(memory.NewNotificationTemplateStore())
	rt := &Router{log: discardLog()}
	rt.SetNotifications(svc)

	response := templateCall(rt, "integration_admin", "tenant", http.MethodPost, "/api/v1/notifications/templates",
		`{"name":"Hook","event_type":"*","family":"webhook","locale":"*","fields":{"body":"{\"a\":{\"{{.title}}\":1}}"}}`)
	var rejection map[string]any
	if response.Code != http.StatusBadRequest || json.Unmarshal(response.Body.Bytes(), &rejection) != nil ||
		rejection["code"] != "expression_in_key" || rejection["path"] != `$.a["{{.title}}"]` || rejection["field"] != "body" {
		t.Fatalf("invalid body = %d %s", response.Code, response.Body.String())
	}

	created := decodeTemplate(t, templateCall(rt, "integration_admin", "tenant", http.MethodPost, "/api/v1/notifications/templates",
		`{"name":"Hook","event_type":"*","family":"webhook","locale":"*","fields":{"body":"{\"source\":\"synapse\",\"n\":1}"}}`), http.StatusCreated)
	decodeTemplate(t, templateCall(rt, "integration_admin", "tenant", http.MethodPost, "/api/v1/notifications/templates/"+created.ID+"/activate", `{"revision":1}`), http.StatusOK)
	response = templateCall(rt, "integration_admin", "tenant", http.MethodPatch, "/api/v1/notifications/channels/c1",
		`{"name":"hook","enabled":true,"revision":1,"template_id":"`+created.ID+`","custom_body":true}`)
	var channel map[string]any
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &channel) != nil || channel["custom_body"] != true {
		t.Fatalf("opt in = %d %s", response.Code, response.Body.String())
	}
}
