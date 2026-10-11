package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type redriveHandlerRepo struct {
	ports.NotificationRepository
	delivery domain.Delivery
	channel  domain.Channel
	fence    int64
}

func (r *redriveHandlerRepo) GetDelivery(context.Context, shared.ID, shared.ID) (domain.Delivery, error) {
	return r.delivery, nil
}

func (r *redriveHandlerRepo) LoadWork(context.Context, shared.ID, shared.ID) (ports.NotificationWork, error) {
	return ports.NotificationWork{Delivery: r.delivery, Channel: r.channel, Sealed: `{}`}, nil
}

func (r *redriveHandlerRepo) RedriveDelivery(_ context.Context, _, _ shared.ID, fence int64) (domain.Delivery, domain.Channel, error) {
	r.fence = fence
	r.delivery.State = domain.DeliveryPending
	r.delivery.RedriveFence = fence + 1
	return r.delivery, r.channel, nil
}

func TestNotificationRoutesRefuseRolesWithoutManageIntegrations(t *testing.T) {
	rt := &Router{log: discardLog()}
	req := httptest.NewRequest("GET", "/api/v1/notifications/channels", nil)
	response := httptest.NewRecorder()
	rt.routes().ServeHTTP(response, req)
	if response.Code != 404 {
		t.Fatal("notification routes enabled without configuration")
	}
	rt.SetNotifications(&notificationuc.Service{})
	routes := []struct{ method, path string }{
		{"GET", "channels"}, {"POST", "channels"}, {"GET", "channels/id"}, {"PATCH", "channels/id"}, {"DELETE", "channels/id"}, {"POST", "channels/id/test"},
		{"POST", "channels/id/resume"}, {"GET", "channels/id/health-events"},
		{"GET", "rules"}, {"POST", "rules"}, {"GET", "rules/id"}, {"PATCH", "rules/id"}, {"DELETE", "rules/id"},
		{"GET", "deliveries"}, {"GET", "deliveries/id"}, {"GET", "deliveries/id/attempts"}, {"POST", "deliveries/id/redrive"}, {"GET", "quarantined-sources"},
	}
	for _, route := range routes {
		roles := []string{"member", "readonly", "reviewer", "agent", "mcp", ""}
		if route.method == "POST" && (route.path == "channels" || route.path == "deliveries/id/redrive") {
			roles = append(roles, "integration_admin")
		}
		for _, role := range roles {
			req := httptest.NewRequest(route.method, "/api/v1/notifications/"+route.path, nil)
			req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "caller", Role: role, TenantID: "tenant"}))
			response := httptest.NewRecorder()
			rt.routes().ServeHTTP(response, req)
			if response.Code != 403 {
				t.Fatalf("%s %s role=%s got=%d", route.method, route.path, role, response.Code)
			}
		}
	}
}

func TestRedriveNotificationDeliveryAdminContract(t *testing.T) {
	repo := &redriveHandlerRepo{
		delivery: domain.Delivery{ID: "d1", ChannelType: domain.ChannelWebhook, State: domain.DeliveryDead, RedriveFence: 6},
		channel:  domain.Channel{ID: "c1", Type: domain.ChannelWebhook, Destination: "https://hooks.example.test/…"},
	}
	svc, err := notificationuc.NewService(repo, handlerProtector{}, nil, handlerAudit{}, handlerClock{}, handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog()}
	rt.SetNotifications(svc)
	call := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/api/v1/notifications/deliveries/d1/redrive", strings.NewReader(body))
		ctx := shared.WithTenant(req.Context(), "tenant")
		req = req.WithContext(context.WithValue(ctx, principalKey, Principal{ID: "admin-1", Role: "admin", TenantID: "tenant"}))
		response := httptest.NewRecorder()
		rt.routes().ServeHTTP(response, req)
		return response
	}
	if got := call(`{"reason":"Receiver recovered","expected_fence":6,"force":true}`); got.Code != 400 {
		t.Fatalf("unknown request field: %d %s", got.Code, got.Body)
	}
	got := call(`{"reason":"Receiver recovered","expected_fence":6}`)
	if got.Code != 202 || repo.fence != 6 || !strings.Contains(got.Body.String(), `"redrive_fence":7`) || !strings.Contains(got.Body.String(), `"state":"pending"`) {
		t.Fatalf("redrive response: status=%d body=%s fence=%d", got.Code, got.Body, repo.fence)
	}
}

func TestDecodeNotificationBodyRejectsTrailingJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/notifications/channels", strings.NewReader(`{"name":"first"}{"name":"second"}`))
	response := httptest.NewRecorder()
	var input map[string]any
	if err := decodeNotificationBody(response, req, &input); err == nil {
		t.Fatal("accepted multiple JSON objects")
	}
}

func TestDecodeNotificationBodyRejectsUnknownFields(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/notifications/channels", strings.NewReader(`{"unknown":true}`))
	response := httptest.NewRecorder()
	var input struct {
		Name string `json:"name"`
	}
	if err := decodeNotificationBody(response, req, &input); err == nil {
		t.Fatal("accepted an unknown field")
	}
}

func TestNotificationEventTypesServeTheCatalog(t *testing.T) {
	rt := &Router{log: discardLog()}
	rt.SetNotifications(&notificationuc.Service{})
	for _, role := range []string{"admin", "member", "consultant", "reviewer", "readonly"} {
		req := httptest.NewRequest("GET", "/api/v1/notifications/event-types", nil)
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "caller", Role: role, TenantID: "tenant"}))
		response := httptest.NewRecorder()
		rt.routes().ServeHTTP(response, req)
		if response.Code != 200 {
			t.Fatalf("role=%s got=%d", role, response.Code)
		}
		var body struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		catalog := domain.EventCatalog()
		if len(body.Items) != len(catalog) {
			t.Fatalf("got %d event types, catalog has %d", len(body.Items), len(catalog))
		}
		for i, item := range body.Items {
			if item["type"] != string(catalog[i].Type) || item["label"] != catalog[i].Label {
				t.Fatalf("item %d = %v, want %s", i, item, catalog[i].Type)
			}
			for _, key := range []string{"filters", "max_data_class", "variables", "mandatory", "operator_only"} {
				if _, ok := item[key]; !ok {
					t.Fatalf("%s is missing %s", catalog[i].Type, key)
				}
			}
		}
	}
	for _, role := range []string{"agent", "mcp", ""} {
		req := httptest.NewRequest("GET", "/api/v1/notifications/event-types", nil)
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "caller", Role: role, TenantID: "tenant"}))
		response := httptest.NewRecorder()
		rt.routes().ServeHTTP(response, req)
		if response.Code != 403 {
			t.Fatalf("role=%s got=%d", role, response.Code)
		}
	}
}
