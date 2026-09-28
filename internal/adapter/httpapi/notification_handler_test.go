package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

func TestNotificationRoutesRequireAdministrator(t *testing.T) {
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
		{"GET", "rules"}, {"POST", "rules"}, {"GET", "rules/id"}, {"PATCH", "rules/id"}, {"DELETE", "rules/id"},
		{"GET", "deliveries"}, {"GET", "deliveries/id"}, {"GET", "deliveries/id/attempts"},
	}
	for _, route := range routes {
		for _, role := range []string{"member", "readonly", "reviewer", "agent", "mcp", ""} {
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
