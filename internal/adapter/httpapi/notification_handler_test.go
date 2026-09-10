package httpapi

import (
	"context"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"net/http/httptest"
	"strings"
	"testing"
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
