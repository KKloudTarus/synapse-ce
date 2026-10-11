package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/capabilities"
)

func newCapabilityRouter(t *testing.T, flags capabilities.Flags) *Router {
	t.Helper()
	svc, err := capabilities.NewService(flags)
	if err != nil {
		t.Fatalf("capabilities service: %v", err)
	}
	rt := &Router{log: discardLog()}
	rt.SetCapabilities(svc)
	return rt
}

func getCapabilities(t *testing.T, rt *Router, role string) (*httptest.ResponseRecorder, map[string]capabilityView) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil).WithContext(ctxAs(role))
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return rec, nil
	}
	var body capabilitiesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	byKey := make(map[string]capabilityView, len(body.Capabilities))
	for _, capability := range body.Capabilities {
		byKey[capability.Key] = capability
	}
	return rec, byKey
}

// TestCapabilitiesReportsDisabledSubsystemWithItsSwitchName is the product requirement: a subsystem
// that is off must answer "off", and name the SYNAPSE_* variable that turns it on, so the dashboard
// can distinguish a disabled subsystem from a broken one.
func TestCapabilitiesReportsDisabledSubsystemWithItsSwitchName(t *testing.T) {
	rt := newCapabilityRouter(t, capabilities.Flags{})
	_, byKey := getCapabilities(t, rt, "readonly")
	cases := []struct {
		key, envVar string
	}{
		{"fleet", "SYNAPSE_FLEET_ENABLED"},
		{"cspm", "SYNAPSE_CSPM_ENABLED"},
		{"agent", "SYNAPSE_AGENT_ENABLED"},
		{"ai_triage", "SYNAPSE_FP_TRIAGE_ENABLED"},
		{"sla", "SYNAPSE_SLA_ENABLED"},
		{"inbound_webhooks", "SYNAPSE_INBOUND_WEBHOOKS_ENABLED"},
	}
	for _, c := range cases {
		got, ok := byKey[c.key]
		if !ok {
			t.Errorf("capability %q is missing from the response", c.key)
			continue
		}
		if got.Enabled {
			t.Errorf("%s reported enabled with every switch off", c.key)
		}
		if got.Switch != c.envVar {
			t.Errorf("%s switch = %q, want %q", c.key, got.Switch, c.envVar)
		}
		if got.Name == "" {
			t.Errorf("%s has no human name to render", c.key)
		}
	}
}

// TestCapabilitiesReportsNotificationChannelsAndPlannedSubsystems pins the #1350 wire shape: the
// channel type list rides in `values`, and a subsystem this build does not ship answers `planned`
// with an empty switch.
func TestCapabilitiesReportsNotificationChannelsAndPlannedSubsystems(t *testing.T) {
	rt := newCapabilityRouter(t, capabilities.Flags{Notifications: true, NotificationChannelTypes: []string{"webhook", "slack", "email"}})
	_, byKey := getCapabilities(t, rt, "readonly")
	if got := byKey["notifications"]; !got.Enabled || got.Switch != "SYNAPSE_NOTIFICATIONS_ENABLED" {
		t.Errorf("notifications = %+v, want enabled with its switch", got)
	}
	types := byKey["notifications.channel_types"]
	if !types.Enabled || strings.Join(types.Values, ",") != "webhook,slack,email" {
		t.Errorf("notifications.channel_types = %+v, want enabled with webhook, slack and email", types)
	}
	for _, key := range []string{"ticketing", "docpublish"} {
		got, ok := byKey[key]
		if !ok || !got.Planned || got.Enabled || got.Switch != "" {
			t.Errorf("%s = %+v (present %v), want planned and disabled without a switch", key, got, ok)
		}
	}
}

func TestCapabilitiesReportsEnabledSubsystem(t *testing.T) {
	rt := newCapabilityRouter(t, capabilities.Flags{Fleet: true, FleetAssets: true, SLA: true, InboundWebhooks: true})
	_, byKey := getCapabilities(t, rt, "readonly")
	for _, key := range []string{"fleet", "fleet_assets", "sla", "inbound_webhooks"} {
		if !byKey[key].Enabled {
			t.Errorf("%s reported disabled although its switch is on", key)
		}
	}
	// An ingest switch left off stays off even when its transport is on.
	if byKey["fleet_host_ingest"].Enabled {
		t.Error("fleet_host_ingest reported enabled with its own switch off")
	}
}

// TestCapabilitiesReportsLegacyAlertWebhookAsABoolean backs the rule-form warning (#1347): the console
// learns whether the deprecated SYNAPSE_ALERT_WEBHOOK_URL is set, and only that. The response carries
// the variable name, never a configured value.
func TestCapabilitiesReportsLegacyAlertWebhookAsABoolean(t *testing.T) {
	for _, set := range []bool{false, true} {
		rt := newCapabilityRouter(t, capabilities.Flags{LegacyAlertWebhook: set})
		rec, byKey := getCapabilities(t, rt, "admin")
		got, ok := byKey["legacy_alert_webhook"]
		if !ok {
			t.Fatal("legacy_alert_webhook is missing from the response")
		}
		if got.Enabled != set || got.Switch != "SYNAPSE_ALERT_WEBHOOK_URL" {
			t.Fatalf("legacy_alert_webhook = %+v, want enabled=%v", got, set)
		}
		body := rec.Body.String()
		if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
			t.Fatalf("capability response carries a URL: %s", body)
		}
	}
}

func TestCapabilitiesRequiresTheViewFloor(t *testing.T) {
	rt := newCapabilityRouter(t, capabilities.Flags{})
	for _, role := range []string{"agent", "mcp", "bogus"} {
		rec, _ := getCapabilities(t, rt, role)
		if rec.Code != http.StatusForbidden {
			t.Errorf("role %q capabilities read = %d, want 403", role, rec.Code)
		}
	}
	for _, role := range []string{"readonly", "consultant", "reviewer", "admin"} {
		rec, _ := getCapabilities(t, rt, role)
		if rec.Code != http.StatusOK {
			t.Errorf("role %q capabilities read = %d, want 200", role, rec.Code)
		}
	}
	if !userdom.Role("readonly").Can(userdom.PermView) {
		t.Fatal("readonly must hold the view floor this route is gated on")
	}
}

// TestCapabilitiesRouteAbsentWhenUnwired keeps the wiring honest: the catalog is a composition-root
// dependency, not a default.
func TestCapabilitiesRouteAbsentWhenUnwired(t *testing.T) {
	rt := &Router{log: discardLog()}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil).WithContext(ctxAs("admin"))
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unwired capabilities route = %d, want 404", rec.Code)
	}
}
