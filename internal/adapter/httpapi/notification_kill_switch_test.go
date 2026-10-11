package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/capabilities"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

// TestCreateNotificationChannelRefusesADisabledType is #1362: creating a channel of a type the
// operator switched off answers 400 naming the type and the switch, before anything is stored.
func TestCreateNotificationChannelRefusesADisabledType(t *testing.T) {
	svc := &notificationuc.Service{}
	svc.SetDisabledChannelTypes([]domain.ChannelType{domain.ChannelSlack})
	rt := &Router{log: discardLog()}
	rt.SetNotifications(svc)
	body := `{"name":"ops","type":"slack","enabled":true,"url":"https://hooks.slack.com/services/x"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/channels", strings.NewReader(body))
	// The auth middleware puts the tenant on the context; the router under test runs without it.
	ctx := shared.WithTenant(req.Context(), "tenant")
	req = req.WithContext(context.WithValue(ctx, principalKey, Principal{ID: "admin", Role: "admin", TenantID: "tenant"}))
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Error, `"slack"`) || !strings.Contains(got.Error, "SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED") {
		t.Fatalf("error %q does not name the type and the switch", got.Error)
	}
	if strings.Contains(got.Error, "hooks.slack.com") {
		t.Fatalf("error %q echoes the destination URL", got.Error)
	}
}

// TestCapabilitiesHideADisabledChannelType pins the wire shape of the kill switch: the disabled
// type is absent from notifications.channel_types and the response names no disabled value.
func TestCapabilitiesHideADisabledChannelType(t *testing.T) {
	rt := newCapabilityRouter(t, capabilities.Flags{
		Notifications:                 true,
		NotificationChannelTypes:      []string{"webhook", "slack", "email"},
		NotificationProvidersDisabled: []string{"slack"},
	})
	_, byKey := getCapabilities(t, rt, "readonly")
	if got := byKey["notifications.channel_types"]; !got.Enabled || strings.Join(got.Values, ",") != "webhook,email" {
		t.Fatalf("notifications.channel_types = %+v, want webhook and email", got)
	}
}
