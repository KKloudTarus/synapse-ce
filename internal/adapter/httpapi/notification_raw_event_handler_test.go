package httpapi

import (
	"net/http"
	"strings"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

func TestRawWebhookOptInRequiresAdministratorOverHTTP(t *testing.T) {
	repo := &channelPatchRepo{channel: domain.Channel{TenantID: "tenant", ID: "c1", Name: "Receiver", Type: domain.ChannelWebhook, DataClass: domain.DataClassDetail, Enabled: true, Revision: 1, SecretVersion: 1}}
	svc, err := notificationuc.NewService(repo, handlerProtector{}, nil, repo, handlerClock{}, handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog()}
	rt.SetNotifications(svc)
	body := `{"name":"Receiver","enabled":true,"revision":1,"raw_event":true}`
	denied := templateCall(rt, "integration_admin", "tenant", http.MethodPatch, "/api/v1/notifications/channels/c1", body)
	if denied.Code != http.StatusForbidden || repo.updates != 0 {
		t.Fatalf("manager opt-in status=%d updates=%d", denied.Code, repo.updates)
	}
	allowed := templateCall(rt, "admin", "tenant", http.MethodPatch, "/api/v1/notifications/channels/c1", body)
	if allowed.Code != http.StatusOK || !repo.channel.RawEvent || !strings.Contains(allowed.Body.String(), `"raw_event":true`) {
		t.Fatalf("admin opt-in status=%d body=%s", allowed.Code, allowed.Body.String())
	}
	if len(repo.audit) != 1 || repo.audit[0].Metadata["raw_event"] != "true" || repo.audit[0].Metadata["previous_raw_event"] != "false" {
		t.Fatalf("opt-in audit=%+v", repo.audit)
	}
	retained := templateCall(rt, "integration_admin", "tenant", http.MethodPatch, "/api/v1/notifications/channels/c1", `{"name":"Renamed","enabled":true,"revision":2}`)
	if retained.Code != http.StatusOK || !repo.channel.RawEvent {
		t.Fatalf("manager rename status=%d raw=%v", retained.Code, repo.channel.RawEvent)
	}
	disabled := templateCall(rt, "integration_admin", "tenant", http.MethodPatch, "/api/v1/notifications/channels/c1", `{"name":"Renamed","enabled":true,"revision":3,"raw_event":false,"data_class":"signal"}`)
	if disabled.Code != http.StatusOK || repo.channel.RawEvent || repo.channel.Class() != domain.DataClassSignal {
		t.Fatalf("manager disable status=%d body=%s", disabled.Code, disabled.Body.String())
	}
}
