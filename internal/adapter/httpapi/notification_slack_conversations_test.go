package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const handlerSlackToken = "xoxb" + "-1111111111-2222222222-handlerSECRETtoken"

type handlerSlackWorkspace struct{ calls int }

func (w *handlerSlackWorkspace) Identify(context.Context, string) (ports.SlackIdentity, error) {
	w.calls++
	return ports.SlackIdentity{TeamID: "T0123", TeamName: "Acme"}, nil
}

func (w *handlerSlackWorkspace) Conversation(context.Context, string, string) (ports.SlackConversation, error) {
	w.calls++
	return ports.SlackConversation{ID: "C0123456789", Name: "security", Member: true}, nil
}

func (w *handlerSlackWorkspace) Conversations(context.Context, string) ([]ports.SlackConversation, bool, error) {
	w.calls++
	return []ports.SlackConversation{{ID: "C0123456789", Name: "security", Member: true}, {ID: "C0123456780", Name: "partners", Shared: true}}, false, nil
}

// The Slack bot conversation picker (#1383) needs administer, never echoes the token, and refuses
// unknown fields like every notification request.
func TestSlackConversationsRouteIsAdministratorOnly(t *testing.T) {
	repo := &channelPatchRepo{channel: domain.Channel{TenantID: "tenant", ID: "c1", Name: "ops", Type: domain.ChannelSlackBot, Enabled: true, Destination: "https://slack.com/…", Revision: 1, SecretVersion: 1}}
	svc, err := notificationuc.NewService(repo, handlerProtector{}, nil, repo, handlerClock{}, handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	workspace := &handlerSlackWorkspace{}
	svc.SetSlackWorkspace(workspace)
	rt := &Router{log: discardLog()}
	rt.SetNotifications(svc)
	post := func(role, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/slack/conversations", strings.NewReader(body))
		req = req.WithContext(context.WithValue(shared.WithTenant(req.Context(), "tenant"), principalKey, Principal{ID: role + "-user", Role: role, TenantID: "tenant"}))
		response := httptest.NewRecorder()
		rt.routes().ServeHTTP(response, req)
		return response
	}
	for _, role := range []string{"integration_admin", "reviewer", "viewer"} {
		if response := post(role, `{"bot_token":"`+handlerSlackToken+`"}`); response.Code != http.StatusForbidden {
			t.Fatalf("%s = %d %s", role, response.Code, response.Body.String())
		}
	}
	if workspace.calls != 0 {
		t.Fatal("a refused caller reached Slack")
	}
	response := post("admin", `{"bot_token":"`+handlerSlackToken+`"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("admin = %d %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"team_id":"T0123"`) || !strings.Contains(body, `"name":"partners"`) || !strings.Contains(body, `"is_shared":true`) {
		t.Fatalf("body = %s", body)
	}
	if strings.Contains(body, "handlerSECRETtoken") {
		t.Fatalf("the response echoes the token: %s", body)
	}
	if response := post("admin", `{"bot_token":"`+handlerSlackToken+`","extra":1}`); response.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d", response.Code)
	}
}
