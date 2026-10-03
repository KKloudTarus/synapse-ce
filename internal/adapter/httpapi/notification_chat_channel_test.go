package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

// The WS3 chat channels (#1378 to #1381) over the channel PATCH: an integration_admin cannot
// re-point one, an administrator can, and neither the response nor the audit entry carries the
// credential-bearing URL, the bot token or the chat.
func TestPatchChatChannelNeverReturnsTheCredential(t *testing.T) {
	cases := []struct {
		kind        domain.ChannelType
		destination string
		repoint     string
		secrets     []string
	}{
		{domain.ChannelTeams, "https://prod-1.westus.logic.azure.com/…",
			`"url":"https://prod-2.westus.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?sig=teams-sig-secret"`,
			[]string{"teams-sig-secret", "/workflows/abc"}},
		{domain.ChannelGoogleChat, "https://chat.googleapis.com/…",
			`"url":"https://chat.googleapis.com/v1/spaces/AAA/messages?key=gchat-key-secret&token=gchat-token-secret"`,
			[]string{"gchat-key-secret", "gchat-token-secret", "spaces/AAA"}},
		{domain.ChannelDiscord, "https://discord.com/…",
			`"url":"https://discord.com/api/webhooks/42/discord-token-secret"`,
			[]string{"discord-token-secret", "webhooks/42"}},
		{domain.ChannelTelegram, "https://api.telegram.org/…",
			`"secret":"123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw","chat_id":"-1009988776655","thread_id":7`,
			[]string{"AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", "-1009988776655"}},
	}
	for _, tc := range cases {
		t.Run(string(tc.kind), func(t *testing.T) {
			repo := &channelPatchRepo{channel: domain.Channel{TenantID: "tenant", ID: "c1", Name: "ops", Type: tc.kind, Enabled: true,
				Destination: tc.destination, Revision: 1, SecretVersion: 1}}
			svc, err := notificationuc.NewService(repo, handlerProtector{}, nil, repo, handlerClock{}, handlerIDs{})
			if err != nil {
				t.Fatal(err)
			}
			rt := &Router{log: discardLog()}
			rt.SetNotifications(svc)
			patch := func(role string, revision int) *httptest.ResponseRecorder {
				body := `{"name":"ops","enabled":true,"revision":` + strconv.Itoa(revision) + `,` + tc.repoint + `}`
				req := httptest.NewRequest(http.MethodPatch, "/api/v1/notifications/channels/c1", strings.NewReader(body))
				req = req.WithContext(context.WithValue(shared.WithTenant(req.Context(), "tenant"), principalKey, Principal{ID: role + "-user", Role: role, TenantID: "tenant"}))
				response := httptest.NewRecorder()
				rt.routes().ServeHTTP(response, req)
				return response
			}
			if response := patch("integration_admin", 1); response.Code != http.StatusForbidden || repo.updates != 0 {
				t.Fatalf("integration_admin re-point = %d %s", response.Code, response.Body.String())
			}
			response := patch("admin", 1)
			if response.Code != http.StatusOK || repo.updates != 1 {
				t.Fatalf("admin re-point = %d %s", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), `"destination":"https://`) {
				t.Errorf("response has no masked destination: %s", response.Body.String())
			}
			everything := response.Body.String()
			for _, e := range repo.audit {
				for k, v := range e.Metadata {
					everything += " " + k + "=" + v
				}
			}
			for _, secret := range tc.secrets {
				if strings.Contains(everything, secret) {
					t.Errorf("response or audit leaks %q: %s", secret, everything)
				}
			}
		})
	}
}
