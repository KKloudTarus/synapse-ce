package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/teamslink"
)

type handlerTeamsVerifier struct {
	allow bool
	seen  []string
}

func (v *handlerTeamsVerifier) Verify(_ context.Context, authorization, serviceURL string) error {
	v.seen = append(v.seen, authorization+"|"+serviceURL)
	if !v.allow {
		return errors.New("unauthorized")
	}
	return nil
}

type handlerTeamsBot struct{ replies []string }

func (b *handlerTeamsBot) Send(_ context.Context, _ ports.TeamsConversationRef, activity []byte) (string, error) {
	b.replies = append(b.replies, string(activity))
	return "id", nil
}

type handlerTeamsOffers struct{ n int }

func (o *handlerTeamsOffers) OfferTeamsLink(context.Context, string, string, string, time.Time) (bool, error) {
	o.n++
	return true, nil
}

type handlerTeamsContacts struct{ attempts int }

func (c *handlerTeamsContacts) LinkTeamsContact(context.Context, shared.ID, shared.ID, string, ports.TeamsLinker) (ports.UserContact, bool, error) {
	return ports.UserContact{}, false, nil
}
func (c *handlerTeamsContacts) CountTeamsLinkAttempt(context.Context, shared.ID, shared.ID, shared.ID, time.Time) error {
	c.attempts++
	return nil
}
func (c *handlerTeamsContacts) TeamsConversation(context.Context, shared.ID, shared.ID) (string, bool, error) {
	return "", false, nil
}

type handlerTeamsClock struct{}

func (handlerTeamsClock) Now() time.Time { return time.Unix(1700000000, 0).UTC() }

const teamsService = "https://smba.trafficmanager.net/amer/"

func teamsRouter(t *testing.T, verifier *handlerTeamsVerifier) (*Router, *handlerTeamsBot, *handlerTeamsContacts) {
	t.Helper()
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	bot, contacts := &handlerTeamsBot{}, &handlerTeamsContacts{}
	svc, err := teamslink.NewService(teamslink.Config{Bot: bot, Offers: &handlerTeamsOffers{}, Contacts: contacts, Protector: cipher, IDs: idgen.RandomID{}, Clock: handlerTeamsClock{},
		Key: teamslink.DeriveKey("master"), AcceptsServiceURL: func(raw string) bool { return raw == teamsService }, Formatter: messageformat.TeamsFormatter{}})
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog()}
	rt.SetTeamsLink(svc, verifier)
	return rt, bot, contacts
}

func teamsActivity() string {
	raw, _ := json.Marshal(map[string]any{"type": "message", "text": "hello", "serviceUrl": teamsService,
		"conversation": map[string]any{"id": "a:1conv", "conversationType": "personal", "tenantId": "entra"},
		"from":         map[string]any{"aadObjectId": "0a0b0c0d-1111-2222-3333-444455556666"}})
	return string(raw)
}

func TestTeamsBotEndpointNeedsTheBotFrameworkToken(t *testing.T) {
	verifier := &handlerTeamsVerifier{}
	rt, bot, _ := teamsRouter(t, verifier)
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/teams/messages", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer forged")
		res := httptest.NewRecorder()
		rt.handleTeamsActivity(res, req)
		return res
	}
	if res := post(teamsActivity()); res.Code != http.StatusUnauthorized || len(bot.replies) != 0 {
		t.Fatalf("forged token = %d replies=%d", res.Code, len(bot.replies))
	}
	// The verifier is asked about the activity's own service URL.
	if len(verifier.seen) != 1 || verifier.seen[0] != "Bearer forged|"+teamsService {
		t.Fatalf("verifier saw %v", verifier.seen)
	}
	if res := post(`not json`); res.Code != http.StatusUnauthorized {
		t.Fatalf("malformed body = %d", res.Code)
	}
	verifier.allow = true
	if res := post(teamsActivity()); res.Code != http.StatusOK || len(bot.replies) != 1 || !strings.Contains(bot.replies[0], "link code") {
		t.Fatalf("verified activity = %d replies=%v", res.Code, bot.replies)
	}
	if res := post(strings.Repeat("x", teamsBotBodyCap+1)); res.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = %d", res.Code)
	}
}

func TestMyPersonalChannelsAndTeamsLink(t *testing.T) {
	rt, _, contacts := teamsRouter(t, &handlerTeamsVerifier{})
	as := func(method, path, body string, handler http.HandlerFunc) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req = req.WithContext(context.WithValue(shared.WithTenant(req.Context(), "tenant"), principalKey, Principal{ID: "ada", Role: "member", TenantID: "tenant"}))
		res := httptest.NewRecorder()
		handler(res, req)
		return res
	}
	res := as(http.MethodGet, "/api/v1/me/personal-channels", "", rt.getMyPersonalChannels)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"teams":{"available":true}`) || !strings.Contains(res.Body.String(), `"workspaces":[]`) {
		t.Fatalf("personal channels = %d %s", res.Code, res.Body.String())
	}
	if res := as(http.MethodPost, "/api/v1/me/contacts/teams", `{"code":"ABCDE-FGHJK"}`, rt.linkMyTeams); res.Code != http.StatusForbidden || contacts.attempts != 1 {
		t.Fatalf("unknown code = %d attempts=%d", res.Code, contacts.attempts)
	}
	if res := as(http.MethodPost, "/api/v1/me/contacts/teams", `{"code":"x","user_id":"bob"}`, rt.linkMyTeams); res.Code != http.StatusBadRequest {
		t.Fatalf("caller-supplied identity = %d", res.Code)
	}
	plain := &Router{log: discardLog()}
	if res := as(http.MethodPost, "/api/v1/me/contacts/teams", `{"code":"ABCDE-FGHJK"}`, plain.linkMyTeams); res.Code != http.StatusServiceUnavailable {
		t.Fatalf("without the bot = %d", res.Code)
	}
}
