package httpapi

import (
	"context"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	ticketuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type jiraWebhookAdmin interface {
	ConfigureInboundWebhook(context.Context, shared.ID, shared.ID, string, string) (ticketuc.WebhookConfiguration, error)
}

type jiraWebhookReceiver struct{ fallback, jira ports.InboundWebhookReceiver }

func (r jiraWebhookReceiver) ReceiveInboundWebhook(ctx context.Context, id ports.InboundWebhookIdentity, event ports.InboundWebhookEvent) error {
	if event.Provider == "jira-cloud" || event.Provider == "jira-dc" {
		return r.jira.ReceiveInboundWebhook(ctx, id, event)
	}
	return r.fallback.ReceiveInboundWebhook(ctx, id, event)
}

func (rt *Router) SetJiraInboundWebhooks(admin jiraWebhookAdmin, receiver ports.InboundWebhookReceiver) {
	if rt.inboundWebhooks == nil || rt.inboundWebhooks.receiver == nil || admin == nil || receiver == nil {
		return
	}
	rt.jiraWebhookAdmin = admin
	rt.inboundWebhooks.receiver = jiraWebhookReceiver{fallback: rt.inboundWebhooks.receiver, jira: receiver}
}

func (rt *Router) configureJiraInboundWebhook(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Secret string `json:"secret"`
	}
	if !decodeIntegrationJSON(w, r, &input) {
		return
	}
	out, err := rt.jiraWebhookAdmin.ConfigureInboundWebhook(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("integrationID")), PrincipalFrom(r.Context()), input.Secret)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

func (rt *Router) mountJiraInboundWebhook(mux *http.ServeMux) {
	if rt.jiraWebhookAdmin != nil {
		mux.HandleFunc("POST /api/v1/integrations/{integrationID}/jira/inbound-webhook", rt.authz(userdom.PermAdminister, rt.configureJiraInboundWebhook))
	}
}
