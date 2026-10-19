package jira

import (
	"context"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.TicketWebhookCapability = (*Adapter)(nil)

func (a *Adapter) TicketWebhookPrincipal(ctx context.Context) (string, error) {
	if !a.cloud {
		var info struct {
			VersionNumbers []int  `json:"versionNumbers"`
			DeploymentType string `json:"deploymentType"`
		}
		if _, err := a.request(ctx, http.MethodGet, "/serverInfo", nil, nil, &info, http.StatusOK); err != nil {
			return "", err
		}
		// 11.3 is the oldest server release supported by this signed-hook
		// implementation. Older and unknown versions fail closed; support can
		// expand when their outgoing HMAC contract is verified.
		v := info.VersionNumbers
		if (info.DeploymentType != "Data Center" && info.DeploymentType != "Server") || len(v) < 2 || v[0] < 11 || (v[0] == 11 && v[1] < 3) {
			return "", ticketError(0, "webhook_secrets_unsupported", 0, false)
		}
	}
	return a.authenticatedIdentity(ctx)
}
