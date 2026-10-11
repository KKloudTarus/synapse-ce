package notificationsender

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// teamsDriver posts an Adaptive Card message to a Microsoft Teams Workflows webhook (#1378). The
// trigger answers 202 Accepted and returns no message handle, so the delivery has no RemoteRef.
type teamsDriver struct{ s *Sender }

func (teamsDriver) ChannelType() notification.ChannelType { return notification.ChannelTeams }

func (d teamsDriver) Send(ctx context.Context, w ports.NotificationWork, config ports.NotificationChannelConfig) ports.NotificationSendResult {
	cfg, ok := config.(ports.TeamsChannelConfig)
	if !ok || cfg.URL == "" {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	payload, fallback, ok := formatChat(w, teamsFormatter)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "format_failed", TemplateFallback: fallback}
	}
	result, _ := d.s.postChat(ctx, cfg.URL, payload)
	result.TemplateFallback = fallback
	return result
}
