package notificationsender

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type rocketChatDriver struct{ s *Sender }

func (rocketChatDriver) ChannelType() notification.ChannelType { return notification.ChannelRocketChat }
func (d rocketChatDriver) Send(ctx context.Context, w ports.NotificationWork, config ports.NotificationChannelConfig) ports.NotificationSendResult {
	cfg, ok := config.(ports.RocketChatChannelConfig)
	if !ok || !d.s.selfHostedURLAllowed(cfg.URL) {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	payload, fallback, ok := formatChat(w, rocketChatFormatter)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "format_failed", TemplateFallback: fallback}
	}
	result, _ := d.s.postChat(ctx, cfg.URL, payload)
	result.TemplateFallback = fallback
	return result
}
