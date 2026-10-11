package notificationsender

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// channelConfig builds the configuration of an HTTP channel type for tests that run the same
// check against several types.
func channelConfig(kind notification.ChannelType, url, secret string) ports.NotificationChannelConfig {
	if kind == notification.ChannelSlack {
		return ports.SlackChannelConfig{URL: url}
	}
	return ports.WebhookChannelConfig{URL: url, Secret: secret}
}
