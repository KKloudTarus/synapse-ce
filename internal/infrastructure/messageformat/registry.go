package messageformat

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Formatters returns one formatter per channel type that has one. The generic webhook has none:
// its body is a versioned contract (EPIC #1327 D5), not rendered content.
func Formatters() map[notification.ChannelType]ports.NotificationFormatter {
	out := map[notification.ChannelType]ports.NotificationFormatter{}
	for _, f := range []ports.NotificationFormatter{Slack{}, Email{}, TeamsFormatter{}, TelegramFormatter{}, GoogleChatFormatter{}, DiscordFormatter{}} {
		out[f.ChannelType()] = f
	}
	return out
}
