package messageformat

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TeamsFormatter, TelegramFormatter, GoogleChatFormatter and DiscordFormatter register the chat
// renderers of #1536 as the ports.NotificationFormatter of their channel types (#1378 to #1381), so
// delivery and the template preview produce the same bytes.

type TeamsFormatter struct{}

func (TeamsFormatter) ChannelType() notification.ChannelType { return notification.ChannelTeams }
func (TeamsFormatter) Format(m ports.RenderedMessage) (ports.FormattedMessage, error) {
	return Teams(m)
}

// TelegramFormatter returns a sendMessage body without chat_id; the driver adds the chat and topic
// of the channel, which are configuration rather than content.
type TelegramFormatter struct{}

func (TelegramFormatter) ChannelType() notification.ChannelType { return notification.ChannelTelegram }
func (TelegramFormatter) Format(m ports.RenderedMessage) (ports.FormattedMessage, error) {
	return Telegram(m)
}

type GoogleChatFormatter struct{}

func (GoogleChatFormatter) ChannelType() notification.ChannelType {
	return notification.ChannelGoogleChat
}
func (GoogleChatFormatter) Format(m ports.RenderedMessage) (ports.FormattedMessage, error) {
	return GoogleChat(m)
}

type DiscordFormatter struct{}

func (DiscordFormatter) ChannelType() notification.ChannelType { return notification.ChannelDiscord }
func (DiscordFormatter) Format(m ports.RenderedMessage) (ports.FormattedMessage, error) {
	return Discord(m)
}

var (
	_ ports.NotificationFormatter = TeamsFormatter{}
	_ ports.NotificationFormatter = TelegramFormatter{}
	_ ports.NotificationFormatter = GoogleChatFormatter{}
	_ ports.NotificationFormatter = DiscordFormatter{}
)
