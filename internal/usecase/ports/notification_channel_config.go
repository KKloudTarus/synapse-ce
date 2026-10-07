package ports

import "github.com/KKloudTarus/synapse-ce/internal/domain/notification"

// NotificationChannelConfig is the decrypted configuration of one notification channel. Each
// channel type has its own struct, so a driver receives only the fields its type defines and a
// new type adds a struct instead of widening a shared one.
//
// The structs are sealed as JSON with the field names the single shared struct used before, so
// configurations sealed by earlier releases decode unchanged.
type NotificationChannelConfig interface {
	NotificationChannelType() notification.ChannelType
}

// WebhookChannelConfig is a generic signed webhook: the receiver URL and the HMAC signing secret.
type WebhookChannelConfig struct {
	URL    string `json:"url,omitempty"`
	Secret string `json:"secret,omitempty"`
}

// NotificationChannelType implements NotificationChannelConfig.
func (WebhookChannelConfig) NotificationChannelType() notification.ChannelType {
	return notification.ChannelWebhook
}

// SlackChannelConfig is a Slack incoming webhook. The URL is the credential.
type SlackChannelConfig struct {
	URL string `json:"url,omitempty"`
}

// NotificationChannelType implements NotificationChannelConfig.
func (SlackChannelConfig) NotificationChannelType() notification.ChannelType {
	return notification.ChannelSlack
}

// EmailChannelConfig lists the recipients of an email channel. The relay is operator
// configuration and is not part of a channel.
type EmailChannelConfig struct {
	Recipients []string `json:"recipients,omitempty"`
}

// NotificationChannelType implements NotificationChannelConfig.
func (EmailChannelConfig) NotificationChannelType() notification.ChannelType {
	return notification.ChannelEmail
}

// TeamsChannelConfig is a Microsoft Teams Workflows (Power Automate) webhook. The URL carries the
// trigger signature (sig=), so the whole URL is the credential.
type TeamsChannelConfig struct {
	URL string `json:"url,omitempty"`
}

// NotificationChannelType implements NotificationChannelConfig.
func (TeamsChannelConfig) NotificationChannelType() notification.ChannelType {
	return notification.ChannelTeams
}

// TelegramChannelConfig is a Telegram bot posting to one chat. BotToken is the credential; it is
// part of the Bot API request path, so the request URL is never logged or stored. MessageThreadID
// is a forum topic, or 0 for the chat's main thread.
type TelegramChannelConfig struct {
	BotToken        string `json:"bot_token,omitempty"`
	ChatID          string `json:"chat_id,omitempty"`
	MessageThreadID int64  `json:"message_thread_id,omitempty"`
}

// NotificationChannelType implements NotificationChannelConfig.
func (TelegramChannelConfig) NotificationChannelType() notification.ChannelType {
	return notification.ChannelTelegram
}

// GoogleChatChannelConfig is a Google Chat incoming webhook. The key and token query parameters
// make the whole URL the credential.
type GoogleChatChannelConfig struct {
	URL string `json:"url,omitempty"`
}

// NotificationChannelType implements NotificationChannelConfig.
func (GoogleChatChannelConfig) NotificationChannelType() notification.ChannelType {
	return notification.ChannelGoogleChat
}

// DiscordChannelConfig is a Discord channel webhook. The token is a path segment, so the whole URL
// is the credential.
type DiscordChannelConfig struct {
	URL string `json:"url,omitempty"`
}

// NotificationChannelType implements NotificationChannelConfig.
func (DiscordChannelConfig) NotificationChannelType() notification.ChannelType {
	return notification.ChannelDiscord
}
