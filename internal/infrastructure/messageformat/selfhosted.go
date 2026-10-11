package messageformat

import (
	"encoding/json"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// MattermostFormatter and RocketChatFormatter deliberately use their common incoming-webhook
// subset: a single text field. Neither payload relies on Slack Block Kit or rich-text extensions.
// Values are escaped as Markdown so an event value cannot create a mention, link, or formatting.
type MattermostFormatter struct{}
type RocketChatFormatter struct{}

var (
	_ ports.NotificationFormatter = MattermostFormatter{}
	_ ports.NotificationFormatter = RocketChatFormatter{}
)

func (MattermostFormatter) ChannelType() notification.ChannelType {
	return notification.ChannelMattermost
}
func (RocketChatFormatter) ChannelType() notification.ChannelType {
	return notification.ChannelRocketChat
}

func (MattermostFormatter) Format(message ports.RenderedMessage) (ports.FormattedMessage, error) {
	return selfHostedChat(message)
}
func (RocketChatFormatter) Format(message ports.RenderedMessage) (ports.FormattedMessage, error) {
	return selfHostedChat(message)
}

func selfHostedChat(message ports.RenderedMessage) (ports.FormattedMessage, error) {
	links, err := checkLinks(message.Links)
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	parts := make([]string, 0, 2+len(links))
	if title := literalMarkdown(message.Fields["title"]); title != "" {
		parts = append(parts, "**"+title+"**")
	}
	if body := literalMarkdown(message.Fields["body"]); body != "" {
		parts = append(parts, body)
	}
	// Links originate from a checked console-link builder. The labels are still rendered literally.
	for _, link := range links {
		parts = append(parts, "["+literalMarkdown(link.label)+"]("+link.url+")")
	}
	body, err := json.Marshal(map[string]string{"text": strings.Join(parts, "\n\n")})
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	return ports.FormattedMessage{ContentType: "application/json", Body: body}, nil
}

func literalMarkdown(v string) string {
	return msgtemplate.EscapeMarkdown(strings.TrimSpace(msgtemplate.Sanitize(v)))
}
