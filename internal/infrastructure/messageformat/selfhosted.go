package messageformat

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgmarkdown"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// MattermostFormatter and RocketChatFormatter deliberately use their common incoming-webhook
// subset: a single text field. Neither payload relies on Slack Block Kit or rich-text extensions.
// Canonical template Markdown supplies structure. Text nodes came from values that the template
// renderer already escaped, so they are emitted as provider-safe literals while trusted template
// strong, emphasis, lists and code retain their presentation.
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
	return rocketChat(message)
}

func selfHostedChat(message ports.RenderedMessage) (ports.FormattedMessage, error) {
	return selfHostedChatWithLiteral(message, selfHostedLiteral)
}

func rocketChat(message ports.RenderedMessage) (ports.FormattedMessage, error) {
	return selfHostedChatWithLiteral(message, rocketChatLiteral)
}

func selfHostedChatWithLiteral(message ports.RenderedMessage, literal func(string) string) (ports.FormattedMessage, error) {
	links, err := checkLinks(message.Links)
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	parts := make([]string, 0, 2+len(links))
	if title := selfHostedBlocks(msgmarkdown.Parse(message.Fields["title"]), literal); title != "" {
		parts = append(parts, "**"+title+"**")
	}
	if body := selfHostedBlocks(msgmarkdown.Parse(message.Fields["body"]), literal); body != "" {
		parts = append(parts, body)
	}
	// Links originate from a checked console-link builder. Only those URLs are rendered as links.
	for _, link := range links {
		parts = append(parts, "["+selfHostedLiteral(strings.TrimSpace(link.label))+"]("+discordURL(link.url)+")")
	}
	body, err := json.Marshal(map[string]string{"text": strings.Join(parts, "\n\n")})
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	return ports.FormattedMessage{ContentType: "application/json", Body: body}, nil
}

func selfHostedBlocks(doc msgmarkdown.Document, literal func(string) string) string {
	parts := make([]string, 0, len(doc.Blocks))
	for _, block := range doc.Blocks {
		switch v := block.(type) {
		case msgmarkdown.Paragraph:
			if text := selfHostedInlines(v.Inlines, literal); text != "" {
				parts = append(parts, text)
			}
		case msgmarkdown.List:
			items := make([]string, 0, len(v.Items))
			for _, item := range v.Items {
				if text := selfHostedInlines(item, literal); text != "" {
					items = append(items, "- "+text)
				}
			}
			if len(items) > 0 {
				parts = append(parts, strings.Join(items, "\n"))
			}
		}
	}
	return strings.Join(parts, "\n\n")
}

func selfHostedInlines(inlines []msgmarkdown.Inline, literal func(string) string) string {
	var b strings.Builder
	for _, node := range inlines {
		switch v := node.(type) {
		case msgmarkdown.Text:
			b.WriteString(literal(v.Value))
		case msgmarkdown.Strong:
			b.WriteString("**" + selfHostedInlines(v.Children, literal) + "**")
		case msgmarkdown.Emphasis:
			b.WriteString("_" + selfHostedInlines(v.Children, literal) + "_")
		case msgmarkdown.Code:
			b.WriteString(selfHostedCode(v.Value))
		case msgmarkdown.LineBreak:
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// selfHostedLiteral prevents a parsed value node from becoming a provider mention, auto-link or
// Markdown syntax. It intentionally leaves ordinary colons and slashes alone; an untrusted URL
// and mention get an invisible separator while trusted links use checked RenderedMessage.Links.
func selfHostedLiteral(value string) string {
	value = msgtemplate.Sanitize(value)
	value = neutralizeSelfHostedURLs(value)
	value = strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", "@", "@\u200b",
		"\\", "\\\\", "*", "\\*", "_", "\\_", "`", "\\`", "[", "\\[", "]", "\\]", "(", "\\(", ")", "\\)", "~", "\\~", "!", "\\!", "|", "\\|", "#", "\\#", "-", "\\-", "+", "\\+", "=", "\\=",
	).Replace(value)
	return selfHostedOrderedMarker.ReplaceAllString(value, `${1}\.${2}`)
}

// rocketChatLiteral uses an inline-code span for parsed text that could be interpreted by
// Rocket.Chat's message grammar. Unlike backslash and entity escapes, code spans render the
// value literally there while trusted template structure remains outside the span.
func rocketChatLiteral(value string) string {
	value = msgtemplate.Sanitize(value)
	value = neutralizeSelfHostedURLs(value)
	value = strings.ReplaceAll(value, "@", "@\u200b")
	if strings.ContainsAny(value, "\\*_[]()`<>@~!|#+=-") || selfHostedURLPrefix.MatchString(value) || selfHostedOrderedMarker.MatchString(value) {
		return selfHostedCode(value)
	}
	return value
}

var (
	selfHostedURLPrefix     = regexp.MustCompile(`(?i)\b(?:https?://|www\.)`)
	selfHostedOrderedMarker = regexp.MustCompile(`(?m)^(\s*[0-9]+)\.(\s)`)
)

// neutralizeSelfHostedURLs handles the link forms that Mattermost and Rocket.Chat auto-link.
// The separator remains invisible to a reader but keeps every event-originated destination inert.
func neutralizeSelfHostedURLs(value string) string {
	return selfHostedURLPrefix.ReplaceAllStringFunc(value, func(prefix string) string {
		if strings.HasSuffix(strings.ToLower(prefix), "://") {
			return prefix[:len(prefix)-2] + "\u200b//"
		}
		return prefix[:1] + "\u200b" + prefix[1:]
	})
}

func selfHostedCode(value string) string {
	longest, run := 0, 0
	for _, r := range value {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	delimiter := strings.Repeat("`", longest+1)
	if strings.HasPrefix(value, "`") || strings.HasSuffix(value, "`") {
		value = " " + value + " "
	}
	return delimiter + value + delimiter
}
