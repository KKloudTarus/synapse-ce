package messageformat

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgmarkdown"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Discord formats the chat fields as an execute-webhook body with one embed. Discord Markdown
// escapes any punctuation with a backslash, so every ASCII punctuation character of a value is
// escaped; that neutralizes formatting, masked links, headings, quotes, "<@id>" and ":emoji:".
// allowed_mentions with an empty parse list makes certain nothing in the message pings anyone,
// whatever the text holds.
//
// Discord limits an embed title to 256 characters and its description to 4096; content beyond
// that is cut with an ellipsis.
func Discord(message ports.RenderedMessage) (ports.FormattedMessage, error) {
	links, err := checkLinks(message.Links)
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	title := escapedPrefix(strings.TrimSpace(msgtemplate.Sanitize(message.Fields["title"])), discordTitleRunes, escapeDiscord)
	linkLines := make([]string, len(links))
	for i, l := range links {
		linkLines[i] = "[" + escapeDiscord(l.label) + "](" + discordURL(l.url) + ")"
	}
	linkText := strings.Join(linkLines, "\n")
	// The limit counts the raw description, escapes and markers included.
	bodyLimit := discordDescriptionRunes - utf8.RuneCountInString(linkText) - len("\n\n")
	var parts []string
	if body := fitRendered(msgmarkdown.Parse(message.Fields["body"]), bodyLimit, discordBlocks); body != "" {
		parts = append(parts, body)
	}
	if linkText != "" {
		parts = append(parts, linkText)
	}
	embed := map[string]any{"description": strings.Join(parts, "\n\n")}
	if title != "" {
		embed["title"] = escapeDiscord(title)
	}
	body, err := json.Marshal(map[string]any{
		"embeds":           []any{embed},
		"allowed_mentions": map[string]any{"parse": []string{}},
	})
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	return ports.FormattedMessage{ContentType: "application/json", Body: body}, nil
}

const (
	discordTitleRunes       = 256
	discordDescriptionRunes = 4096
)

// discordURL percent-encodes parentheses so a URL cannot end the masked link early.
func discordURL(value string) string {
	return strings.NewReplacer("(", "%28", ")", "%29").Replace(value)
}

func escapeDiscord(value string) string {
	return escapeWith(value, asciiPunctuation)
}

// asciiPunctuation is every printable ASCII character that is neither a letter, a digit nor a space.
const asciiPunctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

func discordBlocks(doc msgmarkdown.Document) string {
	parts := make([]string, 0, len(doc.Blocks))
	for _, block := range doc.Blocks {
		switch v := block.(type) {
		case msgmarkdown.Paragraph:
			parts = append(parts, discordInlines(v.Inlines))
		case msgmarkdown.List:
			lines := make([]string, 0, len(v.Items))
			for _, item := range v.Items {
				lines = append(lines, "- "+discordInlines(item))
			}
			parts = append(parts, strings.Join(lines, "\n"))
		}
	}
	return strings.Join(parts, "\n\n")
}

func discordInlines(inlines []msgmarkdown.Inline) string {
	var b strings.Builder
	for _, n := range inlines {
		switch v := n.(type) {
		case msgmarkdown.Text:
			b.WriteString(escapeDiscord(v.Value))
		case msgmarkdown.Strong:
			b.WriteString("**" + discordInlines(v.Children) + "**")
		case msgmarkdown.Emphasis:
			b.WriteString("*" + discordInlines(v.Children) + "*")
		case msgmarkdown.Code:
			b.WriteString(discordCode(v.Value))
		case msgmarkdown.LineBreak:
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// discordCode wraps a code value in a backtick run longer than any run inside it, padding with a
// space when the value starts or ends with a backtick, as Markdown code spans require. Backslashes
// are literal inside a code span, so nothing is escaped.
func discordCode(value string) string {
	longest, run := 0, 0
	for _, r := range value {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if strings.HasPrefix(value, "`") || strings.HasSuffix(value, "`") {
		value = " " + value + " "
	}
	return fence + value + fence
}
