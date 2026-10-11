package messageformat

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgmarkdown"
	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Telegram formats the chat fields as a sendMessage body with parse_mode MarkdownV2. The Telegram
// channel adds chat_id. Every character Telegram treats as markup is escaped as the Bot API
// documents: the 18 special characters and the backslash in text, "`" and "\" in code, ")" and "\"
// in a link URL. Link previews are disabled so a URL in a value is never fetched and shown.
//
// Telegram limits the text to 4096 characters after parsing; content beyond that is cut with an
// ellipsis, leaving room for the title and the links.
func Telegram(message ports.RenderedMessage) (ports.FormattedMessage, error) {
	links, err := checkLinks(message.Links)
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	title := truncateRunes(strings.TrimSpace(msgtemplate.Sanitize(message.Fields["title"])), telegramTitleRunes)
	// Room left for the body after the title, the links and the blank lines between them.
	room := telegramTextRunes - utf8.RuneCountInString(title) - linksRunes(links) - 4
	doc := msgmarkdown.Parse(message.Fields["body"])
	for budget := room; telegramVisibleRunes(doc) > room && budget > 0; budget -= max(budget/20, 1) {
		doc = truncateDocument(msgmarkdown.Parse(message.Fields["body"]), budget)
	}

	var parts []string
	if title != "" {
		parts = append(parts, "*"+escapeTelegram(title)+"*")
	}
	if body := telegramBlocks(doc); body != "" {
		parts = append(parts, body)
	}
	if len(links) > 0 {
		lines := make([]string, len(links))
		for i, l := range links {
			lines[i] = "[" + escapeTelegram(l.label) + "](" + escapeTelegramURL(l.url) + ")"
		}
		parts = append(parts, strings.Join(lines, "\n"))
	}
	body, err := json.Marshal(map[string]any{
		"text":                 strings.Join(parts, "\n\n"),
		"parse_mode":           "MarkdownV2",
		"link_preview_options": map[string]any{"is_disabled": true},
	})
	if err != nil {
		return ports.FormattedMessage{}, err
	}
	return ports.FormattedMessage{ContentType: "application/json", Body: body}, nil
}

const (
	telegramTextRunes  = 4096
	telegramTitleRunes = 256
)

// telegramVisibleRunes is the length of the body once Telegram has parsed it: its text, plus the
// blank lines between blocks, the "• " of every list item and the line breaks between items.
func telegramVisibleRunes(doc msgmarkdown.Document) int {
	n := visibleRunes(doc)
	for i, block := range doc.Blocks {
		if i > 0 {
			n += 2
		}
		if list, ok := block.(msgmarkdown.List); ok {
			n += 3*len(list.Items) - 1
		}
	}
	return n
}

// linksRunes estimates the visible characters links take, so the body leaves room for them.
func linksRunes(links []link) int {
	n := 0
	for _, l := range links {
		n += len([]rune(l.label)) + 1
	}
	return n
}

const telegramSpecial = "_*[]()~`>#+-=|{}.!\\"

func escapeTelegram(value string) string {
	return escapeWith(value, telegramSpecial)
}

func escapeTelegramCode(value string) string {
	return escapeWith(value, "`\\")
}

func escapeTelegramURL(value string) string {
	return escapeWith(value, ")\\")
}

// escapeWith puts a backslash before every character of value that is in special.
func escapeWith(value, special string) string {
	var b strings.Builder
	b.Grow(len(value) + len(value)/4)
	for _, r := range value {
		if r < 128 && strings.ContainsRune(special, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func telegramBlocks(doc msgmarkdown.Document) string {
	parts := make([]string, 0, len(doc.Blocks))
	for _, block := range doc.Blocks {
		switch v := block.(type) {
		case msgmarkdown.Paragraph:
			parts = append(parts, telegramInlines(v.Inlines))
		case msgmarkdown.List:
			lines := make([]string, 0, len(v.Items))
			for _, item := range v.Items {
				lines = append(lines, "• "+telegramInlines(item))
			}
			parts = append(parts, strings.Join(lines, "\n"))
		}
	}
	return strings.Join(parts, "\n\n")
}

// telegramInlines emits MarkdownV2. Telegram rejects an entity nested in itself, so emphasis
// inside emphasis (or strong inside strong) adds no second marker. An italic that closes right
// before another one opens would read as "__", the underline marker, so an empty bold entity
// separates them, as the Bot API recommends.
func telegramInlines(inlines []msgmarkdown.Inline) string {
	var b strings.Builder
	italicJustClosed := false
	write := func(s string) {
		if s != "" {
			b.WriteString(s)
			italicJustClosed = false
		}
	}
	var walk func([]msgmarkdown.Inline, bool, bool)
	walk = func(inlines []msgmarkdown.Inline, bold, italic bool) {
		for _, n := range inlines {
			switch v := n.(type) {
			case msgmarkdown.Text:
				write(escapeTelegram(v.Value))
			case msgmarkdown.Code:
				write("`" + escapeTelegramCode(v.Value) + "`")
			case msgmarkdown.LineBreak:
				write("\n")
			case msgmarkdown.Strong:
				if bold {
					walk(v.Children, bold, italic)
					continue
				}
				write("*")
				walk(v.Children, true, italic)
				write("*")
			case msgmarkdown.Emphasis:
				if italic {
					walk(v.Children, bold, italic)
					continue
				}
				if italicJustClosed {
					write("**")
				}
				write("_")
				walk(v.Children, bold, true)
				write("_")
				italicJustClosed = true
			}
		}
	}
	walk(inlines, false, false)
	return b.String()
}
