package notificationsender

import (
	"bytes"
	"context"
	"net/http"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The WS3 chat drivers (#1378 to #1381) share one shape: build the chat fields, run the channel's
// formatter from messageformat, and POST the wire payload. For every one of them the request URL
// (or, for Telegram, its path) is the credential, so a driver never returns, wraps or logs a
// transport error; it returns only a stable code, which is all the worker stores on the attempt.

// chatMessage is the content every chat driver sends until the send-time renderer (#1365, #1367)
// hands drivers a rendered template: the event's built-in title and summary, with the summary
// escaped so nothing in it is read as Markdown, and the event type and ID as literal code.
// fallback reports that the event carried no title or summary of its own.
func chatMessage(w ports.NotificationWork) (ports.RenderedMessage, bool) {
	title, summary, fallback := eventText(w)
	lines := make([]string, 0, 3)
	for _, line := range strings.Split(summary, "\n") {
		if line = strings.TrimSpace(msgtemplate.Sanitize(line)); line != "" {
			lines = append(lines, msgtemplate.EscapeMarkdown(limit(line, 2500)))
		}
	}
	body := strings.Join(lines, "\n\n")
	if body != "" {
		body += "\n\n"
	}
	// The type is a catalog key and the ID a UUID, so neither holds a backtick that could end the
	// code span early.
	body += "Event `" + string(w.Event.Type) + "` · `" + w.Event.ID.String() + "`"
	return ports.RenderedMessage{Fields: map[string]string{"title": title, "body": body}}, fallback
}

// postChat formats the message for the channel and POSTs it to target. read is true when the
// driver needs the response body (a message ID, a provider error).
func (s *Sender) postChat(ctx context.Context, target string, payload []byte) (ports.NotificationSendResult, []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		// err holds the URL, which is the credential; only the code leaves the driver.
		return ports.NotificationSendResult{ErrorCode: "request_invalid"}, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "synapse-notifications/1")
	return s.doRead(req)
}

// formatChat runs a channel formatter over the chat message of the work item.
func formatChat(w ports.NotificationWork, formatter ports.NotificationFormatter) ([]byte, bool, bool) {
	message, fallback := chatMessage(w)
	formatted, err := formatter.Format(message)
	if err != nil || len(formatted.Body) == 0 {
		return nil, fallback, false
	}
	return formatted.Body, fallback, true
}

var (
	teamsFormatter      ports.NotificationFormatter = messageformat.TeamsFormatter{}
	telegramFormatter   ports.NotificationFormatter = messageformat.TelegramFormatter{}
	googleChatFormatter ports.NotificationFormatter = messageformat.GoogleChatFormatter{}
	discordFormatter    ports.NotificationFormatter = messageformat.DiscordFormatter{}
)
