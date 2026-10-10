package notificationsender

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// slackDriver posts a Block Kit message to a Slack incoming webhook.
type slackDriver struct{ s *Sender }

func (slackDriver) ChannelType() notification.ChannelType { return notification.ChannelSlack }

func (d slackDriver) Send(ctx context.Context, w ports.NotificationWork, config ports.NotificationChannelConfig) ports.NotificationSendResult {
	cfg, ok := config.(ports.SlackChannelConfig)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	if w.Formatted != nil {
		// A template rendered this message (#1365); its Block Kit payload is sent as it is.
		return d.post(ctx, cfg.URL, w.Formatted.Body, false)
	}
	title, summary, fallback := eventText(w)
	body, _ := json.Marshal(slackFallbackPayload(title, summary, w.Event))
	return d.post(ctx, cfg.URL, body, fallback)
}

// slackFallbackPayload uses only Slack literal text primitives. A failed renderer must not turn
// a value from the filtered snapshot into mrkdwn, a mention, or an unfurled link.
func slackFallbackPayload(title, summary string, event notification.Event) map[string]any {
	title = safeHeader(title)
	summary = limit(msgtemplate.Sanitize(summary), 2500)
	blocks := []any{}
	if title != "" {
		blocks = append(blocks, map[string]any{"type": "header", "text": map[string]any{"type": "plain_text", "text": limit(title, 150), "emoji": false}})
	}
	if summary != "" {
		blocks = append(blocks, map[string]any{"type": "rich_text", "elements": []any{map[string]any{"type": "rich_text_section", "elements": []any{map[string]any{"type": "text", "text": summary}}}}})
	}
	blocks = append(blocks, map[string]any{"type": "rich_text", "elements": []any{map[string]any{"type": "rich_text_section", "elements": []any{map[string]any{"type": "text", "text": "Event " + string(event.Type) + " · " + event.ID.String()}}}}})
	return map[string]any{
		"text":         escapeSlack(title),
		"blocks":       blocks,
		"unfurl_links": false,
		"unfurl_media": false,
	}
}

func (d slackDriver) post(ctx context.Context, url string, body []byte, fallback bool) ports.NotificationSendResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "request_invalid", TemplateFallback: fallback}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "synapse-notifications/1")
	result := d.s.do(req)
	result.TemplateFallback = fallback
	return result
}

func escapeSlack(v string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(v)
}
