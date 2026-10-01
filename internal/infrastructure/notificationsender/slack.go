package notificationsender

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"

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
	body, _ := json.Marshal(map[string]any{"text": title, "blocks": []map[string]any{{"type": "header", "text": map[string]string{"type": "plain_text", "text": limit(title, 150)}}, {"type": "section", "text": map[string]string{"type": "mrkdwn", "text": escapeSlack(limit(summary, 2500))}}, {"type": "context", "elements": []map[string]string{{"type": "mrkdwn", "text": "Event `" + string(w.Event.Type) + "` · `" + w.Event.ID.String() + "`"}}}}})
	return d.post(ctx, cfg.URL, body, fallback)
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
