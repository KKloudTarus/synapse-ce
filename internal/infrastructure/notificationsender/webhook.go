package notificationsender

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// webhookDriver posts the event envelope to a generic receiver, signed with HMAC-SHA256 over
// "<timestamp>.<body>" so the receiver can reject replays and forgeries.
//
// A channel that opted into a custom body (#1376) gets the rendered body the send-time renderer
// put in NotificationWork.CustomWebhookBody instead. The driver sends those exact bytes, signs the
// same bytes and sets X-Synapse-Body: custom, so the signature always covers the body as sent. It
// checks the bytes are one JSON value within the size cap and refuses the attempt otherwise; the
// renderer builds them with json.Marshal, so a refusal means a bug, not a tenant input.
type webhookDriver struct{ s *Sender }

func (webhookDriver) ChannelType() notification.ChannelType { return notification.ChannelWebhook }

func (d webhookDriver) Send(ctx context.Context, w ports.NotificationWork, config ports.NotificationChannelConfig) ports.NotificationSendResult {
	cfg, ok := config.(ports.WebhookChannelConfig)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	class, deliver := notification.EffectiveDataClass(w.Channel.Class(), w.Engagement)
	if !deliver {
		return ports.NotificationSendResult{ErrorCode: notification.CodeEngagementSuppressed}
	}
	custom := len(w.CustomWebhookBody) > 0
	var body []byte
	if custom {
		if len(w.CustomWebhookBody) > notification.MaxRenderedWebhookBodyBytes || !json.Valid(w.CustomWebhookBody) {
			return ports.NotificationSendResult{ErrorCode: "custom_body_invalid"}
		}
		body = w.CustomWebhookBody
	} else if w.Channel.RawEvent && class == notification.DataClassDetail {
		var err error
		if body, err = json.Marshal(w.Event); err != nil {
			return ports.NotificationSendResult{ErrorCode: "encode_failed"}
		}
	} else if len(w.WebhookBody) > 0 {
		if len(w.WebhookBody) > notification.MaxRenderedWebhookBodyBytes || !json.Valid(w.WebhookBody) {
			return ports.NotificationSendResult{ErrorCode: "webhook_body_invalid"}
		}
		body = w.WebhookBody
	} else {
		var err error
		if body, err = filteredWebhookEnvelope(w, class); err != nil {
			return ports.NotificationSendResult{ErrorCode: "encode_failed"}
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "request_invalid"}
	}
	timestamp := strconv.FormatInt(d.s.now().UTC().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "synapse-notifications/1")
	req.Header.Set("X-Synapse-Timestamp", timestamp)
	req.Header.Set("X-Synapse-Signature", webhookSignature(cfg.Secret, timestamp, body))
	req.Header.Set("X-Synapse-Event-ID", w.Event.ID.String())
	req.Header.Set("X-Synapse-Delivery-ID", w.Delivery.ID.String())
	if custom {
		req.Header.Set(notification.CustomWebhookBodyHeader, "custom")
	}
	return d.s.do(req)
}

// filteredWebhookEnvelope protects callers that invoke the sender without the worker's renderer.
// It never falls back to Event.Data, so a new direct-send path cannot revive the legacy raw body.
func filteredWebhookEnvelope(w ports.NotificationWork, class notification.DataClass) ([]byte, error) {
	context, err := notification.DecodeTemplateContext(w.Event.Context)
	if err != nil {
		return nil, err
	}
	if spec, ok := notification.LookupEvent(w.Event.Type); ok {
		context = context.Filter(spec, class)
	} else {
		context = notification.TemplateContext{Vars: map[string]string{}}
	}
	return notification.RenderWebhookEnvelope(w.Event, context)
}

// webhookSignature is "sha256=" and the hex HMAC-SHA256 of "<timestamp>.<body>" under secret.
func webhookSignature(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "."))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
