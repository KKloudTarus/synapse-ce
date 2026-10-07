package notificationsender

import (
	"context"
	"encoding/json"
	"regexp"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// googleChatDriver posts a cardsV2 message to a Google Chat incoming webhook (#1380). Chat answers
// with the created message; its resource name is kept as the RemoteRef, so a later event about the
// same subject can be threaded under it (#1384).
type googleChatDriver struct{ s *Sender }

func (googleChatDriver) ChannelType() notification.ChannelType {
	return notification.ChannelGoogleChat
}

// googleChatMessageName is the shape of a message resource name. Anything else in the reply is
// ignored rather than stored.
var googleChatMessageName = regexp.MustCompile(`^spaces/[A-Za-z0-9_-]{1,128}/messages/[A-Za-z0-9_.-]{1,128}$`)

func (d googleChatDriver) Send(ctx context.Context, w ports.NotificationWork, config ports.NotificationChannelConfig) ports.NotificationSendResult {
	cfg, ok := config.(ports.GoogleChatChannelConfig)
	if !ok || cfg.URL == "" {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	payload, fallback, ok := formatChat(w, googleChatFormatter)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "format_failed", TemplateFallback: fallback}
	}
	result, body := d.s.postChat(ctx, cfg.URL, payload)
	result.TemplateFallback = fallback
	if result.ErrorCode == "" {
		var reply struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(body, &reply) == nil && googleChatMessageName.MatchString(reply.Name) {
			result.RemoteRef = reply.Name
		}
	}
	return result
}
