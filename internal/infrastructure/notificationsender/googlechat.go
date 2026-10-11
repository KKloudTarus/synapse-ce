package notificationsender

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"

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
	var message map[string]any
	if json.Unmarshal(payload, &message) != nil {
		return ports.NotificationSendResult{ErrorCode: "format_failed", TemplateFallback: fallback}
	}
	if threadKey := googleChatThreadKey(w); threadKey != "" {
		message["thread"] = map[string]string{"threadKey": threadKey}
		var err error
		payload, err = json.Marshal(message)
		if err != nil {
			return ports.NotificationSendResult{ErrorCode: "encode_failed", TemplateFallback: fallback}
		}
	}
	target, err := googleChatReplyTarget(cfg.URL)
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid", TemplateFallback: fallback}
	}
	result, body := d.s.postChat(ctx, target, payload)
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

// googleChatThreadKey derives an opaque provider thread identity from the tenant, channel and
// pinned configuration version. It deliberately uses the subject identity, never event data.
func googleChatThreadKey(w ports.NotificationWork) string {
	if w.Event.SubjectKind == "" || w.Event.SubjectID == "" || w.Channel.SecretVersion < 1 {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{w.Event.TenantID.String(), w.Channel.ID.String(), strconv.Itoa(w.Channel.SecretVersion), w.Event.SubjectKind, w.Event.SubjectID}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func googleChatReplyTarget(raw string) (string, error) {
	target, err := url.Parse(raw)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return "", err
	}
	query := target.Query()
	query.Set("messageReplyOption", "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD")
	target.RawQuery = query.Encode()
	return target.String(), nil
}
