package notificationsender

import (
	"context"
	"encoding/json"
	"math"
	"net/url"
	"regexp"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// discordDriver executes a Discord channel webhook with one embed (#1381). allowed_mentions.parse
// is always empty (the formatter sets it), so no value can ping a user, a role or @everyone.
//
// The driver adds wait=true, so Discord answers with the created message instead of 204 and its
// snowflake ID becomes the RemoteRef.
type discordDriver struct{ s *Sender }

func (discordDriver) ChannelType() notification.ChannelType { return notification.ChannelDiscord }

var discordSnowflake = regexp.MustCompile(`^[0-9]{1,20}$`)

func (d discordDriver) Send(ctx context.Context, w ports.NotificationWork, config ports.NotificationChannelConfig) ports.NotificationSendResult {
	cfg, ok := config.(ports.DiscordChannelConfig)
	if !ok || cfg.URL == "" {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	target, err := url.Parse(cfg.URL)
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	query := target.Query()
	query.Set("wait", "true")
	target.RawQuery = query.Encode()
	payload, fallback, ok := formatChat(w, discordFormatter)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "format_failed", TemplateFallback: fallback}
	}
	result, body := d.s.postChat(ctx, target.String(), payload)
	result.TemplateFallback = fallback
	var reply struct {
		ID         string  `json:"id"`
		RetryAfter float64 `json:"retry_after"`
	}
	_ = json.Unmarshal(body, &reply)
	switch {
	case result.ErrorCode == "" && discordSnowflake.MatchString(reply.ID):
		result.RemoteRef = reply.ID
	case result.StatusCode == 429 && result.RetryAfter == 0:
		// Discord always sends Retry-After, but its JSON body carries the same hint in seconds
		// with a fraction; use it when the header is missing.
		result.RetryAfter = discordRetryAfter(reply.RetryAfter)
	}
	return result
}

func discordRetryAfter(seconds float64) time.Duration {
	if seconds <= 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return 0
	}
	return time.Duration(math.Ceil(min(seconds, 3600))) * time.Second
}
