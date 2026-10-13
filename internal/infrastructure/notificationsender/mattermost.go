package notificationsender

import (
	"context"
	"net/url"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type mattermostDriver struct{ s *Sender }

func (mattermostDriver) ChannelType() notification.ChannelType { return notification.ChannelMattermost }
func (d mattermostDriver) Send(ctx context.Context, w ports.NotificationWork, config ports.NotificationChannelConfig) ports.NotificationSendResult {
	cfg, ok := config.(ports.MattermostChannelConfig)
	if !ok || !d.s.selfHostedURLAllowed(cfg.URL) {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	payload, fallback, ok := formatChat(w, mattermostFormatter)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "format_failed", TemplateFallback: fallback}
	}
	result, _ := d.s.postChat(ctx, cfg.URL, payload)
	result.TemplateFallback = fallback
	return result
}

func (s *Sender) selfHostedURLAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.RawQuery != "" || u.EscapedPath() == "" || u.EscapedPath() == "/" {
		return false
	}
	if port := u.Port(); port != "" && port != "443" {
		return false
	}
	return s.selfHostedHosts[strings.ToLower(u.Hostname())]
}
