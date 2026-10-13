package notification

import (
	"fmt"
	"strings"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	pagerDutyUSHost = "events.pagerduty.com"
	pagerDutyEUHost = "events.eu.pagerduty.com"
	jsmAPIHost      = "api.atlassian.com"
	jsmAPIPath      = "/jsm/ops/integration/v2/alerts"
)

// validateMattermostChannel and validateRocketChatChannel accept only a configured operator
// allowlist. The Service supplies that allowlist through its channel-validation wrapper; this
// low-level shape check keeps malformed URLs out of sealed configuration.
func validateMattermostChannel(in ChannelInput, _ bool) (ports.NotificationChannelConfig, string, []string, error) {
	return validateSelfHostedChannel(in, domain.ChannelMattermost)
}

func validateRocketChatChannel(in ChannelInput, _ bool) (ports.NotificationChannelConfig, string, []string, error) {
	return validateSelfHostedChannel(in, domain.ChannelRocketChat)
}

func validateSelfHostedChannel(in ChannelInput, kind domain.ChannelType) (ports.NotificationChannelConfig, string, []string, error) {
	u, host, err := parseVendorURL(in.URL)
	if err != nil {
		return nil, "", nil, err
	}
	if u.EscapedPath() == "" || u.EscapedPath() == "/" || u.RawQuery != "" {
		return nil, "", nil, fmt.Errorf("%w: self-hosted channel requires an HTTPS webhook URL", shared.ErrValidation)
	}
	switch kind {
	case domain.ChannelMattermost:
		return ports.MattermostChannelConfig{URL: u.String()}, maskedVendorURL(host), nil, nil
	case domain.ChannelRocketChat:
		return ports.RocketChatChannelConfig{URL: u.String()}, maskedVendorURL(host), nil, nil
	default:
		return nil, "", nil, fmt.Errorf("%w: unsupported self-hosted channel", shared.ErrValidation)
	}
}

func validatePagerDutyChannel(in ChannelInput, _ bool) (ports.NotificationChannelConfig, string, []string, error) {
	u, host, err := parseVendorURL(in.URL)
	if err != nil {
		return nil, "", nil, err
	}
	if (host != pagerDutyUSHost && host != pagerDutyEUHost) || u.EscapedPath() != "/v2/enqueue" || u.RawQuery != "" {
		return nil, "", nil, fmt.Errorf("%w: PagerDuty requires the Events API v2 endpoint", shared.ErrValidation)
	}
	key := strings.TrimSpace(in.Secret)
	if len(key) < 16 || len(key) > 256 {
		return nil, "", nil, fmt.Errorf("%w: PagerDuty routing key is invalid", shared.ErrValidation)
	}
	return ports.PagerDutyChannelConfig{Region: host, RoutingKey: key}, maskedVendorURL(host), nil, nil
}

func validateJSMChannel(in ChannelInput, _ bool) (ports.NotificationChannelConfig, string, []string, error) {
	if raw := strings.TrimSpace(in.URL); raw != "" {
		u, host, err := parseVendorURL(raw)
		if err != nil || host != jsmAPIHost || u.EscapedPath() != jsmAPIPath || u.RawQuery != "" {
			return nil, "", nil, fmt.Errorf("%w: JSM requires the supported Operations alerts endpoint", shared.ErrValidation)
		}
	}
	key := strings.TrimSpace(in.Secret)
	if len(key) < 16 || len(key) > 256 {
		return nil, "", nil, fmt.Errorf("%w: JSM integration key is invalid", shared.ErrValidation)
	}
	return ports.JSMChannelConfig{APIKey: key}, maskedVendorURL(jsmAPIHost), nil, nil
}
