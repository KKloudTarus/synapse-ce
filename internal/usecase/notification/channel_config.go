package notification

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// channelSchema is what the service knows about one channel type: how to validate the
// administrator's input into the type's sealed configuration, and how to decode that
// configuration again at send time. Adding a channel type adds an entry here and a driver in
// the sender; no switch elsewhere changes.
type channelSchema struct {
	// validate returns the configuration to seal, the masked destination shown in the console,
	// and the recipients stored on the channel (email only).
	validate func(in ChannelInput, requireSecret bool) (config ports.NotificationChannelConfig, destination string, recipients []string, err error)
	decode   func(raw []byte) (ports.NotificationChannelConfig, error)
}

var channelSchemas = map[domain.ChannelType]channelSchema{
	domain.ChannelWebhook: {validate: validateWebhookChannel, decode: decodeConfig[ports.WebhookChannelConfig]},
	domain.ChannelSlack:   {validate: validateSlackChannel, decode: decodeConfig[ports.SlackChannelConfig]},
	domain.ChannelEmail:   {validate: validateEmailChannel, decode: decodeConfig[ports.EmailChannelConfig]},
	// The WS3 chat channels (#1378 to #1381), validated in chat_channel_config.go.
	domain.ChannelTeams:      {validate: validateTeamsChannel, decode: decodeConfig[ports.TeamsChannelConfig]},
	domain.ChannelTelegram:   {validate: validateTelegramChannel, decode: decodeConfig[ports.TelegramChannelConfig]},
	domain.ChannelGoogleChat: {validate: validateGoogleChatChannel, decode: decodeConfig[ports.GoogleChatChannelConfig]},
	domain.ChannelDiscord:    {validate: validateDiscordChannel, decode: decodeConfig[ports.DiscordChannelConfig]},
}

const (
	codeUnsupportedChannel   = "unsupported_channel"
	codeChannelConfigInvalid = "channel_config_invalid"
)

func validateChannel(in ChannelInput, requireSecret bool) (ports.NotificationChannelConfig, string, []string, error) {
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 200 || !in.Type.Valid() {
		return nil, "", nil, fmt.Errorf("%w: channel name and valid type are required", shared.ErrValidation)
	}
	schema, ok := channelSchemas[in.Type]
	if !ok {
		return nil, "", nil, fmt.Errorf("%w: unsupported channel type", shared.ErrValidation)
	}
	return schema.validate(in, requireSecret)
}

// decodeChannelConfig opens a sealed configuration for its channel type. It returns a delivery
// error code instead of an error so the worker records a stable, secret-free reason.
func decodeChannelConfig(channelType domain.ChannelType, raw []byte) (ports.NotificationChannelConfig, string) {
	schema, ok := channelSchemas[channelType]
	if !ok {
		return nil, codeUnsupportedChannel
	}
	config, err := schema.decode(raw)
	if err != nil {
		return nil, codeChannelConfigInvalid
	}
	return config, ""
}

func decodeConfig[T ports.NotificationChannelConfig](raw []byte) (ports.NotificationChannelConfig, error) {
	var config T
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, err
	}
	return config, nil
}

func validateWebhookChannel(in ChannelInput, requireSecret bool) (ports.NotificationChannelConfig, string, []string, error) {
	u, err := validateHTTPS(in.URL, false)
	if err != nil {
		return nil, "", nil, err
	}
	if requireSecret && len(in.Secret) < 16 {
		return nil, "", nil, fmt.Errorf("%w: webhook signing secret must be at least 16 bytes", shared.ErrValidation)
	}
	return ports.WebhookChannelConfig{URL: u.String(), Secret: in.Secret}, u.Scheme + "://" + u.Host + "/…", nil, nil
}

func validateSlackChannel(in ChannelInput, _ bool) (ports.NotificationChannelConfig, string, []string, error) {
	u, err := validateHTTPS(in.URL, true)
	if err != nil {
		return nil, "", nil, err
	}
	return ports.SlackChannelConfig{URL: u.String()}, "https://" + u.Host + "/services/…", nil, nil
}

func validateEmailChannel(in ChannelInput, _ bool) (ports.NotificationChannelConfig, string, []string, error) {
	recipients := make([]string, 0, len(in.Recipients))
	seen := map[string]bool{}
	for _, v := range in.Recipients {
		a, err := mail.ParseAddress(strings.TrimSpace(v))
		if err != nil || strings.ContainsAny(a.Address, "\r\n") {
			return nil, "", nil, fmt.Errorf("%w: invalid email recipient", shared.ErrValidation)
		}
		normalized := strings.ToLower(a.Address)
		if !seen[normalized] {
			seen[normalized] = true
			recipients = append(recipients, normalized)
		}
	}
	if len(recipients) == 0 || len(recipients) > 50 {
		return nil, "", nil, fmt.Errorf("%w: email channel requires 1-50 recipients", shared.ErrValidation)
	}
	return ports.EmailChannelConfig{Recipients: recipients}, recipientSummary(recipients), recipients, nil
}

func validateHTTPS(raw string, slack bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%w: channel URL must be an HTTPS URL without credentials", shared.ErrValidation)
	}
	host := strings.ToLower(u.Hostname())
	if slack && !((host == "hooks.slack.com" || host == "hooks.slack-gov.com") && strings.HasPrefix(u.EscapedPath(), "/services/")) {
		return nil, fmt.Errorf("%w: Slack channel requires a supported incoming-webhook URL", shared.ErrValidation)
	}
	return u, nil
}

func recipientSummary(v []string) string {
	if len(v) == 1 {
		return v[0]
	}
	return strconv.Itoa(len(v)) + " recipients"
}
