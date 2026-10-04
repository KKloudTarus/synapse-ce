package notification

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The chat channels of WS3 (#1378 to #1381). Each one posts to a vendor endpoint whose URL, or
// whose bot token, is the credential. Validation pins the vendor's hosts and path shape, so a
// tenant cannot use a chat channel to reach an arbitrary host (EPIC #1327 D6); safehttp still vets
// every address at dial time. The masked destination is only scheme://host/…, because the path or
// query of every one of these URLs holds the secret.

var (
	googleChatPath = regexp.MustCompile(`^/v1/spaces/[A-Za-z0-9_-]{1,128}/messages$`)
	discordPath    = regexp.MustCompile(`^/api(?:/v[0-9]{1,2})?/webhooks/[0-9]{1,20}/[A-Za-z0-9_-]{1,128}$`)
	telegramToken  = regexp.MustCompile(`^[0-9]{5,16}:[A-Za-z0-9_-]{30,64}$`)
	telegramChat   = regexp.MustCompile(`^(?:-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
	decimalID      = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// telegramMaxThreadID bounds message_thread_id to the Bot API's 32-bit integer.
const telegramMaxThreadID = 1<<31 - 1

// teamsHostSuffixes are the hosts a Teams Workflows trigger URL is issued on: Azure Logic Apps
// (commercial and US Government) and the Power Platform environment endpoints. The retired Office
// 365 connector host (webhook.office.com) is deliberately absent.
var teamsHostSuffixes = []string{".logic.azure.com", ".logic.azure.us", ".environment.api.powerplatform.com"}

var discordHosts = map[string]bool{"discord.com": true, "discordapp.com": true, "ptb.discord.com": true, "canary.discord.com": true}

const telegramAPIHost = "api.telegram.org"

var errChatURL = fmt.Errorf("%w: channel URL must be an HTTPS URL without credentials", shared.ErrValidation)

// parseVendorURL parses an https URL on the default port with no userinfo or fragment.
func parseVendorURL(raw string) (*url.URL, string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, "", errChatURL
	}
	if port := u.Port(); port != "" && port != "443" {
		return nil, "", errChatURL
	}
	return u, strings.ToLower(u.Hostname()), nil
}

func maskedVendorURL(host string) string { return "https://" + host + "/…" }

func validateTeamsChannel(in ChannelInput, _ bool) (ports.NotificationChannelConfig, string, []string, error) {
	invalid := fmt.Errorf("%w: Microsoft Teams channel requires a Workflows webhook URL", shared.ErrValidation)
	u, host, err := parseVendorURL(in.URL)
	if err != nil {
		return nil, "", nil, err
	}
	hostOK := false
	for _, suffix := range teamsHostSuffixes {
		if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
			hostOK = true
			break
		}
	}
	path := u.EscapedPath()
	pathOK := strings.HasPrefix(path, "/workflows/") || strings.HasPrefix(path, "/powerautomate/automations/direct/workflows/")
	if !hostOK || !pathOK || u.Query().Get("sig") == "" {
		return nil, "", nil, invalid
	}
	return ports.TeamsChannelConfig{URL: u.String()}, maskedVendorURL(host), nil, nil
}

func validateGoogleChatChannel(in ChannelInput, _ bool) (ports.NotificationChannelConfig, string, []string, error) {
	invalid := fmt.Errorf("%w: Google Chat channel requires an incoming-webhook URL with key and token", shared.ErrValidation)
	u, host, err := parseVendorURL(in.URL)
	if err != nil {
		return nil, "", nil, err
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || host != "chat.googleapis.com" || !googleChatPath.MatchString(u.EscapedPath()) {
		return nil, "", nil, invalid
	}
	// Only the credential parameters are accepted, so the driver alone decides threading and
	// reply options.
	for name, values := range query {
		if (name != "key" && name != "token") || len(values) != 1 || values[0] == "" {
			return nil, "", nil, invalid
		}
	}
	if query.Get("key") == "" || query.Get("token") == "" {
		return nil, "", nil, invalid
	}
	return ports.GoogleChatChannelConfig{URL: u.String()}, maskedVendorURL(host), nil, nil
}

func validateDiscordChannel(in ChannelInput, _ bool) (ports.NotificationChannelConfig, string, []string, error) {
	invalid := fmt.Errorf("%w: Discord channel requires a channel webhook URL", shared.ErrValidation)
	u, host, err := parseVendorURL(in.URL)
	if err != nil {
		return nil, "", nil, err
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil || !discordHosts[host] || !discordPath.MatchString(u.EscapedPath()) {
		return nil, "", nil, invalid
	}
	// thread_id posts into a thread of a forum or text channel; nothing else is accepted, so the
	// driver alone decides wait and the other execution options.
	for name, values := range query {
		if name != "thread_id" || len(values) != 1 || !decimalID.MatchString(values[0]) {
			return nil, "", nil, invalid
		}
	}
	return ports.DiscordChannelConfig{URL: u.String()}, maskedVendorURL(host), nil, nil
}

func validateTelegramChannel(in ChannelInput, _ bool) (ports.NotificationChannelConfig, string, []string, error) {
	token := strings.TrimSpace(in.Secret)
	chat := strings.TrimSpace(in.ChatID)
	if !telegramToken.MatchString(token) {
		// The message never echoes the token, even a malformed one.
		return nil, "", nil, fmt.Errorf("%w: Telegram channel requires a bot token from @BotFather", shared.ErrValidation)
	}
	if !telegramChat.MatchString(chat) {
		return nil, "", nil, fmt.Errorf("%w: Telegram chat ID must be a numeric ID or an @channel username", shared.ErrValidation)
	}
	if in.ThreadID < 0 || in.ThreadID > telegramMaxThreadID {
		return nil, "", nil, fmt.Errorf("%w: Telegram topic ID is out of range", shared.ErrValidation)
	}
	return ports.TelegramChannelConfig{BotToken: token, ChatID: chat, MessageThreadID: in.ThreadID}, maskedVendorURL(telegramAPIHost), nil, nil
}
