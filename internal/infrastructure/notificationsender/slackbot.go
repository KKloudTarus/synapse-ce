package notificationsender

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/slackapi"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// slackBotDriver posts as a Slack app with chat.postMessage (#1383). The payload is the same Block
// Kit message the incoming-webhook driver sends, plus the conversation and unfurl_links and
// unfurl_media set to false, so a link in a finding title never expands into a preview.
//
// Before posting, the driver reads the conversation again unless an administrator allowed shared
// conversations: a channel that became Slack Connect or organisation-shared after it was saved is
// refused with slack_conversation_shared, a final failure the administrator has to resolve. The
// message's ts becomes the RemoteRef, so a later event about the same subject can thread under it
// (#1384).
type slackBotDriver struct{ s *Sender }

func (slackBotDriver) ChannelType() notification.ChannelType { return notification.ChannelSlackBot }

// codeSlackShared is the final failure of a post into a shared conversation that is not allowed.
const codeSlackShared = "slack_conversation_shared"

func (d slackBotDriver) Send(ctx context.Context, w ports.NotificationWork, config ports.NotificationChannelConfig) ports.NotificationSendResult {
	cfg, ok := config.(ports.SlackBotChannelConfig)
	if !ok || cfg.BotToken == "" || cfg.ChannelID == "" {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	formatted, fallback, ok := formatChat(w, slackBotFormatter)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "format_failed", TemplateFallback: fallback}
	}
	if !cfg.AllowShared {
		conversation, err := d.s.slack.ConversationInfo(ctx, cfg.BotToken, cfg.ChannelID)
		if err != nil {
			result := slackResult(err)
			result.TemplateFallback = fallback
			return result
		}
		if conversation.SharedAnyway() {
			return ports.NotificationSendResult{ErrorCode: codeSlackShared, TemplateFallback: fallback}
		}
	}
	result := d.s.postSlack(ctx, cfg.BotToken, cfg.ChannelID, "", formatted)
	result.TemplateFallback = fallback
	return result
}

// postSlack sends a formatted Block Kit message to one conversation (a channel, or the DM opened
// for a person by #1419), optionally as a reply in the thread of threadTS.
func (s *Sender) postSlack(ctx context.Context, token, conversation, threadTS string, formatted []byte) ports.NotificationSendResult {
	// The formatter owns the blocks and their escaping; the conversation and the unfurl switches
	// belong to the driver.
	var payload map[string]any
	if err := json.Unmarshal(formatted, &payload); err != nil {
		return ports.NotificationSendResult{ErrorCode: "format_failed"}
	}
	payload["channel"] = conversation
	payload["unfurl_links"] = false
	payload["unfurl_media"] = false
	if threadTS != "" {
		payload["thread_ts"] = threadTS
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "encode_failed"}
	}
	ts, err := s.slack.PostMessage(ctx, token, body)
	if err != nil {
		return slackResult(err)
	}
	return ports.NotificationSendResult{StatusCode: http.StatusOK, RemoteRef: ts}
}

// slackResult reduces a Web API error to the attempt's result. Slack's own error strings become
// slack_<error>; transport codes (network_error, destination_blocked, http_<n>) stay as the other
// HTTP drivers record them, so channel health classifies them the same way.
func slackResult(err error) ports.NotificationSendResult {
	slackErr := slackapi.AsError(err)
	code := slackErr.Code
	switch {
	case code == "network_error" || code == "destination_blocked" || code == "invalid_reply":
	case len(code) > 5 && code[:5] == "http_":
	default:
		code = "slack_" + code
	}
	return ports.NotificationSendResult{ErrorCode: code, StatusCode: slackErr.Status, Retryable: slackErr.Retryable, RetryAfter: slackErr.RetryAfter}
}

var _ ports.SlackDirectSender = (*Sender)(nil)

// SendSlackDirect posts a personal message as the Slack app's direct message to one member (#1419).
// conversations.open returns the app's DM with the member; the message ts is the RemoteRef.
func (s *Sender) SendSlackDirect(ctx context.Context, token, member string, formatted []byte) ports.NotificationSendResult {
	if token == "" || member == "" || len(formatted) == 0 {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	dm, err := s.slack.OpenDM(ctx, token, member)
	if err != nil {
		return slackResult(err)
	}
	return s.postSlack(ctx, token, dm, "", formatted)
}
