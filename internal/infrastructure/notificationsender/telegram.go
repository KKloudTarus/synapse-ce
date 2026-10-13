package notificationsender

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// telegramDriver calls the Bot API sendMessage method (#1379) with MarkdownV2 text from the
// formatter, the channel's chat and, when set, its forum topic.
//
// The bot token is a path segment of the request URL ("/bot<token>/sendMessage"), so the URL is
// never placed in a result, an error or a log line. The reply's message_id becomes the RemoteRef,
// which a later event about the same subject can reply to (#1384).
type telegramDriver struct{ s *Sender }

func (telegramDriver) ChannelType() notification.ChannelType { return notification.ChannelTelegram }

// telegramAPIBase is the Bot API origin. Tests point a Sender at a fake server instead.
const telegramAPIBase = "https://api.telegram.org"

// codeTelegramChatMigrated is the final error of a group that became a supergroup: Telegram
// answers with the new chat ID, and an administrator has to re-enter the channel with it.
const codeTelegramChatMigrated = "telegram_chat_migrated"

// A 2xx whose reply cannot be read is final, not retried: Telegram answers 2xx only for a message it
// posted, so a retry would post it again (#1553). The delivery fails without a remote reference.
const (
	// codeTelegramResponseTooLarge is a 2xx reply longer than telegramMaxResponseBytes, or one the
	// connection cut off before its end.
	codeTelegramResponseTooLarge = "telegram_response_too_large"
	// codeTelegramResponseInvalid is a whole 2xx reply that is not a Bot API JSON object.
	codeTelegramResponseInvalid = "telegram_response_invalid"
)

// telegramMaxResponseBytes bounds a sendMessage reply. A successful reply echoes the sent Message:
// up to 4096 UTF-16 code units of text, which the Bot API may escape to six bytes each, its entities,
// and, for a follow-up, the message it replies to. That is well over maxResponseBytes, so a valid
// reply to a long or non-Latin message would be cut short; 1 MiB holds the largest with a wide margin
// and is still never an unbounded download.
const telegramMaxResponseBytes = 1 << 20

// telegramReply is the Bot API envelope. ok is a pointer so a missing or null ok is told apart from
// an explicit false. result and parameters stay raw and are decoded on their own, so an optional
// field of an unexpected type (a string message_id) never hides an ok:true.
type telegramReply struct {
	OK         *bool           `json:"ok"`
	Result     json.RawMessage `json:"result"`
	Parameters json.RawMessage `json:"parameters"`
}

type telegramMessage struct {
	MessageID int64 `json:"message_id"`
}

type telegramParameters struct {
	RetryAfter      int   `json:"retry_after"`
	MigrateToChatID int64 `json:"migrate_to_chat_id"`
}

func (d telegramDriver) Send(ctx context.Context, w ports.NotificationWork, config ports.NotificationChannelConfig) ports.NotificationSendResult {
	cfg, ok := config.(ports.TelegramChannelConfig)
	if !ok || cfg.BotToken == "" || cfg.ChatID == "" {
		return ports.NotificationSendResult{ErrorCode: "channel_config_invalid"}
	}
	formatted, fallback, ok := formatChat(w, telegramFormatter)
	if !ok {
		return ports.NotificationSendResult{ErrorCode: "format_failed", TemplateFallback: fallback}
	}
	// The formatter owns the text and its escaping; the chat and topic are channel configuration.
	var payload map[string]any
	if err := json.Unmarshal(formatted, &payload); err != nil {
		return ports.NotificationSendResult{ErrorCode: "format_failed", TemplateFallback: fallback}
	}
	payload["chat_id"] = cfg.ChatID
	if cfg.MessageThreadID > 0 {
		payload["message_thread_id"] = cfg.MessageThreadID
	}
	if messageID, err := strconv.ParseInt(w.SubjectAnchor, 10, 64); err == nil && messageID > 0 {
		// The old message may have been deleted. Telegram then creates a new root message,
		// rather than failing a notification whose provider reference is stale.
		payload["reply_parameters"] = map[string]any{
			"message_id":                  messageID,
			"allow_sending_without_reply": true,
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "encode_failed", TemplateFallback: fallback}
	}
	result, raw, truncated := d.s.postChatLimit(ctx, d.s.telegramAPI+"/bot"+cfg.BotToken+"/sendMessage", body, telegramMaxResponseBytes)
	result.TemplateFallback = fallback
	var reply telegramReply
	decodeErr := json.Unmarshal(raw, &reply)
	var params telegramParameters
	_ = json.Unmarshal(reply.Parameters, &params)
	switch {
	case result.ErrorCode == "" && truncated:
		// Only part of the reply was read, so ok and message_id are unknown, not false.
		result.ErrorCode, result.Retryable = codeTelegramResponseTooLarge, false
	case result.ErrorCode == "" && (decodeErr != nil || reply.OK == nil):
		// Not a Bot API envelope: null, {}, an ok that is missing, null or not a boolean.
		result.ErrorCode, result.Retryable = codeTelegramResponseInvalid, false
	case result.ErrorCode == "" && !*reply.OK:
		// A 2xx with an explicit ok:false is not a delivered message; retrying is the safe reading.
		result.ErrorCode, result.Retryable = "telegram_not_ok", true
	case result.ErrorCode == "":
		// ok:true is the delivery. The message ID is only a threading reference (#1384), so one that
		// is missing, not a positive integer or out of range leaves the delivery without it.
		var message telegramMessage
		if json.Unmarshal(reply.Result, &message) == nil && message.MessageID > 0 {
			result.RemoteRef = strconv.FormatInt(message.MessageID, 10)
		}
	case params.MigrateToChatID != 0:
		result.ErrorCode, result.Retryable = codeTelegramChatMigrated, false
	case result.StatusCode == http.StatusTooManyRequests && params.RetryAfter > 0:
		// Telegram sends the wait in the body, not in a Retry-After header.
		result.RetryAfter = time.Duration(min(params.RetryAfter, 3600)) * time.Second
	}
	return result
}
