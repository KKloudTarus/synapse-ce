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

type telegramReply struct {
	OK     bool `json:"ok"`
	Result struct {
		MessageID int64 `json:"message_id"`
	} `json:"result"`
	Parameters struct {
		RetryAfter      int   `json:"retry_after"`
		MigrateToChatID int64 `json:"migrate_to_chat_id"`
	} `json:"parameters"`
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
	body, err := json.Marshal(payload)
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "encode_failed", TemplateFallback: fallback}
	}
	result, raw := d.s.postChat(ctx, d.s.telegramAPI+"/bot"+cfg.BotToken+"/sendMessage", body)
	result.TemplateFallback = fallback
	var reply telegramReply
	_ = json.Unmarshal(raw, &reply)
	switch {
	case result.ErrorCode == "" && !reply.OK:
		// A 2xx without ok:true is not a delivered message; retrying is the safe reading.
		result.ErrorCode, result.Retryable = "telegram_not_ok", true
	case result.ErrorCode == "":
		if reply.Result.MessageID > 0 {
			result.RemoteRef = strconv.FormatInt(reply.Result.MessageID, 10)
		}
	case reply.Parameters.MigrateToChatID != 0:
		result.ErrorCode, result.Retryable = codeTelegramChatMigrated, false
	case result.StatusCode == http.StatusTooManyRequests && reply.Parameters.RetryAfter > 0:
		// Telegram sends the wait in the body, not in a Retry-After header.
		result.RetryAfter = time.Duration(min(reply.Parameters.RetryAfter, 3600)) * time.Second
	}
	return result
}
