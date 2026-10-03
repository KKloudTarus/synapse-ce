package notificationsender

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	testTelegramToken = "123456789:AAH-telegram-secret-token-0123456789ab"
	testChatSecret    = "s3cr3t-webhook-token-value"
)

// chatCase drives the four WS3 chat drivers through one fake server. config builds the channel
// configuration for the server's base URL; success is the body a real provider answers with.
type chatCase struct {
	kind    notification.ChannelType
	config  func(base string) ports.NotificationChannelConfig
	success string
	// path is the request path the driver must use against base.
	path string
}

var chatCases = []chatCase{
	{
		kind: notification.ChannelTeams,
		config: func(base string) ports.NotificationChannelConfig {
			return ports.TeamsChannelConfig{URL: base + "/workflows/abc?sig=" + testChatSecret}
		},
		success: "",
		path:    "/workflows/abc",
	},
	{
		kind: notification.ChannelTelegram,
		config: func(string) ports.NotificationChannelConfig {
			return ports.TelegramChannelConfig{BotToken: testTelegramToken, ChatID: "-1001234567890", MessageThreadID: 42}
		},
		success: `{"ok":true,"result":{"message_id":777}}`,
		path:    "/bot" + testTelegramToken + "/sendMessage",
	},
	{
		kind: notification.ChannelGoogleChat,
		config: func(base string) ports.NotificationChannelConfig {
			return ports.GoogleChatChannelConfig{URL: base + "/v1/spaces/AAA/messages?key=k&token=" + testChatSecret}
		},
		success: `{"name":"spaces/AAA/messages/BBB.CCC"}`,
		path:    "/v1/spaces/AAA/messages",
	},
	{
		kind: notification.ChannelDiscord,
		config: func(base string) ports.NotificationChannelConfig {
			return ports.DiscordChannelConfig{URL: base + "/api/webhooks/1/" + testChatSecret}
		},
		success: `{"id":"1234567890123"}`,
		path:    "/api/webhooks/1/" + testChatSecret,
	},
}

type chatServer struct {
	*httptest.Server
	body  []byte
	path  string
	query string
}

func newChatServer(t *testing.T, handler func(w http.ResponseWriter)) *chatServer {
	t.Helper()
	cs := &chatServer{}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.body, _ = io.ReadAll(r.Body)
		cs.path, cs.query = r.URL.Path, r.URL.RawQuery
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		handler(w)
	}))
	t.Cleanup(cs.Close)
	return cs
}

func chatSender(server *chatServer) *Sender {
	s := New(SMTPConfig{}, time.Second)
	s.http = server.Client()
	s.telegramAPI = server.URL
	return s
}

func TestChatDriversDeliverAndKeepTheProviderReference(t *testing.T) {
	wantRef := map[notification.ChannelType]string{
		notification.ChannelTeams:      "",
		notification.ChannelTelegram:   "777",
		notification.ChannelGoogleChat: "spaces/AAA/messages/BBB.CCC",
		notification.ChannelDiscord:    "1234567890123",
	}
	for _, tc := range chatCases {
		t.Run(string(tc.kind), func(t *testing.T) {
			server := newChatServer(t, func(w http.ResponseWriter) {
				if tc.success == "" {
					w.WriteHeader(http.StatusAccepted)
					return
				}
				_, _ = io.WriteString(w, tc.success)
			})
			result := chatSender(server).Send(context.Background(), testWork(tc.kind), tc.config(server.URL))
			if result.ErrorCode != "" || result.Retryable || result.RemoteRef != wantRef[tc.kind] {
				t.Fatalf("result = %+v", result)
			}
			if server.path != tc.path {
				t.Errorf("path = %q, want %q", server.path, tc.path)
			}
			if !json.Valid(server.body) {
				t.Fatalf("body is not JSON: %s", server.body)
			}
		})
	}
}

func TestChatDriversClassifyProviderFailures(t *testing.T) {
	for _, tc := range chatCases {
		for _, status := range []struct {
			code      int
			retryable bool
		}{{400, false}, {401, false}, {404, false}, {429, true}, {500, true}, {503, true}} {
			t.Run(fmt.Sprintf("%s/%d", tc.kind, status.code), func(t *testing.T) {
				server := newChatServer(t, func(w http.ResponseWriter) {
					if status.code == http.StatusTooManyRequests {
						w.Header().Set("Retry-After", "17")
					}
					w.WriteHeader(status.code)
					_, _ = io.WriteString(w, `{"ok":false,"description":"echo `+testChatSecret+`"}`)
				})
				result := chatSender(server).Send(context.Background(), testWork(tc.kind), tc.config(server.URL))
				if result.Retryable != status.retryable || result.ErrorCode != fmt.Sprintf("http_%d", status.code) || result.RemoteRef != "" {
					t.Fatalf("result = %+v", result)
				}
				if status.code == http.StatusTooManyRequests && result.RetryAfter != 17*time.Second {
					t.Errorf("retry after = %v, want 17s", result.RetryAfter)
				}
				assertNoSecret(t, result)
			})
		}
	}
}

func TestTelegramReadsRetryAfterFromTheBody(t *testing.T) {
	server := newChatServer(t, func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"ok":false,"error_code":429,"parameters":{"retry_after":23}}`)
	})
	result := chatSender(server).Send(context.Background(), testWork(notification.ChannelTelegram), chatCases[1].config(server.URL))
	if !result.Retryable || result.RetryAfter != 23*time.Second || result.ErrorCode != "http_429" {
		t.Fatalf("result = %+v", result)
	}
}

func TestDiscordReadsRetryAfterFromTheBodyWithoutHeader(t *testing.T) {
	server := newChatServer(t, func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"message":"You are being rate limited.","retry_after":2.4,"global":false}`)
	})
	result := chatSender(server).Send(context.Background(), testWork(notification.ChannelDiscord), chatCases[3].config(server.URL))
	if !result.Retryable || result.RetryAfter != 3*time.Second {
		t.Fatalf("result = %+v", result)
	}
}

func TestTelegramMigratedChatIsFinal(t *testing.T) {
	server := newChatServer(t, func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"ok":false,"error_code":400,"description":"Bad Request: group chat was upgraded to a supergroup chat","parameters":{"migrate_to_chat_id":-1009876543210}}`)
	})
	result := chatSender(server).Send(context.Background(), testWork(notification.ChannelTelegram), chatCases[1].config(server.URL))
	if result.Retryable || result.ErrorCode != codeTelegramChatMigrated {
		t.Fatalf("result = %+v", result)
	}
}

func TestTelegramSuccessWithoutOKIsRetried(t *testing.T) {
	server := newChatServer(t, func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"ok":false}`) })
	result := chatSender(server).Send(context.Background(), testWork(notification.ChannelTelegram), chatCases[1].config(server.URL))
	if !result.Retryable || result.ErrorCode != "telegram_not_ok" || result.RemoteRef != "" {
		t.Fatalf("result = %+v", result)
	}
}

func TestChatDriversIgnoreMalformedReferences(t *testing.T) {
	replies := map[notification.ChannelType]string{
		notification.ChannelGoogleChat: `{"name":"../../admin"}`,
		notification.ChannelDiscord:    `{"id":"<script>"}`,
		notification.ChannelTelegram:   `{"ok":true,"result":{"message_id":-3}}`,
	}
	for _, tc := range chatCases {
		reply, ok := replies[tc.kind]
		if !ok {
			continue
		}
		t.Run(string(tc.kind), func(t *testing.T) {
			server := newChatServer(t, func(w http.ResponseWriter) { _, _ = io.WriteString(w, reply) })
			result := chatSender(server).Send(context.Background(), testWork(tc.kind), tc.config(server.URL))
			if result.ErrorCode != "" || result.RemoteRef != "" {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestTelegramAddsTheChatAndTopic(t *testing.T) {
	server := newChatServer(t, func(w http.ResponseWriter) { _, _ = io.WriteString(w, chatCases[1].success) })
	chatSender(server).Send(context.Background(), testWork(notification.ChannelTelegram), chatCases[1].config(server.URL))
	var payload map[string]any
	if err := json.Unmarshal(server.body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["chat_id"] != "-1001234567890" || payload["message_thread_id"] != float64(42) || payload["parse_mode"] != "MarkdownV2" {
		t.Fatalf("payload = %v", payload)
	}
	if preview, _ := payload["link_preview_options"].(map[string]any); preview["is_disabled"] != true {
		t.Errorf("link previews are not disabled: %v", payload)
	}

	// Without a topic the field is absent, so Telegram posts to the main thread.
	cfg := chatCases[1].config(server.URL).(ports.TelegramChannelConfig)
	cfg.MessageThreadID = 0
	chatSender(server).Send(context.Background(), testWork(notification.ChannelTelegram), cfg)
	if strings.Contains(string(server.body), "message_thread_id") {
		t.Errorf("topic sent without one configured: %s", server.body)
	}
}

func TestDiscordWaitsAndNeverMentions(t *testing.T) {
	server := newChatServer(t, func(w http.ResponseWriter) { _, _ = io.WriteString(w, chatCases[3].success) })
	cfg := ports.DiscordChannelConfig{URL: server.URL + "/api/webhooks/1/" + testChatSecret + "?thread_id=99"}
	chatSender(server).Send(context.Background(), testWork(notification.ChannelDiscord), cfg)
	if server.query != "thread_id=99&wait=true" {
		t.Errorf("query = %q", server.query)
	}
	var payload struct {
		AllowedMentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
	}
	if err := json.Unmarshal(server.body, &payload); err != nil || payload.AllowedMentions.Parse == nil || len(payload.AllowedMentions.Parse) != 0 {
		t.Fatalf("allowed_mentions.parse must be an empty list: %s", server.body)
	}
}

// hostileWork carries every injection vector the WS3 evidence lists in its title and summary.
func hostileWork(kind notification.ChannelType) ports.NotificationWork {
	w := testWork(kind)
	hostile := "[Reset password](https://evil.example) @everyone <!channel> <users/all> **bold** <@U1>"
	w.Event.Data, _ = json.Marshal(map[string]string{"title": "Finding " + hostile, "summary": "Title: " + hostile})
	return w
}

func TestChatDriversSendHostileValuesAsLiteralText(t *testing.T) {
	// Each channel's own escaping of the markdown link. Teams has no markup in a TextRun, so the
	// raw text is right there; the other three must escape it.
	literalLink := map[notification.ChannelType][]string{
		notification.ChannelTeams:      {`"text":"Finding [Reset password](https://evil.example) @everyone \u003c!channel\u003e`},
		notification.ChannelTelegram:   {`\\[Reset password\\]\\(https://evil\\.example\\)`, `\\*\\*bold\\*\\*`},
		notification.ChannelGoogleChat: {`[Reset password](https://evil.example) @everyone \u0026lt;!channel\u0026gt; \u0026lt;users/all\u0026gt; **bold**`},
		notification.ChannelDiscord:    {`\\[Reset password\\]\\(https\\:\\/\\/evil\\.example\\)`, `\\@everyone`, `\\\u003c\\!channel\\\u003e`},
	}
	for _, tc := range chatCases {
		t.Run(string(tc.kind), func(t *testing.T) {
			server := newChatServer(t, func(w http.ResponseWriter) {
				if tc.success == "" {
					w.WriteHeader(http.StatusAccepted)
					return
				}
				_, _ = io.WriteString(w, tc.success)
			})
			if result := chatSender(server).Send(context.Background(), hostileWork(tc.kind), tc.config(server.URL)); result.ErrorCode != "" {
				t.Fatalf("result = %+v", result)
			}
			body := string(server.body)
			for _, want := range literalLink[tc.kind] {
				if !strings.Contains(body, want) {
					t.Errorf("payload lacks the literal form %s:\n%s", want, body)
				}
			}
			// No channel may carry the URL as a button or a link target. Teams TextRuns and Google
			// Chat card HTML do not read Markdown, so there the raw "[..](..)" is already literal;
			// Telegram and Discord parse it and must have escaped it.
			forbidden := []string{`"url":"https://evil.example"`, `Action.OpenUrl`, `openLink`, `href=`}
			if tc.kind == notification.ChannelTelegram || tc.kind == notification.ChannelDiscord {
				forbidden = append(forbidden, `](https://evil.example)`)
			}
			for _, forbidden := range forbidden {
				if strings.Contains(body, forbidden) {
					t.Errorf("payload carries %s as a link:\n%s", forbidden, body)
				}
			}
		})
	}
}

// assertNoSecret fails when the credential appears anywhere in what the driver returns, which is
// all the worker stores on the attempt and all the API ever shows of a send.
func assertNoSecret(t *testing.T, result ports.NotificationSendResult) {
	t.Helper()
	raw := fmt.Sprintf("%+v %#v", result, result)
	for _, secret := range []string{testTelegramToken, testChatSecret, "AAH-telegram"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("result leaks the credential: %s", raw)
		}
	}
}

func TestChatDriversNeverLeakTheCredentialOnTransportErrors(t *testing.T) {
	// A listener that is closed at once gives every dial a connection error whose text, in the
	// net/http client, holds the full request URL with the credential.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + listener.Addr().String()
	_ = listener.Close()
	for _, tc := range chatCases {
		t.Run(string(tc.kind), func(t *testing.T) {
			s := New(SMTPConfig{}, time.Second)
			s.http = &http.Client{Timeout: time.Second}
			s.telegramAPI = base
			result := s.Send(context.Background(), testWork(tc.kind), tc.config(base))
			if result.ErrorCode != "network_error" || !result.Retryable {
				t.Fatalf("result = %+v", result)
			}
			assertNoSecret(t, result)
		})
	}
}

func TestChatDriversNeverLeakTheCredentialOnBlockedDestinations(t *testing.T) {
	// The production client refuses loopback, the answer for a URL that resolves to an internal
	// address; the result is a stable code without the URL.
	for _, tc := range chatCases {
		t.Run(string(tc.kind), func(t *testing.T) {
			s := New(SMTPConfig{}, time.Second)
			s.telegramAPI = "https://127.0.0.1"
			result := s.Send(context.Background(), testWork(tc.kind), tc.config("https://127.0.0.1"))
			if result.ErrorCode != "destination_blocked" || result.Retryable {
				t.Fatalf("result = %+v", result)
			}
			assertNoSecret(t, result)
		})
	}
}

func TestChatDriversRefuseAMismatchedOrEmptyConfig(t *testing.T) {
	empty := map[notification.ChannelType]ports.NotificationChannelConfig{
		notification.ChannelTeams:      ports.TeamsChannelConfig{},
		notification.ChannelTelegram:   ports.TelegramChannelConfig{ChatID: "1"},
		notification.ChannelGoogleChat: ports.GoogleChatChannelConfig{},
		notification.ChannelDiscord:    ports.DiscordChannelConfig{},
	}
	s := New(SMTPConfig{}, time.Second)
	for kind, cfg := range empty {
		if result := s.Send(context.Background(), testWork(kind), cfg); result.ErrorCode != "channel_config_invalid" {
			t.Errorf("%s with empty config: %+v", kind, result)
		}
		if result := s.Send(context.Background(), testWork(kind), ports.SlackChannelConfig{URL: "https://hooks.slack.com/services/x"}); result.ErrorCode != "channel_config_invalid" {
			t.Errorf("%s with a Slack config: %+v", kind, result)
		}
	}
}

func TestChatDriversReportBuiltInContentAsFallback(t *testing.T) {
	for _, tc := range chatCases {
		t.Run(string(tc.kind), func(t *testing.T) {
			server := newChatServer(t, func(w http.ResponseWriter) { _, _ = io.WriteString(w, tc.success) })
			work := testWork(tc.kind)
			work.Event.Data = json.RawMessage(`{}`)
			result := chatSender(server).Send(context.Background(), work, tc.config(server.URL))
			if !result.TemplateFallback {
				t.Fatalf("result = %+v", result)
			}
			if !strings.Contains(string(server.body), "vulnerability_action.created") {
				t.Errorf("fallback content does not name the event type: %s", server.body)
			}
			if result = chatSender(server).Send(context.Background(), testWork(tc.kind), tc.config(server.URL)); result.TemplateFallback {
				t.Errorf("event with title and summary reported as fallback: %+v", result)
			}
		})
	}
}
