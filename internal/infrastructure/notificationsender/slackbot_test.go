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
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const testSlackBotToken = "xoxb" + "-1111111111-2222222222-slackBOTsecretValue"

// slackServer is a fake Slack Web API: conversations.info answers info, chat.postMessage answers
// post. It records the methods called and the last posted body.
type slackServer struct {
	*httptest.Server
	mu      sync.Mutex
	methods []string
	posted  []byte
	auth    string
}

func newSlackServer(t *testing.T, info, post func(w http.ResponseWriter)) *slackServer {
	t.Helper()
	s := &slackServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := strings.TrimPrefix(r.URL.Path, "/api/")
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.methods = append(s.methods, method)
		s.auth = r.Header.Get("Authorization")
		if method == "chat.postMessage" {
			s.posted = body
		}
		s.mu.Unlock()
		switch method {
		case "conversations.info":
			info(w)
		case "chat.postMessage":
			post(w)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func slackSender(server *slackServer) *Sender {
	s := New(SMTPConfig{}, time.Second)
	s.http = server.Client()
	s.slack = s.slack.WithBase(server.Client(), server.URL+"/api")
	return s
}

func slackBotConfig() ports.SlackBotChannelConfig {
	return ports.SlackBotChannelConfig{BotToken: testSlackBotToken, ChannelID: "C0123456789", TeamID: "T0123"}
}

func replyJSON(body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { _, _ = io.WriteString(w, body) }
}

const (
	slackInfoPrivate = `{"ok":true,"channel":{"id":"C0123456789","name":"security","is_member":true}}`
	slackPostOK      = `{"ok":true,"channel":"C0123456789","ts":"1700000000.000100"}`
)

func TestSlackBotPostsToTheConversationWithoutUnfurling(t *testing.T) {
	server := newSlackServer(t, replyJSON(slackInfoPrivate), replyJSON(slackPostOK))
	result := slackSender(server).Send(context.Background(), testWork(notification.ChannelSlackBot), slackBotConfig())
	if result.ErrorCode != "" || result.Retryable || result.StatusCode != http.StatusOK || result.RemoteRef != "1700000000.000100" {
		t.Fatalf("result = %+v", result)
	}
	if strings.Join(server.methods, ",") != "conversations.info,chat.postMessage" {
		t.Fatalf("methods = %v", server.methods)
	}
	if server.auth != "Bearer "+testSlackBotToken {
		t.Fatalf("authorization = %q", server.auth)
	}
	var payload map[string]any
	if err := json.Unmarshal(server.posted, &payload); err != nil {
		t.Fatalf("payload is not JSON: %s", server.posted)
	}
	if payload["channel"] != "C0123456789" || payload["unfurl_links"] != false || payload["unfurl_media"] != false {
		t.Fatalf("payload = %s", server.posted)
	}
	if _, ok := payload["blocks"]; !ok {
		t.Fatalf("payload has no Block Kit blocks: %s", server.posted)
	}
	if _, threaded := payload["thread_ts"]; threaded {
		t.Fatalf("a channel post must not be a thread reply: %s", server.posted)
	}
	if strings.Contains(string(server.posted), testSlackBotToken) {
		t.Fatal("the token is in the message body")
	}
}

func TestSlackBotRefusesAConversationThatBecameShared(t *testing.T) {
	for _, flag := range []string{"is_shared", "is_ext_shared", "is_org_shared"} {
		t.Run(flag, func(t *testing.T) {
			server := newSlackServer(t, replyJSON(`{"ok":true,"channel":{"id":"C0123456789","`+flag+`":true}}`), replyJSON(slackPostOK))
			result := slackSender(server).Send(context.Background(), testWork(notification.ChannelSlackBot), slackBotConfig())
			if result.ErrorCode != codeSlackShared || result.Retryable {
				t.Fatalf("result = %+v", result)
			}
			if server.posted != nil {
				t.Fatal("the driver posted into a shared conversation")
			}
			if !notification.PermanentChannelFailure(result.ErrorCode) {
				t.Fatal("a shared conversation must count towards pausing the channel")
			}
		})
	}
}

func TestSlackBotSkipsTheSharingCheckWhenAllowed(t *testing.T) {
	server := newSlackServer(t, replyJSON(`{"ok":true,"channel":{"id":"C0123456789","is_ext_shared":true}}`), replyJSON(slackPostOK))
	cfg := slackBotConfig()
	cfg.AllowShared = true
	result := slackSender(server).Send(context.Background(), testWork(notification.ChannelSlackBot), cfg)
	if result.ErrorCode != "" || strings.Join(server.methods, ",") != "chat.postMessage" {
		t.Fatalf("result = %+v methods = %v", result, server.methods)
	}
}

func TestSlackBotClassifiesWebAPIErrors(t *testing.T) {
	cases := []struct {
		name      string
		info      func(http.ResponseWriter)
		post      func(http.ResponseWriter)
		code      string
		retryable bool
		permanent bool
		after     time.Duration
	}{
		{"revoked token", replyJSON(`{"ok":false,"error":"token_revoked"}`), replyJSON(slackPostOK), "slack_token_revoked", false, true, 0},
		{"channel gone", replyJSON(slackInfoPrivate), replyJSON(`{"ok":false,"error":"channel_not_found"}`), "slack_channel_not_found", false, true, 0},
		{"bot removed", replyJSON(slackInfoPrivate), replyJSON(`{"ok":false,"error":"not_in_channel"}`), "slack_not_in_channel", false, true, 0},
		{"archived", replyJSON(slackInfoPrivate), replyJSON(`{"ok":false,"error":"is_archived"}`), "slack_is_archived", false, true, 0},
		{"slack fault", replyJSON(slackInfoPrivate), replyJSON(`{"ok":false,"error":"internal_error"}`), "slack_internal_error", true, false, 0},
		{"rate limited", replyJSON(slackInfoPrivate), func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
		}, "slack_ratelimited", true, false, 7 * time.Second},
		{"gateway error", replyJSON(slackInfoPrivate), func(w http.ResponseWriter) { w.WriteHeader(http.StatusBadGateway) }, "http_502", true, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := newSlackServer(t, tc.info, tc.post)
			result := slackSender(server).Send(context.Background(), testWork(notification.ChannelSlackBot), slackBotConfig())
			if result.ErrorCode != tc.code || result.Retryable != tc.retryable || result.RetryAfter != tc.after {
				t.Fatalf("result = %+v, want %s retryable=%v after=%s", result, tc.code, tc.retryable, tc.after)
			}
			if notification.PermanentChannelFailure(result.ErrorCode) != tc.permanent {
				t.Fatalf("%s permanent = %v, want %v", result.ErrorCode, !tc.permanent, tc.permanent)
			}
			assertNoSlackToken(t, result)
		})
	}
}

func TestSlackBotSendsHostileValuesAsLiteralText(t *testing.T) {
	server := newSlackServer(t, replyJSON(slackInfoPrivate), replyJSON(slackPostOK))
	if result := slackSender(server).Send(context.Background(), hostileWork(notification.ChannelSlackBot), slackBotConfig()); result.ErrorCode != "" {
		t.Fatalf("result = %+v", result)
	}
	body := string(server.posted)
	// The fallback text is mrkdwn, so its control characters are escaped; the blocks carry the
	// values as rich_text elements, which Slack never parses.
	for _, want := range []string{`\u0026lt;!channel\u0026gt;`, `"type":"rich_text"`} {
		if !strings.Contains(body, want) {
			t.Errorf("payload lacks %s:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{`<!channel>`, `"url":"https://evil.example"`, `"type":"link"`} {
		if strings.Contains(body, forbidden) {
			t.Errorf("payload carries %s:\n%s", forbidden, body)
		}
	}
}

func TestSlackBotSendsTheRenderedPayload(t *testing.T) {
	server := newSlackServer(t, replyJSON(slackInfoPrivate), replyJSON(slackPostOK))
	work := testWork(notification.ChannelSlackBot)
	formatted, err := messageformat.Formatters()[notification.ChannelSlackBot].Format(ports.RenderedMessage{Fields: map[string]string{"title": "Rendered heading", "body": "Rendered text"}})
	if err != nil {
		t.Fatal(err)
	}
	work.Formatted = &formatted
	result := slackSender(server).Send(context.Background(), work, slackBotConfig())
	if result.ErrorCode != "" || result.TemplateFallback {
		t.Fatalf("result = %+v", result)
	}
	body := string(server.posted)
	if !strings.Contains(body, "Rendered heading") || !strings.Contains(body, `"channel":"C0123456789"`) || !strings.Contains(body, `"unfurl_links":false`) {
		t.Fatalf("body = %s", body)
	}
}

func TestSlackBotNeverLeaksTheTokenOnTransportErrors(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + listener.Addr().String()
	_ = listener.Close()
	s := New(SMTPConfig{}, time.Second)
	s.slack = s.slack.WithBase(&http.Client{Timeout: time.Second}, base+"/api")
	result := s.Send(context.Background(), testWork(notification.ChannelSlackBot), slackBotConfig())
	if result.ErrorCode != "network_error" || !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
	assertNoSlackToken(t, result)

	// The production client refuses loopback at dial time.
	blocked := New(SMTPConfig{}, time.Second)
	blocked.slack = blocked.slack.WithBase(blocked.http, "https://127.0.0.1/api")
	result = blocked.Send(context.Background(), testWork(notification.ChannelSlackBot), slackBotConfig())
	if result.ErrorCode != "destination_blocked" || result.Retryable {
		t.Fatalf("blocked result = %+v", result)
	}
	assertNoSlackToken(t, result)
}

func TestSlackBotRefusesAnIncompleteConfig(t *testing.T) {
	s := New(SMTPConfig{}, time.Second)
	for _, cfg := range []ports.NotificationChannelConfig{ports.SlackBotChannelConfig{ChannelID: "C0123456789"}, ports.SlackBotChannelConfig{BotToken: testSlackBotToken}, ports.SlackChannelConfig{URL: "https://hooks.slack.com/services/x"}} {
		if result := s.Send(context.Background(), testWork(notification.ChannelSlackBot), cfg); result.ErrorCode != "channel_config_invalid" {
			t.Fatalf("%T: result = %+v", cfg, result)
		}
	}
}

func assertNoSlackToken(t *testing.T, result ports.NotificationSendResult) {
	t.Helper()
	raw := fmt.Sprintf("%+v %#v", result, result)
	if strings.Contains(raw, testSlackBotToken) || strings.Contains(raw, "slackBOTsecret") {
		t.Fatalf("result leaks the token: %s", raw)
	}
}
