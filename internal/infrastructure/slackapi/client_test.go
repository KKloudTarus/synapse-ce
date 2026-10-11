package slackapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testToken = "xoxb" + "-1234567890-0987654321-secretSECRETsecret"

// fakeSlack answers Web API methods from a table and records every request it saw.
type fakeSlack struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
	answer   func(method string, r *http.Request) (int, string, http.Header)
}

func newFakeSlack(t *testing.T, answer func(method string, r *http.Request) (int, string, http.Header)) (*fakeSlack, *Client) {
	t.Helper()
	f := &fakeSlack{answer: answer}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.requests = append(f.requests, r)
		f.bodies = append(f.bodies, string(raw))
		f.mu.Unlock()
		status, body, header := f.answer(strings.TrimPrefix(r.URL.Path, "/api/"), r)
		for k, v := range header {
			w.Header()[k] = v
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return f, New(nil).WithBase(server.Client(), server.URL+"/api")
}

func TestTokenTravelsOnlyInTheAuthorizationHeader(t *testing.T) {
	f, c := newFakeSlack(t, func(string, *http.Request) (int, string, http.Header) {
		return 200, `{"ok":true,"channel":{"id":"C0123456789","name":"sec"}}`, nil
	})
	if _, err := c.ConversationInfo(context.Background(), testToken, "C0123456789"); err != nil {
		t.Fatal(err)
	}
	r := f.requests[0]
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		t.Fatalf("authorization header = %q", r.Header.Get("Authorization"))
	}
	if strings.Contains(r.URL.String(), testToken) {
		t.Fatal("the token is in the request URL")
	}
	if r.URL.Query().Get("channel") != "C0123456789" {
		t.Fatalf("channel query = %q", r.URL.Query().Get("channel"))
	}
}

func TestAuthTestRequiresABotToken(t *testing.T) {
	_, c := newFakeSlack(t, func(string, *http.Request) (int, string, http.Header) {
		return 200, `{"ok":true,"team_id":"T1","team":"Acme","user_id":"U1"}`, nil
	})
	if _, err := c.AuthTest(context.Background(), testToken); AsError(err).Code != "not_a_bot_token" {
		t.Fatalf("user token: err = %v", err)
	}
	_, c = newFakeSlack(t, func(string, *http.Request) (int, string, http.Header) {
		return 200, `{"ok":true,"team_id":"T1","team":"Acme","user_id":"U1","bot_id":"B1"}`, nil
	})
	id, err := c.AuthTest(context.Background(), testToken)
	if err != nil || id.TeamID != "T1" || id.TeamName != "Acme" || id.BotUserID != "U1" {
		t.Fatalf("identity = %+v, %v", id, err)
	}
}

func TestErrorsAreStableCodesWithoutTheToken(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		header    http.Header
		code      string
		retryable bool
		after     time.Duration
	}{
		{"slack error", 200, `{"ok":false,"error":"channel_not_found"}`, nil, "channel_not_found", false, 0},
		{"retryable slack error", 200, `{"ok":false,"error":"internal_error"}`, nil, "internal_error", true, 0},
		{"rate limited", 429, ``, http.Header{"Retry-After": {"30"}}, "ratelimited", true, 30 * time.Second},
		{"rate limit capped", 429, ``, http.Header{"Retry-After": {"999999"}}, "ratelimited", true, time.Hour},
		{"server error", 503, `oops`, nil, "http_503", true, 0},
		{"client error", 404, `nope`, nil, "http_404", false, 0},
		{"hostile error text", 200, `{"ok":false,"error":"` + testToken + ` <script>"}`, nil, "slack_error", false, 0},
		{"not json", 200, `<html>`, nil, "invalid_reply", true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, c := newFakeSlack(t, func(string, *http.Request) (int, string, http.Header) {
				return tc.status, tc.body, tc.header
			})
			_, err := c.PostMessage(context.Background(), testToken, []byte(`{}`))
			got := AsError(err)
			if got.Code != tc.code || got.Retryable != tc.retryable || got.RetryAfter != tc.after {
				t.Fatalf("error = %+v, want code %s retryable %v after %s", got, tc.code, tc.retryable, tc.after)
			}
			if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "http://") {
				t.Fatalf("error leaks the token or URL: %v", err)
			}
		})
	}
}

func TestTransportFailureNeverLeaksTheToken(t *testing.T) {
	c := New(&http.Client{Timeout: time.Second}).WithBase(&http.Client{Timeout: time.Second}, "http://127.0.0.1:1/api")
	_, err := c.PostMessage(context.Background(), testToken, []byte(`{}`))
	got := AsError(err)
	if got.Code != "network_error" || !got.Retryable || strings.Contains(err.Error(), testToken) {
		t.Fatalf("error = %+v (%v)", got, err)
	}
	if _, err := c.PostMessage(context.Background(), "", []byte(`{}`)); AsError(err).Code != "not_authed" {
		t.Fatalf("empty token: %v", err)
	}
}

func TestListConversationsFollowsTheCursorWithinABound(t *testing.T) {
	pages := 0
	f, c := newFakeSlack(t, func(_ string, r *http.Request) (int, string, http.Header) {
		pages++
		reply := map[string]any{"ok": true, "channels": []map[string]any{{"id": "C00000000" + string(rune('0'+pages%10)), "name": "c"}}, "response_metadata": map[string]any{"next_cursor": "next"}}
		if r.URL.Query().Get("types") != "public_channel,private_channel" || r.URL.Query().Get("exclude_archived") != "true" {
			return 400, "", nil
		}
		raw, _ := json.Marshal(reply)
		return 200, string(raw), nil
	})
	items, truncated, err := c.ListConversations(context.Background(), testToken)
	if err != nil || !truncated || len(items) != maxConversationPages || len(f.requests) != maxConversationPages {
		t.Fatalf("items=%d truncated=%v requests=%d err=%v", len(items), truncated, len(f.requests), err)
	}
	if f.requests[1].URL.Query().Get("cursor") != "next" {
		t.Fatal("the second page did not send the cursor")
	}
}

func TestListConversationsStopsAtTheLastPage(t *testing.T) {
	_, c := newFakeSlack(t, func(string, *http.Request) (int, string, http.Header) {
		return 200, `{"ok":true,"channels":[{"id":"C0123456789","name":"sec","is_ext_shared":true}],"response_metadata":{"next_cursor":""}}`, nil
	})
	items, truncated, err := c.ListConversations(context.Background(), testToken)
	if err != nil || truncated || len(items) != 1 || !items[0].SharedAnyway() {
		t.Fatalf("items=%+v truncated=%v err=%v", items, truncated, err)
	}
}

func TestPostMessageSendsJSONAndReturnsTheTimestamp(t *testing.T) {
	f, c := newFakeSlack(t, func(method string, r *http.Request) (int, string, http.Header) {
		if method != "chat.postMessage" || r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			return 400, "", nil
		}
		return 200, `{"ok":true,"ts":"1700000000.000100"}`, nil
	})
	ts, err := c.PostMessage(context.Background(), testToken, []byte(`{"channel":"C0123456789"}`))
	if err != nil || ts != "1700000000.000100" {
		t.Fatalf("ts=%q err=%v", ts, err)
	}
	if f.bodies[0] != `{"channel":"C0123456789"}` {
		t.Fatalf("body = %s", f.bodies[0])
	}
}

func TestOpenDMAndUserInfo(t *testing.T) {
	f, c := newFakeSlack(t, func(method string, r *http.Request) (int, string, http.Header) {
		switch method {
		case "conversations.open":
			return 200, `{"ok":true,"channel":{"id":"D0123456789"}}`, nil
		case "users.info":
			return 200, `{"ok":true,"user":{"id":"U0123456789","team_id":"T1","is_restricted":true}}`, nil
		}
		return 404, "", nil
	})
	dm, err := c.OpenDM(context.Background(), testToken, "U0123456789")
	if err != nil || dm != "D0123456789" {
		t.Fatalf("dm=%q err=%v", dm, err)
	}
	if !strings.Contains(f.bodies[0], `"users":"U0123456789"`) {
		t.Fatalf("open body = %s", f.bodies[0])
	}
	user, err := c.UserInfo(context.Background(), testToken, "U0123456789")
	if err != nil || user.TeamID != "T1" || !user.Restricted || user.Deleted {
		t.Fatalf("user=%+v err=%v", user, err)
	}
}

func TestWorkspaceAdapterMapsSharing(t *testing.T) {
	_, c := newFakeSlack(t, func(method string, _ *http.Request) (int, string, http.Header) {
		switch method {
		case "auth.test":
			return 200, `{"ok":true,"team_id":"T1","team":"Acme","user_id":"U1","bot_id":"B1"}`, nil
		case "conversations.info":
			return 200, `{"ok":true,"channel":{"id":"C0123456789","name":"sec","is_org_shared":true,"is_member":true}}`, nil
		}
		return 200, `{"ok":false,"error":"invalid_auth"}`, nil
	})
	w := Workspace{Client: c}
	id, err := w.Identify(context.Background(), testToken)
	if err != nil || id.TeamID != "T1" {
		t.Fatalf("identify = %+v, %v", id, err)
	}
	conv, err := w.Conversation(context.Background(), testToken, "C0123456789")
	if err != nil || !conv.Shared || !conv.Member {
		t.Fatalf("conversation = %+v, %v", conv, err)
	}
	_, _, err = w.Conversations(context.Background(), testToken)
	if err == nil || AsError(err).SlackCode() != "invalid_auth" {
		t.Fatalf("conversations error = %v", err)
	}
}
