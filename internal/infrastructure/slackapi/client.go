// Package slackapi is a small client for the Slack Web API methods Synapse uses as a Slack app:
// auth.test, conversations.info, conversations.list and chat.postMessage (EPIC #1327, #1383).
//
// The bot token is the credential. It travels only in the Authorization header, never in a URL,
// and no error this package returns contains it: a failure is reduced to a stable code (Slack's
// own error string, an HTTP status or "network_error"), which is all a caller may store or log.
package slackapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
)

// DefaultBase is the Web API origin. Slack serves every workspace's Web API on slack.com, so the
// client never takes a host from a tenant; only tests point it elsewhere.
const DefaultBase = "https://slack.com/api"

// maxResponseBytes bounds a Web API reply. A conversations.list page of 200 channels stays well
// under it; anything larger is not read.
const maxResponseBytes = 1 << 20

// maxConversationPages bounds conversations.list pagination: 10 pages of 200 is 2,000 channels.
const maxConversationPages = 10

// Error is a failed Web API call. Code is Slack's error string ("channel_not_found"), "http_<n>"
// for a non-2xx reply without one, or "network_error"; it never holds the token or a URL.
type Error struct {
	Code       string
	Status     int
	Retryable  bool
	RetryAfter time.Duration
}

func (e *Error) Error() string { return "slack api: " + e.Code }

// AsError returns the Slack error inside err, or a generic network error.
func AsError(err error) *Error {
	var slackErr *Error
	if errors.As(err, &slackErr) {
		return slackErr
	}
	if errors.Is(err, safehttp.ErrBlockedDestination) {
		return &Error{Code: "destination_blocked"}
	}
	return &Error{Code: "network_error", Retryable: true}
}

// retryableCodes are Slack errors that a later attempt can succeed past. Every other error string
// (invalid_auth, channel_not_found, not_in_channel, is_archived, …) needs an administrator.
var retryableCodes = map[string]bool{
	"ratelimited":         true,
	"internal_error":      true,
	"fatal_error":         true,
	"service_unavailable": true,
	"request_timeout":     true,
}

// safeCode keeps an error string from a reply only when it looks like a Slack error identifier, so
// a hostile or broken reply cannot put arbitrary text into an attempt row.
var safeCode = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// Client calls the Web API through a guarded HTTP client.
type Client struct {
	http *http.Client
	base string
}

// New returns a client on DefaultBase. httpClient must be the SSRF-guarded client (safehttp).
func New(httpClient *http.Client) *Client {
	return &Client{http: httpClient, base: DefaultBase}
}

// WithBase returns a copy that calls base instead of DefaultBase. Tests use it for a fake server.
func (c *Client) WithBase(httpClient *http.Client, base string) *Client {
	return &Client{http: httpClient, base: strings.TrimRight(base, "/")}
}

// Identity is the workspace and bot user a token belongs to.
type Identity struct {
	TeamID    string
	TeamName  string
	BotUserID string
}

// Conversation is the part of a conversation object Synapse reads.
type Conversation struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Private   bool   `json:"is_private"`
	Shared    bool   `json:"is_shared"`
	ExtShared bool   `json:"is_ext_shared"`
	OrgShared bool   `json:"is_org_shared"`
	Archived  bool   `json:"is_archived"`
	Member    bool   `json:"is_member"`
}

// AuthTest identifies the token's workspace and bot user.
func (c *Client) AuthTest(ctx context.Context, token string) (Identity, error) {
	var reply struct {
		TeamID string `json:"team_id"`
		Team   string `json:"team"`
		UserID string `json:"user_id"`
		BotID  string `json:"bot_id"`
	}
	if err := c.call(ctx, token, "auth.test", nil, nil, &reply); err != nil {
		return Identity{}, err
	}
	if reply.TeamID == "" {
		return Identity{}, &Error{Code: "invalid_reply"}
	}
	// A user token also passes auth.test; only a bot token has a bot_id.
	if reply.BotID == "" {
		return Identity{}, &Error{Code: "not_a_bot_token"}
	}
	return Identity{TeamID: reply.TeamID, TeamName: reply.Team, BotUserID: reply.UserID}, nil
}

// ConversationInfo reads one conversation.
func (c *Client) ConversationInfo(ctx context.Context, token, channel string) (Conversation, error) {
	var reply struct {
		Channel Conversation `json:"channel"`
	}
	if err := c.call(ctx, token, "conversations.info", url.Values{"channel": {channel}}, nil, &reply); err != nil {
		return Conversation{}, err
	}
	if reply.Channel.ID == "" {
		return Conversation{}, &Error{Code: "invalid_reply"}
	}
	return reply.Channel, nil
}

// ListConversations lists the public channels and the private channels the bot is in, without
// archived ones, up to maxConversationPages pages. truncated reports that more pages remained.
func (c *Client) ListConversations(ctx context.Context, token string) (items []Conversation, truncated bool, err error) {
	cursor := ""
	for page := 0; page < maxConversationPages; page++ {
		params := url.Values{"types": {"public_channel,private_channel"}, "exclude_archived": {"true"}, "limit": {"200"}}
		if cursor != "" {
			params.Set("cursor", cursor)
		}
		var reply struct {
			Channels []Conversation `json:"channels"`
			Metadata struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if err := c.call(ctx, token, "conversations.list", params, nil, &reply); err != nil {
			return nil, false, err
		}
		items = append(items, reply.Channels...)
		cursor = reply.Metadata.NextCursor
		if cursor == "" {
			return items, false, nil
		}
	}
	return items, true, nil
}

// OpenDM opens (or returns) the app's direct-message conversation with one user. Posting to the
// returned ID puts the message in the user's DM with the app.
func (c *Client) OpenDM(ctx context.Context, token, user string) (string, error) {
	var reply struct {
		Channel struct {
			ID string `json:"id"`
		} `json:"channel"`
	}
	body, err := json.Marshal(map[string]any{"users": user, "return_im": false})
	if err != nil {
		return "", &Error{Code: "encode_failed"}
	}
	if err := c.call(ctx, token, "conversations.open", nil, body, &reply); err != nil {
		return "", err
	}
	if reply.Channel.ID == "" {
		return "", &Error{Code: "invalid_reply"}
	}
	return reply.Channel.ID, nil
}

// User is the part of a user object Synapse reads.
type User struct {
	ID       string `json:"id"`
	TeamID   string `json:"team_id"`
	Deleted  bool   `json:"deleted"`
	IsBot    bool   `json:"is_bot"`
	IsAppBot bool   `json:"is_app_user"`
	// Restricted users are guests; they are allowed, but the console says so.
	Restricted bool `json:"is_restricted"`
}

// UserInfo reads one member of the token's workspace.
func (c *Client) UserInfo(ctx context.Context, token, user string) (User, error) {
	var reply struct {
		User User `json:"user"`
	}
	if err := c.call(ctx, token, "users.info", url.Values{"user": {user}}, nil, &reply); err != nil {
		return User{}, err
	}
	if reply.User.ID == "" {
		return User{}, &Error{Code: "invalid_reply"}
	}
	return reply.User, nil
}

// PostMessage calls chat.postMessage with a JSON payload the caller built and returns the
// message's ts, which identifies it for threaded replies.
func (c *Client) PostMessage(ctx context.Context, token string, payload []byte) (string, error) {
	var reply struct {
		TS string `json:"ts"`
	}
	if err := c.call(ctx, token, "chat.postMessage", nil, payload, &reply); err != nil {
		return "", err
	}
	return reply.TS, nil
}

// call runs one Web API method. A GET carries params as the query; a POST carries body as JSON.
// Both send the token as a bearer header.
func (c *Client) call(ctx context.Context, token, method string, params url.Values, body []byte, out any) error {
	if token == "" {
		return &Error{Code: "not_authed"}
	}
	target := c.base + "/" + method
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
		}
	} else {
		if len(params) > 0 {
			target += "?" + params.Encode()
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	}
	if err != nil {
		return &Error{Code: "request_invalid"}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "synapse-notifications/1")
	resp, err := c.http.Do(req)
	if err != nil {
		// The error text holds the request URL; only a code leaves this function.
		if errors.Is(err, safehttp.ErrBlockedDestination) {
			return &Error{Code: "destination_blocked"}
		}
		return &Error{Code: "network_error", Retryable: true}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode == http.StatusTooManyRequests {
		return &Error{Code: "ratelimited", Status: resp.StatusCode, Retryable: true, RetryAfter: retryAfter(resp.Header.Get("Retry-After"))}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retryable := resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500
		return &Error{Code: "http_" + strconv.Itoa(resp.StatusCode), Status: resp.StatusCode, Retryable: retryable}
	}
	var envelope struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return &Error{Code: "invalid_reply", Status: resp.StatusCode, Retryable: true}
	}
	if !envelope.OK {
		code := envelope.Error
		if !safeCode.MatchString(code) {
			code = "slack_error"
		}
		return &Error{Code: code, Status: resp.StatusCode, Retryable: retryableCodes[code]}
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return &Error{Code: "invalid_reply", Status: resp.StatusCode}
	}
	return nil
}

func retryAfter(v string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(min(seconds, 3600)) * time.Second
}

// SlackCode implements ports.SlackErrorCoder.
func (e *Error) SlackCode() string { return e.Code }

// SharedAnyway reports whether people outside the workspace, or in other workspaces of the same
// organisation, can read the conversation: Slack Connect, externally shared or org-shared.
func (c Conversation) SharedAnyway() bool { return c.Shared || c.ExtShared || c.OrgShared }
