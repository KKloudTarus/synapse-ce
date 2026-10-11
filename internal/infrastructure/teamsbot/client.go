// Package teamsbot talks to the Microsoft Bot Framework as the operator's Microsoft Teams bot
// (EPIC #1327, #1420): it gets a Bot Connector token with the bot's client credentials, sends
// activities into a 1:1 conversation, and verifies the JWT on activities Teams sends to the bot.
//
// The bot password is the credential. It is sent only in the token request body, never in a URL,
// and no error this package returns holds it or a token; a failure is a stable code.
package teamsbot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	// loginBase is the Microsoft identity platform. A single-tenant bot asks its own Entra tenant;
	// a multi-tenant bot asks botframework.com.
	loginBase = "https://login.microsoftonline.com"
	// connectorScope is the Bot Connector resource a token is requested for.
	connectorScope = "https://api.botframework.com/.default"
	// maxResponseBytes bounds a token or connector reply.
	maxResponseBytes = 64 << 10
)

// serviceHosts are the Bot Connector service URL hosts Teams uses for commercial, GCC, GCC High
// and DoD clouds. A conversation reference is only stored and used when its service URL is on one
// of them, so a forged activity cannot make the bot post its token to another host.
var serviceHosts = map[string]bool{
	"smba.trafficmanager.net":            true,
	"smba.infra.gcc.teams.microsoft.com": true,
	"smba.infra.gov.teams.microsoft.us":  true,
	"smba.infra.dod.teams.microsoft.us":  true,
}

// ValidServiceURL reports whether a service URL is an https Teams Bot Connector endpoint.
func ValidServiceURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(raw) > 512 {
		return false
	}
	if port := u.Port(); port != "" && port != "443" {
		return false
	}
	return serviceHosts[strings.ToLower(u.Hostname())]
}

// Config is the operator's bot registration.
type Config struct {
	AppID       string
	AppPassword string
	// TenantID is the Entra tenant of a single-tenant bot; empty uses botframework.com.
	TenantID string
}

// Enabled reports whether a bot is configured.
func (c Config) Enabled() bool { return c.AppID != "" && c.AppPassword != "" }

// Error is a failed Bot Framework call reduced to a stable code.
type Error struct {
	Code       string
	Status     int
	Retryable  bool
	RetryAfter time.Duration
}

func (e *Error) Error() string { return "teams bot: " + e.Code }

// Client sends activities as the bot.
type Client struct {
	cfg       Config
	http      *http.Client
	loginBase string
	now       func() time.Time
	// validService checks a conversation's service URL; tests point it at a fake connector.
	validService func(string) bool

	mu      sync.Mutex
	token   string
	expires time.Time
}

// New returns a client that reaches Microsoft through httpClient, which must be the SSRF-guarded
// client.
func New(cfg Config, httpClient *http.Client) *Client {
	return &Client{cfg: cfg, http: httpClient, loginBase: loginBase, now: time.Now, validService: ValidServiceURL}
}

// WithLoginBase returns a copy that asks another token endpoint origin. Tests use it.
func (c *Client) WithLoginBase(httpClient *http.Client, base string) *Client {
	return &Client{cfg: c.cfg, http: httpClient, loginBase: strings.TrimRight(base, "/"), now: c.now, validService: c.validService}
}

// accessToken returns a cached Bot Connector token, refreshing it five minutes before it expires.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Before(c.expires) {
		return c.token, nil
	}
	if !c.cfg.Enabled() {
		return "", &Error{Code: "teams_bot_not_configured"}
	}
	tenant := c.cfg.TenantID
	if tenant == "" {
		tenant = "botframework.com"
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.cfg.AppID},
		"client_secret": {c.cfg.AppPassword},
		"scope":         {connectorScope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.loginBase+"/"+url.PathEscape(tenant)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", &Error{Code: "request_invalid"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", transportError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode != http.StatusOK {
		// 400 and 401 mean the registration or password is wrong; nothing a retry fixes.
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return "", &Error{Code: "teams_token_" + strconv.Itoa(resp.StatusCode), Status: resp.StatusCode, Retryable: retryable}
	}
	var reply struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if json.Unmarshal(raw, &reply) != nil || reply.AccessToken == "" {
		return "", &Error{Code: "teams_token_invalid", Retryable: true}
	}
	lifetime := time.Duration(reply.ExpiresIn) * time.Second
	if lifetime <= 10*time.Minute {
		lifetime = 10 * time.Minute
	}
	c.token, c.expires = reply.AccessToken, c.now().Add(lifetime-5*time.Minute)
	return c.token, nil
}

// Send posts an activity (a message with text or an Adaptive Card) into a conversation and returns
// the created activity's ID.
func (c *Client) Send(ctx context.Context, ref ports.TeamsConversationRef, activity []byte) (string, error) {
	if !c.validService(ref.ServiceURL) || ref.ConversationID == "" || len(ref.ConversationID) > 512 {
		return "", &Error{Code: "teams_conversation_invalid"}
	}
	token, err := c.accessToken(ctx)
	if err != nil {
		return "", err
	}
	target := strings.TrimRight(ref.ServiceURL, "/") + "/v3/conversations/" + url.PathEscape(ref.ConversationID) + "/activities"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(activity))
	if err != nil {
		return "", &Error{Code: "request_invalid"}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "synapse-notifications/1")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", transportError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		var reply struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &reply)
		return reply.ID, nil
	case resp.StatusCode == http.StatusUnauthorized:
		// A rejected token is dropped so the next attempt asks for a fresh one.
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		return "", &Error{Code: "teams_401", Status: resp.StatusCode, Retryable: true}
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound:
		// The person removed the bot, or the conversation no longer exists.
		return "", &Error{Code: "teams_conversation_gone", Status: resp.StatusCode}
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 || resp.StatusCode == http.StatusRequestTimeout:
		return "", &Error{Code: "http_" + strconv.Itoa(resp.StatusCode), Status: resp.StatusCode, Retryable: true, RetryAfter: retryAfter(resp.Header.Get("Retry-After"))}
	default:
		return "", &Error{Code: "http_" + strconv.Itoa(resp.StatusCode), Status: resp.StatusCode}
	}
}

// AsError returns the bot error inside err.
func AsError(err error) *Error {
	var botErr *Error
	if errors.As(err, &botErr) {
		return botErr
	}
	return transportError(err)
}

func transportError(err error) *Error {
	if errors.Is(err, safehttp.ErrBlockedDestination) {
		return &Error{Code: "destination_blocked"}
	}
	return &Error{Code: "network_error", Retryable: true}
}

func retryAfter(v string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(min(seconds, 3600)) * time.Second
}

// TeamsResult implements ports.TeamsErrorCoder.
func (e *Error) TeamsResult() ports.NotificationSendResult {
	return ports.NotificationSendResult{ErrorCode: e.Code, StatusCode: e.Status, Retryable: e.Retryable, RetryAfter: e.RetryAfter}
}

var _ ports.TeamsBot = (*Client)(nil)
