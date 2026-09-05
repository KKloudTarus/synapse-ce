// Package webhook delivers alerts as signed JSON POSTs to an operator-configured URL. The receiver
// verifies X-Synapse-Signature (HMAC-SHA256 over "<timestamp>.<body>" with the shared secret) and can
// reject replays by the timestamp. Delivery uses the SSRF-guarded client from safehttp: no redirects, and
// private or link-local destinations are refused unless the operator opts in for a loopback or in-network
// receiver.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/alerting"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	// attempts bounds retries on a transient failure (network error, 429, 5xx). A 4xx is final.
	attempts = 3
	// baseBackoff doubles per attempt: 200ms, 400ms.
	baseBackoff = 200 * time.Millisecond
	// maxResponse caps how much of an error body is read for the error message.
	maxResponse = 4 << 10
	userAgent   = "synapse-alerts/1"
)

// Sink posts alerts to one URL.
type Sink struct {
	url    string
	secret []byte
	client *http.Client
	sleep  func(context.Context, time.Duration) error
	now    func() time.Time
}

var _ ports.AlertSink = (*Sink)(nil)

// New validates the destination. The URL must be https, or http to a loopback host; a secret, when set,
// must be at least 16 bytes so the signature is worth verifying. allowPrivate lets the client dial
// private and link-local addresses (an in-network receiver); it is off in production.
func New(rawURL, secret string, timeout time.Duration, allowPrivate bool) (*Sink, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%w: alert webhook url is not a valid absolute URL", shared.ErrValidation)
	}
	loopback := isLoopbackHost(u.Hostname())
	switch u.Scheme {
	case "https":
	case "http":
		if !loopback {
			return nil, fmt.Errorf("%w: alert webhook must use https (http is allowed only for a loopback host)", shared.ErrValidation)
		}
	default:
		return nil, fmt.Errorf("%w: alert webhook scheme %q is not http or https", shared.ErrValidation, u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: alert webhook url must not carry credentials", shared.ErrValidation)
	}
	if secret != "" && len(secret) < 16 {
		return nil, fmt.Errorf("%w: alert webhook secret must be at least 16 bytes", shared.ErrValidation)
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	// The SSRF-guarded client refuses loopback by design (it exists for untrusted source URLs). A loopback
	// receiver is a development posture the scheme rule above already restricts to http://127.0.0.1 or
	// localhost, so it gets a plain client with the same timeout and the same no-redirect policy.
	client := safehttp.New(timeout, allowPrivate)
	if loopback {
		client = &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &Sink{
		url:    u.String(),
		secret: []byte(secret),
		client: client,
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
		now: time.Now,
	}, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Name identifies the sink in audit entries.
func (s *Sink) Name() string { return "webhook" }

type envelope struct {
	Type   alerting.Kind  `json:"type"`
	SentAt time.Time      `json:"sent_at"`
	Alert  alerting.Alert `json:"alert"`
}

// Deliver posts the alert, retrying transient failures. A 2xx response is an acknowledgement.
func (s *Sink) Deliver(ctx context.Context, a alerting.Alert) error {
	body, err := json.Marshal(envelope{Type: a.Kind, SentAt: s.now().UTC(), Alert: a})
	if err != nil {
		return fmt.Errorf("encode alert: %w", err)
	}
	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if err := s.sleep(ctx, baseBackoff<<(attempt-1)); err != nil {
				return fmt.Errorf("%w (last attempt: %v)", err, last)
			}
		}
		final, err := s.post(ctx, a, body)
		if err == nil {
			return nil
		}
		last = err
		if final {
			break
		}
	}
	return last
}

// post performs one delivery. final reports whether the failure must not be retried.
func (s *Sink) post(ctx context.Context, a alerting.Alert, body []byte) (final bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return true, fmt.Errorf("build alert request: %w", err)
	}
	ts := strconv.FormatInt(s.now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-Synapse-Alert-Kind", string(a.Kind))
	req.Header.Set("X-Synapse-Alert-ID", a.ID.String())
	req.Header.Set("X-Synapse-Timestamp", ts)
	if len(s.secret) > 0 {
		req.Header.Set("X-Synapse-Signature", "sha256="+Sign(s.secret, ts, body))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		// *url.Error prints the request URL, and for Slack-style hooks the URL path is the credential.
		// Keep the transport cause and drop the URL before it reaches an audit entry.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return false, fmt.Errorf("deliver alert: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
		return true, nil
	}
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	err = fmt.Errorf("alert webhook responded %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return false, err
	}
	return true, err
}

// Sign computes the hex HMAC-SHA256 the receiver verifies: key = secret, message = timestamp + "." + body.
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify is the receiver-side check for a signature header value ("sha256=<hex>").
func Verify(secret []byte, timestamp string, body []byte, header string) bool {
	want := "sha256=" + Sign(secret, timestamp, body)
	return hmac.Equal([]byte(want), []byte(header))
}
