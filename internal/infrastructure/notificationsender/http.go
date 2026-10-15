package notificationsender

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// do sends an HTTP request through the guarded client and classifies the response the same way
// for every HTTP driver: 2xx is delivered, 408, 429 and 5xx are retried, anything else is final.
func (s *Sender) do(req *http.Request) ports.NotificationSendResult {
	result, _ := s.doRead(req)
	return result
}

// maxResponseBytes bounds how much of a response body is read: enough for a provider's JSON reply
// (a message ID, a retry hint), never an unbounded download.
const maxResponseBytes = 4 << 10

// doRead is do that also returns up to maxResponseBytes of the response body, for drivers that read
// the provider's reply. Transport errors are reduced to a code here and never returned: the error
// of a failed request holds the request URL, which for the chat channels is the credential.
func (s *Sender) doRead(req *http.Request) (ports.NotificationSendResult, []byte) {
	result, body, _ := s.doReadLimit(req, maxResponseBytes)
	return result, body
}

// doReadLimit is doRead with a caller-chosen bound on the body. truncated reports that the body was
// not read whole, because it was longer than limit or the connection failed mid-body, so a driver that
// decodes the reply can tell a reply cut short here from one the provider sent malformed.
func (s *Sender) doReadLimit(req *http.Request, limit int64) (result ports.NotificationSendResult, body []byte, truncated bool) {
	resp, err := s.http.Do(req)
	if errors.Is(err, safehttp.ErrBlockedDestination) {
		// Retrying cannot change the answer; the destination has to be corrected.
		return ports.NotificationSendResult{ErrorCode: "destination_blocked"}, nil, false
	}
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "network_error", Retryable: true}, nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	// One byte past the limit is enough to know the body did not fit.
	body, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(body)) > limit {
		return s.classify(resp), body[:limit], true
	}
	return s.classify(resp), body, err != nil
}

func (s *Sender) classify(resp *http.Response) ports.NotificationSendResult {
	result := ports.NotificationSendResult{StatusCode: resp.StatusCode}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return result
	}
	switch {
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		result.Retryable = true
		result.ErrorCode = "http_" + strconv.Itoa(resp.StatusCode)
		if resp.StatusCode == http.StatusTooManyRequests {
			result.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), s.now())
		}
	default:
		result.ErrorCode = "http_" + strconv.Itoa(resp.StatusCode)
	}
	return result
}

func parseRetryAfter(v string, now time.Time) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && seconds > 0 {
		return time.Duration(min(seconds, 3600)) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}
