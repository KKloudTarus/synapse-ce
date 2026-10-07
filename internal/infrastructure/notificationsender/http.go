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
	resp, err := s.http.Do(req)
	if errors.Is(err, safehttp.ErrBlockedDestination) {
		// Retrying cannot change the answer; the destination has to be corrected.
		return ports.NotificationSendResult{ErrorCode: "destination_blocked"}, nil
	}
	if err != nil {
		return ports.NotificationSendResult{ErrorCode: "network_error", Retryable: true}, nil
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	return s.classify(resp), body
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
