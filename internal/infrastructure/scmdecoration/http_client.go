package scmdecoration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultResponseBodyLimit int64 = 2 << 20
	defaultRetryAttempts           = 3
	defaultRetryCap                = 30 * time.Second
)

type jsonHTTPClient struct {
	client      *http.Client
	baseURL     string
	responseCap int64
	maxAttempts int
	retryCap    time.Duration
	sleep       func(context.Context, time.Duration) error
}

func newJSONHTTPClient(client *http.Client, baseURL string) *jsonHTTPClient {
	return &jsonHTTPClient{
		client: client, baseURL: strings.TrimRight(baseURL, "/"), responseCap: defaultResponseBodyLimit,
		maxAttempts: defaultRetryAttempts, retryCap: defaultRetryCap, sleep: sleepContext,
	}
}

// doJSON sends one bounded JSON request. safeRetry allows retries after network/408/5xx failures only
// for operations whose semantics are idempotent. A 429, or a 403 identified as GitHub rate limiting,
// is safe to retry for every method because GitHub rejected the request before accepting the write.
func (c *jsonHTTPClient) doJSON(ctx context.Context, method, path string, headers http.Header, input, output any, safeRetry bool) error {
	if c == nil || c.client == nil || c.baseURL == "" || !strings.HasPrefix(path, "/") {
		return fmt.Errorf("invalid forge HTTP client request")
	}
	var payload []byte
	var err error
	if input != nil {
		payload, err = json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode forge request: %w", err)
		}
	}
	attempts := c.maxAttempts
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 0; attempt < attempts; attempt++ {
		req, reqErr := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(payload))
		if reqErr != nil {
			return fmt.Errorf("build forge request: %w", reqErr)
		}
		for key, values := range headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
		if input != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, doErr := c.client.Do(req)
		if doErr != nil {
			if !safeRetry || attempt+1 >= attempts {
				return fmt.Errorf("forge request failed: %w", doErr)
			}
			if err := c.wait(ctx, attempt, "", ""); err != nil {
				return err
			}
			continue
		}

		body, readErr := readBounded(resp.Body, c.responseCap)
		_ = resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if output != nil && len(bytes.TrimSpace(body)) > 0 {
				if err := json.Unmarshal(body, output); err != nil {
					return fmt.Errorf("decode forge response: %w", err)
				}
			}
			return nil
		}

		retryAfter := resp.Header.Get("Retry-After")
		remaining := strings.TrimSpace(resp.Header.Get("X-RateLimit-Remaining"))
		reset := resp.Header.Get("X-RateLimit-Reset")
		rateLimited := resp.StatusCode == http.StatusTooManyRequests ||
			(resp.StatusCode == http.StatusForbidden && (retryAfter != "" || remaining == "0"))
		transient := resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500
		if attempt+1 < attempts && (rateLimited || (safeRetry && transient)) {
			if err := c.wait(ctx, attempt, retryAfter, reset); err != nil {
				return err
			}
			continue
		}
		return fmt.Errorf("forge API %s %s returned HTTP %d", method, path, resp.StatusCode)
	}
	return fmt.Errorf("forge request exhausted retries")
}

func readBounded(r io.Reader, capBytes int64) ([]byte, error) {
	if capBytes <= 0 {
		capBytes = defaultResponseBodyLimit
	}
	body, err := io.ReadAll(io.LimitReader(r, capBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read forge response: %w", err)
	}
	if int64(len(body)) > capBytes {
		return nil, fmt.Errorf("forge response exceeds %d-byte limit", capBytes)
	}
	return body, nil
}

func (c *jsonHTTPClient) wait(ctx context.Context, attempt int, retryAfter, rateLimitReset string) error {
	now := time.Now()
	delay := parseRetryAfter(retryAfter, now, c.retryCap)
	if delay <= 0 {
		delay = parseRateLimitReset(rateLimitReset, now, c.retryCap)
	}
	if delay <= 0 {
		delay = 200 * time.Millisecond * time.Duration(1<<attempt)
		if c.retryCap > 0 && delay > c.retryCap {
			delay = c.retryCap
		}
	}
	if c.sleep == nil {
		c.sleep = sleepContext
	}
	return c.sleep(ctx, delay)
}

func parseRetryAfter(raw string, now time.Time, capDelay time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	var delay time.Duration
	if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 0 {
		delay = time.Duration(seconds) * time.Second
	} else if when, err := http.ParseTime(raw); err == nil {
		delay = when.Sub(now)
	}
	return capRetryDelay(delay, capDelay)
}

func parseRateLimitReset(raw string, now time.Time, capDelay time.Duration) time.Duration {
	seconds, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || seconds <= 0 {
		return 0
	}
	return capRetryDelay(time.Unix(seconds, 0).Sub(now), capDelay)
}

func capRetryDelay(delay, capDelay time.Duration) time.Duration {
	if delay < 0 {
		delay = 0
	}
	if capDelay > 0 && delay > capDelay {
		delay = capDelay
	}
	return delay
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
