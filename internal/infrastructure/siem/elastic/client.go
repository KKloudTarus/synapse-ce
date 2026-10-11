// Package elastic sends redacted batches with the Elasticsearch bulk API.
// A HTTP 200 response still carries per-item failures. The cursor may cross
// only the contiguous acknowledged prefix; this client reports each item and
// does not treat 409 as a duplicate success.
package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
)

// Client is an Elasticsearch bulk driver.
type Client struct {
	HTTP  *http.Client
	Guard func(host string) error
}

// New returns a client that dials through the shared safe HTTP guard.
func New(timeout time.Duration) *Client {
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 5 * time.Second
	}
	return &Client{HTTP: safehttp.New(timeout, false)}
}

// Deliver posts one bulk request to the configured normal index.
func (c *Client) Deliver(ctx context.Context, req siem.Delivery) (siem.DeliveryResult, error) {
	if c == nil || c.HTTP == nil {
		return siem.DeliveryResult{}, fmt.Errorf("elasticsearch client is not configured")
	}
	if req.AckMode != siem.AckBulkItem {
		return failedAll(len(req.Records), true, false, 0, "elasticsearch acknowledgement mode must be bulk item"), nil
	}
	if strings.ContainsAny(req.Target, "\r\n") || strings.Contains(req.Target, "/") || strings.HasPrefix(req.Target, "_") {
		return failedAll(len(req.Records), true, false, 0, "elasticsearch index name is invalid"), nil
	}
	endpoint, host, err := bulkURL(req.Origin, req.Target)
	if err != nil {
		return siem.DeliveryResult{}, err
	}
	if err := c.allow(host); err != nil {
		return failedAll(len(req.Records), true, false, 0, "destination host is blocked"), nil
	}
	body, err := encode(req.Target, req.Records)
	if err != nil {
		return failedAll(len(req.Records), true, false, 0, siem.SafeDiagnostic(err.Error())), nil
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return siem.DeliveryResult{}, err
	}
	httpReq.Header.Set("Authorization", "ApiKey "+req.Secret)
	httpReq.Header.Set("Content-Type", "application/x-ndjson")
	response, err := c.HTTP.Do(httpReq)
	if err != nil {
		return siem.DeliveryResult{}, err
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := readLimited(response.Body)
	if err != nil {
		return siem.DeliveryResult{}, err
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return failedAll(len(req.Records), true, false, 0, "redirects are not followed"), nil
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return failedAll(len(req.Records), false, true, retryAfter(response.Header), "elasticsearch returned "+strconv.Itoa(response.StatusCode)), nil
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return failedAll(len(req.Records), true, false, 0, "elasticsearch rejected the credential"), nil
	}
	if response.StatusCode != http.StatusOK {
		return failedAll(len(req.Records), true, false, 0, "elasticsearch rejected the batch"), nil
	}
	return parseItems(req.Records, payload)
}

func parseItems(records []siem.DeliveryRecord, payload []byte) (siem.DeliveryResult, error) {
	var parsed struct {
		Items []map[string]struct {
			ID     string `json:"_id"`
			Status int    `json:"status"`
			Error  any    `json:"error"`
		} `json:"items"`
	}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return siem.DeliveryResult{}, fmt.Errorf("elasticsearch response was malformed")
	}
	if len(parsed.Items) != len(records) {
		return siem.DeliveryResult{}, fmt.Errorf("elasticsearch response item count mismatched")
	}
	result := siem.DeliveryResult{Items: make([]siem.DeliveryItem, len(records))}
	for i, item := range parsed.Items {
		action, ok := item["index"]
		if !ok {
			return siem.DeliveryResult{}, fmt.Errorf("elasticsearch response item was misaligned")
		}
		if action.ID != "" && action.ID != records[i].ID {
			return siem.DeliveryResult{}, fmt.Errorf("elasticsearch response id mismatched")
		}
		switch {
		case action.Status == http.StatusOK || action.Status == http.StatusCreated:
			result.Items[i].Disposition = siem.ItemAcked
		case action.Status == http.StatusTooManyRequests || action.Status >= 500:
			result.Items[i] = siem.DeliveryItem{Disposition: siem.ItemFailed, Retryable: true, Diagnostic: "elasticsearch item was not stored"}
		default:
			// 409 is included. A conflict is not evidence the current
			// generation was stored.
			result.Items[i] = siem.DeliveryItem{Disposition: siem.ItemFailed, Blocked: action.Status < 500 && action.Status != http.StatusTooManyRequests, Diagnostic: "elasticsearch item failed"}
			if action.Status == http.StatusTooManyRequests {
				result.Items[i].Blocked = false
				result.Items[i].Retryable = true
			}
		}
	}
	return result, nil
}

func (c *Client) allow(host string) error {
	if c.Guard != nil {
		return c.Guard(host)
	}
	if siem.ForbiddenHost(host) {
		return fmt.Errorf("blocked")
	}
	return nil
}

func bulkURL(origin, index string) (string, string, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", "", fmt.Errorf("elasticsearch origin must be https without userinfo")
	}
	parsed.Path = "/" + index + "/_bulk"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), parsed.Hostname(), nil
}

func encode(index string, records []siem.DeliveryRecord) ([]byte, error) {
	var buf bytes.Buffer
	for _, record := range records {
		if bytes.Contains(record.Body, []byte("\n")) || !json.Valid(record.Body) {
			return nil, fmt.Errorf("record is not a single json object")
		}
		action, _ := json.Marshal(map[string]any{"index": map[string]string{"_index": index, "_id": record.ID}})
		buf.Write(action)
		buf.WriteByte('\n')
		buf.Write(record.Body)
		buf.WriteByte('\n')
	}
	if buf.Len() > siem.MaxBatchBytes {
		return nil, fmt.Errorf("batch exceeds the byte cap")
	}
	return buf.Bytes(), nil
}

func readLimited(body io.Reader) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(body, int64(siem.MaxResponseBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > siem.MaxResponseBytes {
		return nil, fmt.Errorf("elasticsearch response exceeded the byte cap")
	}
	return payload, nil
}

func retryAfter(header http.Header) time.Duration {
	seconds, err := strconv.Atoi(header.Get("Retry-After"))
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func failedAll(n int, blocked, retryable bool, after time.Duration, reason string) siem.DeliveryResult {
	items := make([]siem.DeliveryItem, n)
	for i := range items {
		items[i] = siem.DeliveryItem{Disposition: siem.ItemFailed, Blocked: blocked, Retryable: retryable, RetryAfter: after, Diagnostic: siem.SafeDiagnostic(reason)}
	}
	return siem.DeliveryResult{Items: items}
}
