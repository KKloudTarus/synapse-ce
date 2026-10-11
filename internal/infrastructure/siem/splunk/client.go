// Package splunk sends redacted batches to a Splunk HTTP Event Collector.
// HTTP 200 is not success: the HEC code must be zero. Indexer acknowledgement
// is used only when the client was explicitly constructed with that capability.
package splunk

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

// Client is a Splunk HEC driver. Guard runs before any dial.
type Client struct {
	HTTP       *http.Client
	Guard      func(host string) error
	IndexerAck bool
}

// New returns a client that dials through the shared safe HTTP guard and
// does not follow redirects or use a proxy. Indexer acknowledgement stays
// off unless indexerAck is true; it is not inferred.
func New(timeout time.Duration, indexerAck bool) *Client {
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 5 * time.Second
	}
	return &Client{HTTP: safehttp.New(timeout, false), IndexerAck: indexerAck}
}

// Deliver posts one batch. A transport error is returned to the caller and
// acknowledges nothing. Item results are aligned with req.Records.
func (c *Client) Deliver(ctx context.Context, req siem.Delivery) (siem.DeliveryResult, error) {
	if c == nil || c.HTTP == nil {
		return siem.DeliveryResult{}, fmt.Errorf("splunk client is not configured")
	}
	if req.AckMode == siem.AckIndexer && !c.IndexerAck {
		return blocked(len(req.Records), "indexer acknowledgement was requested but this client is not configured for it"), nil
	}
	if req.AckMode != siem.AckHECAcceptance && req.AckMode != siem.AckIndexer {
		return blocked(len(req.Records), "splunk acknowledgement mode is not supported"), nil
	}
	endpoint, host, err := endpoint(req.Origin, req.Target, req.Channel, req.AckMode == siem.AckIndexer)
	if err != nil {
		return siem.DeliveryResult{}, err
	}
	if err := c.allow(host); err != nil {
		return blocked(len(req.Records), "destination host is blocked"), nil
	}
	body, err := encode(req.Records)
	if err != nil {
		return blocked(len(req.Records), siem.SafeDiagnostic(err.Error())), nil
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return siem.DeliveryResult{}, err
	}
	httpReq.Header.Set("Authorization", "Splunk "+req.Secret)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Splunk-Request-Channel", req.Channel)
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
		return blocked(len(req.Records), "redirects are not followed"), nil
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return retryAll(len(req.Records), retryAfter(response.Header), "splunk returned "+strconv.Itoa(response.StatusCode)), nil
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return blocked(len(req.Records), "splunk rejected the credential"), nil
	}
	if response.StatusCode != http.StatusOK {
		return blocked(len(req.Records), "splunk rejected the batch"), nil
	}
	var hec struct {
		Code  *int   `json:"code"`
		Text  string `json:"text"`
		AckID *int64 `json:"ackId"`
	}
	if err := json.Unmarshal(payload, &hec); err != nil {
		return siem.DeliveryResult{}, fmt.Errorf("splunk response was malformed")
	}
	if hec.Code == nil {
		return siem.DeliveryResult{}, fmt.Errorf("splunk response omitted the HEC code")
	}
	if *hec.Code != 0 {
		return blocked(len(req.Records), "hec code was not success"), nil
	}
	if req.AckMode == siem.AckIndexer {
		if hec.AckID == nil || *hec.AckID < 0 {
			return siem.DeliveryResult{}, fmt.Errorf("splunk response omitted a valid ack id")
		}
		return siem.DeliveryResult{IndexerAckID: hec.AckID}, nil
	}
	return acked(len(req.Records)), nil
}

// PollAck continues an already persisted HEC receipt without resending data.
func (c *Client) PollAck(ctx context.Context, req siem.Delivery, ackID int64) (bool, time.Duration, error) {
	_, host, err := endpoint(req.Origin, req.Target, req.Channel, true)
	if err != nil {
		return false, 0, err
	}
	pollURL, _, err := endpoint(req.Origin, "/services/collector/ack", req.Channel, true)
	if err != nil {
		return false, 0, err
	}
	if err := c.allow(host); err != nil {
		return false, 0, err
	}
	body, _ := json.Marshal(map[string]any{"acks": []int64{ackID}})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, pollURL, bytes.NewReader(body))
	if err != nil {
		return false, 0, err
	}
	httpReq.Header.Set("Authorization", "Splunk "+req.Secret)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Splunk-Request-Channel", req.Channel)
	response, err := c.HTTP.Do(httpReq)
	if err != nil {
		return false, 0, err
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := readLimited(response.Body)
	if err != nil {
		return false, 0, err
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return false, retryAfter(response.Header), nil
	}
	if response.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("splunk ack poll was rejected")
	}
	var parsed struct {
		Acks map[string]bool `json:"acks"`
	}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return false, 0, fmt.Errorf("splunk ack response was malformed")
	}
	return parsed.Acks[strconv.FormatInt(ackID, 10)], 0, nil
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

func endpoint(origin, path, channel string, withChannel bool) (string, string, error) {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", "", fmt.Errorf("splunk origin must be https without userinfo")
	}
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return "", "", fmt.Errorf("splunk path is invalid")
	}
	parsed.Path = path
	parsed.RawQuery = ""
	if withChannel {
		query := parsed.Query()
		query.Set("channel", channel)
		parsed.RawQuery = query.Encode()
	}
	return parsed.String(), parsed.Hostname(), nil
}

func encode(records []siem.DeliveryRecord) ([]byte, error) {
	var buf bytes.Buffer
	for _, record := range records {
		if bytes.Contains(record.Body, []byte("\n")) || !json.Valid(record.Body) {
			return nil, fmt.Errorf("record is not a single json object")
		}
		buf.WriteString(`{"event":`)
		buf.Write(record.Body)
		buf.WriteString(`,"sourcetype":"synapse:siem","fields":{"record_id":`)
		quoted, _ := json.Marshal(record.ID)
		buf.Write(quoted)
		buf.WriteString("}}\n")
	}
	if buf.Len() > siem.MaxBatchBytes {
		return nil, fmt.Errorf("batch exceeds the byte cap")
	}
	return buf.Bytes(), nil
}

func readLimited(body io.Reader) ([]byte, error) {
	limited := io.LimitReader(body, int64(siem.MaxResponseBytes)+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(payload) > siem.MaxResponseBytes {
		return nil, fmt.Errorf("splunk response exceeded the byte cap")
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

func blocked(n int, reason string) siem.DeliveryResult {
	return fill(n, siem.DeliveryItem{Disposition: siem.ItemFailed, Blocked: true, Diagnostic: siem.SafeDiagnostic(reason)})
}

func retryAll(n int, after time.Duration, reason string) siem.DeliveryResult {
	return fill(n, siem.DeliveryItem{Disposition: siem.ItemFailed, Retryable: true, RetryAfter: after, Diagnostic: siem.SafeDiagnostic(reason)})
}

func acked(n int) siem.DeliveryResult {
	return fill(n, siem.DeliveryItem{Disposition: siem.ItemAcked})
}

func fill(n int, item siem.DeliveryItem) siem.DeliveryResult {
	items := make([]siem.DeliveryItem, n)
	for i := range items {
		items[i] = item
	}
	return siem.DeliveryResult{Items: items}
}
