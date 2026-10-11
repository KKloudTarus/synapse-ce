// Package sentinel sends redacted SIEM batches to the Microsoft Sentinel backing
// Log Analytics workspace through the Azure Monitor Logs Ingestion API.
package sentinel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/KKloudTarus/synapse-ce/internal/domain/siem"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
)

const (
	defaultAuthority = "https://login.microsoftonline.com"
	monitorScope     = "https://monitor.azure.com/.default"
	apiVersion       = "2023-01-01"
	maxRequestBytes  = 1_000_000
)

// Client is a Microsoft Sentinel Logs Ingestion API driver. The Entra
// authority is package-private so production callers cannot redirect client
// credentials away from Microsoft's identity endpoint.
type Client struct {
	http               *http.Client
	guard              func(host string) error
	authority          string
	allowIngestionHost func(host string) bool
}

// New returns a client that dials through the shared SSRF guard, refuses
// redirects and proxies, verifies TLS certificates, and requires TLS 1.2+.
func New(timeout time.Duration) *Client {
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 5 * time.Second
	}
	client := safehttp.New(timeout, false)
	if transport, ok := client.Transport.(*http.Transport); ok {
		clone := transport.Clone()
		tlsConfig := clone.TLSClientConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		if tlsConfig.MinVersion < tls.VersionTLS12 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
		clone.TLSClientConfig = tlsConfig
		client.Transport = clone
	}
	return &Client{http: client, authority: defaultAuthority}
}

type credential struct {
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type remoteFailure struct {
	blocked    bool
	retryable  bool
	retryAfter time.Duration
	diagnostic string
}

// Deliver obtains a short-lived Entra token and posts one JSON array to the
// configured DCR stream. Only HTTP 204 is treated as accepted.
func (c *Client) Deliver(ctx context.Context, req siem.Delivery) (siem.DeliveryResult, error) {
	if c == nil || c.http == nil {
		return siem.DeliveryResult{}, fmt.Errorf("microsoft sentinel client is not configured")
	}
	if req.AckMode != siem.AckIngestionAcceptance {
		return failedAll(len(req.Records), true, false, 0, "microsoft sentinel acknowledgement mode must be ingestion acceptance"), nil
	}
	endpoint, host, err := ingestionURL(req.Origin, req.Target)
	if err != nil {
		return failedAll(len(req.Records), true, false, 0, "microsoft sentinel destination is invalid"), nil
	}
	if !c.validIngestionHost(host) || !c.validIngestionPort(req.Origin) {
		return failedAll(len(req.Records), true, false, 0, "microsoft sentinel destination must be an Azure Monitor ingestion endpoint on HTTPS port 443"), nil
	}
	if err := c.allow(host); err != nil {
		return failedAll(len(req.Records), true, false, 0, "destination host is blocked"), nil
	}
	body, err := encode(req.Records)
	if err != nil {
		return failedAll(len(req.Records), true, false, 0, siem.SafeDiagnostic(err.Error())), nil
	}
	cred, err := parseCredential(req.Secret)
	if err != nil {
		return failedAll(len(req.Records), true, false, 0, "microsoft sentinel credential is invalid"), nil
	}
	token, failure, err := c.accessToken(ctx, cred)
	if err != nil {
		return siem.DeliveryResult{}, err
	}
	if failure != nil {
		return failedAll(len(req.Records), failure.blocked, failure.retryable, failure.retryAfter, failure.diagnostic), nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return siem.DeliveryResult{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(httpReq)
	if err != nil {
		if errors.Is(err, safehttp.ErrBlockedDestination) {
			return failedAll(len(req.Records), true, false, 0, "destination address is blocked"), nil
		}
		return siem.DeliveryResult{}, err
	}
	defer func() { _ = response.Body.Close() }()
	if _, err := readLimited(response.Body); err != nil {
		return siem.DeliveryResult{}, err
	}
	switch {
	case response.StatusCode == http.StatusNoContent:
		return acked(len(req.Records)), nil
	case response.StatusCode >= 300 && response.StatusCode < 400:
		return failedAll(len(req.Records), true, false, 0, "redirects are not followed"), nil
	case response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500:
		return failedAll(len(req.Records), false, true, retryAfter(response.Header), "microsoft sentinel ingestion is temporarily unavailable"), nil
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return failedAll(len(req.Records), true, false, 0, "microsoft sentinel rejected the credential or DCR permission"), nil
	default:
		return failedAll(len(req.Records), true, false, 0, "microsoft sentinel rejected the batch"), nil
	}
}

func (c *Client) accessToken(ctx context.Context, cred credential) (string, *remoteFailure, error) {
	authority := strings.TrimSpace(c.authority)
	if authority == "" {
		authority = defaultAuthority
	}
	endpoint, host, err := tokenURL(authority, cred.TenantID)
	if err != nil {
		return "", &remoteFailure{blocked: true, diagnostic: "microsoft identity authority is invalid"}, nil
	}
	if err := c.allow(host); err != nil {
		return "", &remoteFailure{blocked: true, diagnostic: "identity host is blocked"}, nil
	}
	form := url.Values{}
	form.Set("client_id", cred.ClientID)
	form.Set("client_secret", cred.ClientSecret)
	form.Set("grant_type", "client_credentials")
	form.Set("scope", monitorScope)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", nil, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.http.Do(httpReq)
	if err != nil {
		if errors.Is(err, safehttp.ErrBlockedDestination) {
			return "", &remoteFailure{blocked: true, diagnostic: "identity address is blocked"}, nil
		}
		return "", nil, err
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := readLimited(response.Body)
	if err != nil {
		return "", nil, err
	}
	defer clear(payload)
	switch {
	case response.StatusCode >= 300 && response.StatusCode < 400:
		return "", &remoteFailure{blocked: true, diagnostic: "microsoft identity redirect was refused"}, nil
	case response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500:
		return "", &remoteFailure{retryable: true, retryAfter: retryAfter(response.Header), diagnostic: "microsoft identity is temporarily unavailable"}, nil
	case response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return "", &remoteFailure{blocked: true, diagnostic: "microsoft identity rejected the credential"}, nil
	case response.StatusCode != http.StatusOK:
		return "", &remoteFailure{blocked: true, diagnostic: "microsoft identity rejected the token request"}, nil
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(payload, &parsed); err != nil || strings.TrimSpace(parsed.AccessToken) == "" {
		return "", nil, fmt.Errorf("microsoft identity response was malformed")
	}
	if parsed.TokenType != "" && !strings.EqualFold(parsed.TokenType, "Bearer") {
		return "", nil, fmt.Errorf("microsoft identity returned an unsupported token type")
	}
	return parsed.AccessToken, nil, nil
}

// ValidateSecret rejects malformed Entra client credentials without returning
// any credential material. The service calls it before sealing configuration.
func (c *Client) ValidateSecret(secret string) error {
	_, err := parseCredential(secret)
	return err
}

func parseCredential(raw string) (credential, error) {
	var cred credential
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cred); err != nil {
		return credential{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return credential{}, fmt.Errorf("credential must contain one json object")
	}
	cred.TenantID = strings.TrimSpace(cred.TenantID)
	cred.ClientID = strings.TrimSpace(cred.ClientID)
	tenantID, err := uuid.Parse(cred.TenantID)
	if err != nil || tenantID == uuid.Nil {
		return credential{}, fmt.Errorf("tenant id is invalid")
	}
	clientID, err := uuid.Parse(cred.ClientID)
	if err != nil || clientID == uuid.Nil {
		return credential{}, fmt.Errorf("client id is invalid")
	}
	cred.TenantID = tenantID.String()
	cred.ClientID = clientID.String()
	if len(cred.ClientSecret) < 4 || len(cred.ClientSecret) > 4096 || strings.ContainsAny(cred.ClientSecret, "\r\n") {
		return credential{}, fmt.Errorf("client secret is invalid")
	}
	return cred, nil
}

func ingestionURL(origin, target string) (string, string, error) {
	dcr, stream, ok := strings.Cut(target, "/")
	if !ok || strings.Contains(stream, "/") || !validDCR(dcr) || !validStream(stream) {
		return "", "", fmt.Errorf("microsoft sentinel target is invalid")
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", fmt.Errorf("microsoft sentinel origin must be an https origin")
	}
	parsed.Path = "/dataCollectionRules/" + dcr + "/streams/" + stream
	parsed.RawQuery = url.Values{"api-version": []string{apiVersion}}.Encode()
	return parsed.String(), parsed.Hostname(), nil
}

func tokenURL(authority, tenantID string) (string, string, error) {
	parsed, err := url.Parse(authority)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", fmt.Errorf("microsoft identity authority must be an https origin")
	}
	parsed.Path = "/" + tenantID + "/oauth2/v2.0/token"
	return parsed.String(), parsed.Hostname(), nil
}

func validDCR(value string) bool {
	if len(value) != 36 || !strings.HasPrefix(value, "dcr-") {
		return false
	}
	for _, r := range value[4:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validStream(value string) bool {
	if !strings.HasPrefix(value, "Custom-") || len(value) <= len("Custom-") || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

type wireRecord struct {
	TimeGenerated  string          `json:"TimeGenerated"`
	RecordID       string          `json:"SynapseRecordId"`
	SourcePosition json.RawMessage `json:"SynapseSourcePosition"`
	SourceHash     string          `json:"SynapseSourceHash,omitempty"`
	Payload        json.RawMessage `json:"SynapsePayload"`
}

func encode(records []siem.DeliveryRecord) ([]byte, error) {
	out := make([]wireRecord, 0, len(records))
	for _, record := range records {
		if bytes.Contains(record.Body, []byte("\n")) || !json.Valid(record.Body) {
			return nil, fmt.Errorf("record is not a single json object")
		}
		generated, err := eventTime(record.Body)
		if err != nil {
			return nil, err
		}
		position, hash := sourceEvidence(record.Body)
		out = append(out, wireRecord{
			TimeGenerated:  generated.Format("2006-01-02T15:04:05.000000Z"),
			RecordID:       record.ID,
			SourcePosition: position,
			SourceHash:     hash,
			Payload:        json.RawMessage(append([]byte(nil), record.Body...)),
		})
	}
	body, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	if len(body) > maxRequestBytes {
		return nil, fmt.Errorf("batch exceeds the byte cap")
	}
	return body, nil
}

func eventTime(body []byte) (time.Time, error) {
	var doc struct {
		Time int64 `json:"time"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Time <= 0 {
		return time.Time{}, fmt.Errorf("record time is invalid")
	}
	return time.UnixMilli(doc.Time).UTC(), nil
}

func sourceEvidence(body []byte) (json.RawMessage, string) {
	empty := json.RawMessage(`{}`)
	var doc map[string]json.RawMessage
	if json.Unmarshal(body, &doc) != nil {
		return empty, ""
	}
	if raw := doc["source"]; len(raw) > 0 && json.Valid(raw) {
		var source map[string]json.RawMessage
		if json.Unmarshal(raw, &source) == nil {
			position := map[string]json.RawMessage{}
			if value := source["source"]; len(value) > 0 {
				position["source"] = value
			} else if value := source["kind"]; len(value) > 0 {
				position["source"] = value
			}
			for _, key := range []string{"id", "hash_version", "stream_seq", "incident_id", "event_seq"} {
				if value := source[key]; len(value) > 0 {
					position[key] = value
				}
			}
			for _, key := range []string{"incident_id", "event_seq"} {
				if _, exists := position[key]; exists {
					continue
				}
				if value := doc[key]; len(value) > 0 {
					position[key] = value
				}
			}
			if encoded, marshalErr := json.Marshal(position); marshalErr == nil {
				return encoded, rawString(source["source_hash"])
			}
		}
	}
	var unmapped map[string]json.RawMessage
	if json.Unmarshal(doc["unmapped"], &unmapped) != nil {
		return empty, ""
	}
	position := unmapped["synapse_source_position"]
	if len(position) == 0 || !json.Valid(position) {
		position = empty
	}
	return append(json.RawMessage(nil), position...), rawString(unmapped["synapse_source_hash"])
}

func rawString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

func (c *Client) validIngestionHost(host string) bool {
	if c.allowIngestionHost != nil {
		return c.allowIngestionHost(host)
	}
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	const suffix = ".ingest.monitor.azure.com"
	return len(name) > len(suffix) && strings.HasSuffix(name, suffix)
}

func (c *Client) validIngestionPort(origin string) bool {
	if c.allowIngestionHost != nil {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	port := parsed.Port()
	return port == "" || port == "443"
}

func (c *Client) allow(host string) error {
	if c.guard != nil {
		return c.guard(host)
	}
	if siem.ForbiddenHost(host) {
		return fmt.Errorf("blocked")
	}
	return nil
}

func readLimited(body io.Reader) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(body, int64(siem.MaxResponseBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > siem.MaxResponseBytes {
		return nil, fmt.Errorf("microsoft response exceeded the byte cap")
	}
	return payload, nil
}

func retryAfter(header http.Header) time.Duration {
	seconds, err := strconv.ParseInt(strings.TrimSpace(header.Get("Retry-After")), 10, 64)
	if err != nil || seconds <= 0 {
		return 0
	}
	maxSeconds := int64(siem.MaxRetry / time.Second)
	if seconds > maxSeconds {
		return siem.MaxRetry
	}
	return time.Duration(seconds) * time.Second
}

func acked(n int) siem.DeliveryResult {
	items := make([]siem.DeliveryItem, n)
	for i := range items {
		items[i].Disposition = siem.ItemAcked
	}
	return siem.DeliveryResult{Items: items}
}

func failedAll(n int, blocked, retryable bool, after time.Duration, reason string) siem.DeliveryResult {
	items := make([]siem.DeliveryItem, n)
	for i := range items {
		items[i] = siem.DeliveryItem{Disposition: siem.ItemFailed, Blocked: blocked, Retryable: retryable, RetryAfter: after, Diagnostic: siem.SafeDiagnostic(reason)}
	}
	return siem.DeliveryResult{Items: items}
}
