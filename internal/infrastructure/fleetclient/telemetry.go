package fleetclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// HostInventoryResponse returns the server-reconciled canonical asset identity. The
// agent persists this value and never substitutes its mutable name or AgentID for it.
type HostInventoryResponse struct {
	AssetID string `json:"asset_id"`
}

func (c *Client) SendHostInventoryResolved(ctx context.Context, token string, inv any) (HostInventoryResponse, error) {
	var out HostInventoryResponse
	err := c.do(ctx, http.MethodPost, "/api/v1/fleet/inventory/host", token, inv, &out)
	return out, err
}

// RegisterTelemetrySigningKey registers the telemetry-batch key through the canonical
// A0.2/A4 fleet key registry. The private key never crosses the API; proof is the
// purpose/agent/window-bound proof-of-possession produced by fleetagent.ProveKeyPossession.
func (c *Client) RegisterTelemetrySigningKey(ctx context.Context, token string, key fleetagent.AgentSigningKey, proof string) error {
	if err := key.Validate(); err != nil {
		return err
	}
	if key.Purpose != fleetagent.PurposeTelemetryBatch {
		return fmt.Errorf("fleetclient: telemetry registration requires purpose %q", fleetagent.PurposeTelemetryBatch)
	}
	body, err := json.Marshal(map[string]any{
		"public_key": base64.StdEncoding.EncodeToString(key.PublicKey),
		"purpose":    string(key.Purpose),
		"not_before": key.NotBefore,
		"not_after":  key.NotAfter,
		"proof":      proof,
	})
	if err != nil {
		return fmt.Errorf("fleetclient: marshal telemetry signing-key registration: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/fleet/keys", tokenBody(body))
	if err != nil {
		return fmt.Errorf("fleetclient: telemetry signing-key request: %w", err)
	}
	req.Header.Set(protoHeader, protoVersion)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("fleetclient: telemetry signing-key registration: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		status := telemetryHTTPStatusError(resp)
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return status
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return nil
}

func tokenBody(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// TelemetryEventPayload is the client-side wire mirror of telemetryingest.EventPayload.
// It intentionally keeps the canonical Go field names because the server currently decodes
// telemetryingest.IngestRequest directly.
type TelemetryEventPayload struct {
	EventID    shared.ID
	Class      detection.Class
	Payload    []byte
	ObservedAt time.Time
}

// TelemetryIngestRequest is the client-side wire mirror of telemetryingest.IngestRequest.
// Keeping this mirror in infrastructure avoids making the fleet client depend on a use-case package.
type TelemetryIngestRequest struct {
	Manifest fleetagent.TelemetryBatchManifest
	Events   []TelemetryEventPayload
}

// TelemetryShipResponse is the canonical #651 ingest response. ACK is the highest
// contiguous batch sequence for the stream incarnation represented by the request.
type TelemetryShipResponse struct {
	Accepted   bool   `json:"accepted"`
	Duplicate  bool   `json:"duplicate"`
	ACK        uint64 `json:"ack"`
	Provenance string `json:"provenance"`
	GapOpen    bool   `json:"gap_open"`
}

// HTTPStatusError preserves the status required by A2's retry policy without
// exposing or depending on server response text.
type HTTPStatusError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("fleetclient: telemetry status %d", e.StatusCode)
}

func (e *HTTPStatusError) Retryable() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

func telemetryHTTPStatusError(resp *http.Response) *HTTPStatusError {
	h := &HTTPStatusError{StatusCode: resp.StatusCode}
	if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds > 0 {
		h.RetryAfter = time.Duration(seconds) * time.Second
	}
	return h
}

// ShipTelemetry sends the canonical ingest request gzip-compressed. The manifest
// signature commits to the uncompressed event bytes; HTTP compression happens only
// after signing and therefore cannot change the transport commitment.
func (c *Client) ShipTelemetry(ctx context.Context, token string, in TelemetryIngestRequest) (TelemetryShipResponse, error) {
	var out TelemetryShipResponse
	body, err := json.Marshal(in)
	if err != nil {
		return out, fmt.Errorf("fleetclient: marshal telemetry: %w", err)
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(body); err != nil {
		_ = zw.Close()
		return out, fmt.Errorf("fleetclient: gzip telemetry: %w", err)
	}
	if err := zw.Close(); err != nil {
		return out, fmt.Errorf("fleetclient: gzip telemetry close: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/fleet/telemetry", bytes.NewReader(compressed.Bytes()))
	if err != nil {
		return out, fmt.Errorf("fleetclient: telemetry request: %w", err)
	}
	req.Header.Set(protoHeader, protoVersion)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return out, fmt.Errorf("fleetclient: telemetry: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h := telemetryHTTPStatusError(resp)
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return out, h
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&out); err != nil {
		return out, fmt.Errorf("fleetclient: decode telemetry ack: %w", err)
	}
	return out, nil
}

// BuildTelemetrySigningKey reconstructs the public lifecycle value from an agent's
// persisted private key and exact registration window.
func BuildTelemetrySigningKey(agentID string, private ed25519.PrivateKey, notBefore, notAfter time.Time) (fleetagent.AgentSigningKey, error) {
	if len(private) != ed25519.PrivateKeySize {
		return fleetagent.AgentSigningKey{}, fmt.Errorf("fleetclient: invalid telemetry private key")
	}
	pub, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return fleetagent.AgentSigningKey{}, fmt.Errorf("fleetclient: telemetry private key has no Ed25519 public key")
	}
	return fleetagent.NewSigningKey(shared.ID(agentID), fleetagent.PurposeTelemetryBatch, pub, notBefore, notAfter)
}
