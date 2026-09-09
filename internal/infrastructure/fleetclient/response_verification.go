package fleetclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const responseVerificationMediaType = "application/vnd.synapse.response-verification+json"

type ResponseVerificationShipResponse struct {
	Acknowledged bool      `json:"acknowledged"`
	ReportID     shared.ID `json:"report_id"`
}

// ShipResponseVerification sends one purpose-signed P0 post-condition report and requires an exact ACK.
func (c *Client) ShipResponseVerification(ctx context.Context, token string, report fleetagent.ResponseVerificationReport) (ResponseVerificationShipResponse, error) {
	var out ResponseVerificationShipResponse
	body, err := json.Marshal(report)
	if err != nil {
		return out, fmt.Errorf("fleetclient: marshal response verification: %w", err)
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(body); err != nil {
		_ = zw.Close()
		return out, fmt.Errorf("fleetclient: gzip response verification: %w", err)
	}
	if err := zw.Close(); err != nil {
		return out, fmt.Errorf("fleetclient: gzip response verification close: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/fleet/response-verifications", bytes.NewReader(compressed.Bytes()))
	if err != nil {
		return out, fmt.Errorf("fleetclient: response verification request: %w", err)
	}
	req.Header.Set(protoHeader, protoVersion)
	req.Header.Set("Content-Type", responseVerificationMediaType)
	req.Header.Set("Content-Encoding", "gzip")
	c.setAuthorization(req, token, false)
	resp, err := c.http.Do(req)
	if err != nil {
		return out, fmt.Errorf("fleetclient: response verification: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		statusErr := telemetryHTTPStatusError(resp)
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return out, statusErr
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&out); err != nil {
		return out, fmt.Errorf("fleetclient: decode response verification ack: %w", err)
	}
	if !out.Acknowledged || out.ReportID != report.ReportID {
		return out, fmt.Errorf("fleetclient: response verification acknowledgement does not match report %q", report.ReportID)
	}
	return out, nil
}

func BuildResponseResultSigningKey(agentID string, private ed25519.PrivateKey, notBefore, notAfter time.Time) (fleetagent.AgentSigningKey, error) {
	if len(private) != ed25519.PrivateKeySize {
		return fleetagent.AgentSigningKey{}, fmt.Errorf("fleetclient: invalid response-result private key")
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return fleetagent.AgentSigningKey{}, fmt.Errorf("fleetclient: response-result private key has no Ed25519 public key")
	}
	return fleetagent.NewSigningKey(shared.ID(agentID), fleetagent.PurposeResponseResult, public, notBefore, notAfter)
}
