package fleetclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const telemetryGapMediaType = "application/vnd.synapse.telemetry-gap+json"

// TelemetryGapShipResponse acknowledges one stable local loss object. GapID is
// echoed by the server only after the signed report has passed validation and
// durable persistence; callers must match it before deleting the local journal.
type TelemetryGapShipResponse struct {
	Acknowledged bool      `json:"acknowledged"`
	GapID        shared.ID `json:"gap_id"`
}

// ShipTelemetryGap sends one purpose-bound signed durable-loss report over the
// authenticated telemetry endpoint with a distinct media type. HTTP gzip is
// transport-only: the Ed25519 signature commits to canonical report fields.
func (c *Client) ShipTelemetryGap(ctx context.Context, token string, report fleetagent.TelemetryGapReport) (TelemetryGapShipResponse, error) {
	var out TelemetryGapShipResponse
	if err := report.Validate(); err != nil {
		return out, err
	}
	body, err := json.Marshal(report)
	if err != nil {
		return out, fmt.Errorf("fleetclient: marshal telemetry gap: %w", err)
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(body); err != nil {
		_ = zw.Close()
		return out, fmt.Errorf("fleetclient: gzip telemetry gap: %w", err)
	}
	if err := zw.Close(); err != nil {
		return out, fmt.Errorf("fleetclient: gzip telemetry gap close: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/fleet/telemetry", bytes.NewReader(compressed.Bytes()))
	if err != nil {
		return out, fmt.Errorf("fleetclient: telemetry gap request: %w", err)
	}
	req.Header.Set(protoHeader, protoVersion)
	req.Header.Set("Content-Type", telemetryGapMediaType)
	req.Header.Set("Content-Encoding", "gzip")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return out, fmt.Errorf("fleetclient: telemetry gap: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		status := telemetryHTTPStatusError(resp)
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return out, status
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&out); err != nil {
		return out, fmt.Errorf("fleetclient: decode telemetry gap ack: %w", err)
	}
	if !out.Acknowledged || out.GapID.IsZero() {
		return out, fmt.Errorf("fleetclient: telemetry gap response is not an acknowledgement")
	}
	return out, nil
}
