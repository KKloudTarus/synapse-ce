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

const sensorStateMediaType = "application/vnd.synapse.sensor-state+json"

// SensorStateShipResponse acknowledges the precise immutable sensor-state report
// which the control plane has accepted into append-only history.
type SensorStateShipResponse struct {
	Acknowledged bool      `json:"acknowledged"`
	ReportID     shared.ID `json:"report_id"`
}

// ShipSensorState sends a signed P0 coverage or sensor-state report. The caller
// retains its durable WAL record until the returned acknowledgement names the
// exact report ID it issued.
func (c *Client) ShipSensorState(ctx context.Context, token string, report fleetagent.SensorStateReport) (SensorStateShipResponse, error) {
	var out SensorStateShipResponse
	body, err := json.Marshal(report)
	if err != nil {
		return out, fmt.Errorf("fleetclient: marshal sensor-state: %w", err)
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(body); err != nil {
		_ = zw.Close()
		return out, fmt.Errorf("fleetclient: gzip sensor-state: %w", err)
	}
	if err := zw.Close(); err != nil {
		return out, fmt.Errorf("fleetclient: gzip sensor-state close: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/fleet/sensor-states", bytes.NewReader(compressed.Bytes()))
	if err != nil {
		return out, fmt.Errorf("fleetclient: sensor-state request: %w", err)
	}
	req.Header.Set(protoHeader, protoVersion)
	req.Header.Set("Content-Type", sensorStateMediaType)
	req.Header.Set("Content-Encoding", "gzip")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return out, fmt.Errorf("fleetclient: sensor-state: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		h := telemetryHTTPStatusError(resp)
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return out, h
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&out); err != nil {
		return out, fmt.Errorf("fleetclient: decode sensor-state ack: %w", err)
	}
	if !out.Acknowledged || out.ReportID != report.ReportID {
		return out, fmt.Errorf("fleetclient: sensor-state acknowledgement does not match report %q", report.ReportID)
	}
	return out, nil
}
