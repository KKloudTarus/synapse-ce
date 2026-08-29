package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/telemetryingest"
)

type sensorStateHandlerFake struct {
	report fleetagent.SensorStateReport
	called bool
}

func (f *sensorStateHandlerFake) Ingest(context.Context, shared.ID, telemetryingest.IngestRequest) (telemetryingest.IngestResult, error) {
	return telemetryingest.IngestResult{}, nil
}

func (f *sensorStateHandlerFake) IngestGap(context.Context, shared.ID, fleetagent.TelemetryGapReport) (telemetryingest.GapIngestResult, error) {
	return telemetryingest.GapIngestResult{}, nil
}

func (f *sensorStateHandlerFake) IngestSensorState(_ context.Context, _ shared.ID, report fleetagent.SensorStateReport) (telemetryingest.SensorStateIngestResult, error) {
	f.called = true
	f.report = report
	return telemetryingest.SensorStateIngestResult{ReportID: report.ReportID}, nil
}

func TestFleetSensorStateDispatchesDedicatedSignedMediaType(t *testing.T) {
	agentID := shared.ID("agent-state-http")
	at := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	report := fleetagent.SensorStateReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion, ReportID: "state-http", AgentID: agentID, HostID: agentID,
		AgentSessionID: fleetagent.CanonicalSessionID(agentID), AssetID: "asset-http", Kind: "sensor_state", ObservedAt: at,
		SchemaVersion: 1, PayloadDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", KeyID: "key-http", Signature: "c2lnbmVkLXVwc3RyZWFt",
		States: []detection.ClassCoverage{{Class: detection.ClassProcess, HostID: agentID, AgentID: agentID, State: detection.StateActive, Since: at}},
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/sensor-states", bytes.NewReader(body))
	req.Header.Set("Content-Type", fleetSensorStateMediaType)
	req = req.WithContext(context.WithValue(req.Context(), agentKeyCtx, &fleetagent.Agent{ID: agentID}))
	rec := httptest.NewRecorder()
	fake := &sensorStateHandlerFake{}

	(&fleetRouter{telemetry: fake, log: slog.Default()}).ingestSensorState(rec, req)
	if rec.Code != http.StatusOK || !fake.called || fake.report.ReportID != report.ReportID {
		t.Fatalf("status=%d called=%t report=%+v body=%s", rec.Code, fake.called, fake.report, rec.Body.String())
	}
	var ack struct {
		Acknowledged bool      `json:"acknowledged"`
		ReportID     shared.ID `json:"report_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil || !ack.Acknowledged || ack.ReportID != report.ReportID {
		t.Fatalf("ACK=%+v decode=%v", ack, err)
	}
}

func TestFleetSensorStateRejectsWrongMediaType(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/sensor-states", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), agentKeyCtx, &fleetagent.Agent{ID: "agent-state-http"}))
	rec := httptest.NewRecorder()
	(&fleetRouter{telemetry: &sensorStateHandlerFake{}, log: slog.Default()}).ingestSensorState(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d, want 415", rec.Code)
	}
}
