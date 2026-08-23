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

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/telemetryingest"
)

type telemetryGapHandlerFake struct {
	gapCalled bool
	report    fleetagent.TelemetryGapReport
}

func (f *telemetryGapHandlerFake) Ingest(context.Context, shared.ID, telemetryingest.IngestRequest) (telemetryingest.IngestResult, error) {
	return telemetryingest.IngestResult{}, nil
}

func (f *telemetryGapHandlerFake) IngestGap(_ context.Context, authAgentID shared.ID, report fleetagent.TelemetryGapReport) (telemetryingest.GapIngestResult, error) {
	f.gapCalled = true
	f.report = report
	return telemetryingest.GapIngestResult{GapID: report.GapID}, nil
}

func TestFleetTelemetryGapMediaDispatchesToSignedGapUsecase(t *testing.T) {
	agentID := shared.ID("agent-gap-http")
	session := fleetagent.CanonicalSessionID(agentID)
	streamID, err := fleetagent.TelemetryDeliveryStreamID(agentID, session, fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	report := fleetagent.TelemetryGapReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion,
		GapID:           shared.ID("gap-http"), AgentID: agentID, HostID: agentID,
		AgentSessionID: session, AssetID: shared.ID("asset-http"), StreamID: streamID,
		Priority: fleetagent.PriorityP3, Epoch: 1, Count: 2,
		Reason: fleetagent.TelemetryGapQuotaEviction, FromAt: now.Add(-time.Second), ToAt: now,
		KeyID: "key-http", Signature: "signed-upstream",
	}
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/telemetry", bytes.NewReader(body))
	req.Header.Set("Content-Type", fleetTelemetryGapMediaType+"; charset=utf-8")
	req = req.WithContext(context.WithValue(req.Context(), agentKeyCtx, &fleetagent.Agent{ID: agentID}))
	rec := httptest.NewRecorder()
	fake := &telemetryGapHandlerFake{}
	router := &fleetRouter{telemetry: fake, log: slog.Default()}

	router.ingestTelemetry(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !fake.gapCalled || fake.report.GapID != report.GapID {
		t.Fatalf("gap usecase not called with report: called=%t report=%+v", fake.gapCalled, fake.report)
	}
	var ack struct {
		Acknowledged bool      `json:"acknowledged"`
		GapID        shared.ID `json:"gap_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil {
		t.Fatal(err)
	}
	if !ack.Acknowledged || ack.GapID != report.GapID {
		t.Fatalf("ACK = %+v", ack)
	}
}
