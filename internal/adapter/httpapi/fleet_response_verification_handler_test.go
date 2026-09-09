package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/responseverificationingest"
)

type responseVerificationHandlerFake struct {
	agentID shared.ID
	report  fleetagent.ResponseVerificationReport
	called  bool
	err     error
}

func (f *responseVerificationHandlerFake) Ingest(_ context.Context, agentID shared.ID, report fleetagent.ResponseVerificationReport) (responseverificationingest.Result, error) {
	f.called = true
	f.agentID = agentID
	f.report = report
	if f.err != nil {
		return responseverificationingest.Result{}, f.err
	}
	return responseverificationingest.Result{ReportID: report.ReportID}, nil
}

func responseVerificationHTTPReport() fleetagent.ResponseVerificationReport {
	at := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	return fleetagent.ResponseVerificationReport{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion, ReportID: "response-report-http", AgentID: "agent-response-http", HostID: "agent-response-http",
		AgentSessionID: fleetagent.CanonicalSessionID("agent-response-http"), AssetID: "asset-http", EngagementID: "eng-http", ActionID: "action-http",
		ActionDigest: strings.Repeat("a", 64), AttemptKey: "attempt-http", VerificationChallenge: strings.Repeat("b", 64),
		Target:     responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-http", ProcessEntityID: "process-http"},
		ObservedAt: at, KeyID: "key-http", Signature: "c2lnbmVkLXVwc3RyZWFt",
	}
}

func TestFleetResponseVerificationDispatchesDedicatedSignedMediaType(t *testing.T) {
	report := responseVerificationHTTPReport()
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/response-verifications", bytes.NewReader(body))
	req.Header.Set("Content-Type", fleetResponseVerificationMediaType)
	req = req.WithContext(context.WithValue(req.Context(), agentKeyCtx, &fleetagent.Agent{ID: report.AgentID}))
	recorder := httptest.NewRecorder()
	fake := &responseVerificationHandlerFake{}
	(&fleetRouter{responseVerify: fake, log: slog.Default()}).ingestResponseVerification(recorder, req)
	if recorder.Code != http.StatusOK || !fake.called || fake.agentID != report.AgentID || fake.report.ReportID != report.ReportID {
		t.Fatalf("status=%d called=%t agent=%s report=%+v body=%s", recorder.Code, fake.called, fake.agentID, fake.report, recorder.Body.String())
	}
	var ack struct {
		Acknowledged bool      `json:"acknowledged"`
		ReportID     shared.ID `json:"report_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &ack); err != nil || !ack.Acknowledged || ack.ReportID != report.ReportID {
		t.Fatalf("ack=%+v decode=%v", ack, err)
	}
}

func TestFleetResponseVerificationRejectsWrongMediaType(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/response-verifications", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), agentKeyCtx, &fleetagent.Agent{ID: "agent-response-http"}))
	recorder := httptest.NewRecorder()
	(&fleetRouter{responseVerify: &responseVerificationHandlerFake{}, log: slog.Default()}).ingestResponseVerification(recorder, req)
	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d, want 415", recorder.Code)
	}
}
