package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	dastworkflowuc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastworkflow"
)

type recordingDASTScan struct{ proposed dastworkflowuc.ScanConfig }

func (s *recordingDASTScan) ProposeScan(_ context.Context, _ string, _ shared.ID, c dastworkflowuc.ScanConfig) (dastworkflowuc.Proposal, error) {
	s.proposed = c
	return dastworkflowuc.Proposal{}, nil
}
func (s *recordingDASTScan) Decide(context.Context, string, shared.ID, shared.ID, bool, string) (agent.ApprovalDecision, error) {
	return agent.ApprovalDecision{}, nil
}
func (s *recordingDASTScan) RunScan(context.Context, string, shared.ID, shared.ID, dastworkflowuc.ScanConfig) (dastworkflowuc.ScanResult, error) {
	return dastworkflowuc.ScanResult{}, nil
}

func TestDASTScanHandlerRejectsSecretsAndUnknownFields(t *testing.T) {
	for _, body := range []string{
		`{"target":"https://app.test","unknown":true}`,
		`{"target":"https://app.test","session":{"credentials":[{"name":"token","reference":"{{secret:token}}"}]}}`,
	} {
		rt := &Router{log: discardLog()}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/e/dast/proposals", strings.NewReader(body))
		req.SetPathValue("id", "e")
		rec := httptest.NewRecorder()
		rt.proposeDASTScan(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	}
}

func TestDASTScanHandlerMapsVaultReferences(t *testing.T) {
	scan := &recordingDASTScan{}
	rt := &Router{log: discardLog()}
	rt.SetDASTScan(scan)
	body := `{"target":"https://app.test","session":{"scheme":"bearer","credentials":[{"name":"token","reference":"login-token"}],"login_request":{"method":"GET","path":"/"},"success":{"status_code":200},"check_request":{"method":"GET","path":"/"}},"crawler":{}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/e/dast/proposals", strings.NewReader(body))
	req.SetPathValue("id", "e")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice"}))
	rec := httptest.NewRecorder()
	rt.proposeDASTScan(rec, req)
	if rec.Code != http.StatusAccepted || len(scan.proposed.Session.Credentials) != 1 || scan.proposed.Session.Credentials[0].Reference != "login-token" {
		t.Fatalf("status=%d proposed=%+v", rec.Code, scan.proposed)
	}
}
