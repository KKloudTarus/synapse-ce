package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/runtimeevidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetwork"
)

// stubRuntimeEvidence records the report the handler decoded and returns a canned result, so the handler's
// auth, decode, and response mapping are exercised without the full judgment stack (the ingest use case
// itself is unit-tested in internal/usecase/fleet/runtimeevidence).
type stubRuntimeEvidence struct {
	got    runtimereach.Report
	tenant shared.ID
	agent  shared.ID
	result runtimeevidence.Result
	err    error
}

func (s *stubRuntimeEvidence) Ingest(_ context.Context, tenantID, agentID shared.ID, report runtimereach.Report) (runtimeevidence.Result, error) {
	s.tenant, s.agent, s.got = tenantID, agentID, report
	return s.result, s.err
}

func setupFleetWithRuntime(t *testing.T, stub *stubRuntimeEvidence) (http.Handler, *fleetagentuc.Service) {
	t.Helper()
	agentSvc, err := fleetagentuc.NewService(memory.NewFleetAgentStore(), ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatalf("agent svc: %v", err)
	}
	signer, err := worksign.New([]byte("0123456789012345678901234567890123"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	workSvc, err := fleetwork.NewService(memory.NewWorkOrderStore(), signer, ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatalf("work svc: %v", err)
	}
	rt := &Router{log: discardLog()}
	rt.SetFleet(agentSvc, workSvc, func() time.Time { return time.Now().UTC() }, "")
	if stub != nil {
		rt.SetFleetRuntimeEvidence(stub)
	}
	return rt.fleet.handler(), agentSvc
}

func sampleRuntimeReport() runtimereach.Report {
	return runtimereach.Report{
		PackageFiles: []runtimereach.PackageFiles{{
			Package: runtimereach.PackageRef{Name: "libssl3", Version: "3.0.13"},
			Files:   []runtimereach.OwnedFile{{Path: "/usr/lib/libssl.so.3", ID: runtimereach.FileID{Device: 64, Inode: 111}}},
		}},
		Loads: []runtimereach.LoadEvent{{Path: "/usr/lib/libssl.so.3", ID: runtimereach.FileID{Device: 64, Inode: 111}}},
	}
}

func TestRuntimeEvidenceIngestMapsResultAndIdentity(t *testing.T) {
	stub := &stubRuntimeEvidence{result: runtimeevidence.Result{AssetID: "asset-1", EngagementID: "eng-1", Minted: 2}}
	h, agentSvc := setupFleetWithRuntime(t, stub)
	token := enrolAgentToken(t, h, agentSvc)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/inventory/runtime", token, sampleRuntimeReport(), true)
	if w.Code != http.StatusOK {
		t.Fatalf("runtime ingest should be 200, got %d (%s)", w.Code, w.Body.String())
	}
	// The handler must pass the AUTHENTICATED agent's tenant/id, never anything from the body.
	if stub.agent.IsZero() || stub.tenant.IsZero() {
		t.Fatalf("handler did not pass the authenticated agent identity: tenant=%q agent=%q", stub.tenant, stub.agent)
	}
	// The decoded report round-tripped the runtime evidence.
	if len(stub.got.Loads) != 1 || stub.got.Loads[0].ID.Inode != 111 || stub.got.PackageFiles[0].Package.Name != "libssl3" {
		t.Fatalf("handler decoded the wrong report: %+v", stub.got)
	}
}

func TestRuntimeEvidenceIngestEchoesCoverageAndPending(t *testing.T) {
	stub := &stubRuntimeEvidence{result: runtimeevidence.Result{
		AssetID:  "asset-1",
		Coverage: []runtimereach.CoverageReason{runtimereach.CoverageSensorUnavailable},
		Pending:  true,
	}}
	h, agentSvc := setupFleetWithRuntime(t, stub)
	token := enrolAgentToken(t, h, agentSvc)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/inventory/runtime", token, sampleRuntimeReport(), true)
	if w.Code != http.StatusOK {
		t.Fatalf("runtime ingest should be 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Coverage []string `json:"coverage"`
		Pending  bool     `json:"pending"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Pending {
		t.Fatalf("response must echo pending, got %s", w.Body.String())
	}
	if len(resp.Coverage) != 1 || resp.Coverage[0] != "sensor-unavailable" {
		t.Fatalf("response must echo the coverage gap, got %s", w.Body.String())
	}
}

func TestRuntimeEvidenceIngestWireContractIsSnakeCase(t *testing.T) {
	stub := &stubRuntimeEvidence{}
	h, agentSvc := setupFleetWithRuntime(t, stub)
	token := enrolAgentToken(t, h, agentSvc)
	// Post an explicit snake_case body; if the DTO json tags drift, these fields decode to zero.
	body := map[string]any{
		"package_files": []map[string]any{{
			"package": map[string]any{"name": "libpng16-16", "version": "1.6.43"},
			"files":   []map[string]any{{"path": "/usr/lib/libpng16.so.16", "id": map[string]any{"device": 64, "inode": 222}}},
		}},
		"loads":    []map[string]any{{"path": "/usr/lib/libpng16.so.16", "real_path": "/usr/lib/libpng16.so.16.43", "id": map[string]any{"device": 64, "inode": 222}, "deleted": false}},
		"coverage": []string{"sensor-unavailable"},
	}
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/inventory/runtime", token, body, true)
	if w.Code != http.StatusOK {
		t.Fatalf("runtime ingest should be 200, got %d (%s)", w.Code, w.Body.String())
	}
	if len(stub.got.PackageFiles) != 1 || stub.got.PackageFiles[0].Package.Name != "libpng16-16" ||
		len(stub.got.PackageFiles[0].Files) != 1 || stub.got.PackageFiles[0].Files[0].ID.Device != 64 {
		t.Fatalf("snake_case package_files did not decode: %+v", stub.got.PackageFiles)
	}
	if len(stub.got.Loads) != 1 || stub.got.Loads[0].RealPath != "/usr/lib/libpng16.so.16.43" || stub.got.Loads[0].ID.Inode != 222 {
		t.Fatalf("snake_case loads did not decode: %+v", stub.got.Loads)
	}
	if len(stub.got.Coverage) != 1 || stub.got.Coverage[0] != runtimereach.CoverageSensorUnavailable {
		t.Fatalf("snake_case coverage did not decode: %+v", stub.got.Coverage)
	}
}

func TestRuntimeEvidenceIngestRequiresAuth(t *testing.T) {
	h, _ := setupFleetWithRuntime(t, &stubRuntimeEvidence{})
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/inventory/runtime", "", sampleRuntimeReport(), true)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated runtime ingest must be 401, got %d", w.Code)
	}
}

func TestRuntimeEvidenceIngestNotEnabled(t *testing.T) {
	h, agentSvc := setupFleetWithRuntime(t, nil) // route not wired
	token := enrolAgentToken(t, h, agentSvc)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/inventory/runtime", token, sampleRuntimeReport(), true)
	if w.Code != http.StatusNotFound {
		t.Fatalf("runtime ingest with no service must be 404, got %d", w.Code)
	}
}
