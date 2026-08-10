package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/businessassetuc"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	findingsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
)

func TestDashboardRangeDays(t *testing.T) {
	for input, want := range map[string]int{"": 30, "7d": 7, "30d": 30, "90d": 90} {
		got, ok := dashboardRangeDays(input)
		if !ok || got != want {
			t.Fatalf("range %q = %d,%v want %d,true", input, got, ok, want)
		}
	}
	if _, ok := dashboardRangeDays("365d"); ok {
		t.Fatal("unbounded range must be rejected")
	}
}

func TestBuildSecurityOperationsSummary(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	assets := []*asset.BusinessAsset{
		{ID: "a1", Criticality: asset.CriticalityCritical},
		{ID: "a2", Criticality: asset.CriticalityHigh},
		{ID: "a3", Criticality: asset.CriticalityLow},
	}
	postures := map[shared.ID]string{"a1": "critical", "a2": "good", "a3": "unexpected"}
	rows := []dashboardFinding{
		{ID: "critical", Severity: shared.SeverityCritical, Status: finding.StatusOpen, CreatedAt: now.AddDate(0, 0, -1)},
		{ID: "high", Severity: shared.SeverityHigh, Status: finding.StatusConfirmed, CreatedAt: now},
		{ID: "remediated", Severity: shared.SeverityMedium, Status: finding.StatusRemediated, CreatedAt: now},
		{ID: "historical", Severity: shared.SeverityCritical, Status: finding.StatusOpen, Class: finding.ClassFirstPartyHistoric, CreatedAt: now},
		{ID: "unknown-date", Severity: shared.SeverityUnknown, Status: finding.StatusTriage},
	}

	summary := buildSecurityOperationsSummary(assets, postures, rows, 7, now, true)
	if summary.AssetPosture["critical"] != 1 || summary.AssetPosture["good"] != 1 || summary.AssetPosture["unknown"] != 1 {
		t.Fatalf("posture counts = %#v", summary.AssetPosture)
	}
	if summary.AssetsByCriticality["critical"] != 1 || summary.AssetsByCriticality["high"] != 1 || summary.AssetsByCriticality["low"] != 1 {
		t.Fatalf("criticality counts = %#v", summary.AssetsByCriticality)
	}
	if summary.ActiveFindingsBySeverity["critical"] != 1 || summary.ActiveFindingsBySeverity["high"] != 1 || summary.ActiveFindingsBySeverity["medium"] != 0 || summary.ActiveFindingsBySeverity["unknown"] != 1 {
		t.Fatalf("active severity counts = %#v", summary.ActiveFindingsBySeverity)
	}
	if summary.FindingsOverTime[5].Counts["critical"] != 1 || summary.FindingsOverTime[6].Counts["high"] != 1 || summary.FindingsOverTime[6].Counts["medium"] != 1 {
		t.Fatalf("trend = %#v", summary.FindingsOverTime)
	}
	if summary.FindingsWithoutTimestamp != 1 || !summary.ExternalFindingsIncluded {
		t.Fatalf("coverage metadata = %#v", summary)
	}
}

func TestDashboardSecurityOperationsRouteRBACRangeAndTenantIsolation(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	engagements := memory.NewEngagementRepository()
	assets := memory.NewAssetStore()
	assets.SetEngagementRepository(engagements)
	findings := memory.NewFindingRepository()
	imported := memory.NewImportedFindingStore()
	assetService, err := businessassetuc.NewService(assets, findings, imported, memory.NewJudgmentStore(), memory.NewRetestRepository(), &fakeAudit{}, fixedClock{t: now}, engIDs{})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []*asset.BusinessAsset{
		{ID: "asset-a", TenantID: "tenant-a", Key: "asset-a", Name: "Tenant A Asset", Type: asset.BusinessAssetApplication, Criticality: asset.CriticalityCritical, Lifecycle: asset.BusinessAssetActive, Owner: "team-a", Version: 1},
		{ID: "asset-b", TenantID: "tenant-b", Key: "asset-b", Name: "Tenant B Asset", Type: asset.BusinessAssetSystem, Criticality: asset.CriticalityLow, Lifecycle: asset.BusinessAssetActive, Owner: "team-b", Version: 1},
	} {
		if err := assets.CreateBusinessAsset(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []*engdom.Engagement{
		{ID: "eng-a", TenantID: "tenant-a", BusinessAssetID: "asset-a", Name: "Tenant A Engagement", Client: "A", Status: engdom.StatusActive, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}},
		{ID: "eng-b", TenantID: "tenant-b", BusinessAssetID: "asset-b", Name: "Tenant B Engagement", Client: "B", Status: engdom.StatusActive, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}},
	} {
		if err := engagements.Create(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	tenantAFinding, err := finding.NewManual("finding-a", "eng-a", finding.ManualInput{Title: "Tenant A only", Severity: shared.SeverityCritical}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := findings.Upsert(context.Background(), []finding.Finding{tenantAFinding}); err != nil {
		t.Fatal(err)
	}

	routes := (&Router{
		log:            discardLog(),
		businessAssets: assetService,
		eng:            enguc.NewService(engagements, fixedClock{t: now}, engIDs{}, &fakeAudit{}),
		findings:       findingsuc.NewService(findings, nil, nil, &fakeAudit{}, fixedClock{t: now}, engIDs{}),
	}).routes()
	call := func(role, tenant, target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", Role: role, TenantID: tenant}))
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		return rec
	}

	if rec := call("agent", "tenant-a", "/api/v1/dashboard/security-operations"); rec.Code != http.StatusForbidden {
		t.Fatalf("machine role status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := call("readonly", "tenant-a", "/api/v1/dashboard/security-operations?range=365d"); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid range status=%d body=%s", rec.Code, rec.Body.String())
	}
	tenantA := call("readonly", "tenant-a", "/api/v1/dashboard/security-operations?range=7d")
	if tenantA.Code != http.StatusOK {
		t.Fatalf("tenant A read status=%d body=%s", tenantA.Code, tenantA.Body.String())
	}
	var tenantASummary securityOperationsSummary
	if err := json.Unmarshal(tenantA.Body.Bytes(), &tenantASummary); err != nil {
		t.Fatal(err)
	}
	if tenantASummary.ActiveFindingsBySeverity["critical"] != 1 {
		t.Fatalf("tenant A finding missing from own summary=%#v", tenantASummary)
	}
	rec := call("readonly", "tenant-b", "/api/v1/dashboard/security-operations?range=7d")
	if rec.Code != http.StatusOK {
		t.Fatalf("same-tenant read status=%d body=%s", rec.Code, rec.Body.String())
	}
	var summary securityOperationsSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.RangeDays != 7 || summary.AssetsByCriticality["low"] != 1 {
		t.Fatalf("tenant B asset summary=%#v", summary)
	}
	if summary.AssetsByCriticality["critical"] != 0 || summary.ActiveFindingsBySeverity["critical"] != 0 {
		t.Fatalf("tenant A data leaked into tenant B summary=%#v", summary)
	}
}
