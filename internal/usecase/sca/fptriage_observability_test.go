package sca

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestBuildAITriageAlertsUsesConfiguredBaselineAndMinimumSamples(t *testing.T) {
	telemetry := &ports.FPTriageTelemetry{RequestCount: 20, ParseFailureCount: 5, Comparisons: 20, Disagreements: 8, GateExemptions: 6}
	policy := aiTriageAlertPolicy{minSamples: 10, disagreementBaseline: 1000, exemptionBaseline: 1000, parseFailureBaseline: 100, deviation: 500}
	alerts := buildAITriageAlerts(telemetry, 20, policy)
	if len(alerts) != 3 {
		t.Fatalf("alerts = %+v, want all three safety rates", alerts)
	}
	if got := buildAITriageAlerts(telemetry, 20, aiTriageAlertPolicy{minSamples: 50, disagreementBaseline: 1000, exemptionBaseline: 1000, parseFailureBaseline: 100, deviation: 500}); len(got) != 0 {
		t.Fatalf("small sample emitted alerts: %+v", got)
	}
}

type dashboardEngagementRepo struct {
	*fakeEngRepo
	items []*engdom.Engagement
}

func (r dashboardEngagementRepo) List(context.Context, shared.ID) ([]*engdom.Engagement, error) {
	return r.items, nil
}

func TestAITriageObservabilityGroupsLatestTenantResult(t *testing.T) {
	engagement := &engdom.Engagement{ID: "e1", TenantID: shared.TenantOrDefault(""), Name: "checkout"}
	result := ScanResult{
		Findings: []finding.Finding{{DedupKey: "k1", CWE: "CWE-89"}},
		AITriage: []ports.AICritique{{DedupKey: "k1", ProposerProvider: "provider", ProposerModel: "model", PromptVersion: "v1", GateExempt: true}},
		AITriageTelemetry: &ports.FPTriageTelemetry{Calls: []ports.FPTriageCallMetric{{
			DedupKey: "k1", Role: "proposer", Provider: "provider", Model: "model", PromptVersion: "v1", Outcome: "success",
			LatencyMillis: 25, TotalTokens: 120, EstimatedCostMicroUSD: 50,
		}}},
		AITriageAlerts: []AITriageAlert{{Metric: "exemption_rate", Message: "alert"}},
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		engagements: dashboardEngagementRepo{fakeEngRepo: &fakeEngRepo{}, items: []*engdom.Engagement{engagement}},
		results:     staticScanResultStore{data: data},
	}
	dashboard, err := service.AITriageObservability(context.Background(), shared.TenantOrDefault(""))
	if err != nil {
		t.Fatal(err)
	}
	if dashboard.GeneratedAt.Before(time.Now().Add(-time.Minute)) || dashboard.Totals.RequestCount != 1 || dashboard.Totals.GateExemptions != 1 {
		t.Fatalf("totals = %+v", dashboard.Totals)
	}
	if len(dashboard.ByModel) != 1 || len(dashboard.ByPrompt) != 1 || len(dashboard.ByCWE) != 1 || dashboard.ByCWE[0].Value != "CWE-89" || len(dashboard.ByProject) != 1 {
		t.Fatalf("dashboard dimensions = model:%+v prompt:%+v cwe:%+v project:%+v", dashboard.ByModel, dashboard.ByPrompt, dashboard.ByCWE, dashboard.ByProject)
	}
	if len(dashboard.Alerts) != 1 || dashboard.Alerts[0].ProjectID != "e1" {
		t.Fatalf("alerts = %+v", dashboard.Alerts)
	}
}
