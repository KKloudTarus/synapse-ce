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
		Languages: []ports.DetectedLanguage{{Name: "Go", Percent: 75}, {Name: "TypeScript", Percent: 25}},
		Findings:  []finding.Finding{{DedupKey: "k1", CWE: "CWE-89"}},
		AITriage:  []ports.AICritique{{DedupKey: "k1", ProposerProvider: "provider", ProposerModel: "model", PromptVersion: "v1", GateExempt: true}},
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
	if dashboard.Distribution.SchemaVersion != aiTriageDistributionSchemaVersion || dashboard.Distribution.SampleSize != 1 ||
		dashboard.Distribution.Language["go"] != 7500 || dashboard.Distribution.Language["typescript"] != 2500 ||
		dashboard.Distribution.CWE["CWE-89"] != 10_000 || dashboard.Distribution.Project["e1"] != 10_000 {
		t.Fatalf("distribution = %+v", dashboard.Distribution)
	}
}

func TestAITriageDistributionNormalizesDeterministically(t *testing.T) {
	got := normalizeDistributionWeights(map[string]float64{"c": 1, "a": 1, "b": 1})
	if got["a"] != 3334 || got["b"] != 3333 || got["c"] != 3333 {
		t.Fatalf("normalized tie = %+v", got)
	}
	languages := map[string]float64{}
	addLanguageDistributionWeights(languages, nil, 3)
	if got := normalizeDistributionWeights(languages); got["unknown"] != 10_000 {
		t.Fatalf("missing languages = %+v", got)
	}
	weighted := map[string]float64{}
	addLanguageDistributionWeights(weighted, []ports.DetectedLanguage{{Name: "Go", Percent: 100}}, 3)
	addLanguageDistributionWeights(weighted, []ports.DetectedLanguage{{Name: "TypeScript", Percent: 100}}, 1)
	if got := normalizeDistributionWeights(weighted); got["go"] != 7500 || got["typescript"] != 2500 {
		t.Fatalf("sample-weighted languages = %+v", got)
	}
}

func TestAITriageObservabilityIncludesDistributionWithoutLegacyTelemetry(t *testing.T) {
	engagement := &engdom.Engagement{ID: "e-without-telemetry", TenantID: shared.TenantOrDefault("")}
	data, err := json.Marshal(ScanResult{
		Findings: []finding.Finding{{DedupKey: "k1"}},
		AITriage: []ports.AICritique{{DedupKey: "k1"}},
	})
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
	if dashboard.Distribution.SampleSize != 1 || dashboard.Distribution.Language["unknown"] != 10_000 ||
		dashboard.Distribution.CWE["unclassified"] != 10_000 || dashboard.Distribution.Project["e-without-telemetry"] != 10_000 {
		t.Fatalf("distribution = %+v", dashboard.Distribution)
	}
}
