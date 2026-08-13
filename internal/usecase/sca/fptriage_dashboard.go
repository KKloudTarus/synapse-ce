package sca

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AITriageMetricRow struct {
	Value                 string `json:"value"`
	RequestCount          int    `json:"request_count"`
	AverageLatencyMillis  int64  `json:"average_latency_ms"`
	TimeoutCount          int    `json:"timeout_count"`
	ParseFailureCount     int    `json:"parse_failure_count"`
	ProviderFailureCount  int    `json:"provider_failure_count"`
	CircuitOpenCount      int    `json:"circuit_open_count"`
	TotalTokens           int64  `json:"total_tokens"`
	EstimatedCostMicroUSD int64  `json:"estimated_cost_micro_usd"`
	Comparisons           int    `json:"comparisons"`
	Disagreements         int    `json:"disagreements"`
	GateExemptions        int    `json:"gate_exemptions"`
	Findings              int    `json:"findings"`
	latencyTotalMillis    int64
}

type AITriageDashboardAlert struct {
	ProjectID   string        `json:"project_id"`
	ProjectName string        `json:"project_name"`
	Alert       AITriageAlert `json:"alert"`
}

type AITriageDashboard struct {
	GeneratedAt  time.Time                    `json:"generated_at"`
	Totals       AITriageMetricRow            `json:"totals"`
	ByModel      []AITriageMetricRow          `json:"by_model"`
	ByPrompt     []AITriageMetricRow          `json:"by_prompt_version"`
	ByCWE        []AITriageMetricRow          `json:"by_cwe"`
	ByProject    []AITriageMetricRow          `json:"by_project"`
	Distribution AITriageDistributionSnapshot `json:"distribution"`
	Alerts       []AITriageDashboardAlert     `json:"alerts"`
}

// AITriageObservability aggregates the latest evidence-sealed result for each tenant-visible project.
// It never returns source, prompts, provider errors, or credentials.
func (s *Service) AITriageObservability(ctx context.Context, tenantID shared.ID) (AITriageDashboard, error) {
	dashboard := AITriageDashboard{
		GeneratedAt: time.Now().UTC(),
		Distribution: AITriageDistributionSnapshot{
			SchemaVersion: aiTriageDistributionSchemaVersion,
			Language:      map[string]int{},
			CWE:           map[string]int{},
			Project:       map[string]int{},
		},
	}
	if s == nil || s.engagements == nil || s.results == nil {
		return dashboard, fmt.Errorf("AI triage observability: %w", shared.ErrValidation)
	}
	engagements, err := s.engagements.List(ctx, tenantID)
	if err != nil {
		return dashboard, err
	}
	if projectLister, ok := s.engagements.(ports.ProjectEngagementLister); ok {
		projects, listErr := projectLister.ListProjectEngagements(ctx, tenantID)
		if listErr != nil {
			return dashboard, listErr
		}
		engagements = append(engagements, projects...)
	}
	byModel := map[string]*AITriageMetricRow{}
	byPrompt := map[string]*AITriageMetricRow{}
	byCWE := map[string]*AITriageMetricRow{}
	byProject := map[string]*AITriageMetricRow{}
	languageWeights := map[string]float64{}
	cweWeights := map[string]float64{}
	projectWeights := map[string]float64{}
	distributionSamples := 0
	for _, engagement := range engagements {
		if engagement == nil {
			continue
		}
		data, loadErr := s.results.LatestResult(ctx, engagement.ID)
		if errors.Is(loadErr, shared.ErrNotFound) {
			continue
		}
		if loadErr != nil {
			return dashboard, loadErr
		}
		var result ScanResult
		if err := json.Unmarshal(data, &result); err != nil {
			return dashboard, fmt.Errorf("decode AI triage observability result: %w", err)
		}
		projectID := engagement.ProjectID
		if projectID.IsZero() {
			projectID = engagement.ID
		}
		projectValue := projectID.String() + " · " + strings.TrimSpace(engagement.Name)
		findingsByKey := map[string]string{}
		for _, item := range result.Findings {
			cwe := strings.TrimSpace(item.CWE)
			if cwe == "" {
				cwe = "unclassified"
			}
			findingsByKey[strings.TrimSpace(item.DedupKey)] = cwe
		}
		var calls []ports.FPTriageCallMetric
		if result.AITriageTelemetry != nil {
			calls = result.AITriageTelemetry.Calls
		}
		for _, call := range calls {
			model := strings.TrimSpace(call.Provider + "/" + call.Model + " (" + call.Role + ")")
			prompt := strings.TrimSpace(call.PromptVersion)
			if prompt == "" {
				prompt = "unknown"
			}
			cwe := findingsByKey[strings.TrimSpace(call.DedupKey)]
			if cwe == "" {
				cwe = "unclassified"
			}
			updateCallMetric(&dashboard.Totals, call)
			updateCallMetric(metricRow(byModel, model), call)
			updateCallMetric(metricRow(byPrompt, prompt), call)
			updateCallMetric(metricRow(byCWE, cwe), call)
			updateCallMetric(metricRow(byProject, projectValue), call)
		}
		for _, critique := range result.AITriage {
			cwe := findingsByKey[strings.TrimSpace(critique.DedupKey)]
			if cwe == "" {
				cwe = "unclassified"
			}
			cweWeights[canonicalDistributionCWE(cwe)]++
			projectWeights[projectID.String()]++
			model := strings.TrimSpace(critique.ProposerProvider + "/" + critique.ProposerModel + " (proposer)")
			prompt := strings.TrimSpace(critique.PromptVersion)
			if prompt == "" {
				prompt = "unknown"
			}
			rows := []*AITriageMetricRow{&dashboard.Totals, metricRow(byModel, model), metricRow(byPrompt, prompt), metricRow(byCWE, cwe), metricRow(byProject, projectValue)}
			for _, row := range rows {
				row.Findings++
				if critique.VerifierModel != "" && critique.VerifierVerdict != "" {
					row.Comparisons++
					if !strings.EqualFold(critique.Verdict, critique.VerifierVerdict) || critique.Confidence != critique.VerifierConfidence || !strings.EqualFold(critique.Driver, critique.VerifierDriver) {
						row.Disagreements++
					}
				}
				if critique.GateExempt {
					row.GateExemptions++
				}
			}
		}
		distributionSamples += len(result.AITriage)
		addLanguageDistributionWeights(languageWeights, result.Languages, len(result.AITriage))
		for _, alert := range result.AITriageAlerts {
			dashboard.Alerts = append(dashboard.Alerts, AITriageDashboardAlert{ProjectID: projectID.String(), ProjectName: engagement.Name, Alert: alert})
		}
	}
	finalizeMetricRow(&dashboard.Totals)
	dashboard.Totals.Value = "all"
	dashboard.ByModel = sortedMetricRows(byModel)
	dashboard.ByPrompt = sortedMetricRows(byPrompt)
	dashboard.ByCWE = sortedMetricRows(byCWE)
	dashboard.ByProject = sortedMetricRows(byProject)
	dashboard.Distribution = newAITriageDistributionSnapshot(distributionSamples, languageWeights, cweWeights, projectWeights)
	sort.SliceStable(dashboard.Alerts, func(i, j int) bool {
		if dashboard.Alerts[i].ProjectID != dashboard.Alerts[j].ProjectID {
			return dashboard.Alerts[i].ProjectID < dashboard.Alerts[j].ProjectID
		}
		return dashboard.Alerts[i].Alert.Metric < dashboard.Alerts[j].Alert.Metric
	})
	return dashboard, nil
}

func metricRow(rows map[string]*AITriageMetricRow, value string) *AITriageMetricRow {
	if row := rows[value]; row != nil {
		return row
	}
	row := &AITriageMetricRow{Value: value}
	rows[value] = row
	return row
}

func updateCallMetric(row *AITriageMetricRow, call ports.FPTriageCallMetric) {
	if call.Outcome != "circuit_open" {
		row.RequestCount++
		row.latencyTotalMillis += call.LatencyMillis
	}
	switch call.Outcome {
	case "timeout":
		row.TimeoutCount++
	case "parse_failure":
		row.ParseFailureCount++
	case "provider_error":
		row.ProviderFailureCount++
	case "circuit_open":
		row.CircuitOpenCount++
	}
	row.TotalTokens += int64(call.TotalTokens)
	row.EstimatedCostMicroUSD += call.EstimatedCostMicroUSD
}

func finalizeMetricRow(row *AITriageMetricRow) {
	if row.RequestCount > 0 {
		row.AverageLatencyMillis = row.latencyTotalMillis / int64(row.RequestCount)
	}
}

func sortedMetricRows(rows map[string]*AITriageMetricRow) []AITriageMetricRow {
	out := make([]AITriageMetricRow, 0, len(rows))
	for _, row := range rows {
		finalizeMetricRow(row)
		out = append(out, *row)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}
