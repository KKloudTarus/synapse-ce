package sca

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const aiTriageMetricPrefix = "synapse_sca_ai_triage_"

type AITriageAlert struct {
	Metric               string `json:"metric"`
	ObservedBasisPoints  int    `json:"observed_basis_points"`
	BaselineBasisPoints  int    `json:"baseline_basis_points"`
	DeviationBasisPoints int    `json:"deviation_basis_points"`
	SampleSize           int    `json:"sample_size"`
	Message              string `json:"message"`
}

type aiTriageAlertPolicy struct {
	minSamples           int
	disagreementBaseline int
	exemptionBaseline    int
	parseFailureBaseline int
	deviation            int
}

func defaultAITriageAlertPolicy() aiTriageAlertPolicy {
	return aiTriageAlertPolicy{minSamples: 10, disagreementBaseline: 1500, exemptionBaseline: 1000, parseFailureBaseline: 200, deviation: 1000}
}

// SetFPTriageAlertPolicy configures scan-local baseline deviation alerts. Rates are basis points
// (10000 = 100%); invalid values restore conservative defaults.
func (s *Service) SetFPTriageAlertPolicy(minSamples, disagreementBaseline, exemptionBaseline, parseFailureBaseline, deviation int) {
	p := defaultAITriageAlertPolicy()
	if minSamples > 0 && minSamples <= 10000 {
		p.minSamples = minSamples
	}
	if validBasisPoints(disagreementBaseline) {
		p.disagreementBaseline = disagreementBaseline
	}
	if validBasisPoints(exemptionBaseline) {
		p.exemptionBaseline = exemptionBaseline
	}
	if validBasisPoints(parseFailureBaseline) {
		p.parseFailureBaseline = parseFailureBaseline
	}
	if validBasisPoints(deviation) {
		p.deviation = deviation
	}
	s.fpTriageAlerts = p
}

func validBasisPoints(value int) bool { return value >= 0 && value <= 10000 }

func rateBasisPoints(numerator, denominator int) int {
	if numerator <= 0 || denominator <= 0 {
		return 0
	}
	return numerator * 10000 / denominator
}

func (s *Service) emitAITriageTelemetry(ctx context.Context, result *ScanResult) {
	if s == nil || result == nil || result.AITriageTelemetry == nil {
		return
	}
	t := result.AITriageTelemetry
	result.AITriageAlerts = buildAITriageAlerts(t, len(result.AITriage), s.fpTriageAlerts)
	for _, alert := range result.AITriageAlerts {
		result.SourceWarnings = append(result.SourceWarnings, alert.Message)
		s.logger().LogAttrs(context.WithoutCancel(ctx), slog.LevelWarn, "AI triage safety metric deviated from baseline",
			slog.String("metric", aiTriageMetricPrefix+alert.Metric+"_alert"), slog.String("metric_kind", "alert"),
			slog.Int("observed_basis_points", alert.ObservedBasisPoints), slog.Int("baseline_basis_points", alert.BaselineBasisPoints),
			slog.Int("deviation_basis_points", alert.DeviationBasisPoints), slog.Int("sample_size", alert.SampleSize))
	}

	findingsByKey := make(map[string]finding.Finding, len(result.Findings))
	for _, item := range result.Findings {
		findingsByKey[strings.TrimSpace(item.DedupKey)] = item
	}
	for _, call := range t.Calls {
		item := findingsByKey[strings.TrimSpace(call.DedupKey)]
		s.logger().LogAttrs(context.WithoutCancel(ctx), slog.LevelInfo, "AI triage provider request observed",
			slog.String("metric", aiTriageMetricPrefix+"requests_total"), slog.String("metric_kind", "counter"), slog.Int("metric_value", 1),
			slog.String("role", call.Role), slog.String("provider", call.Provider), slog.String("model", call.Model),
			slog.String("prompt_version", call.PromptVersion), slog.String("cwe", strings.TrimSpace(item.CWE)),
			slog.String("engagement", item.EngagementID.String()),
			slog.String("outcome", call.Outcome), slog.Int64("latency_ms", call.LatencyMillis),
			slog.Int("total_tokens", call.TotalTokens), slog.Int64("estimated_cost_micro_usd", call.EstimatedCostMicroUSD))
	}
}

func buildAITriageAlerts(t *ports.FPTriageTelemetry, critiqueCount int, policy aiTriageAlertPolicy) []AITriageAlert {
	if t == nil {
		return nil
	}
	if policy.minSamples == 0 {
		policy = defaultAITriageAlertPolicy()
	}
	type candidate struct {
		name               string
		numerator, samples int
		baseline           int
	}
	candidates := []candidate{
		{name: "disagreement_rate", numerator: t.Disagreements, samples: t.Comparisons, baseline: policy.disagreementBaseline},
		{name: "exemption_rate", numerator: t.GateExemptions, samples: critiqueCount, baseline: policy.exemptionBaseline},
		{name: "parse_failure_rate", numerator: t.ParseFailureCount, samples: t.RequestCount, baseline: policy.parseFailureBaseline},
	}
	alerts := make([]AITriageAlert, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.samples < policy.minSamples {
			continue
		}
		observed := rateBasisPoints(candidate.numerator, candidate.samples)
		delta := observed - candidate.baseline
		if delta < 0 {
			delta = -delta
		}
		if delta <= policy.deviation {
			continue
		}
		alerts = append(alerts, AITriageAlert{
			Metric: candidate.name, ObservedBasisPoints: observed, BaselineBasisPoints: candidate.baseline,
			DeviationBasisPoints: delta, SampleSize: candidate.samples,
			Message: fmt.Sprintf("AI triage %s is %.2f%% versus %.2f%% baseline across %d samples; review model health before trusting exemptions", strings.ReplaceAll(candidate.name, "_", " "), float64(observed)/100, float64(candidate.baseline)/100, candidate.samples),
		})
	}
	return alerts
}
