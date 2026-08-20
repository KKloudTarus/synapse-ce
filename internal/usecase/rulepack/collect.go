package rulepack

import (
	"context"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	rulepackdomain "github.com/KKloudTarus/synapse-ce/internal/domain/rulepack"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// maxRetroHuntEvents stays at or below the CE telemetry store's bounded hunt cap. A release case must
// state an explicit limit so the collector can tell when the returned window may have been cut by LIMIT.
const maxRetroHuntEvents = 50_000

// TelemetryHunter is satisfied by fleet/telemetry.Service. The candidate RulePack rule is evaluated over
// the returned window here rather than via telemetry.Service.RetroRunRule, because that existing helper
// intentionally re-runs the currently shipped detection catalogue and could false-green a candidate rule.
type TelemetryHunter interface {
	Hunt(ctx context.Context, q ports.HuntQuery) (ports.HuntResult, error)
}

// RetroCase identifies the bounded telemetry window used to prove one candidate rule can be retro-run.
type RetroCase struct {
	RuleID string          `json:"rule_id"`
	Query  ports.HuntQuery `json:"query"`
}

// CollectRetroEvidence evaluates each candidate rule over its requested stored-telemetry window. Exactly
// one case per RulePack rule is required, making missing retro coverage explicit rather than silently
// omitting a rule from the release gate.
func CollectRetroEvidence(ctx context.Context, p rulepackdomain.RulePack, hunter TelemetryHunter, cases []RetroCase) ([]RetroEvidence, error) {
	if hunter == nil {
		return nil, fmt.Errorf("rulepack retro collector requires a telemetry hunter")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	rules := make(map[string]detection.Rule, len(p.Rules))
	for _, rule := range p.Rules {
		rules[rule.ID] = rule
	}
	if len(cases) != len(rules) {
		return nil, fmt.Errorf("rulepack retro collector requires exactly one case per rule (%d rules, %d cases)", len(rules), len(cases))
	}
	seen := make(map[string]struct{}, len(cases))
	out := make([]RetroEvidence, 0, len(cases))
	for _, candidate := range cases {
		rule, ok := rules[candidate.RuleID]
		if !ok {
			return nil, fmt.Errorf("retro case names unknown rule %q", candidate.RuleID)
		}
		if _, duplicate := seen[candidate.RuleID]; duplicate {
			return nil, fmt.Errorf("retro case for rule %q is duplicated", candidate.RuleID)
		}
		seen[candidate.RuleID] = struct{}{}
		q := candidate.Query
		if q.HostID == "" || !q.Class.Valid() || q.Class != rule.Class || q.Since.IsZero() || q.Until.IsZero() || q.Until.Before(q.Since) {
			return nil, fmt.Errorf("retro case for rule %s needs a host, matching class, and bounded time window", candidate.RuleID)
		}
		if q.Limit < 1 || q.Limit > maxRetroHuntEvents {
			return nil, fmt.Errorf("retro case for rule %s needs an explicit event limit between 1 and %d", candidate.RuleID, maxRetroHuntEvents)
		}
		q.Kind = ports.HuntRetroRule
		result, err := hunter.Hunt(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("retro hunt rule %s: %w", candidate.RuleID, err)
		}
		// The telemetry port has no independent total-row count. Hitting the requested LIMIT is therefore
		// ambiguous: there may be more events beyond the returned prefix. Fail closed and require a
		// smaller window (or a larger still-bounded limit) rather than calling a potentially capped hunt
		// complete release evidence.
		if len(result.Events) >= q.Limit {
			return nil, fmt.Errorf("retro hunt rule %s reached its %d-event limit; window completeness is unproven", candidate.RuleID, q.Limit)
		}
		matched := 0
		for _, event := range result.Events {
			if rule.Match(event) {
				matched++
			}
		}
		out = append(out, RetroEvidence{
			RuleID:        candidate.RuleID,
			ContextEvents: len(result.Events),
			MatchedEvents: matched,
			Complete:      result.Complete,
			Sampled:       result.Sampled,
			SequenceGaps:  len(result.SequenceGaps),
			Losses:        len(result.Losses),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out, nil
}

// PurpleReader is satisfied by purplecoverage.Service and keeps the release gate coupled only to the
// existing usecase seam, not to a persistence adapter.
type PurpleReader interface {
	Trend(ctx context.Context, engagementID shared.ID) ([]purplecoverage.Coverage, error)
}

// PurpleRequest selects the exact emulation run whose measured coverage is release evidence.
type PurpleRequest struct {
	EngagementID shared.ID `json:"engagement_id"`
	RunID        shared.ID `json:"run_id"`
}

// CollectPurpleEvidence loads measured purple coverage and returns only rows from the requested run.
// Empty or cross-scope evidence fails closed: claimed ATT&CK coverage cannot be inferred from a missing
// run, another engagement, or a row without the asset on which the emulation was measured.
func CollectPurpleEvidence(ctx context.Context, reader PurpleReader, request PurpleRequest) ([]purplecoverage.Coverage, error) {
	if reader == nil {
		return nil, fmt.Errorf("rulepack purple collector requires a coverage reader")
	}
	if request.EngagementID == "" || request.RunID == "" {
		return nil, fmt.Errorf("rulepack purple collector requires engagement and run ids")
	}
	rows, err := reader.Trend(ctx, request.EngagementID)
	if err != nil {
		return nil, fmt.Errorf("load purple coverage: %w", err)
	}
	out := make([]purplecoverage.Coverage, 0)
	for _, row := range rows {
		if row.RunID != request.RunID {
			continue
		}
		if row.EngagementID != request.EngagementID {
			return nil, fmt.Errorf("purple coverage row engagement %s does not match requested engagement %s", row.EngagementID, request.EngagementID)
		}
		if row.AssetID == "" {
			return nil, fmt.Errorf("purple coverage run %s contains a row without an asset id", request.RunID)
		}
		if err := row.Validate(); err != nil {
			return nil, fmt.Errorf("purple coverage row: %w", err)
		}
		copyRow := row
		copyRow.Actual = append([]string(nil), row.Actual...)
		out = append(out, copyRow)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("purple coverage run %s has no measured rows", request.RunID)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TechniqueID != out[j].TechniqueID {
			return out[i].TechniqueID < out[j].TechniqueID
		}
		return out[i].Expected < out[j].Expected
	})
	return out, nil
}
