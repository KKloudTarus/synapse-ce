package scanrun

import (
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type EngineExecution string

const (
	EngineCompleted EngineExecution = "completed"
	EngineFailed    EngineExecution = "failed"
	EngineTimedOut  EngineExecution = "timed_out"
	EngineCancelled EngineExecution = "cancelled"
	EngineNotRun    EngineExecution = "not_run"
)

type CoverageStatus string

const (
	CoverageComplete      CoverageStatus = "complete"
	CoveragePartial       CoverageStatus = "partial"
	CoverageUnknown       CoverageStatus = "unknown"
	CoverageNotApplicable CoverageStatus = "not_applicable"
)

type EngineReason string

const (
	ReasonNone                 EngineReason = ""
	ReasonNotSelected          EngineReason = "not_selected"
	ReasonDisabled             EngineReason = "disabled"
	ReasonNotApplicable        EngineReason = "not_applicable"
	ReasonUnavailable          EngineReason = "unavailable"
	ReasonLegacyReporter       EngineReason = "legacy_reporter"
	ReasonDeadlineExceeded     EngineReason = "deadline_exceeded"
	ReasonBudgetExhausted      EngineReason = "budget_exhausted"
	ReasonCancelled            EngineReason = "cancelled"
	ReasonEngineError          EngineReason = "engine_error"
	ReasonUpstreamFailure      EngineReason = "upstream_failure"
	ReasonTruncated            EngineReason = "truncated"
	ReasonSourceBudget         EngineReason = "source_budget"
	ReasonUnrenderedCharts     EngineReason = "unrendered_charts"
	ReasonDependencyUnresolved EngineReason = "dependency_unresolved"
	ReasonAnalysisIncomplete   EngineReason = "analysis_incomplete"
)

type EngineMeasure string

const (
	MeasureFindings          EngineMeasure = "findings"
	MeasureFilesSeen         EngineMeasure = "files_seen"
	MeasureFilesParsed       EngineMeasure = "files_parsed"
	MeasureFilesSkipped      EngineMeasure = "files_skipped"
	MeasureFilesUnscanned    EngineMeasure = "files_unscanned"
	MeasureSourceBudgetBytes EngineMeasure = "source_budget_bytes"
	MeasureUnrenderedCharts  EngineMeasure = "unrendered_charts"
	MeasureProposals         EngineMeasure = "proposals"
)

// EngineOutcome records server-owned execution facts, independently of finding presence.
// Reasons and measurements exclude source text, paths, tool output and credentials.
type EngineOutcome struct {
	Engine    string                  `json:"engine"`
	Execution EngineExecution         `json:"execution"`
	Coverage  CoverageStatus          `json:"coverage"`
	Reason    EngineReason            `json:"reason,omitempty"`
	Required  bool                    `json:"required"`
	Counts    map[EngineMeasure]int64 `json:"counts,omitempty"`
}

func (o EngineOutcome) Validate() error {
	if len(o.Engine) == 0 || len(o.Engine) > 64 || o.Engine[0] < 'a' || o.Engine[0] > 'z' {
		return fmt.Errorf("%w: invalid engine identity", shared.ErrValidation)
	}
	for _, c := range o.Engine {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return fmt.Errorf("%w: invalid engine identity", shared.ErrValidation)
		}
	}
	switch o.Execution {
	case EngineCompleted, EngineFailed, EngineTimedOut, EngineCancelled, EngineNotRun:
	default:
		return fmt.Errorf("%w: invalid engine execution", shared.ErrValidation)
	}
	switch o.Coverage {
	case CoverageComplete, CoveragePartial, CoverageUnknown, CoverageNotApplicable:
	default:
		return fmt.Errorf("%w: invalid engine coverage", shared.ErrValidation)
	}
	switch o.Reason {
	case ReasonNone, ReasonNotSelected, ReasonDisabled, ReasonNotApplicable, ReasonUnavailable,
		ReasonLegacyReporter, ReasonDeadlineExceeded, ReasonBudgetExhausted, ReasonCancelled,
		ReasonEngineError, ReasonUpstreamFailure, ReasonTruncated, ReasonSourceBudget,
		ReasonUnrenderedCharts, ReasonDependencyUnresolved, ReasonAnalysisIncomplete:
	default:
		return fmt.Errorf("%w: invalid engine reason", shared.ErrValidation)
	}
	if o.Coverage == CoverageComplete && o.Execution != EngineCompleted {
		return fmt.Errorf("%w: complete coverage requires completed execution", shared.ErrValidation)
	}
	if o.Coverage == CoverageComplete && (o.Reason != ReasonNone || o.Counts[MeasureFilesUnscanned] > 0 || o.Counts[MeasureUnrenderedCharts] > 0) {
		return fmt.Errorf("%w: complete coverage cannot contain an unresolved coverage gap", shared.ErrValidation)
	}
	if o.Coverage == CoverageNotApplicable && (o.Required || o.Execution != EngineNotRun) {
		return fmt.Errorf("%w: not-applicable engines cannot be required or executed", shared.ErrValidation)
	}
	if o.Execution == EngineNotRun && (o.Coverage == CoveragePartial || len(o.Counts) != 0) {
		return fmt.Errorf("%w: an unstarted engine cannot claim measured coverage", shared.ErrValidation)
	}
	if o.Execution == EngineTimedOut && o.Reason != ReasonDeadlineExceeded || o.Execution == EngineCancelled && o.Reason != ReasonCancelled {
		return fmt.Errorf("%w: engine interruption requires its stable reason", shared.ErrValidation)
	}
	for measure, count := range o.Counts {
		switch measure {
		case MeasureFindings, MeasureFilesSeen, MeasureFilesParsed, MeasureFilesSkipped, MeasureFilesUnscanned,
			MeasureSourceBudgetBytes, MeasureUnrenderedCharts, MeasureProposals:
		default:
			return fmt.Errorf("%w: invalid engine measurement", shared.ErrValidation)
		}
		if count < 0 || count > 9007199254740991 {
			return fmt.Errorf("%w: engine measurement outside JSON integer range", shared.ErrValidation)
		}
	}
	return nil
}

// CanonicalEngineOutcomes validates a bounded set and sorts a deep copy for hashing.
func CanonicalEngineOutcomes(outcomes []EngineOutcome) ([]EngineOutcome, error) {
	if len(outcomes) > 64 {
		return nil, fmt.Errorf("%w: too many engine outcomes", shared.ErrValidation)
	}
	copy := CloneEngineOutcomes(outcomes)
	seen := make(map[string]bool, len(copy))
	for _, o := range copy {
		if err := o.Validate(); err != nil {
			return nil, err
		}
		if seen[o.Engine] {
			return nil, fmt.Errorf("%w: duplicate engine outcome", shared.ErrValidation)
		}
		seen[o.Engine] = true
	}
	sort.Slice(copy, func(i, j int) bool { return copy[i].Engine < copy[j].Engine })
	return copy, nil
}

func CloneEngineOutcomes(outcomes []EngineOutcome) []EngineOutcome {
	if outcomes == nil {
		return nil
	}
	cloned := make([]EngineOutcome, len(outcomes))
	for i, o := range outcomes {
		cloned[i] = o
		if o.Counts != nil {
			cloned[i].Counts = make(map[EngineMeasure]int64, len(o.Counts))
			for k, v := range o.Counts {
				cloned[i].Counts[k] = v
			}
		}
	}
	return cloned
}

type EngineCoverage struct {
	Status    CoverageStatus `json:"status"`
	Required  int            `json:"required"`
	Completed int            `json:"completed"`
}

func (c EngineCoverage) Complete() bool {
	return c.Status == CoverageComplete && c.Required > 0 && c.Completed == c.Required
}

// ComputeEngineCoverage classifies only the required capabilities of the current plan.
// Missing historical facts remain unknown; optional exclusions do not become failures.
func ComputeEngineCoverage(outcomes []EngineOutcome) EngineCoverage {
	result := EngineCoverage{Status: CoverageUnknown}
	canonical, err := CanonicalEngineOutcomes(outcomes)
	if err != nil {
		return result
	}
	partial, unknown := false, false
	for _, o := range canonical {
		if !o.Required {
			continue
		}
		result.Required++
		switch {
		case o.Coverage == CoverageComplete && o.Execution == EngineCompleted:
			result.Completed++
		case o.Coverage == CoveragePartial || o.Execution == EngineTimedOut || o.Execution == EngineFailed || o.Execution == EngineCancelled:
			partial = true
		default:
			unknown = true
		}
	}
	switch {
	case result.Required == 0:
	case partial:
		result.Status = CoveragePartial
	case unknown:
	case result.Completed == result.Required:
		result.Status = CoverageComplete
	}
	return result
}
