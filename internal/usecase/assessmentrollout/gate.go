package assessmentrollout

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type Phase string

const (
	PhaseInternalCanary Phase = "internal_canary"
	PhaseOptInCanary    Phase = "opt_in_canary"
	PhaseReadCutover    Phase = "read_cutover"
	PhaseUIDefault      Phase = "ui_default"
	PhaseRollbackDrill  Phase = "rollback_drill"
)

func (phase Phase) Valid() bool {
	switch phase {
	case PhaseInternalCanary, PhaseOptInCanary, PhaseReadCutover, PhaseUIDefault, PhaseRollbackDrill:
		return true
	default:
		return false
	}
}

type Snapshot struct {
	TenantID                           string `json:"tenant_id"`
	IntegrityViolations                int    `json:"integrity_violations"`
	AutomaticFixedPartialUnknown       int    `json:"automatic_fixed_partial_unknown"`
	ComparableItems                    int    `json:"comparable_items"`
	SemanticMismatches                 int    `json:"semantic_mismatches"`
	ProducerItems                      int    `json:"producer_items"`
	ReviewCandidates                   int    `json:"review_candidates"`
	SevenDayReviewCandidateBaselineBPS int    `json:"seven_day_review_candidate_baseline_bps"`
	APIRequests                        int    `json:"api_requests"`
	APIErrors                          int    `json:"api_errors"`
	APIWindowMinutes                   int    `json:"api_window_minutes"`
	LatencyWindowMinutes               int    `json:"latency_window_minutes"`
	CycleListP95Millis                 int    `json:"cycle_list_p95_millis"`
	CycleDetailP95Millis               int    `json:"cycle_detail_p95_millis"`
	ComparisonPageP95Millis            int    `json:"comparison_page_p95_millis"`
	ProductionSLOContinuousMinutes     int    `json:"production_slo_continuous_minutes"`
	TargetCardinality                  bool   `json:"target_cardinality"`
	ComparisonBacklog                  int    `json:"comparison_backlog"`
	OldestComparisonAgeSeconds         int    `json:"oldest_comparison_age_seconds"`
	Comparison100KDurationSeconds      int    `json:"comparison_100k_duration_seconds"`
	DeadLetterGrowth10Minutes          int    `json:"dead_letter_growth_10_minutes"`
	SuccessfulRepairs10Minutes         int    `json:"successful_repairs_10_minutes"`
	MetricsRecorded                    bool   `json:"metrics_recorded"`
	ApprovalRecorded                   bool   `json:"approval_recorded"`
	ReadCutoverApproved                bool   `json:"read_cutover_approved"`
	LifecycleReadEnabled               bool   `json:"lifecycle_read_enabled"`
	LifecycleUIDefaultEnabled          bool   `json:"lifecycle_ui_default_enabled"`
	SourceRowsPreserved                bool   `json:"source_rows_preserved"`
	ImmutableArtifactsPreserved        bool   `json:"immutable_artifacts_preserved"`
	RollbackDrillPassed                bool   `json:"rollback_drill_passed"`
}

type Finding struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Decision struct {
	Phase    Phase     `json:"phase"`
	TenantID string    `json:"tenant_id"`
	Allowed  bool      `json:"allowed"`
	Blockers []Finding `json:"blockers"`
	Warnings []Finding `json:"warnings"`
}

func Evaluate(phase Phase, snapshot Snapshot) (Decision, error) {
	snapshot.TenantID = strings.TrimSpace(snapshot.TenantID)
	if !phase.Valid() || snapshot.TenantID == "" || len(snapshot.TenantID) > 128 || invalidSnapshotCounts(snapshot) {
		return Decision{}, fmt.Errorf("%w: assessment rollout gate input is invalid", shared.ErrValidation)
	}
	decision := Decision{Phase: phase, TenantID: snapshot.TenantID, Blockers: []Finding{}, Warnings: []Finding{}}
	block := func(code, message string) {
		decision.Blockers = append(decision.Blockers, Finding{Code: code, Message: message})
	}
	warn := func(code, message string) {
		decision.Warnings = append(decision.Warnings, Finding{Code: code, Message: message})
	}

	if phase == PhaseRollbackDrill {
		if snapshot.LifecycleReadEnabled || snapshot.LifecycleUIDefaultEnabled {
			block("rollback_flags_enabled", "rollback must disable lifecycle reads and lifecycle UI")
		}
		if !snapshot.SourceRowsPreserved {
			block("rollback_source_not_preserved", "rollback must preserve source rows")
		}
		if !snapshot.ImmutableArtifactsPreserved {
			block("rollback_artifacts_not_preserved", "rollback must preserve immutable lifecycle artifacts")
		}
		if !snapshot.RollbackDrillPassed {
			block("rollback_drill_not_passed", "rollback drill evidence is not recorded as passed")
		}
		if !snapshot.MetricsRecorded || !snapshot.ApprovalRecorded {
			block("phase_record_missing", "phase metrics and approval must both be recorded")
		}
		return finalize(decision), nil
	}

	if snapshot.IntegrityViolations > 0 {
		block("integrity_violation", "tenant, boundary, root, member, snapshot hash, and ownership integrity violations must be zero")
	}
	if snapshot.AutomaticFixedPartialUnknown > 0 {
		block("automatic_fixed_without_coverage", "automatic Fixed claims from partial or unknown coverage must be zero")
	}
	if snapshot.ComparableItems >= 1000 {
		if snapshot.SemanticMismatches*10000 > snapshot.ComparableItems*50 {
			block("semantic_mismatch_rate", "shadow semantic mismatch rate exceeds 0.5 percent")
		}
	} else if phase == PhaseReadCutover || phase == PhaseUIDefault {
		block("comparable_sample_insufficient", "read cutover requires at least 1000 comparable items")
	} else {
		warn("comparable_sample_insufficient", "semantic mismatch rate is not authoritative before 1000 comparable items")
	}
	if snapshot.ProducerItems > 0 {
		rateBPS := snapshot.ReviewCandidates * 10000 / snapshot.ProducerItems
		thresholdBPS := 1000
		if snapshot.SevenDayReviewCandidateBaselineBPS > 0 && snapshot.SevenDayReviewCandidateBaselineBPS*2 < thresholdBPS {
			thresholdBPS = snapshot.SevenDayReviewCandidateBaselineBPS * 2
		}
		if rateBPS > thresholdBPS {
			warn("review_candidate_rate", "producer review-candidate rate exceeds its rollout alert threshold")
		}
	}
	if snapshot.APIWindowMinutes < 15 || snapshot.APIRequests == 0 {
		block("api_window_insufficient", "API error gate requires at least 15 minutes with requests")
	} else if snapshot.APIErrors*100 > snapshot.APIRequests {
		block("api_error_rate", "API error rate exceeds 1 percent over the measured window")
	}
	if snapshot.LatencyWindowMinutes < 15 {
		block("latency_window_insufficient", "latency safety gate requires at least 15 minutes")
	}
	if snapshot.CycleListP95Millis > 750 || snapshot.CycleDetailP95Millis > 1000 || snapshot.ComparisonPageP95Millis > 1000 {
		block("canary_latency_ceiling", "early-canary latency safety ceiling is exceeded")
	}
	if snapshot.ComparisonBacklog > 1000 {
		block("comparison_backlog_hard_limit", "tenant comparison backlog exceeds 1000")
	} else if snapshot.ComparisonBacklog >= 500 {
		warn("comparison_backlog_warning", "tenant comparison backlog is at or above 500")
	}
	if snapshot.OldestComparisonAgeSeconds > 900 {
		block("comparison_oldest_age", "oldest queued or generating comparison exceeds 15 minutes")
	}
	if snapshot.Comparison100KDurationSeconds > 600 {
		block("comparison_100k_duration", "100000-item comparison exceeds 10 minutes")
	}
	if snapshot.DeadLetterGrowth10Minutes > 0 && snapshot.SuccessfulRepairs10Minutes == 0 {
		block("dead_letter_growth", "dead-letter count increased for 10 minutes without successful repair")
	}
	if !snapshot.MetricsRecorded || !snapshot.ApprovalRecorded {
		block("phase_record_missing", "phase metrics and approval must both be recorded")
	}
	if phase == PhaseReadCutover || phase == PhaseUIDefault {
		if !snapshot.TargetCardinality {
			block("target_cardinality_missing", "production SLO must be measured at target cardinality")
		}
		if snapshot.CycleListP95Millis > 500 || snapshot.CycleDetailP95Millis > 750 || snapshot.ComparisonPageP95Millis > 750 {
			block("production_latency_slo", "production 500/750 millisecond read SLO is not met")
		}
		if snapshot.ProductionSLOContinuousMinutes < 30 {
			block("production_slo_window", "production read SLO must hold continuously for 30 minutes")
		}
	}
	if phase == PhaseUIDefault && !snapshot.ReadCutoverApproved {
		block("read_cutover_not_approved", "lifecycle UI default requires approved read cutover")
	}
	return finalize(decision), nil
}

func invalidSnapshotCounts(snapshot Snapshot) bool {
	values := []int{
		snapshot.IntegrityViolations, snapshot.AutomaticFixedPartialUnknown, snapshot.ComparableItems, snapshot.SemanticMismatches,
		snapshot.ProducerItems, snapshot.ReviewCandidates, snapshot.SevenDayReviewCandidateBaselineBPS, snapshot.APIRequests,
		snapshot.APIErrors, snapshot.APIWindowMinutes, snapshot.LatencyWindowMinutes, snapshot.CycleListP95Millis,
		snapshot.CycleDetailP95Millis, snapshot.ComparisonPageP95Millis, snapshot.ProductionSLOContinuousMinutes,
		snapshot.ComparisonBacklog, snapshot.OldestComparisonAgeSeconds, snapshot.Comparison100KDurationSeconds,
		snapshot.DeadLetterGrowth10Minutes, snapshot.SuccessfulRepairs10Minutes,
	}
	for _, value := range values {
		if value < 0 {
			return true
		}
	}
	return snapshot.SemanticMismatches > snapshot.ComparableItems || snapshot.ReviewCandidates > snapshot.ProducerItems || snapshot.APIErrors > snapshot.APIRequests || snapshot.SevenDayReviewCandidateBaselineBPS > 10000
}

func finalize(decision Decision) Decision {
	sort.Slice(decision.Blockers, func(left, right int) bool { return decision.Blockers[left].Code < decision.Blockers[right].Code })
	sort.Slice(decision.Warnings, func(left, right int) bool { return decision.Warnings[left].Code < decision.Warnings[right].Code })
	decision.Allowed = len(decision.Blockers) == 0
	return decision
}
