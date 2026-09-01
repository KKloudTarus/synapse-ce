package assessmentsnapshot

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type Comparability string

const (
	Comparable          Comparability = "comparable"
	PartiallyComparable Comparability = "partially_comparable"
	NotComparable       Comparability = "not_comparable"
)

const (
	CompareCompleteReevaluation    = "complete_re_evaluation"
	CompareBaselineIncomplete      = "baseline_coverage_incomplete"
	CompareCurrentDimensionMissing = "current_dimension_missing"
	CompareTargetMismatch          = "target_mismatch"
	CompareCurrentPartial          = "current_coverage_partial"
	CompareCurrentUnknown          = "current_coverage_unknown"
	CompareScopeChanged            = "scope_changed"
	CompareRuleOrProfileChanged    = "rule_or_profile_changed"
	CompareAdvisoryDatabaseChanged = "advisory_database_changed"
	CompareProducerVersionChanged  = "producer_version_changed"
)

type DimensionComparison struct {
	Baseline      Dimension     `json:"baseline"`
	Current       *Dimension    `json:"current,omitempty"`
	Comparability Comparability `json:"comparability"`
	ReasonCode    string        `json:"reason_code"`
}

func Compare(baseline, current *Snapshot) ([]DimensionComparison, error) {
	if baseline == nil || current == nil {
		return nil, fmt.Errorf("%w: baseline and current snapshots are required", shared.ErrValidation)
	}
	if baseline.Lifecycle == LifecycleBuilding || current.Lifecycle == LifecycleBuilding {
		return nil, fmt.Errorf("%w: only finalized snapshots are comparable", shared.ErrValidation)
	}
	if baseline.TenantID != current.TenantID || baseline.CycleID != current.CycleID {
		return nil, fmt.Errorf("%w: snapshots must belong to the same tenant and cycle", shared.ErrValidation)
	}

	currentByKey := make(map[string]Dimension, len(current.Dimensions))
	currentByProducerKind := make(map[string][]Dimension, len(current.Dimensions))
	for _, dimension := range current.Dimensions {
		currentByKey[dimensionKey(dimension)] = dimension
		key := dimension.Producer + "\x00" + dimension.FindingKind
		currentByProducerKind[key] = append(currentByProducerKind[key], dimension)
	}
	comparisons := make([]DimensionComparison, 0, len(baseline.Dimensions))
	for _, base := range baseline.Dimensions {
		candidate, found := currentByKey[dimensionKey(base)]
		if !found {
			reason := CompareCurrentDimensionMissing
			if len(currentByProducerKind[base.Producer+"\x00"+base.FindingKind]) > 0 {
				reason = CompareTargetMismatch
			}
			comparisons = append(comparisons, DimensionComparison{Baseline: base, Comparability: NotComparable, ReasonCode: reason})
			continue
		}
		state, reason := compareDimension(base, candidate)
		copyCandidate := candidate
		comparisons = append(comparisons, DimensionComparison{Baseline: base, Current: &copyCandidate, Comparability: state, ReasonCode: reason})
	}
	sort.Slice(comparisons, func(i, j int) bool {
		return dimensionKey(comparisons[i].Baseline) < dimensionKey(comparisons[j].Baseline)
	})
	return comparisons, nil
}

func compareDimension(baseline, current Dimension) (Comparability, string) {
	if current.State == CoverageUnknown {
		return NotComparable, CompareCurrentUnknown
	}
	if current.State == CoveragePartial {
		return PartiallyComparable, CompareCurrentPartial
	}
	if baseline.State != CoverageComplete {
		return PartiallyComparable, CompareBaselineIncomplete
	}
	if !equalStrings(baseline.IncludedScope, current.IncludedScope) || !equalStrings(baseline.ExcludedScope, current.ExcludedScope) {
		return PartiallyComparable, CompareScopeChanged
	}
	if !equalVersionKinds(baseline.Versions, current.Versions, scanrun.VersionRulePack, scanrun.VersionProfile) {
		return NotComparable, CompareRuleOrProfileChanged
	}
	if !equalVersionKinds(baseline.Versions, current.Versions, scanrun.VersionAdvisoryDatabase) {
		return PartiallyComparable, CompareAdvisoryDatabaseChanged
	}
	if !equalVersionKinds(baseline.Versions, current.Versions, scanrun.VersionTool, scanrun.VersionScanner, scanrun.VersionCorrelation, scanrun.VersionSchema) {
		return PartiallyComparable, CompareProducerVersionChanged
	}
	return Comparable, CompareCompleteReevaluation
}

func equalVersionKinds(left, right []Version, kinds ...scanrun.VersionKind) bool {
	allowed := make(map[scanrun.VersionKind]struct{}, len(kinds))
	for _, kind := range kinds {
		allowed[kind] = struct{}{}
	}
	project := func(values []Version) []string {
		var out []string
		for _, value := range values {
			if _, ok := allowed[value.Kind]; ok {
				out = append(out, strings.Join([]string{string(value.Kind), value.Name, value.Version, value.Digest}, "\x00"))
			}
		}
		sort.Strings(out)
		return out
	}
	return equalStrings(project(left), project(right))
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
