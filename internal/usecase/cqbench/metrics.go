package cqbench

import "sort"

// Metric-agreement tolerances. A metric "agrees" when the engine's measure is within tolerance of the
// corpus ground truth. The tolerances are deliberately loose: the head-to-head asks "does the engine measure
// the same structure", not "does it match a reference tool to the digit", because two engines legitimately
// count cyclomatic complexity and duplicated lines with slightly different conventions.
const (
	cyclomaticTolerance  = 2 // max_cyclomatic within +/-2 complexity points
	duplicationTolerance = 3 // duplicated_lines within +/-3 lines
	coverageTolerance    = 5 // coverage_percent within +/-5 percentage points
)

// metricAggregator folds per-case ground-truth vs observed metrics into per-metric agreement counters. A
// metric is COMPARABLE for a case only when BOTH the corpus and the observation carry it; a nil on either
// side means the case does not contribute to that metric's denominator, so an engine that simply does not
// measure a metric scores neither for nor against on it.
type metricAggregator struct {
	comparable map[string]int
	agreed     map[string]int
}

func newMetricAggregator() *metricAggregator {
	return &metricAggregator{comparable: map[string]int{}, agreed: map[string]int{}}
}

func (a *metricAggregator) add(truth, observed *Metrics) {
	if truth == nil || observed == nil {
		return
	}
	a.compareInt("max_cyclomatic", truth.MaxCyclomatic, observed.MaxCyclomatic, cyclomaticTolerance)
	a.compareInt("duplicated_lines", truth.DuplicatedLines, observed.DuplicatedLines, duplicationTolerance)
	a.compareFloat("coverage_percent", truth.CoveragePercent, observed.CoveragePercent, coverageTolerance)
}

func (a *metricAggregator) compareInt(metric string, truth, observed *int, tol int) {
	if truth == nil || observed == nil {
		return
	}
	a.comparable[metric]++
	d := *truth - *observed
	if d < 0 {
		d = -d
	}
	if d <= tol {
		a.agreed[metric]++
	}
}

func (a *metricAggregator) compareFloat(metric string, truth, observed *float64, tol float64) {
	if truth == nil || observed == nil {
		return
	}
	a.comparable[metric]++
	d := *truth - *observed
	if d < 0 {
		d = -d
	}
	if d <= tol {
		a.agreed[metric]++
	}
}

func (a *metricAggregator) finalize() []MetricAgreement {
	out := make([]MetricAgreement, 0, len(a.comparable))
	for metric, comparable := range a.comparable {
		agreed := a.agreed[metric]
		ma := MetricAgreement{Metric: metric, Comparable: comparable, Agreed: agreed}
		if comparable > 0 {
			ma.Agreement = float64(agreed) / float64(comparable)
		}
		out = append(out, ma)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metric < out[j].Metric })
	return out
}
