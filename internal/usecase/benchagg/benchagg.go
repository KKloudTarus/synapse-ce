// Package benchagg aggregates the per-dimension accuracy results of the owned scanner benchmark dimensions
// (secrets, IaC/misconfiguration, DAST, CSPM, runtime host-CVE, SAST per-CWE) into one machine-readable
// report WITHOUT erasing per-dimension semantics. This is the #1040 aggregation contract: each dimension
// defines its own truth (what a true/false positive and negative mean for that dimension), so the aggregate
// keeps every dimension as its own row carrying its own metric semantics and never computes a single
// cross-dimension confusion matrix, which would conflate, say, a secrets true-positive with a CSPM one. The
// overall verdict is the CONJUNCTION of each dimension meeting its committed floors, not a merged matrix.
package benchagg

import (
	"encoding/json"
	"fmt"
	"sort"
)

// ReportSchemaVersion tags the serialized aggregate so a checked-in artifact is never compared across an
// incompatible schema.
const ReportSchemaVersion = "synapse-bench-aggregate-v1"

// MetricSemantics records what a dimension's confusion matrix MEANS, so the aggregate never applies one
// dimension's definition of a positive to another. Dimension is a stable id (e.g. "secrets", "cspm");
// Positive states what a positive case is; Unit is the counted entity (finding, resource, observation).
type MetricSemantics struct {
	Dimension string `json:"dimension"`
	Positive  string `json:"positive"`
	Unit      string `json:"unit"`
}

// DimensionResult is one dimension's confusion matrix plus its committed floors. It carries its own semantics,
// so a caller reduces each owned dimension gate into this shape and the aggregate never mixes them.
type DimensionResult struct {
	Semantics      MetricSemantics
	TP             int
	FP             int
	FN             int
	TN             int
	RecallFloor    float64
	PrecisionFloor float64
}

// Recall is TP / (TP + FN); 0 when there are no positive cases (no recall is defined, reported as 0).
func (d DimensionResult) Recall() float64 { return ratio(d.TP, d.TP+d.FN) }

// Precision is TP / (TP + FP); 0 when nothing was flagged (no precision is defined, reported as 0).
func (d DimensionResult) Precision() float64 { return ratio(d.TP, d.TP+d.FP) }

// MeetsFloors reports whether this dimension's recall and precision are at or above its committed floors. A
// floor of 0 is vacuously met (the dimension does not gate that metric).
func (d DimensionResult) MeetsFloors() bool {
	return d.Recall() >= d.RecallFloor && d.Precision() >= d.PrecisionFloor
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

// DimensionRow is one dimension's serialized row in the aggregate: its semantics, its matrix, its derived
// metrics, its floors, and whether it met them. Nothing here is merged across dimensions.
type DimensionRow struct {
	Dimension      string  `json:"dimension"`
	Positive       string  `json:"positive"`
	Unit           string  `json:"unit"`
	TP             int     `json:"tp"`
	FP             int     `json:"fp"`
	FN             int     `json:"fn"`
	TN             int     `json:"tn"`
	Recall         float64 `json:"recall"`
	Precision      float64 `json:"precision"`
	RecallFloor    float64 `json:"recall_floor"`
	PrecisionFloor float64 `json:"precision_floor"`
	FloorsMet      bool    `json:"floors_met"`
}

// Report is the machine-readable aggregate: per-dimension rows (semantics preserved) and the overall
// all-floors-met conjunction. It carries no cross-dimension confusion matrix by design.
type Report struct {
	Schema       string         `json:"schema"`
	Dimensions   []DimensionRow `json:"dimensions"`
	AllFloorsMet bool           `json:"all_floors_met"`
}

// Aggregate reduces per-dimension results into one report, preserving each dimension's semantics. It refuses a
// duplicate or empty dimension id (a machine-readable aggregate must address each dimension unambiguously) and
// sorts the rows by dimension id for a deterministic artifact. AllFloorsMet is the conjunction over dimensions.
func Aggregate(results []DimensionResult) (Report, error) {
	if len(results) == 0 {
		return Report{}, fmt.Errorf("benchagg: no dimension results to aggregate")
	}
	seen := map[string]bool{}
	rows := make([]DimensionRow, 0, len(results))
	all := true
	for _, r := range results {
		id := r.Semantics.Dimension
		if id == "" {
			return Report{}, fmt.Errorf("benchagg: a dimension result has an empty dimension id")
		}
		if seen[id] {
			return Report{}, fmt.Errorf("benchagg: duplicate dimension id %q (each dimension must be aggregated once)", id)
		}
		seen[id] = true
		met := r.MeetsFloors()
		all = all && met
		rows = append(rows, DimensionRow{
			Dimension:      id,
			Positive:       r.Semantics.Positive,
			Unit:           r.Semantics.Unit,
			TP:             r.TP,
			FP:             r.FP,
			FN:             r.FN,
			TN:             r.TN,
			Recall:         r.Recall(),
			Precision:      r.Precision(),
			RecallFloor:    r.RecallFloor,
			PrecisionFloor: r.PrecisionFloor,
			FloorsMet:      met,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Dimension < rows[j].Dimension })
	return Report{Schema: ReportSchemaVersion, Dimensions: rows, AllFloorsMet: all}, nil
}

// MarshalJSON renders the aggregate as the machine-readable artifact.
func (r Report) MarshalJSON() ([]byte, error) {
	type alias Report // avoid recursion
	return json.Marshal(alias(r))
}

// FailingDimensions returns the ids of the dimensions that did not meet their floors, sorted, so a CI gate can
// name exactly which dimension regressed without collapsing the per-dimension detail.
func (r Report) FailingDimensions() []string {
	var out []string
	for _, d := range r.Dimensions {
		if !d.FloorsMet {
			out = append(out, d.Dimension)
		}
	}
	sort.Strings(out)
	return out
}
