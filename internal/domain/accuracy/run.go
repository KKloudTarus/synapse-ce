// Package accuracy holds the domain model for a persisted detection-accuracy regression run: the
// owned engine's precision/recall over the golden corpus, captured over time so the console can show
// a trend. It is deployment-global engine data (the corpus is fixed and self-contained), not
// tenant-scoped, so it carries no tenant id.
package accuracy

import (
	"fmt"
	"time"
)

// Metrics is a confusion-matrix summary for one accuracy reduction. The fields mirror the benchmark
// reducer's output; they are redeclared here so the domain does not depend on the usecase layer.
// Rate conventions (from the reducer): Precision = TP/(TP+FP) (1.0 when nothing produced); Recall =
// TP/(TP+FN) (1.0 when nothing expected); F1 = 2PR/(P+R) (0 when P+R==0); FalseDiscoveryRate =
// 1-Precision; FalseNegativeRate = 1-Recall.
type Metrics struct {
	TruePositives      int64
	FalsePositives     int64
	FalseNegatives     int64
	Precision          float64
	Recall             float64
	F1                 float64
	FalseDiscoveryRate float64
	FalseNegativeRate  float64
}

// GroupMetrics is the reduction for one ecosystem group within a run.
type GroupMetrics struct {
	Group   string
	Cases   int64
	Metrics Metrics
}

// Run is one persisted detection-accuracy regression run over the golden corpus.
type Run struct {
	ID            string
	RanAt         time.Time
	CorpusVersion string
	SchemaVersion string
	Cases         int
	Overall       Metrics
	Groups        []GroupMetrics
}

// New validates and returns a Run. RanAt is normalized to UTC.
func New(id string, ranAt time.Time, corpusVersion, schemaVersion string, cases int, overall Metrics, groups []GroupMetrics) (*Run, error) {
	if id == "" {
		return nil, fmt.Errorf("accuracy run: id is required")
	}
	if ranAt.IsZero() {
		return nil, fmt.Errorf("accuracy run: ranAt is required")
	}
	if corpusVersion == "" {
		return nil, fmt.Errorf("accuracy run: corpus version is required")
	}
	if cases < 0 {
		return nil, fmt.Errorf("accuracy run: cases must be non-negative")
	}
	return &Run{
		ID:            id,
		RanAt:         ranAt.UTC(),
		CorpusVersion: corpusVersion,
		SchemaVersion: schemaVersion,
		Cases:         cases,
		Overall:       overall,
		Groups:        groups,
	}, nil
}
