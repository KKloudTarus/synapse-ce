package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/accuracy"
)

// accuracyRunReader is the narrow read side the HTTP layer needs for the detection-accuracy console
// trend: the most recent regression runs over the golden corpus, newest first. The postgres/memory
// AccuracyRunStore satisfies it. Engine accuracy is deployment-global, so there is no tenant scoping.
type accuracyRunReader interface {
	Recent(ctx context.Context, limit int) ([]accuracy.Run, error)
}

// SetAccuracyReader wires the read route for the engine-accuracy trend (EPIC #860 D8.6). Left unset,
// the route returns an empty list rather than 500 — the nightly job is simply not enabled.
func (rt *Router) SetAccuracyReader(r accuracyRunReader) {
	if r != nil {
		rt.accuracyRuns = r
	}
}

type accuracyMetricsDTO struct {
	TruePositives      int64   `json:"true_positives"`
	FalsePositives     int64   `json:"false_positives"`
	FalseNegatives     int64   `json:"false_negatives"`
	Precision          float64 `json:"precision"`
	Recall             float64 `json:"recall"`
	F1                 float64 `json:"f1"`
	FalseDiscoveryRate float64 `json:"false_discovery_rate"`
	FalseNegativeRate  float64 `json:"false_negative_rate"`
}

type accuracyGroupDTO struct {
	Group   string             `json:"group"`
	Cases   int64              `json:"cases"`
	Metrics accuracyMetricsDTO `json:"metrics"`
}

type accuracyRunDTO struct {
	ID            string             `json:"id"`
	RanAt         string             `json:"ran_at"`
	CorpusVersion string             `json:"corpus_version"`
	SchemaVersion string             `json:"schema_version"`
	Cases         int                `json:"cases"`
	Overall       accuracyMetricsDTO `json:"overall"`
	Groups        []accuracyGroupDTO `json:"groups"`
}

func toAccuracyMetricsDTO(m accuracy.Metrics) accuracyMetricsDTO {
	return accuracyMetricsDTO{
		TruePositives:      m.TruePositives,
		FalsePositives:     m.FalsePositives,
		FalseNegatives:     m.FalseNegatives,
		Precision:          m.Precision,
		Recall:             m.Recall,
		F1:                 m.F1,
		FalseDiscoveryRate: m.FalseDiscoveryRate,
		FalseNegativeRate:  m.FalseNegativeRate,
	}
}

func toAccuracyRunDTO(run accuracy.Run) accuracyRunDTO {
	groups := make([]accuracyGroupDTO, 0, len(run.Groups))
	for _, g := range run.Groups {
		groups = append(groups, accuracyGroupDTO{Group: g.Group, Cases: g.Cases, Metrics: toAccuracyMetricsDTO(g.Metrics)})
	}
	return accuracyRunDTO{
		ID:            run.ID,
		RanAt:         run.RanAt.UTC().Format(time.RFC3339),
		CorpusVersion: run.CorpusVersion,
		SchemaVersion: run.SchemaVersion,
		Cases:         run.Cases,
		Overall:       toAccuracyMetricsDTO(run.Overall),
		Groups:        groups,
	}
}

// listAccuracyRuns returns recent detection-accuracy regression runs (newest first) for the console
// trend. Engine-global (not engagement-scoped); PermView. When unwired it returns an empty list, not
// a 500, consistent with the read being optional.
func (rt *Router) listAccuracyRuns(w http.ResponseWriter, r *http.Request) {
	if rt.accuracyRuns == nil {
		writeJSON(w, http.StatusOK, map[string]any{"runs": []accuracyRunDTO{}})
		return
	}
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	runs, err := rt.accuracyRuns.Recent(r.Context(), limit)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]accuracyRunDTO, 0, len(runs))
	for _, run := range runs {
		out = append(out, toAccuracyRunDTO(run))
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": out})
}
