package accuracyeval

import (
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/accuracy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

// ToRun maps a reduced accuracy report into a persistable domain Run, stamping the run id, time, and
// the embedded corpus version.
func ToRun(id string, ranAt time.Time, rep benchmark.AccuracyReport) (accuracy.Run, error) {
	groups := make([]accuracy.GroupMetrics, 0, len(rep.Groups))
	for _, g := range rep.Groups {
		groups = append(groups, accuracy.GroupMetrics{Group: g.Group, Cases: g.Cases, Metrics: toMetrics(g.Metrics)})
	}
	run, err := accuracy.New(id, ranAt, CorpusVersion, rep.SchemaVersion, int(rep.Cases), toMetrics(rep.Overall), groups)
	if err != nil {
		return accuracy.Run{}, err
	}
	return *run, nil
}

func toMetrics(m benchmark.Metrics) accuracy.Metrics {
	return accuracy.Metrics{
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
