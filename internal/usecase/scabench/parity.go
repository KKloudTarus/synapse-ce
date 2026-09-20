package scabench

import (
	"fmt"
	"sort"
)

// parity.go is the #1037 market-leading flip guard. The owned-only default (ownsbom + ownadvisory, no
// syft/grype) is justified only when the owned engine does not LOSE recall to any pinned comparator on the same
// independent-oracle matrix. Meeting an absolute recall floor is necessary but NOT sufficient: if grype, trivy,
// or osv-scanner out-recalls owned, shipping owned-only would silently lower detection, so the flip must stay
// blocked. This is the relative gate the EPIC #1034 amendment requires, distinct from the absolute per-engine
// floors the ratchet enforces.

// RecallParity is the outcome of the owned-vs-comparators recall comparison on one result.
type RecallParity struct {
	// OwnedRecall is the owned engine's aggregate recall on the matrix.
	OwnedRecall float64
	// Breaches names each comparator whose recall exceeds owned's (empty when owned meets or beats all measured
	// comparators), sorted for a deterministic report.
	Breaches []string
	// ComparedEngines lists the comparators actually measured and compared, so a reader sees the gate was not
	// vacuously satisfied by an absent comparator.
	ComparedEngines []Engine
}

// OwnedBeatsEachComparator reports whether the owned engine's recall is at least that of every measured
// comparator engine on the result, and returns the detail. It fails closed: if the owned engine is absent or its
// metrics are incomplete, the recall is not defined and the flip cannot be justified, so it returns an error
// (ok is false). A comparator whose metrics are incomplete (it was not run on this matrix) is not a pinned
// baseline for this result and is skipped, recorded in ComparedEngines only when compared. Recall parity (equal
// recall) passes; a comparator strictly out-recalling owned is a breach.
func OwnedBeatsEachComparator(result Result) (ok bool, detail RecallParity, err error) {
	byEngine := make(map[Engine]EngineResult, len(result.Engines))
	for _, e := range result.Engines {
		byEngine[e.Engine] = e
	}
	owned, present := byEngine[EngineOwned]
	if !present || !owned.MetricsComplete || owned.Recall == nil {
		return false, RecallParity{}, fmt.Errorf("scabench: owned recall is undefined (engine present=%v, metrics complete=%v); the owned-only flip cannot be justified", present, present && owned.MetricsComplete)
	}
	detail.OwnedRecall = *owned.Recall
	for _, engine := range Engines() {
		if engine == EngineOwned {
			continue
		}
		comp, ok := byEngine[engine]
		if !ok || !comp.MetricsComplete || comp.Recall == nil {
			// Not measured on this matrix: not a pinned baseline for this result, so it cannot be compared.
			continue
		}
		detail.ComparedEngines = append(detail.ComparedEngines, engine)
		if *comp.Recall > *owned.Recall {
			detail.Breaches = append(detail.Breaches, fmt.Sprintf("%s recall %.4f exceeds owned recall %.4f", engine, *comp.Recall, *owned.Recall))
		}
	}
	sort.Strings(detail.Breaches)
	return len(detail.Breaches) == 0, detail, nil
}
