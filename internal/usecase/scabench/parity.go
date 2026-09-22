package scabench

import (
	"fmt"
	"sort"
	"strings"
)

// The owned-only default is justified only when the owned engine does not lose recall to any pinned comparator on
// the same independent-oracle matrix. Meeting an absolute recall floor is necessary but not sufficient: if Grype,
// Trivy, or OSV-Scanner out-recalls Owned, shipping owned-only would silently lower detection, so the flip remains
// blocked. This relative gate is distinct from the absolute per-engine floors the ratchet enforces.

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

// ValidateMeasuredPerTargetRecallParity requires every expected target to have one measured cell for each
// benchmark engine. A supported comparator may not out-recall the owned engine. An unsupported comparator is
// excluded only when its run has a validated capability identity and the unsupported-only metric shape.
func ValidateMeasuredPerTargetRecallParity(result Result, targetIDs []string) error {
	targets := make(map[string]struct{}, len(targetIDs))
	for _, targetID := range targetIDs {
		if strings.TrimSpace(targetID) == "" {
			return fmt.Errorf("scabench: measured recall parity target is required")
		}
		if _, exists := targets[targetID]; exists {
			return fmt.Errorf("scabench: measured recall parity target %q is duplicated", targetID)
		}
		targets[targetID] = struct{}{}
	}
	if len(targets) == 0 {
		return fmt.Errorf("scabench: measured recall parity requires at least one target")
	}
	if want := len(targets) * len(Engines()); len(result.RunMetrics) != want {
		return fmt.Errorf("scabench: measured recall parity has %d run metrics, want %d", len(result.RunMetrics), want)
	}

	cells := make(map[observationKey]RunMetric, len(result.RunMetrics))
	for index, metric := range result.RunMetrics {
		if _, expected := targets[metric.Run.TargetID]; !expected {
			return fmt.Errorf("scabench: measured recall parity run metric %d has unexpected target %q", index, metric.Run.TargetID)
		}
		if !metric.Run.Engine.valid() || !metric.Run.State.valid() {
			return fmt.Errorf("scabench: measured recall parity run metric %d has unsupported engine or state", index)
		}
		if metric.Metrics.Engine != metric.Run.Engine {
			return fmt.Errorf("scabench: measured recall parity run metric %d engine does not match its run", index)
		}
		if err := validateEngineResult(metric.Metrics); err != nil {
			return fmt.Errorf("scabench: measured recall parity run metric %d is malformed: %w", index, err)
		}
		if metric.Run.State == ObservationUnsupported {
			if err := validateRequiredCapabilityIdentity(metric.Run.CapabilityKind, metric.Run.CapabilityDigest); err != nil {
				return fmt.Errorf("scabench: measured recall parity unsupported run metric %d capability: %w", index, err)
			}
			capabilityEngine, _ := capabilityKindEngine(metric.Run.CapabilityKind)
			if metric.Run.Engine != capabilityEngine {
				return fmt.Errorf("scabench: measured recall parity unsupported run metric %d capability does not apply to engine %q", index, metric.Run.Engine)
			}
		} else if metric.Run.CapabilityKind != "" || metric.Run.CapabilityDigest != "" {
			return fmt.Errorf("scabench: measured recall parity supported run metric %d carries a capability identity", index)
		}
		key := observationKey{Engine: metric.Run.Engine, TargetID: metric.Run.TargetID}
		if _, exists := cells[key]; exists {
			return fmt.Errorf("scabench: measured recall parity cell for engine %q target %q is duplicated", key.Engine, key.TargetID)
		}
		cells[key] = metric
	}

	for _, targetID := range targetIDs {
		owned, err := measuredRecallCell(cells, targetID, EngineOwned)
		if err != nil {
			return err
		}
		for _, engine := range Engines() {
			if engine == EngineOwned {
				continue
			}
			comparator, err := measuredRecallCell(cells, targetID, engine)
			if err != nil {
				return err
			}
			switch comparator.Run.State {
			case ObservationUnsupported:
				if !comparator.Metrics.MetricsComplete || !hasUnsupportedOnlyMetricShape(comparator.Metrics) {
					return fmt.Errorf("scabench: measured recall parity comparator %q target %q has malformed unsupported metrics", engine, targetID)
				}
				continue
			case ObservationComplete:
				if !comparator.Metrics.MetricsComplete || comparator.Metrics.Recall == nil {
					return fmt.Errorf("scabench: measured recall parity comparator %q target %q has incomplete recall", engine, targetID)
				}
			default:
				return fmt.Errorf("scabench: measured recall parity comparator %q target %q is %q rather than complete or unsupported", engine, targetID, comparator.Run.State)
			}
			if *comparator.Metrics.Recall > *owned.Metrics.Recall {
				return fmt.Errorf("scabench: measured recall parity comparator %q target %q recall %.4f exceeds owned recall %.4f", engine, targetID, *comparator.Metrics.Recall, *owned.Metrics.Recall)
			}
		}
	}
	return nil
}

func measuredRecallCell(cells map[observationKey]RunMetric, targetID string, engine Engine) (RunMetric, error) {
	metric, exists := cells[observationKey{Engine: engine, TargetID: targetID}]
	if !exists {
		return RunMetric{}, fmt.Errorf("scabench: measured recall parity cell for engine %q target %q is missing", engine, targetID)
	}
	if engine != EngineOwned {
		return metric, nil
	}
	if metric.Run.State != ObservationComplete || !metric.Metrics.MetricsComplete || metric.Metrics.Recall == nil {
		return RunMetric{}, fmt.Errorf("scabench: measured recall parity owned target %q has incomplete recall", targetID)
	}
	return metric, nil
}
