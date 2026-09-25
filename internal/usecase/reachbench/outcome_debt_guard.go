package reachbench

import (
	"fmt"
	"sort"
)

// checkSuccessorOutcomeDebt prevents an aggregate C2 gain from hiding a per-cell
// outcome regression. A successor candidate may retain a reviewed baseline outcome
// or move that cell to the exact reviewed oracle outcome.
func checkSuccessorOutcomeDebt(candidate MeasurementReport, baseline *MeasurementReport, oracle ReachabilityOracle) []string {
	if baseline == nil {
		return []string{"successor candidate acceptance requires replayed baseline context"}
	}

	baselineOutcomes := make(map[string]Outcome, len(baseline.Observations))
	for _, observation := range baseline.Observations {
		baselineOutcomes[observationKey(observation)] = observation.Outcome
	}
	oracleOutcomes := make(map[string]Outcome, len(oracle.Cases))
	for _, item := range oracle.Cases {
		oracleOutcomes[item.CaseID] = item.Expected
	}
	executionKeys := executionKeysByObservation(candidate.ExecutionCoverage)
	reasons := make([]string, 0)
	for _, observation := range candidate.Observations {
		key := observationKey(observation)
		baselineOutcome, found := baselineOutcomes[key]
		if !found {
			reasons = append(reasons, fmt.Sprintf("successor candidate has no replayed baseline outcome at %s", executionKeys[key]))
			continue
		}
		oracleOutcome, found := oracleOutcomes[observation.CaseID]
		if !found {
			reasons = append(reasons, fmt.Sprintf("successor candidate has no reviewed oracle outcome at %s", executionKeys[key]))
			continue
		}
		if observation.Outcome != baselineOutcome && observation.Outcome != oracleOutcome {
			reasons = append(reasons, fmt.Sprintf("outcome debt regression at %s", executionKeys[key]))
		}
	}
	sort.Strings(reasons)
	return deduplicateStrings(reasons)
}

func observationKey(observation MeasuredObservation) string {
	return observation.CaseID + "\x00" + observation.BindingID
}

func executionKeysByObservation(coverage []ExecutionCoverage) map[string]string {
	keys := make(map[string]string, len(coverage))
	for _, item := range coverage {
		keys[item.CaseID+"\x00"+item.BindingID] = executionCoverageKey(item)
	}
	return keys
}
