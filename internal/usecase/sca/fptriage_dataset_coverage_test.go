package sca

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestGoldenDatasetCoversRequiredClasses turns issue #388's dataset acceptance criteria into an
// enforced invariant: the shipped golden dataset must keep covering true positives, false positives,
// uncertain cases, and adversarial prompt-injection cases, and must exercise every segmentation
// dimension (language, kind, CWE, severity, framework). Without this a future dataset edit could
// silently drop a whole class and the eval would still pass while measuring less than it claims.
func TestGoldenDatasetCoversRequiredClasses(t *testing.T) {
	dataset := loadGoldenEvaluationDataset(t)
	if err := dataset.Validate(); err != nil {
		t.Fatalf("shipped golden dataset must validate: %v", err)
	}

	labels := map[AIEvaluationLabel]int{}
	adversarial := 0
	languages := map[string]struct{}{}
	kinds := map[string]struct{}{}
	cwes := map[string]struct{}{}
	severities := map[string]struct{}{}
	frameworks := map[string]struct{}{}
	for _, c := range dataset.Cases {
		labels[c.Label]++
		if c.Adversarial {
			adversarial++
		}
		languages[c.Language] = struct{}{}
		kinds[string(c.Kind)] = struct{}{}
		cwes[c.CWE] = struct{}{}
		severities[string(c.Severity)] = struct{}{}
		frameworks[c.Framework] = struct{}{}
	}

	// Every label class the issue names must be present.
	for _, want := range []AIEvaluationLabel{AIEvaluationTruePositive, AIEvaluationFalsePositive, AIEvaluationUncertain} {
		if labels[want] == 0 {
			t.Errorf("golden dataset has no %q case; issue #388 requires it", want)
		}
	}
	// Adversarial prompt-injection cases are called out explicitly; keep at least two so the class is not
	// a single easily-removed fixture.
	if adversarial < 2 {
		t.Errorf("golden dataset has %d adversarial cases; want >= 2", adversarial)
	}
	// Each segmentation dimension must have breadth, otherwise per-segment metrics are meaningless.
	for name, set := range map[string]map[string]struct{}{
		"language": languages, "kind": kinds, "cwe": cwes, "severity": severities, "framework": frameworks,
	} {
		if len(set) < 2 {
			t.Errorf("golden dataset segments too narrowly on %s (%d distinct); want >= 2", name, len(set))
		}
	}
	// The severity floor is a core promotion guard; the corpus must include a critical case so the
	// human-review floor is actually exercised.
	if _, ok := severities[string(shared.SeverityCritical)]; !ok {
		t.Errorf("golden dataset has no critical-severity case; the severity floor is unexercised")
	}
}
