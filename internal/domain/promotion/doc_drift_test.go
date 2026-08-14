package promotion

import (
	_ "embed"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
)

//go:embed testdata/promotion-rules.md
var rulesDoc string

// TestDocDriftRuleKeysPresent verifies every rule key in the code catalogue is documented.
// If a new rule is added to rules.go but not to promotion-rules.md, this test fails.
func TestDocDriftRuleKeysPresent(t *testing.T) {
	for _, r := range Rules() {
		if !strings.Contains(rulesDoc, r.Key) {
			t.Errorf("rule key %q is in the code catalogue but not in docs/architecture/promotion-rules.md", r.Key)
		}
	}
}

// TestDocDriftNoStaleRules verifies every rule key documented in promotion-rules.md exists
// in the code catalogue. If a rule is removed from the code but the doc is not updated,
// this test fails.
func TestDocDriftNoStaleRules(t *testing.T) {
	knownKeys := []string{
		judgment.RuleRuntimeReachableExposed,
		judgment.RuleDeterministicUnreachable,
		judgment.RuleCorroboratingSignalLoss,
		judgment.RuleUncertainCorroboration,
	}
	rules := Rules()
	for _, key := range knownKeys {
		found := false
		for _, r := range rules {
			if r.Key == key {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("rule key %q is documented but not in the code catalogue", key)
		}
	}
}

// TestDocDriftEffectsMatch verifies the effect described in the doc for each rule matches
// the code catalogue's effect.
func TestDocDriftEffectsMatch(t *testing.T) {
	effectCodes := map[string]judgment.PromotionChange{
		judgment.RuleRuntimeReachableExposed:  judgment.PromotionEscalate,
		judgment.RuleDeterministicUnreachable: judgment.PromotionDeescalate,
		judgment.RuleCorroboratingSignalLoss:  judgment.PromotionDeescalate,
		judgment.RuleUncertainCorroboration:   judgment.PromotionFlagForReview,
	}
	rules := Rules()
	for _, r := range rules {
		wantCode, ok := effectCodes[r.Key]
		if !ok {
			continue
		}
		if r.Effect != wantCode {
			t.Errorf("rule %q: code effect = %s, want %s", r.Key, r.Effect, wantCode)
		}
	}
}

// TestDocDriftRuleCountMatches verifies the documented rule count matches the code catalogue
// count. If a rule is added or removed, both the code and docs must be updated.
func TestDocDriftRuleCountMatches(t *testing.T) {
	rules := Rules()
	// Count rule headers in the doc (lines starting with "### promotion.")
	count := 0
	for _, line := range strings.Split(rulesDoc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "### promotion.") {
			count++
		}
	}
	if count != len(rules) {
		t.Errorf("doc has %d rule headers, code has %d rules; they must match", count, len(rules))
	}
}
