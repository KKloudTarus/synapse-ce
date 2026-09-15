package sast

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulemeta"
)

func TestCanonicalBuiltinRulesRetiresReviewedAliases(t *testing.T) {
	rules := canonicalBuiltinRules(builtinRules())
	seen := make(map[string]rule, len(rules))
	for _, entry := range rules {
		seen[entry.id] = entry
	}

	for _, pair := range rulemeta.SemanticAliases() {
		if _, ok := seen[pair.Alias]; ok {
			t.Errorf("legacy semantic alias %s still runs in production", pair.Alias)
		}
		if _, ok := seen[pair.Canonical]; !ok {
			t.Errorf("canonical detector %s missing after alias reconciliation", pair.Canonical)
		}
	}
}

func TestCanonicalBuiltinRulesAppliesReviewedDisplayNames(t *testing.T) {
	rules := canonicalBuiltinRules(builtinRules())
	want := map[string]string{
		"php:get-magic-quotes": "Removed get_magic_quotes_gpc API",
		"php:set-magic-quotes": "Removed set_magic_quotes_runtime API",
	}
	for _, entry := range rules {
		if expected, ok := want[entry.id]; ok {
			if entry.title != expected {
				t.Errorf("rule %s title = %q, want %q", entry.id, entry.title, expected)
			}
			delete(want, entry.id)
		}
	}
	for key := range want {
		t.Errorf("expected rule %s was not present", key)
	}
}
