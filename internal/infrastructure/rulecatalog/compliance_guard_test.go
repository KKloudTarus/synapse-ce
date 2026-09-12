package rulecatalog

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/compliance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
)

// Every rule key the compliance package maps a CIS control to must be a real, current misconfiguration rule.
// This guards against a rule rename silently dropping its CIS mapping (the mapping would fail-open to nothing
// and quietly lose compliance coverage). (EPIC #860 D6.6)
func TestComplianceMappedRuleKeysExist(t *testing.T) {
	keys := map[rule.Key]bool{}
	for _, r := range misconfigRules() {
		keys[r.Key] = true
	}
	mapped := compliance.MappedRuleKeys()
	if len(mapped) == 0 {
		t.Fatal("compliance.MappedRuleKeys() is empty")
	}
	for _, k := range mapped {
		if !keys[rule.Key(k)] {
			t.Errorf("compliance maps a CIS control to rule %q, but no such misconfiguration rule exists (renamed/removed?)", k)
		}
	}
}
