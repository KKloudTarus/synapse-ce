package rulecatalog

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
)

func TestCPPExtendedRules(t *testing.T) {
	rules := cppExtendedRules()
	if len(rules) == 0 {
		t.Fatal("cppExtendedRules() returned no rules")
	}

	seen := map[rule.Key]bool{}
	for _, r := range rules {
		if r.Key == "" {
			t.Error("found rule with empty Key")
		}
		if seen[r.Key] {
			t.Errorf("duplicate rule key: %s", r.Key)
		}
		seen[r.Key] = true

		if r.Name == "" {
			t.Errorf("rule %s has empty Name", r.Key)
		}
		if r.Language != "C++" {
			t.Errorf("rule %s has Language=%s, want C++", r.Key, r.Language)
		}
		if r.Description == "" {
			t.Errorf("rule %s has empty Description", r.Key)
		}
		if r.Rationale == "" {
			t.Errorf("rule %s has empty Rationale", r.Key)
		}
		if r.Remediation == "" {
			t.Errorf("rule %s has empty Remediation", r.Key)
		}
		if r.CompliantExample == "" {
			t.Errorf("rule %s has empty CompliantExample", r.Key)
		}
		if r.NoncompliantExample == "" {
			t.Errorf("rule %s has empty NoncompliantExample", r.Key)
		}
		if r.Detection != rule.DetectionAST {
			t.Errorf("rule %s has Detection=%s, want DetectionAST", r.Key, r.Detection)
		}
	}
}
