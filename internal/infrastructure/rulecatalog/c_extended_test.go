package rulecatalog

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestCExtendedRules(t *testing.T) {
	rules := cExtendedRules()
	if len(rules) == 0 {
		t.Fatal("cExtendedRules() returned no rules")
	}

	seen := map[rule.Key]bool{}
	familyCounts := map[string]int{}

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
		if r.Language != "C" {
			t.Errorf("rule %s has Language=%s, want C", r.Key, r.Language)
		}
		if r.Description == "" {
			t.Errorf("rule %s has empty Description", r.Key)
		}
		if r.Rationale == "" {
			t.Errorf("rule %s has empty Rationale", r.Key)
		}
		if !strings.Contains(r.Rationale, "https://") && !strings.Contains(r.Rationale, "http://") {
			t.Errorf("rule %s Rationale missing reference URL: %s", r.Key, r.Rationale)
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
		if len(r.Qualities) == 0 {
			t.Errorf("rule %s has no Qualities", r.Key)
		}
		if r.DefaultSeverity != shared.SeverityLow && r.DefaultSeverity != shared.SeverityMedium &&
			r.DefaultSeverity != shared.SeverityHigh && r.DefaultSeverity != shared.SeverityCritical &&
			r.DefaultSeverity != shared.SeverityInfo {
			t.Errorf("rule %s has invalid DefaultSeverity: %s", r.Key, r.DefaultSeverity)
		}

		for _, tag := range r.Tags {
			if strings.HasPrefix(tag, "c-") {
				familyCounts[strings.TrimPrefix(tag, "c-")]++
			}
		}
	}

	expectedFamilies := []string{"memory", "format", "types", "nullchecks", "async", "crypto", "maintainability"}
	for _, fam := range expectedFamilies {
		if familyCounts[fam] == 0 {
			t.Errorf("expected at least one rule in family %q, got 0", fam)
		}
	}
}
