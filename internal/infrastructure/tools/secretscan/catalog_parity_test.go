package secretscan

import (
	"context"
	"testing"

	domainrule "github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func TestCatalogParity(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Failed to load catalog: %v", err)
	}

	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("Failed to list catalog: %v", err)
	}

	catalogMap := make(map[string]domainrule.Rule)
	for _, r := range rules {
		catalogMap[string(r.Key)] = r
	}

	expectedCWE := map[string]string{
		"aws-access-key-id": "CWE-798",
		"github-token":      "CWE-798",
		"gitlab-pat":        "CWE-798",
		"slack-token":       "CWE-798",
		"google-api-key":    "CWE-798",
		"private-key":       "CWE-321",
		"jwt":               "CWE-798",
		"generic-secret":    "CWE-798",
	}
	builtin := defaultRules()
	seenInBuiltin := make(map[string]bool, len(builtin))

	for _, tc := range builtin {
		if seenInBuiltin[tc.id] {
			t.Errorf("Duplicate secret scanner rule: %s", tc.id)
			continue
		}
		seenInBuiltin[tc.id] = true
		if _, ok := expectedCWE[tc.id]; !ok {
			t.Errorf("Unexpected secret scanner rule: %s", tc.id)
			continue
		}
		catRule, ok := catalogMap[tc.id]
		if !ok {
			t.Errorf("Rule %s missing from catalog", tc.id)
			continue
		}

		if catRule.Name != tc.title {
			t.Errorf("Rule %s Title mismatch: catalog=%q engine=%q", tc.id, catRule.Name, tc.title)
		}
		if catRule.DefaultSeverity != tc.severity {
			t.Errorf("Rule %s Severity mismatch: catalog=%v engine=%v", tc.id, catRule.DefaultSeverity, tc.severity)
		}

		// Contract assertions
		if catRule.Language != "Secrets" {
			t.Errorf("Rule %s Language mismatch: expected Secrets", tc.id)
		}
		if catRule.Type != domainrule.TypeVulnerability {
			t.Errorf("Rule %s Type mismatch: expected Vulnerability", tc.id)
		}
		if len(catRule.Qualities) != 1 || catRule.Qualities[0] != domainrule.QualitySecurity {
			t.Errorf("Rule %s Quality mismatch: expected exactly Security", tc.id)
		}
		if catRule.Detection != domainrule.DetectionPattern {
			t.Errorf("Rule %s Detection mode mismatch: expected Pattern", tc.id)
		}

		// CWE parity
		expected := expectedCWE[tc.id]
		if expected == "" {
			t.Errorf("Rule %s has no mapped expected CWE", tc.id)
			continue
		}

		foundCWE := false
		for _, cwe := range catRule.CWE {
			if cwe == expected {
				foundCWE = true
				break
			}
		}
		if !foundCWE {
			t.Errorf("Rule %s CWE mismatch: expected %s, got %v", tc.id, expected, catRule.CWE)
		}
	}

	for id := range expectedCWE {
		if !seenInBuiltin[id] {
			t.Errorf("Expected secret scanner rule missing: %s", id)
		}
	}

	// Assert no extra secret entries
	for _, r := range rules {
		if r.Language == "Secrets" && !seenInBuiltin[string(r.Key)] {
			t.Errorf("Extra stale Secrets entry in catalog: %s", r.Key)
		}
	}
}
