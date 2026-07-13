package sast

import (
	"context"
	"strings"
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

	builtin := builtinRules()
	if len(builtin) == 0 {
		t.Fatalf("builtinRules() is empty")
	}

	seenInBuiltin := make(map[string]bool)

	for _, tc := range builtin {
		seenInBuiltin[tc.id] = true
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

		var explicitSASTLanguages = map[string]string{
			"go-sql-dynamic-query": "Go",
			"go-command-dynamic":   "Go",
			"go-ssrf-dynamic-url":  "Go",
		}

		expectedLang := ""

		switch {
		case tc.exts != nil && tc.exts[".js"]:
			expectedLang = "JavaScript/TypeScript"
		case tc.exts != nil && tc.exts[".py"]:
			expectedLang = "Python"
		case tc.exts != nil && tc.exts[".c"]:
			expectedLang = "C/C++/Objective-C"
		case explicitSASTLanguages[tc.id] != "":
			expectedLang = explicitSASTLanguages[tc.id]
		default:
			expectedLang = "General"
		}

		if expectedLang != "" && catRule.Language != expectedLang {
			t.Errorf("Rule %s Language mismatch: catalog=%q expected=%q", tc.id, catRule.Language, expectedLang)
		}

		// Existing CWE
		if tc.cwe != "" {
			found := false
			for _, cwe := range catRule.CWE {
				if cwe == tc.cwe {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Rule %s CWE mismatch: catalog has %v, engine expects %q", tc.id, catRule.CWE, tc.cwe)
			}
		}

		// Contract assertions
		if catRule.Detection != domainrule.DetectionPattern {
			t.Errorf("Rule %s Detection mode mismatch: expected Pattern", tc.id)
		}
		if catRule.Type != domainrule.TypeVulnerability {
			t.Errorf("Rule %s Type mismatch: expected Vulnerability", tc.id)
		}
		if len(catRule.Qualities) != 1 || catRule.Qualities[0] != domainrule.QualitySecurity {
			t.Errorf("Rule %s Quality mismatch: expected exactly Security", tc.id)
		}

		// Example parity verification
		// The noncompliant example must match the regex (and not be skipped).
		if catRule.NoncompliantExample != "" {
			lines := strings.Split(catRule.NoncompliantExample, "\n")
			matched := false
			for _, line := range lines {
				if tc.re.MatchString(line) && !tc.skip(line) {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("Rule %s: Noncompliant example does not trigger the detector", tc.id)
			}
		}

		// The compliant example must not match the regex (or must be skipped).
		if catRule.CompliantExample != "" {
			lines := strings.Split(catRule.CompliantExample, "\n")
			for _, line := range lines {
				if tc.re.MatchString(line) && !tc.skip(line) {
					t.Errorf("Rule %s: Compliant example incorrectly triggers the detector", tc.id)
				}
			}
		}
	}

	// Assert exact subset parity (no extra stale SAST entries)
	for _, r := range rules {
		// Identify SAST rules via a known tag or prefix, or just check those that don't match other engines
		// The builtin rules cover all SAST. We can identify a catalog rule as SAST if it's not in builtin
		// but has the "sast" tag.
		isSast := false
		for _, tag := range r.Tags {
			if tag == "sast" {
				isSast = true
				break
			}
		}

		if isSast && !seenInBuiltin[string(r.Key)] {
			t.Errorf("Extra stale SAST entry in catalog: %s", r.Key)
		}
	}
}
