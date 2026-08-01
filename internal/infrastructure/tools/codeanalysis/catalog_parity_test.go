package codeanalysis

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
		t.Fatal("builtinRules() is empty")
	}

	for _, tc := range builtin {
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

		// Contract for CodeAnalysis
		if tc.id == "quality-todo-comment" || tc.id == "quality-commented-out-code" {
			if catRule.Type != domainrule.TypeCodeSmell {
				t.Errorf("Rule %s Type mismatch: expected CodeSmell", tc.id)
			}
			if len(catRule.Qualities) != 1 || catRule.Qualities[0] != domainrule.QualityMaintainability {
				t.Errorf("Rule %s Quality mismatch: expected Maintainability", tc.id)
			}
			if catRule.Detection != domainrule.DetectionPattern {
				t.Errorf("Rule %s Detection mode mismatch: expected Pattern", tc.id)
			}
		}

		if tc.id == "reliability-empty-catch" || tc.id == "reliability-self-assignment" || tc.id == "reliability-self-comparison" {
			if catRule.Type != domainrule.TypeBug {
				t.Errorf("Rule %s Type mismatch: expected Bug", tc.id)
			}
			if len(catRule.Qualities) != 1 || catRule.Qualities[0] != domainrule.QualityReliability {
				t.Errorf("Rule %s Quality mismatch: expected Reliability", tc.id)
			}
			if catRule.Detection != domainrule.DetectionPattern {
				t.Errorf("Rule %s Detection mode mismatch: expected Pattern", tc.id)
			}
		}

		if tc.id == "quality-commented-out-code" {
			continue // multiline heuristic
		}

		for _, line := range strings.Split(catRule.NoncompliantExample, "\n") {
			if strings.TrimSpace(line) != "" && tc.hit(line) {
				goto non_ok
			}
		}
		t.Errorf("Rule %s noncompliant example does not trigger detector", tc.id)
	non_ok:

		for _, line := range strings.Split(catRule.CompliantExample, "\n") {
			if strings.TrimSpace(line) != "" && tc.hit(line) {
				t.Errorf("Rule %s compliant example unexpectedly triggered detector", tc.id)
				break
			}
		}
	}

	seenXML := map[string]bool{}
	for _, tc := range builtinXMLRules() {
		seenXML[tc.id] = true
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
		if catRule.Language != "XML" {
			t.Errorf("Rule %s Language mismatch: expected XML", tc.id)
		}
		if catRule.Type != tc.ruleType {
			t.Errorf("Rule %s Type mismatch: catalog=%v engine=%v", tc.id, catRule.Type, tc.ruleType)
		}
		if len(catRule.Qualities) != 1 || catRule.Qualities[0] != tc.quality {
			t.Errorf("Rule %s Quality mismatch: catalog=%v engine=%v", tc.id, catRule.Qualities, tc.quality)
		}
		if catRule.Detection != domainrule.DetectionParse {
			t.Errorf("Rule %s Detection mode mismatch: expected Parse", tc.id)
		}

		matched := false
		for _, f := range scanXMLFile("fixture.xml", []byte(catRule.NoncompliantExample)) {
			if f.RuleID == tc.id {
				matched = true
				if f.Title != tc.title {
					t.Errorf("Rule %s Title mismatch in finding: got %q", tc.id, f.Title)
				}
				if f.Severity != tc.severity {
					t.Errorf("Rule %s Severity mismatch in finding: got %v", tc.id, f.Severity)
				}
				if f.Kind != tc.kind {
					t.Errorf("Rule %s Kind mismatch in finding: got %q expected %q", tc.id, f.Kind, tc.kind)
				}
				if f.CWE != tc.cwe {
					t.Errorf("Rule %s CWE mismatch in finding: got %q expected %q", tc.id, f.CWE, tc.cwe)
				}
			}
		}
		if !matched {
			t.Errorf("Rule %s noncompliant example does not trigger detector", tc.id)
		}

		for _, f := range scanXMLFile("fixture.xml", []byte(catRule.CompliantExample)) {
			if f.RuleID == tc.id {
				t.Errorf("Rule %s compliant example unexpectedly triggered detector", tc.id)
			}
		}
	}

	// -- Text engine parity ---------------------------------------------------
	textBuiltin := builtinTextRules()
	seenText := map[string]bool{}
	for _, tc := range textBuiltin {
		seenText[tc.id] = true
		catRule, ok := catalogMap[tc.id]
		if !ok {
			t.Errorf("Text rule %s missing from catalog", tc.id)
			continue
		}

		if catRule.Name != tc.title {
			t.Errorf("Text rule %s Title mismatch: catalog=%q engine=%q", tc.id, catRule.Name, tc.title)
		}
		if catRule.DefaultSeverity != tc.severity {
			t.Errorf("Text rule %s Severity mismatch: catalog=%v engine=%v", tc.id, catRule.DefaultSeverity, tc.severity)
		}
		if catRule.Language != "Text" {
			t.Errorf("Text rule %s Language mismatch: expected Text", tc.id)
		}
		if catRule.Type != tc.ruleType {
			t.Errorf("Text rule %s Type mismatch: catalog=%v engine=%v", tc.id, catRule.Type, tc.ruleType)
		}
		if len(catRule.Qualities) != 1 || catRule.Qualities[0] != tc.quality {
			t.Errorf("Text rule %s Quality mismatch: catalog=%v engine=%v", tc.id, catRule.Qualities, tc.quality)
		}
		if catRule.Detection != domainrule.DetectionPattern {
			t.Errorf("Text rule %s Detection mode mismatch: expected Pattern", tc.id)
		}
		if tc.cwe != "" && (len(catRule.CWE) == 0 || catRule.CWE[0] != tc.cwe) {
			t.Errorf("Text rule %s CWE mismatch: catalog=%v engine=%v", tc.id, catRule.CWE, tc.cwe)
		}

		// Run the noncompliant example through scanTextFile.
		fileSize := int64(len(catRule.NoncompliantExample))
		complete := true
		switch tc.id {
		case textOversizedFileID:
			fileSize = maxFileBytes + 1
		case textMissingFinalNLID:
			// NoncompliantExample has no final newline; complete=true triggers it.
		}

		ext := ".txt"

		matched := false
		for _, f := range mustScanTextFile("fixture.txt", ext, []byte(catRule.NoncompliantExample), fileSize, complete) {
			if f.RuleID == tc.id {
				matched = true
				if f.Title != tc.title {
					t.Errorf("Text rule %s Title mismatch in finding: got %q", tc.id, f.Title)
				}
				if f.Severity != tc.severity {
					t.Errorf("Text rule %s Severity mismatch in finding: got %v", tc.id, f.Severity)
				}
				if f.Kind != tc.kind {
					t.Errorf("Text rule %s Kind mismatch in finding: got %q expected %q", tc.id, f.Kind, tc.kind)
				}
				if tc.cwe != "" && f.CWE != tc.cwe {
					t.Errorf("Text rule %s CWE mismatch in finding: got %q expected %q", tc.id, f.CWE, tc.cwe)
				}
			}
		}
		if !matched {
			t.Errorf("Text rule %s noncompliant example does not trigger detector", tc.id)
		}

		// Compliant example must not trigger this rule.
		complSize := int64(len(catRule.CompliantExample))
		complComplete := true
		for _, f := range mustScanTextFile("fixture.txt", ext, []byte(catRule.CompliantExample), complSize, complComplete) {
			if f.RuleID == tc.id {
				t.Errorf("Text rule %s compliant example unexpectedly triggered detector", tc.id)
			}
		}
	}

	for _, r := range rules {
		if r.Key == "quality-todo-comment" || r.Key == "quality-commented-out-code" || r.Key == "reliability-empty-catch" || r.Key == "reliability-self-assignment" || r.Key == "reliability-self-comparison" {
			found := false
			for _, tc := range builtin {
				if tc.id == string(r.Key) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Rule %s in catalog but missing from builtinRules", r.Key)
			}
		}
		if r.Language == "XML" && !seenXML[string(r.Key)] {
			t.Errorf("Rule %s in XML catalog but missing from builtinXMLRules", r.Key)
		}
		if r.Language == "Text" && !seenText[string(r.Key)] {
			t.Errorf("Rule %s in Text catalog but missing from builtinTextRules", r.Key)
		}
	}
}
