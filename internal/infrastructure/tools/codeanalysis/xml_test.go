package codeanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestXMLBugRules(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"compliant.xml":           "<service><name>api</name></service>",
		"duplicate-attribute.xml": "<service name=\"api\" name=\"worker\" />",
		"not-well-formed.xml":     "<service><name>api</service>",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	findings, err := New().Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	byRuleFile := map[string]bool{}
	for _, f := range findings {
		byRuleFile[f.RuleID+":"+f.File] = true
	}

	if !byRuleFile[xmlDuplicateAttributeRuleID+":duplicate-attribute.xml"] {
		t.Fatalf("expected %s on duplicate-attribute.xml, got %+v", xmlDuplicateAttributeRuleID, findings)
	}
	if !byRuleFile[xmlNotWellFormedRuleID+":not-well-formed.xml"] {
		t.Fatalf("expected %s on not-well-formed.xml, got %+v", xmlNotWellFormedRuleID, findings)
	}
	if byRuleFile[xmlDuplicateAttributeRuleID+":compliant.xml"] || byRuleFile[xmlNotWellFormedRuleID+":compliant.xml"] {
		t.Fatalf("compliant.xml unexpectedly produced XML bug findings: %+v", findings)
	}
}

func TestXMLDuplicateAttributeIgnoresNonMarkupSections(t *testing.T) {
	content := []byte(`<?xml version="1.0"?>
<!-- <service name="api" name="worker" /> -->
<service name="api"><![CDATA[<node id="a" id="b" />]]></service>`)

	findings := scanXMLDuplicateAttributes("service.xml", content)
	if len(findings) != 0 {
		t.Fatalf("expected no duplicate-attribute findings in comments/CDATA, got %+v", findings)
	}
}
