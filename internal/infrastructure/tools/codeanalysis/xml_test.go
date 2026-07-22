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

func TestXMLSecurityRules_CrossIsolationAndSuppression(t *testing.T) {
	t.Run("external general entity isolation", func(t *testing.T) {
		xmlData := []byte(`<!DOCTYPE config [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><config>&xxe;</config>`)
		findings := scanXMLFile("test.xml", xmlData)
		ids := map[string]bool{}
		for _, f := range findings {
			ids[f.RuleID] = true
		}
		if !ids[xmlExternalEntityRuleID] {
			t.Errorf("expected %s, got %+v", xmlExternalEntityRuleID, findings)
		}
		if ids[xmlExternalParamEntityRuleID] {
			t.Errorf("unexpected %s in general entity test", xmlExternalParamEntityRuleID)
		}
		if ids[xmlDoctypePresentRuleID] {
			t.Errorf("expected %s to be suppressed when specific external entity fires", xmlDoctypePresentRuleID)
		}
	})

	t.Run("external parameter entity isolation", func(t *testing.T) {
		xmlData := []byte(`<!DOCTYPE config [ <!ENTITY % remote SYSTEM "https://example.invalid/remote.dtd"> ]><config/>`)
		findings := scanXMLFile("test.xml", xmlData)
		ids := map[string]bool{}
		for _, f := range findings {
			ids[f.RuleID] = true
		}
		if !ids[xmlExternalParamEntityRuleID] {
			t.Errorf("expected %s, got %+v", xmlExternalParamEntityRuleID, findings)
		}
		if ids[xmlExternalEntityRuleID] {
			t.Errorf("unexpected %s in parameter entity test", xmlExternalEntityRuleID)
		}
		if ids[xmlDoctypePresentRuleID] {
			t.Errorf("expected %s to be suppressed when specific parameter entity fires", xmlDoctypePresentRuleID)
		}
	})

	t.Run("external DTD suppresses doctype-present", func(t *testing.T) {
		xmlData := []byte(`<!DOCTYPE root SYSTEM "https://example.invalid/ext.dtd"><root/>`)
		findings := scanXMLFile("test.xml", xmlData)
		ids := map[string]bool{}
		for _, f := range findings {
			ids[f.RuleID] = true
		}
		if !ids[xmlExternalDTDRuleID] {
			t.Errorf("expected %s, got %+v", xmlExternalDTDRuleID, findings)
		}
		if ids[xmlDoctypePresentRuleID] {
			t.Errorf("expected %s to be suppressed when external DTD fires", xmlDoctypePresentRuleID)
		}
	})

	t.Run("doctype-present fires when no specific DTD rule fires", func(t *testing.T) {
		xmlData := []byte(`<!DOCTYPE root [ <!ELEMENT root (#PCDATA)> ]><root>test</root>`)
		findings := scanXMLFile("test.xml", xmlData)
		ids := map[string]bool{}
		for _, f := range findings {
			ids[f.RuleID] = true
		}
		if !ids[xmlDoctypePresentRuleID] {
			t.Errorf("expected %s when generic DOCTYPE present, got %+v", xmlDoctypePresentRuleID, findings)
		}
	})

	t.Run("no doctype present does not fire doctype-present", func(t *testing.T) {
		xmlData := []byte(`<root><child>value</child></root>`)
		findings := scanXMLFile("test.xml", xmlData)
		for _, f := range findings {
			if f.RuleID == xmlDoctypePresentRuleID {
				t.Errorf("unexpected %s when no DOCTYPE present", xmlDoctypePresentRuleID)
			}
		}
	})
}

func TestXMLXInclude_NamespaceAware(t *testing.T) {
	t.Run("xi prefix", func(t *testing.T) {
		xmlData := []byte(`<doc xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></doc>`)
		findings := scanXMLFile("test.xml", xmlData)
		matched := false
		for _, f := range findings {
			if f.RuleID == xmlXIncludeRuleID {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("expected %s for xi:include", xmlXIncludeRuleID)
		}
	})

	t.Run("unrelated include element in custom namespace", func(t *testing.T) {
		xmlData := []byte(`<doc xmlns:other="http://example.org/ns"><other:include href="data.xml"/></doc>`)
		findings := scanXMLFile("test.xml", xmlData)
		for _, f := range findings {
			if f.RuleID == xmlXIncludeRuleID {
				t.Fatalf("unexpected %s for unrelated include element in custom namespace", xmlXIncludeRuleID)
			}
		}
	})
}

func TestXMLExternalSchemaLocation(t *testing.T) {
	t.Run("external noNamespaceSchemaLocation", func(t *testing.T) {
		xmlData := []byte(`<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="https://example.invalid/config.xsd"/>`)
		findings := scanXMLFile("test.xml", xmlData)
		matched := false
		for _, f := range findings {
			if f.RuleID == xmlExternalSchemaLocationRuleID {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("expected %s for external schema location", xmlExternalSchemaLocationRuleID)
		}
	})

	t.Run("relative schema location is ignored", func(t *testing.T) {
		xmlData := []byte(`<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://example.org/ns schemas/local.xsd"/>`)
		findings := scanXMLFile("test.xml", xmlData)
		for _, f := range findings {
			if f.RuleID == xmlExternalSchemaLocationRuleID {
				t.Fatalf("unexpected %s for relative schema path", xmlExternalSchemaLocationRuleID)
			}
		}
	})
}

func TestXMLHardcodedSecret(t *testing.T) {
	secretVal := "literal-" + "credential-value"
	xmlData := []byte(`<database><password>` + secretVal + `</password></database>`)
	findings := scanXMLFile("test.xml", xmlData)

	matched := false
	for _, f := range findings {
		if f.RuleID == xmlHardcodedSecretRuleID {
			matched = true
			if len(f.Description) == 0 {
				t.Errorf("empty description")
			}
			// Strict requirement: Secret literal MUST NOT appear in output!
			for _, text := range []string{f.Title, f.Description} {
				if len(text) > 0 && len(secretVal) > 0 && (text == secretVal || len(secretVal) >= 10 && len(text) >= len(secretVal) && containsSub(text, secretVal)) {
					t.Fatalf("secret literal leaked in finding output: %q", text)
				}
			}
		}
	}
	if !matched {
		t.Fatalf("expected %s for hardcoded secret", xmlHardcodedSecretRuleID)
	}

	t.Run("placeholders skipped", func(t *testing.T) {
		xmlData := []byte(`<database><password>${DB_PASSWORD}</password></database>`)
		findings := scanXMLFile("test.xml", xmlData)
		for _, f := range findings {
			if f.RuleID == xmlHardcodedSecretRuleID {
				t.Fatalf("unexpected %s for interpolated placeholder ${DB_PASSWORD}", xmlHardcodedSecretRuleID)
			}
		}
	})
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestXMLEntityExpansion_SafetyAndHostileInput(t *testing.T) {
	t.Run("self reference recursion safety", func(t *testing.T) {
		xmlData := []byte(`<!DOCTYPE test [ <!ENTITY a "&a;"> ]><test>&a;</test>`)
		findings := scanXMLFile("test.xml", xmlData)
		matched := false
		for _, f := range findings {
			if f.RuleID == xmlEntityExpansionRuleID {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("expected %s for self-referential entity", xmlEntityExpansionRuleID)
		}
	})

	t.Run("mutual cycle recursion safety", func(t *testing.T) {
		xmlData := []byte(`<!DOCTYPE test [ <!ENTITY a "&b;"> <!ENTITY b "&a;"> ]><test>&a;</test>`)
		findings := scanXMLFile("test.xml", xmlData)
		matched := false
		for _, f := range findings {
			if f.RuleID == xmlEntityExpansionRuleID {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("expected %s for mutual cycle entity", xmlEntityExpansionRuleID)
		}
	})

	t.Run("invalid utf8 and random bytes do not panic", func(t *testing.T) {
		randomBytes := []byte("<!DOCTYPE \xff\xfe\x00<tag attr=\"\x80\x90\"><!ENTITY % \xff SYSTEM \"\x00\x01\">")
		_ = scanXMLFile("test.xml", randomBytes)
	})
}
