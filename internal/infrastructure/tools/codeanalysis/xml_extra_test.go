package codeanalysis

import (
	"reflect"
	"testing"
)

func TestXMLDTD_ExtraLexicalRules(t *testing.T) {
	tests := []struct {
		name    string
		xml     string
		wantIDs []string
		notWant []string
	}{
		{
			name:    "quoted > inside entity value does not terminate declaration",
			xml:     `<!DOCTYPE root [ <!ENTITY message "value > remaining"> ]><root/>`,
			wantIDs: []string{xmlDoctypePresentRuleID},
			notWant: []string{xmlExternalDTDRuleID, xmlExternalEntityRuleID},
		},
		{
			name:    "SYSTEM text inside an internal literal is not external DTD",
			xml:     `<!DOCTYPE root [ <!ENTITY message "SYSTEM"> ]><root/>`,
			wantIDs: []string{xmlDoctypePresentRuleID},
			notWant: []string{xmlExternalDTDRuleID},
		},
		{
			name:    "lowercase <!doctype is not accepted",
			xml:     `<!doctype root SYSTEM "file:///etc/passwd"><root/>`,
			wantIDs: []string{}, // Because it's malformed XML or not matched by strict case
			notWant: []string{xmlExternalDTDRuleID, xmlDoctypePresentRuleID},
		},
		{
			name:    "lowercase <!entity is not accepted",
			xml:     `<!DOCTYPE root [ <!entity xxe SYSTEM "file:///etc/passwd"> ]><root/>`,
			wantIDs: []string{xmlDoctypePresentRuleID},
			notWant: []string{xmlExternalEntityRuleID},
		},
		{
			name:    "comment containing <!ENTITY does not trigger",
			xml:     `<!DOCTYPE root [ <!-- <!ENTITY xxe SYSTEM "file:///etc/passwd"> --> ]><root/>`,
			wantIDs: []string{xmlDoctypePresentRuleID},
			notWant: []string{xmlExternalEntityRuleID},
		},
		{
			name:    "processing instruction containing attack-like text does not trigger",
			xml:     `<?xml-stylesheet type="text/xsl" href="<!DOCTYPE root SYSTEM 'http://...'>"?><root/>`,
			wantIDs: []string{},
			notWant: []string{xmlExternalDTDRuleID, xmlDoctypePresentRuleID},
		},
		{
			name:    "external entity does not emit external-dtd",
			xml:     `<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><root/>`,
			wantIDs: []string{xmlExternalEntityRuleID},
			notWant: []string{xmlExternalDTDRuleID}, // Should NOT be external DTD
		},
		{
			name:    "parameter entity does not emit external-dtd",
			xml:     `<!DOCTYPE root [ <!ENTITY % pe SYSTEM "http://bad.com/dtd"> %pe; ]><root/>`,
			wantIDs: []string{xmlExternalParamEntityRuleID},
			notWant: []string{xmlExternalDTDRuleID},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanXMLFile("test.xml", []byte(tt.xml))
			ids := make(map[string]bool)
			for _, f := range findings {
				ids[f.RuleID] = true
			}
			for _, want := range tt.wantIDs {
				if !ids[want] {
					t.Errorf("missing expected rule %s", want)
				}
			}
			for _, notWant := range tt.notWant {
				if ids[notWant] {
					t.Errorf("unexpected rule %s triggered", notWant)
				}
			}
		})
	}
}

func TestXMLSecurity_ExtraRules(t *testing.T) {
	t.Run("unused XInclude namespace does not trigger", func(t *testing.T) {
		xmlData := []byte(`<include xmlns:xi="http://www.w3.org/2001/XInclude" href="local.xml"/>`)
		findings := scanXMLFile("test.xml", xmlData)
		for _, f := range findings {
			if f.RuleID == xmlXIncludeRuleID {
				t.Errorf("unexpected %s", xmlXIncludeRuleID)
			}
		}
	})

	t.Run("XInclude element names remain case-sensitive", func(t *testing.T) {
		xmlData := []byte(`<Include xmlns="http://www.w3.org/2001/XInclude"/>`)
		findings := scanXMLFile("test.xml", xmlData)
		for _, f := range findings {
			if f.RuleID == xmlXIncludeRuleID {
				t.Errorf("unexpected %s for capitalized Include", xmlXIncludeRuleID)
			}
		}
	})

	t.Run("XInclude correct case triggers", func(t *testing.T) {
		xmlData := []byte(`<include xmlns="http://www.w3.org/2001/XInclude"/>`)
		findings := scanXMLFile("test.xml", xmlData)
		found := false
		for _, f := range findings {
			if f.RuleID == xmlXIncludeRuleID {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %s", xmlXIncludeRuleID)
		}
	})

	t.Run("hardcoded-secret element context resets on EndElement and sibling text does not inherit secret field name", func(t *testing.T) {
		xmlData := []byte(`
			<root>
				<password>${DB_PASSWORD}</password>
				normal-text
			</root>
		`)
		findings := scanXMLFile("test.xml", xmlData)
		for _, f := range findings {
			if f.RuleID == xmlHardcodedSecretRuleID {
				t.Errorf("unexpected %s", xmlHardcodedSecretRuleID)
			}
		}
	})

	t.Run("hardcoded-secret nested elements restore parent context", func(t *testing.T) {
		xmlData := []byte(`
			<password>
				<description>database credential</description>
				ActualSecret123
			</password>
		`)
		findings := scanXMLFile("test.xml", xmlData)
		found := false
		for _, f := range findings {
			if f.RuleID == xmlHardcodedSecretRuleID {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %s", xmlHardcodedSecretRuleID)
		}
	})

	t.Run("repeated scan returns identical ordered findings", func(t *testing.T) {
		xmlData := []byte(`<!DOCTYPE root SYSTEM "http://bad.com/dtd" [
			<!ENTITY xxe SYSTEM "file:///etc/passwd">
		]>
		<root>
			<password>MySuperSecret12345</password>
			<include xmlns="http://www.w3.org/2001/XInclude"/>
		</root>`)

		findings1 := scanXMLFile("test.xml", xmlData)
		findings2 := scanXMLFile("test.xml", xmlData)

		if len(findings1) != len(findings2) {
			t.Fatalf("lengths differ: %d vs %d", len(findings1), len(findings2))
		}
		for i := range findings1 {
			if !reflect.DeepEqual(findings1[i], findings2[i]) {
				t.Errorf("finding %d differs: %+v vs %+v", i, findings1[i], findings2[i])
			}
		}
	})
}
