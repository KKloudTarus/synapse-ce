package codeanalysis

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
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
		{
			name:    "Root element named SYSTEM is not external DTD",
			xml:     `<!DOCTYPE SYSTEM [ <!ELEMENT SYSTEM EMPTY> ]><SYSTEM/>`,
			wantIDs: []string{xmlDoctypePresentRuleID},
			notWant: []string{xmlExternalDTDRuleID},
		},
		{
			name:    "Root element named PUBLIC is not external DTD",
			xml:     `<!DOCTYPE PUBLIC [ <!ELEMENT PUBLIC EMPTY> ]><PUBLIC/>`,
			wantIDs: []string{xmlDoctypePresentRuleID},
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

	t.Run("one namespace token -> no finding", func(t *testing.T) {
		xmlData := []byte(`<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="https://example.com/namespace"/>`)
		findings := scanXMLFile("test.xml", xmlData)
		for _, f := range findings {
			if f.RuleID == xmlExternalSchemaLocationRuleID {
				t.Errorf("unexpected %s", xmlExternalSchemaLocationRuleID)
			}
		}
	})

	t.Run("odd trailing namespace token -> ignore trailing namespace", func(t *testing.T) {
		xmlData := []byte(`<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://example.org/ns https://example.com/schema.xsd http://example.org/ns2"/>`)
		findings := scanXMLFile("test.xml", xmlData)
		found := false
		for _, f := range findings {
			if f.RuleID == xmlExternalSchemaLocationRuleID {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %s", xmlExternalSchemaLocationRuleID)
		}
	})

	t.Run("external entity inside <password> -> external-entity only", func(t *testing.T) {
		xmlData := []byte(`<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><root><password>&xxe;</password></root>`)
		findings := scanXMLFile("test.xml", xmlData)
		foundXXE := false
		for _, f := range findings {
			if f.RuleID == xmlHardcodedSecretRuleID {
				t.Errorf("unexpected %s for external entity ref", xmlHardcodedSecretRuleID)
			}
			if f.RuleID == xmlExternalEntityRuleID {
				foundXXE = true
			}
		}
		if !foundXXE {
			t.Errorf("expected %s", xmlExternalEntityRuleID)
		}
	})

	t.Run("empty entity inside <password> -> no hardcoded-secret", func(t *testing.T) {
		xmlData := []byte(`<!DOCTYPE root [ <!ENTITY empty ""> ]><root><password>&empty;</password></root>`)
		findings := scanXMLFile("test.xml", xmlData)
		for _, f := range findings {
			if f.RuleID == xmlHardcodedSecretRuleID {
				t.Errorf("unexpected %s for empty entity ref", xmlHardcodedSecretRuleID)
			}
		}
	})

	t.Run("local entity inside <password> -> no secret invented by decoder", func(t *testing.T) {
		xmlData := []byte(`<!DOCTYPE root [ <!ENTITY local "safe"> ]><root><password>&local;</password></root>`)
		findings := scanXMLFile("test.xml", xmlData)
		for _, f := range findings {
			if f.RuleID == xmlHardcodedSecretRuleID {
				t.Errorf("unexpected %s for local entity ref", xmlHardcodedSecretRuleID)
			}
		}
	})
}

func TestXMLDTD_OverflowDeclarations(t *testing.T) {
	t.Run("external general entity after 500 benign entities is detected", func(t *testing.T) {
		var xmlData strings.Builder
		xmlData.WriteString("<!DOCTYPE root [\n")
		for i := 0; i < 500; i++ {
			fmt.Fprintf(&xmlData, "  <!ENTITY e%d \"value\">\n", i)
		}
		xmlData.WriteString("  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n")
		xmlData.WriteString("]><root/>")

		findings := scanXMLFile("test.xml", []byte(xmlData.String()))
		foundXXE := false
		for _, f := range findings {
			if f.RuleID == xmlExternalEntityRuleID {
				foundXXE = true
			}
		}
		if !foundXXE {
			t.Errorf("expected %s for external entity after cap", xmlExternalEntityRuleID)
		}
	})

	t.Run("more than 500 internal entities emit overflow", func(t *testing.T) {
		var xmlData strings.Builder
		xmlData.WriteString("<!DOCTYPE root [\n")
		for i := 0; i < 501; i++ {
			fmt.Fprintf(&xmlData, "  <!ENTITY e%d \"value\">\n", i)
		}
		xmlData.WriteString("]><root/>")

		findings := scanXMLFile("test.xml", []byte(xmlData.String()))
		foundOverflow := false
		for _, f := range findings {
			if f.RuleID == xmlEntityExpansionRuleID && strings.Contains(f.Description, "Excessive number") {
				foundOverflow = true
			}
		}
		if !foundOverflow {
			t.Errorf("expected %s for entity overflow", xmlEntityExpansionRuleID)
		}
	})

	t.Run("501 internal entities + reference to entity 501 does not emit not-well-formed", func(t *testing.T) {
		var xmlData strings.Builder
		xmlData.WriteString("<!DOCTYPE root [\n")
		for i := 0; i <= 501; i++ {
			fmt.Fprintf(&xmlData, "  <!ENTITY e%d \"value\">\n", i)
		}
		xmlData.WriteString("]><root>&e501;</root>")

		findings := scanXMLFile("test.xml", []byte(xmlData.String()))
		for _, f := range findings {
			if f.RuleID == xmlNotWellFormedRuleID {
				t.Errorf("unexpected %s for entity 501 ref", xmlNotWellFormedRuleID)
			}
		}
	})

	t.Run("external parameter entity after 500 benign entities is detected", func(t *testing.T) {
		var xmlData strings.Builder
		xmlData.WriteString("<!DOCTYPE root [\n")
		for i := 0; i < 500; i++ {
			fmt.Fprintf(&xmlData, "  <!ENTITY e%d \"value\">\n", i)
		}
		xmlData.WriteString("  <!ENTITY % pe SYSTEM \"http://bad.com/dtd\"> %pe;\n")
		xmlData.WriteString("]><root/>")

		findings := scanXMLFile("test.xml", []byte(xmlData.String()))
		foundPE := false
		for _, f := range findings {
			if f.RuleID == xmlExternalParamEntityRuleID {
				foundPE = true
			}
		}
		if !foundPE {
			t.Errorf("expected %s for external param entity after cap", xmlExternalParamEntityRuleID)
		}
	})

	t.Run("Entity beyond 10000 limit remains well-formed", func(t *testing.T) {
		var xmlData strings.Builder
		xmlData.WriteString("<!DOCTYPE root [\n")
		for i := 0; i <= 10100; i++ {
			fmt.Fprintf(&xmlData, "  <!ENTITY e%d \"value\">\n", i)
		}
		xmlData.WriteString("]><root>&e10100;</root>")

		findings := scanXMLFile("test.xml", []byte(xmlData.String()))
		for _, f := range findings {
			if f.RuleID == xmlNotWellFormedRuleID {
				t.Errorf("unexpected %s for entity 10100 ref", xmlNotWellFormedRuleID)
			}
		}
	})
}

func TestXML_FallbackSuppression(t *testing.T) {
	// Undeclared prefix is non-terminal, so malformed attribute on the same line should STILL be reported by fallback
	xml := []byte("<root>\n<p:x> < </p:x>\n</root>")
	res := scanXMLFile("test.xml", xml)

	hasPrefix := false
	hasFallback := false
	for _, f := range res {
		if f.RuleID == xmlUndeclaredPrefixRuleID {
			hasPrefix = true
		}
		if f.RuleID == xmlNotWellFormedRuleID {
			hasFallback = true
		}
	}
	if !hasPrefix || !hasFallback {
		t.Errorf("expected both undeclared prefix and not-well-formed fallback for non-terminal failure line, got: %+v", res)
	}
}

func TestXML_FullPipelineSuppression(t *testing.T) {
	tests := []struct {
		name       string
		xml        string
		expected   []string
		unexpected []string
	}{
		{
			name:       "mismatched tag only",
			xml:        `<root><item></root>`,
			expected:   []string{xmlMismatchedTagRuleID},
			unexpected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:       "multiple root elements only",
			xml:        `<first/><second/>`,
			expected:   []string{xmlMultipleRootElementsRuleID},
			unexpected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:       "invalid character reference only",
			xml:        `<root>&#0;</root>`,
			expected:   []string{xmlInvalidCharacterReferenceRuleID},
			unexpected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:       "invalid character reference in attribute only",
			xml:        `<root a="&#0;"/>`,
			expected:   []string{xmlInvalidCharacterReferenceRuleID},
			unexpected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:       "malformed attribute + mismatched tag",
			xml:        `<root bad=oops><a></b></root>`,
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{},
		},
		{
			name: "invalid comment inside DTD",
			xml: `<!DOCTYPE root [
  <!-- invalid -- comment -->
  <!ELEMENT root EMPTY>
]>
<root/>`,
			expected:   []string{xmlDoctypePresentRuleID, xmlInvalidCommentRuleID},
			unexpected: []string{},
		},
		{
			name: "DTD comment body ending in -",
			xml: `<!DOCTYPE root [
  <!-- invalid --->
  <!ELEMENT root EMPTY>
]>
<root/>`,
			expected:   []string{xmlDoctypePresentRuleID, xmlInvalidCommentRuleID},
			unexpected: []string{},
		},
		{
			name: "DTD string literal containing comment",
			xml: `<!DOCTYPE root [
  <!ENTITY x "<!-- invalid -- comment -->">
]>
<root/>`,
			expected:   []string{xmlDoctypePresentRuleID},
			unexpected: []string{xmlInvalidCommentRuleID},
		},
		{
			name: "unterminated DTD comment",
			xml: `<!DOCTYPE root [
  <!-- invalid 
  <!ELEMENT root EMPTY>
]>
<root/>`,
			expected:   []string{xmlDoctypePresentRuleID, xmlInvalidCommentRuleID},
			unexpected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:       "closed invalid comment",
			xml:        `<root><!-- invalid -- comment --></root>`,
			expected:   []string{xmlInvalidCommentRuleID},
			unexpected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:       "comment ending in hyphen",
			xml:        `<root><!-- invalid ---></root>`,
			expected:   []string{xmlInvalidCommentRuleID},
			unexpected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:       "valid comment",
			xml:        `<root><!-- valid comment --></root>`,
			expected:   []string{},
			unexpected: []string{xmlInvalidCommentRuleID, xmlNotWellFormedRuleID},
		},
		{
			name:       "clean mismatched tag",
			xml:        `<a></b>`,
			expected:   []string{xmlMismatchedTagRuleID},
			unexpected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:       "clean mismatched tag with whitespace",
			xml:        `<a></b   >`,
			expected:   []string{xmlMismatchedTagRuleID},
			unexpected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:       "malformed end tag attribute",
			xml:        `<a></b bad=oops>`,
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{xmlMismatchedTagRuleID},
		},
		{
			name:       "malformed end tag token",
			xml:        `<a></b x>`,
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{xmlMismatchedTagRuleID},
		},
		{
			name:       "nested malformed end tag",
			xml:        `<root><a></wrong bad=oops></root>`,
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{xmlMismatchedTagRuleID},
		},
		{
			name:       "mismatched tag matching name but bad syntax",
			xml:        `<a></a bad><b>`,
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{},
		},
		{
			name:       "malformed start tag attribute missing quote",
			xml:        `<a bad=oops>`,
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{},
		},
		{
			name:       "malformed start tag unterminated quote",
			xml:        `<a x="unterminated>`,
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{},
		},
		{
			name:       "multiple roots with malformed second root",
			xml:        `<a/><b bad=oops/>`,
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{},
		},
		{
			name:       "char ref in malformed tag",
			xml:        `<a x=&#0;>`,
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{},
		},
		{
			name:       "unclosed element exactly one",
			xml:        `<root><a><b>`,
			expected:   []string{xmlUnclosedElementRuleID},
			unexpected: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := scanXMLFile("test.xml", []byte(tc.xml))
			var got []string
			for _, f := range findings {
				got = append(got, f.RuleID)
			}
			sort.Strings(got)
			expected := make([]string, len(tc.expected))
			copy(expected, tc.expected)
			sort.Strings(expected)

			if len(got) != len(expected) {
				t.Errorf("expected %v, got %v\nfindings: %+v", expected, got, findings)
			} else {
				for i := range got {
					if got[i] != expected[i] {
						t.Errorf("expected %v, got %v\nfindings: %+v", expected, got, findings)
						break
					}
				}
			}
		})
	}
}

func TestXML_TokenCompletenessMatrix(t *testing.T) {
	tests := []struct {
		name       string
		xml        string
		expected   []string
		unexpected []string
	}{
		{
			name:       "unterminated start tag",
			xml:        "<a x=\"v\"",
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{xmlUnclosedElementRuleID},
		},
		{
			name:       "incomplete second root",
			xml:        "<a /><b x=\"v\"",
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{xmlMultipleRootElementsRuleID, xmlUnclosedElementRuleID},
		},
		{
			name:       "malformed self-closing",
			xml:        "<a / x>",
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{xmlUnclosedElementRuleID},
		},
		{
			name:       "invalid qname first root",
			xml:        "<1a/><b/>",
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{xmlMultipleRootElementsRuleID},
		},
		{
			name:       "unterminated end tag",
			xml:        "<a></b",
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{xmlMismatchedTagRuleID},
		},
		{
			name:       "empty end tag",
			xml:        "<a></>",
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{xmlMismatchedTagRuleID},
		},
		{
			name:       "invalid qname end tag",
			xml:        "<a></1bad>",
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{xmlMismatchedTagRuleID},
		},
		{
			name:       "clean mismatched end tag with space",
			xml:        "<a></b >",
			expected:   []string{xmlMismatchedTagRuleID},
			unexpected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:       "unterminated CDATA",
			xml:        "<root><![CDATA[unfinished",
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{xmlUnclosedElementRuleID},
		},
		{
			name:       "unterminated PI",
			xml:        "<root><?pi unfinished",
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{xmlUnclosedElementRuleID},
		},
		{
			name:       "unterminated DOCTYPE",
			xml:        "<root><!DOCTYPE root [<!ELEMENT root EMPTY>",
			expected:   []string{xmlDoctypePresentRuleID, xmlNotWellFormedRuleID},
			unexpected: []string{xmlUnclosedElementRuleID},
		},
		{
			name:       "invalid char ref before malformed attribute",
			xml:        "<a x=\"&#0;\" y=oops>",
			expected:   []string{xmlInvalidCharacterReferenceRuleID},
			unexpected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:       "malformed first root + valid second root",
			xml:        "<a@b/><d/>",
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{},
		},
		{
			name:       "invalid QName first root + valid second root",
			xml:        "<a:b:c/><d/>",
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{},
		},
		{
			name:       "malformed attribute QName",
			xml:        `<a x@y="1"/><b/>`,
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{},
		},
		{
			name:       "malformed token instead of attr val",
			xml:        `<a x="<"/><b/>`,
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{},
		},
		{
			name:       "undefined entity in attr",
			xml:        `<a x="&bogus;"/><b/>`,
			expected:   []string{xmlNotWellFormedRuleID},
			unexpected: []string{},
		},
		// ── Duplicate-attribute: barrier-aware ──────────────────────────
		{
			name:     "raw duplicate attribute in valid doc",
			xml:      `<a x="1" x="2"/>`,
			expected: []string{xmlDuplicateAttributeRuleID},
		},
		{
			name:     "no duplicate when first root is malformed",
			xml:      `<a@b/><d x="1" x="2"/>`,
			expected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:     "no duplicate when attr parse fails first",
			xml:      `<a bad=oops x="1" x="2"/>`,
			expected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:     "expanded duplicate only when doc is valid",
			xml:      `<a xmlns:p="u" xmlns:q="u" p:x="1" q:x="2"/>`,
			expected: []string{xmlDuplicateAttributeRuleID},
		},
		// ── Barrier at exact offset (bogus entity) ───────────────────────
		{
			name:     "bogus entity + mismatched end tag: not-well-formed only",
			xml:      `<a>&bogus;</b>`,
			expected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:     "bogus entity + matching end tag: not-well-formed only, no unclosed",
			xml:      `<a>&bogus;</a>`,
			expected: []string{xmlNotWellFormedRuleID},
		},
		{
			name:     "bogus entity + second root: not-well-formed only",
			xml:      `<a>&bogus;</a><b/>`,
			expected: []string{xmlNotWellFormedRuleID},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := scanXMLFile("test.xml", []byte(tt.xml))
			findingIDs := []string{}
			for _, f := range res {
				findingIDs = append(findingIDs, f.RuleID)
			}
			sort.Strings(findingIDs)

			expected := make([]string, len(tt.expected))
			copy(expected, tt.expected)
			sort.Strings(expected)

			if !reflect.DeepEqual(findingIDs, expected) {
				t.Errorf("expected exact findings %v, got %v\n", expected, findingIDs)
			}
		})
	}
}
