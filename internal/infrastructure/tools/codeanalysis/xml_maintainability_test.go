package codeanalysis

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Helper to run scanner and verify specific finding counts.
func assertMaintRuleCount(t *testing.T, xml, ruleID string, expectedCount int) {
	t.Helper()
	findings := scanXMLFile("test.xml", []byte(xml))
	count := 0
	for _, f := range findings {
		if f.RuleID == ruleID {
			count++
		}
	}
	if count != expectedCount {
		t.Errorf("Expected %d findings for %s, got %d. Findings: %v", expectedCount, ruleID, count, findings)
	}
}

// Strict helper to assert the exact set of maintainability findings produced.
func assertExactMaintRules(t *testing.T, xmlStr string, expected ...string) {
	t.Helper()
	findings := scanXMLFile("test.xml", []byte(xmlStr))
	var got []string
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "xml:") && f.Kind == kindQuality {
			got = append(got, f.RuleID)
		}
	}
	if len(got) == 0 && len(expected) == 0 {
		return
	}
	sort.Strings(got)
	sort.Strings(expected)
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("Expected exact findings %v, got %v", expected, got)
	}
}

// ─── Malformed suppression matrix ──────────────────────────────────────────────

func TestXMLMaintainability_MalformedSuppression(t *testing.T) {
	cases := []struct {
		name string
		xml  string
	}{
		{"unterminated start", "<a"},
		{"missing quote", "<a x=1>"},
		{"mismatched", "<a></b>"},
		{"mismatched with attr error", "<a></b bad=oops>"},
		{"unterminated attr", "<a x=\"unterminated>"},
		{"invalid char ref", "<a>&#;</a>"},
		{"unterminated comment", "<!-- unterminated"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertExactMaintRules(t, tc.xml)
		})
	}
}

// ─── Golden Tests (using assertExactMaintRules) ──────────────────────────────────

func TestXMLMaintainability_SchemaMissing(t *testing.T) {
	assertExactMaintRules(t, `<!DOCTYPE config [ <!ELEMENT config ANY> ]><config/>`)
	assertExactMaintRules(t, `<config xmlns="urn:config" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:config schema.xsd"/>`)
	assertExactMaintRules(t, `<config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="schema.xsd"/>`)

	// Positive, but expect it on rootLine (line 3)
	xmlStr := `<?xml version="1.0"?>
	
	<config><service name="api"/></config>`

	assertExactMaintRules(t, xmlStr, xmlSchemaMissingRuleID)

	// Verify line number of schema missing
	findings := scanXMLFile("test.xml", []byte(xmlStr))
	for _, f := range findings {
		if f.RuleID == xmlSchemaMissingRuleID && f.Line != 3 {
			t.Errorf("Expected schema missing on line 3, got %d", f.Line)
		}
	}
}

func TestXMLMaintainability_DuplicateSchemaNamespace(t *testing.T) {
	assertExactMaintRules(t, `<root xmlns="urn:a" xmlns:b="urn:b" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:a a.xsd urn:b b.xsd"><b:child/></root>`)
	assertExactMaintRules(t, `<root xmlns="urn:a" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:a a1.xsd urn:a a2.xsd"/>`, xmlDuplicateSchemaNamespaceRuleID)
}

func TestXMLMaintainability_UnusedSchemaLocation(t *testing.T) {
	assertExactMaintRules(t, `<root xmlns="urn:used" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:used used.xsd"/>`)
	assertExactMaintRules(t, `<root xmlns:u="urn:used" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:used used.xsd"><u:child/></root>`)
	assertExactMaintRules(t, `<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="root.xsd"/>`)

	assertExactMaintRules(t, `<root xmlns="urn:used" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:used used.xsd urn:stale stale.xsd"/>`, xmlUnusedSchemaLocationRuleID)
	assertExactMaintRules(t, `<root xmlns="urn:all" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="stale.xsd"/>`, xmlUnusedSchemaLocationRuleID)
}

func TestXMLMaintainability_UnusedNamespaceDeclaration(t *testing.T) {
	assertExactMaintRules(t, `<root xmlns:cfg="urn:config"><cfg:child/></root>`, xmlSchemaMissingRuleID)
	assertExactMaintRules(t, `<root xmlns="urn:config"><child/></root>`, xmlSchemaMissingRuleID)
	// One is unused, schema missing is also there
	assertExactMaintRules(t, `<r:root xmlns:r="urn:root"><r:left xmlns="urn:shared"/><x:right xmlns:x="urn:shared"/></r:root>`, xmlSchemaMissingRuleID, xmlUnusedNamespaceDeclarationRuleID)

	assertExactMaintRules(t, `<root xmlns:unused="urn:unused"><child/></root>`, xmlSchemaMissingRuleID, xmlUnusedNamespaceDeclarationRuleID)
	assertExactMaintRules(t, `<p:root xmlns="urn:default" xmlns:p="urn:p"><p:child/></p:root>`, xmlSchemaMissingRuleID, xmlUnusedNamespaceDeclarationRuleID)
}

func TestXMLMaintainability_RedundantNamespaceDeclaration(t *testing.T) {
	assertExactMaintRules(t, `<root xmlns:cfg="urn:v1"><group xmlns:cfg="urn:v2"><cfg:item/></group></root>`, xmlSchemaMissingRuleID, xmlNamespacePrefixShadowingRuleID, xmlUnusedNamespaceDeclarationRuleID)
	assertExactMaintRules(t, `<root xmlns:cfg="urn:config"><group xmlns:cfg="urn:config"><cfg:item/></group></root>`, xmlSchemaMissingRuleID, xmlRedundantNamespaceDeclarationRuleID, xmlUnusedNamespaceDeclarationRuleID)
	assertExactMaintRules(t, `<root xmlns="urn:a"><child xmlns="urn:a"/></root>`, xmlSchemaMissingRuleID, xmlRedundantNamespaceDeclarationRuleID)
}

func TestXMLMaintainability_NamespacePrefixShadowing(t *testing.T) {
	assertExactMaintRules(t, `<root xmlns:a="urn:a"><group xmlns:b="urn:b"><b:item/><a:item/></group></root>`, xmlSchemaMissingRuleID)
	assertExactMaintRules(t, `<root xmlns:cfg="urn:v1"><group xmlns:cfg="urn:v2"><cfg:item/></group></root>`, xmlSchemaMissingRuleID, xmlNamespacePrefixShadowingRuleID, xmlUnusedNamespaceDeclarationRuleID)
}

func TestXMLMaintainability_MultiplePrefixesSameNamespace(t *testing.T) {
	assertExactMaintRules(t, `<root xmlns:a="urn:shared" xmlns:b="urn:shared"><a:first/></root>`, xmlSchemaMissingRuleID, xmlUnusedNamespaceDeclarationRuleID)
	assertExactMaintRules(t, `<root xmlns="urn:shared" xmlns:a="urn:shared"><first/><a:second/></root>`, xmlSchemaMissingRuleID)
	assertExactMaintRules(t, `<root xmlns:a="urn:shared" xmlns:b="urn:shared"><a:first/><b:second/></root>`, xmlSchemaMissingRuleID, xmlMultiplePrefixesSameNamespaceRuleID)
}

func TestXMLMaintainability_ExcessiveNestingDepth(t *testing.T) {
	xml16 := strings.Repeat("<n>", 16) + strings.Repeat("</n>", 16)
	assertExactMaintRules(t, xml16, xmlSchemaMissingRuleID)

	xml17 := strings.Repeat("<n>", 17) + strings.Repeat("</n>", 17)
	assertExactMaintRules(t, xml17, xmlSchemaMissingRuleID, xmlExcessiveNestingDepthRuleID)
}

func TestXMLMaintainability_TooManyAttributes(t *testing.T) {
	attrs12 := ""
	for i := 1; i <= 12; i++ {
		attrs12 += " a" + string(rune('A'+i)) + `="v"`
	}
	assertExactMaintRules(t, `<root`+attrs12+`/>`, xmlSchemaMissingRuleID)
	assertExactMaintRules(t, `<root xmlns:a="urn:a" xmlns:b="urn:b"`+attrs12+`/>`, xmlSchemaMissingRuleID, xmlUnusedNamespaceDeclarationRuleID, xmlUnusedNamespaceDeclarationRuleID)

	attrs13 := attrs12 + ` aM="v"`
	assertExactMaintRules(t, `<root`+attrs13+`/>`, xmlSchemaMissingRuleID, xmlTooManyAttributesRuleID)
}

func TestXMLMaintainability_TooManyChildElements(t *testing.T) {
	sb := strings.Builder{}
	sb.WriteString("<root>")
	for i := 0; i < 25; i++ {
		sb.WriteString("<c" + string(rune('A'+(i%7))) + "/>")
	}
	sb.WriteString("</root>")
	assertExactMaintRules(t, sb.String(), xmlSchemaMissingRuleID)

	sb.Reset()
	sb.WriteString("<root>")
	for i := 0; i < 26; i++ {
		sb.WriteString("<c" + string(rune('A'+(i%7))) + "/>")
	}
	sb.WriteString("</root>")
	assertExactMaintRules(t, sb.String(), xmlSchemaMissingRuleID, xmlTooManyChildElementsRuleID)

	// Homogeneous list
	sb.Reset()
	sb.WriteString("<root>")
	for i := 0; i < 50; i++ {
		sb.WriteString("<item/>")
	}
	for i := 0; i < 5; i++ {
		sb.WriteString("<meta" + string(rune('A'+i)) + "/>")
	}
	sb.WriteString("</root>")
	assertExactMaintRules(t, sb.String(), xmlSchemaMissingRuleID)
}

func TestXMLMaintainability_OversizedElement(t *testing.T) {
	// Boundary: exactly 200-line span = no finding
	// <root> on line 1, 198 blank lines, then 20 children (5 distinct names, min needed: 5),
	// </root> on line 220 → span = 220-1+1 = 220 → too long but let's build it precisely.
	// We need line span to be exactly 200 (no finding) and 201 (finding).
	// lineSpan = closeLine - startLine + 1, so for span=200:
	//   closeLine = startLine + 199, startLine=1 → closeLine=200.
	//   So we need 20 descendants across 5+ distinct names, placed at lines 2-199,
	//   with </root> at line 200.

	// Span == 200 → no finding.
	// Build: <root> [line 1], 174 blank lines, 20 children (6 distinct names), </root> [line 200]
	sb := strings.Builder{}
	sb.WriteString("<root>\n")                // line 1
	sb.WriteString(strings.Repeat("\n", 178)) // lines 2–179 (178 blanks)
	for i := 0; i < 20; i++ {                 // lines 180–199 (20 children)
		sb.WriteString("<c" + string(rune('A'+(i%6))) + "/>\n")
	}
	// </root> is at line 200 → span = 200 - 1 + 1 = 200 (threshold is >200, so no finding)
	sb.WriteString("</root>\n")
	assertExactMaintRules(t, sb.String(), xmlSchemaMissingRuleID)

	// Span == 201 → finding.
	sb.Reset()
	sb.WriteString("<root>\n")                // line 1
	sb.WriteString(strings.Repeat("\n", 179)) // lines 2–180 (179 blanks)
	for i := 0; i < 20; i++ {                 // lines 181–200 (20 children)
		sb.WriteString("<c" + string(rune('A'+(i%6))) + "/>\n")
	}
	// </root> is at line 201 → span = 201 - 1 + 1 = 201 (>200 threshold, finding expected)
	sb.WriteString("</root>\n")
	assertExactMaintRules(t, sb.String(), xmlSchemaMissingRuleID, xmlOversizedElementRuleID)
}

func TestXMLMaintainability_CommentedOutMarkup(t *testing.T) {
	assertExactMaintRules(t, `<root><!-- Use <service> to configure --></root>`, xmlSchemaMissingRuleID)
	assertExactMaintRules(t, `<root><!-- <service></wrong> --></root>`, xmlSchemaMissingRuleID)
	assertExactMaintRules(t, "<root><!--\n<service name=\"legacy\">\n  <port>8080</port>\n</service>\n--></root>", xmlSchemaMissingRuleID, xmlCommentedOutMarkupRuleID)
}

func TestXMLMaintainability_RedundantCDATASection(t *testing.T) {
	assertExactMaintRules(t, `<root><![CDATA[ <a> & b </a> ]]></root>`, xmlSchemaMissingRuleID)
	assertExactMaintRules(t, `<root><![CDATA[ plain text ]]></root>`, xmlSchemaMissingRuleID, xmlRedundantCDATASectionRuleID)
}

func TestXMLMaintainability_OversizedComment(t *testing.T) {
	// Byte boundary: 1000 bytes = no finding, 1001 bytes = finding.
	body1000 := strings.Repeat("a", 1000)
	body1001 := strings.Repeat("a", 1001)
	assertExactMaintRules(t, "<root><!--"+body1000+"--></root>", xmlSchemaMissingRuleID)
	assertExactMaintRules(t, "<root><!--"+body1001+"--></root>", xmlSchemaMissingRuleID, xmlOversizedCommentRuleID)

	// Line boundary: 20 lines = no finding, 21 lines = finding.
	// A comment body with N newlines has (N+1) lines.
	// So 20 newlines → 21 lines → finding; 19 newlines → 20 lines → no finding.
	body20Lines := strings.Repeat("\n", 19) // 20 lines (newlines=19)
	body21Lines := strings.Repeat("\n", 20) // 21 lines (newlines=20)
	assertExactMaintRules(t, "<root><!--"+body20Lines+"--></root>", xmlSchemaMissingRuleID)
	assertExactMaintRules(t, "<root><!--"+body21Lines+"--></root>", xmlSchemaMissingRuleID, xmlOversizedCommentRuleID)
}

// ─── Blocker 1: Lexical False Positives & Resumes ────────────────────────────

func TestXMLMaintainability_LexicalFalsePositives(t *testing.T) {
	xml1 := `<?note <!-- <disabled/> --> <![CDATA[ content ]]> ?>
	<root/>`
	assertExactMaintRules(t, xml1, xmlSchemaMissingRuleID)

	xml2 := `<!DOCTYPE root [
	  <!ENTITY sample "<!--<disabled/>--> <![CDATA[ content ]]>">
	]>
	<root/>`
	assertExactMaintRules(t, xml2)
}

func TestXMLMaintainability_LexicalResumesAfterPI(t *testing.T) {
	xml1 := `<?xml version="1.0"?>
<root>
  <!-- <legacy/> -->
  <![CDATA[plain text]]>
</root>`
	assertExactMaintRules(t, xml1, xmlSchemaMissingRuleID, xmlCommentedOutMarkupRuleID, xmlRedundantCDATASectionRuleID)
}

func TestXMLMaintainability_LexicalResumesAfterDOCTYPE(t *testing.T) {
	xml2 := `<!DOCTYPE root>
<root>
  <!-- <legacy/> -->
  <![CDATA[plain text]]>
</root>`
	// Note: DOCTYPE suppresses schema missing
	assertExactMaintRules(t, xml2, xmlCommentedOutMarkupRuleID, xmlRedundantCDATASectionRuleID)
}

func TestXMLMaintainability_DTDQuotedMarkersIgnored(t *testing.T) {
	xml := `<!DOCTYPE root [
	  <!ENTITY x " > ">
	]>
<root><!-- <legacy/> --></root>`
	assertExactMaintRules(t, xml, xmlCommentedOutMarkupRuleID)
}

func TestXMLMaintainability_DTDCommentRecognized(t *testing.T) {
	xml := `<!DOCTYPE root [
	  <!-- A > B -->
	]>
<root><![CDATA[plain text]]></root>`
	assertExactMaintRules(t, xml, xmlRedundantCDATASectionRuleID)
}

// ─── Blocker 3: Reserved / Empty namespaces ──────────────────────────────────

func TestXMLMaintainability_ReservedXMLPrefixIgnored(t *testing.T) {
	xml := `<root
  xmlns:xml="http://www.w3.org/XML/1998/namespace"
  xml:lang="en"/>`
	assertExactMaintRules(t, xml, xmlSchemaMissingRuleID) // Should NOT emit unused-namespace or redundant
}

func TestXMLMaintainability_DefaultNamespaceUndeclarationIgnored(t *testing.T) {
	xml := `<root xmlns="urn:a">
  <child xmlns="">
    <leaf/>
  </child>
</root>`
	assertExactMaintRules(t, xml, xmlSchemaMissingRuleID) // leaf has no namespace, so default xmlns="urn:a" is used by root and child has xmlns="" which is valid undeclaration and should not be warned about as unused.
	// Wait, is urn:a used by root? Yes, root is in urn:a.
	// Is child in urn:a? No, child uses xmlns="". So child is no-namespace.
	// So xmlns="urn:a" is used by root. xmlns="" is undeclaration and should not trigger unused.
}

// ─── Blocker 4: Source Line Accuracy & Whitespace ────────────────────────────

func TestXMLMaintainability_SourceLineAccuracy(t *testing.T) {
	xml := `<root
	xmlns:unused  =  "urn:unused">
	<child/>
	</root>`

	findings := scanXMLFile("test.xml", []byte(xml))
	found := false
	for _, f := range findings {
		if f.RuleID == xmlUnusedNamespaceDeclarationRuleID {
			if f.Line != 2 {
				t.Errorf("Expected unused namespace on line 2, got %d", f.Line)
			}
			found = true
		}
	}
	if !found {
		t.Errorf("Expected unused namespace finding")
	}
}

// ─── Output caps tests ────────────────────────────────────────────────────────

func TestXMLMaintainability_OutputCaps(t *testing.T) {
	sb := strings.Builder{}
	sb.WriteString("<root ")
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&sb, `xmlns:ns%d="urn:%d" `, i, i)
	}
	sb.WriteString(">\n")

	for i := 0; i < 30; i++ {
		sb.WriteString("  <child")
		for j := 0; j < 13; j++ {
			fmt.Fprintf(&sb, ` a%d="v"`, j)
		}
		sb.WriteString("/>\n")
	}

	for i := 0; i < 30; i++ {
		sb.WriteString("<![CDATA[ plain text ]]>\n")
	}

	for i := 0; i < 30; i++ {
		sb.WriteString("<!-- <disabled/> -->\n")
	}

	for i := 0; i < 30; i++ {
		sb.WriteString("<!-- " + strings.Repeat("a", 1001) + " -->\n")
	}

	sb.WriteString("</root>")

	findings := scanXMLFile("caps.xml", []byte(sb.String()))

	maintCount := 0
	perRule := make(map[string]int)

	for _, f := range findings {
		if f.Kind == kindQuality && strings.HasPrefix(f.RuleID, "xml:") {
			maintCount++
			perRule[f.RuleID]++
		}
	}

	if maintCount != 100 {
		t.Errorf("Expected exactly 100 maintainability findings (global cap), got %d", maintCount)
	}

	if perRule[xmlUnusedNamespaceDeclarationRuleID] != 20 {
		t.Errorf("Expected exactly 20 unused namespace findings (rule cap), got %d", perRule[xmlUnusedNamespaceDeclarationRuleID])
	}
}

// ─── Blocker 5: Hostile-size safety (Bounded Memory) ─────────────────────────

func TestXMLMaintainability_HostileSizeMemoryBounds(t *testing.T) {
	sb := strings.Builder{}
	sb.WriteString("<root>\n")
	// 5000 distinct direct children
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&sb, "<c%d/>\n", i)
	}
	sb.WriteString("</root>\n")

	// Ensure it doesn't crash or trigger O(N) map growth (bounded to 64 items)
	findings := scanXMLFile("hostile_children.xml", []byte(sb.String()))
	for _, f := range findings {
		if f.RuleID == xmlTooManyChildElementsRuleID {
			t.Errorf("Should not report too many child elements if saturated/homogeneity unknown")
		}
	}
}

func TestXMLMaintainability_DTDCommentedOutMarkup(t *testing.T) {
	xmlData := `<!DOCTYPE root [
      <!-- <legacy/> -->
    ]><root/>`

	assertExactMaintRules(
		t,
		xmlData,
		xmlCommentedOutMarkupRuleID,
	)
}

func TestXMLMaintainability_DTDOversizedComment(t *testing.T) {
	xmlData := `<!DOCTYPE root [
      <!--` + strings.Repeat("a", 1001) + `-->
    ]><root/>`

	assertExactMaintRules(
		t,
		xmlData,
		xmlOversizedCommentRuleID,
	)
}

func TestXMLMaintainability_AlternateXSIPrefixLineNumber(t *testing.T) {
	xmlData := `<root
  xmlns:schema="http://www.w3.org/2001/XMLSchema-instance"
  schema:schemaLocation="urn:stale root.xsd"/>`

	findings := scanXMLFile("test.xml", []byte(xmlData))
	found := false
	for _, f := range findings {
		if f.RuleID == xmlUnusedSchemaLocationRuleID {
			found = true
			if f.Line != 3 {
				t.Errorf("Expected unused schema location on line 3, got %d", f.Line)
			}
		}
	}
	if !found {
		t.Errorf("Expected unused schema location finding")
	}
}
