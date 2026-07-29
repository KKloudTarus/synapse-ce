//go:build cgo

package astwalk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func scanHTMLFixture(source string) []QualityFinding {
	tmpDir, err := os.MkdirTemp("", "htmltest-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)

	filePath := filepath.Join(tmpDir, "test.html")
	if err := os.WriteFile(filePath, []byte(source), 0644); err != nil {
		panic(err)
	}

	res, err := QualityFor(context.Background(), tmpDir)
	if err != nil {
		panic(err)
	}
	return res.Findings
}

func assertExactHTMLRules(t *testing.T, source string, expected ...string) {
	t.Helper()
	findings := scanHTMLFixture(source)
	var existingFamilyFindings []QualityFinding

	for _, f := range findings {
		if f.Kind == "" {
			t.Errorf("empty Kind for rule %s", f.Rule)
		}
		if f.Severity == "" {
			t.Errorf("empty Severity for rule %s", f.Rule)
		}
		if f.Title == "" {
			t.Errorf("empty Title for rule %s", f.Rule)
		}
		if f.Description == "" {
			t.Errorf("empty Description for rule %s", f.Rule)
		}
		if f.File == "" {
			t.Errorf("empty File for rule %s", f.Rule)
		}
		if f.Line <= 0 {
			t.Errorf("invalid Line %d for rule %s", f.Line, f.Rule)
		}
		if f.Kind != "quality" {
			existingFamilyFindings = append(existingFamilyFindings, f)
		}
	}

	gotRules := make([]string, len(existingFamilyFindings))
	for i, f := range existingFamilyFindings {
		gotRules[i] = f.Rule
	}

	sort.Strings(gotRules)
	expSorted := append([]string(nil), expected...)
	sort.Strings(expSorted)

	if len(gotRules) != len(expSorted) {
		t.Fatalf("rules count mismatch:\nGot:  %v\nWant: %v", gotRules, expSorted)
	}
	for i := range gotRules {
		if gotRules[i] != expSorted[i] {
			t.Fatalf("rules mismatch at index %d:\nGot:  %v\nWant: %v", i, gotRules, expSorted)
		}
	}
}

func assertHTMLRuleLine(t *testing.T, source, ruleID string, expectedLine int) {
	t.Helper()
	findings := scanHTMLFixture(source)
	found := false
	for _, f := range findings {
		if f.Rule == ruleID {
			if f.Line != expectedLine {
				t.Fatalf("rule %s expected line %d, got %d", ruleID, expectedLine, f.Line)
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("rule %s not emitted for source:\n%s", ruleID, source)
	}
}

// 7.2 Per-rule golden cases

func TestHTMLDoctypeRules(t *testing.T) {
	// Full document without doctype
	assertExactHTMLRules(t, "<html><body><p>Hello</p></body></html>", "html:doctype-missing")

	// Valid doctypes
	assertExactHTMLRules(t, "<!doctype html>\n<html></html>")
	assertExactHTMLRules(t, "<!DOCTYPE HTML>\n<html></html>")
	assertExactHTMLRules(t, "\uFEFF<!-- comment -->\n  <!doctype html>\n<html></html>")

	// Invalid doctypes
	assertExactHTMLRules(t, "<!doctype svg>\n<html></html>", "html:doctype-invalid")
	assertExactHTMLRules(t, "<!doctype html>\n<!doctype html>\n<html></html>", "html:doctype-invalid")
	assertExactHTMLRules(t, "<html></html>\n<!doctype html>", "html:doctype-invalid")

	// Empty / whitespace / comment only
	assertExactHTMLRules(t, "")
	assertExactHTMLRules(t, "   \n\t  ")
	assertExactHTMLRules(t, "<!-- only comments -->")
}

func TestHTMLDuplicateAttributeRule(t *testing.T) {
	assertExactHTMLRules(t, "<!doctype html><div class=\"a\" CLASS=\"b\"></div>", "html:duplicate-attribute")
	assertExactHTMLRules(t, "<!doctype html><input disabled disabled>", "html:duplicate-attribute")
	assertExactHTMLRules(t, "<!doctype html><div class=\"a\"></div><span class=\"b\"></span>")
	assertExactHTMLRules(t, "<!doctype html><div data-x=\"1\" data-y=\"2\"></div>")
	assertExactHTMLRules(t, "<!doctype html><div É=\"one\" é=\"two\"></div>")
}

func TestHTMLDuplicateAndInvalidIDRules(t *testing.T) {
	assertExactHTMLRules(t, "<!doctype html><div id=\"item\"></div><span id=\"item\"></span>", "html:duplicate-id")
	assertExactHTMLRules(t, "<!doctype html><div id=\"Item\"></div><span id=\"item\"></span>")
	assertExactHTMLRules(t, "<!doctype html><div id=\"a&amp;b\"></div><span id=\"a&b\"></span>", "html:duplicate-id")
	assertExactHTMLRules(t, "<!doctype html><div id=\"active\"></div><button active>Save</button>")
	assertExactHTMLRules(t, "<!doctype html><div id=\"\"></div>", "html:invalid-id")
	assertExactHTMLRules(t, "<!doctype html><div id></div>", "html:invalid-id")
	assertExactHTMLRules(t, "<!doctype html><div id=></div>", "html:invalid-id")
	assertExactHTMLRules(t, "<!doctype html><div id=\"a b\"></div>", "html:invalid-id")
	assertExactHTMLRules(t, "<!doctype html><div id=\"123\"></div>")
	assertExactHTMLRules(t, "<!doctype html><div id=\"_\"></div>")
	assertExactHTMLRules(t, "<!doctype html><div id=\"{{ item.id }}\"></div><span id=\"{{ item.id }}\"></span>")
	assertExactHTMLRules(t, "<!doctype html><div id=\"{% id %}\"></div>")
	assertExactHTMLRules(t, "<!doctype html><div id=\"${id}\"></div>")
	assertExactHTMLRules(t, "<!doctype html><div id=\"<% id %>\"></div>")
}

func TestHTMLTagCompletenessRules(t *testing.T) {
	assertExactHTMLRules(t, "<!doctype html><div><span></div>", "html:unclosed-tag")
	assertExactHTMLRules(t, "<!doctype html><div><span>", "html:unclosed-tag", "html:unclosed-tag")
	assertExactHTMLRules(t, "<!doctype html><script>console.log('hi');", "html:unclosed-tag")
	assertExactHTMLRules(t, "<!doctype html><style>body { color: red; }", "html:unclosed-tag")

	src := "<!doctype html>\n<div>\n  <span>"
	findings := scanHTMLFixture(src)
	lines := make(map[int]bool)
	for _, f := range findings {
		if f.Rule == "html:unclosed-tag" {
			lines[f.Line] = true
		}
	}
	if len(lines) != 2 || !lines[2] || !lines[3] {
		t.Fatalf("expected exactly two unclosed tags at lines 2 and 3, got: %v", findings)
	}

	// Void elements & optional end tags
	assertExactHTMLRules(t, "<!doctype html><img src=\"a.jpg\"><br><hr><input type=\"text\">")
	assertExactHTMLRules(t, "<!doctype html><html><head><title>T</title><body><p>Para<li>Item1<li>Item2")

	// Erroneous end tags
	assertExactHTMLRules(t, "<!doctype html></div>", "html:unexpected-end-tag")
	assertExactHTMLRules(t, "<!doctype html><img src=\"a.jpg\"></img>", "html:unexpected-end-tag")
}

func TestHTMLNonvoidSelfClosingRule(t *testing.T) {
	assertExactHTMLRules(t, "<!doctype html><div />", "html:nonvoid-self-closing")
	assertExactHTMLRules(t, "<!doctype html><x-card />", "html:nonvoid-self-closing")
	assertExactHTMLRules(t, "<!doctype html><img />")
	assertExactHTMLRules(t, "<!doctype html><svg><path /></svg>")
	assertExactHTMLRules(t, "<!doctype html><math><mi /></math>")
}

func TestHTMLMalformedEndTagDoesNotCloseElement(t *testing.T) {
	assertExactHTMLRules(
		t,
		"<!doctype html><div></>",
		"html:unclosed-tag",
		"html:unexpected-end-tag",
	)
}

func TestHTMLNestedFormRule(t *testing.T) {
	assertExactHTMLRules(t, "<!doctype html><form><form></form></form>", "html:nested-form")
	assertExactHTMLRules(t, "<!doctype html><form><div><form></form></div></form>", "html:nested-form")
	assertExactHTMLRules(t, "<!doctype html><form></form><form></form>")
	assertExactHTMLRules(t, "<!doctype html><form><template><form></form></template></form>")
	assertExactHTMLRules(t, "<!doctype html><script>var x = '<form></form>';</script>")
}

func TestHTMLDuplicateDocumentElementRule(t *testing.T) {
	assertExactHTMLRules(t, "<!doctype html><html></html><html></html>", "html:duplicate-document-element")
	assertExactHTMLRules(t, "<!doctype html><head></head><head></head>", "html:duplicate-document-element")
	assertExactHTMLRules(t, "<!doctype html><body></body><body></body>", "html:duplicate-document-element")
	assertExactHTMLRules(t, "<!doctype html><html><head></head><body></body></html>")
}

// 7.3 Recovery and noise tests

func TestHTMLRecoveryPreservesValidSiblings(t *testing.T) {
	assertExactHTMLRules(
		t,
		`<!doctype html><div id="same"></div><div title="<span id=same>"></div>`,
	)

	src := `<!doctype html>
<div id="same"></div>
<div class="
<span id="same"></span>`
	findings := scanHTMLFixture(src)
	for _, f := range findings {
		if f.Rule == "html:duplicate-id" {
			t.Fatalf("unexpected html:duplicate-id from malformed unclosed attribute parsing: %v", f)
		}
	}
}

func TestHTMLCommentsAndRawTextAreNotMarkup(t *testing.T) {
	src := `<!doctype html>
<!-- <form><form></form></form> </div> -->
<script>
  var html = '<form><form></form></form>';
</script>
<style>
  div { content: '</form>'; }
</style>
<div></div>`
	assertExactHTMLRules(t, src)
}

func TestHTMLMalformedAttributesFailClosed(t *testing.T) {
	src := `<!doctype html>
<div class= = ></div>`
	findings := scanHTMLFixture(src)
	// Should fail closed without crashing or generating false duplicate attribute findings
	for _, f := range findings {
		if f.Rule == "html:duplicate-attribute" {
			t.Fatalf("unexpected duplicate attribute finding on malformed attribute: %v", f)
		}
	}
}

func TestHTMLCRLFLineMapping(t *testing.T) {
	src := "<!doctype html>\r\n<form>\r\n<div>\r\n<form></form>\r\n</div>\r\n</form>"
	assertHTMLRuleLine(t, src, "html:nested-form", 4)
}

// 7.4 Inventory and severity parity

func TestHTMLInventoryAndSeverityParity(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default(): %v", err)
	}

	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("cat.List: %v", err)
	}

	var catHTMLRules []rule.Rule
	for _, r := range rules {
		if r.Language == "HTML" {
			catHTMLRules = append(catHTMLRules, r)
		}
	}

	if len(catHTMLRules) != 50 {
		t.Fatalf("expected 50 catalog rules for HTML, got %d", len(catHTMLRules))
	}

	if len(htmlRuntimeRules) != 50 {
		t.Fatalf("expected 50 runtime rules for HTML, got %d", len(htmlRuntimeRules))
	}

	for key, rtRule := range htmlRuntimeRules {
		catRule, err := cat.Get(context.Background(), rule.Key(rtRule.id))
		if err != nil {
			t.Fatalf("runtime rule %s (key: %s) not found in catalog: %v", rtRule.id, key, err)
		}
		if string(catRule.DefaultSeverity) != rtRule.severity {
			t.Fatalf("severity mismatch for %s: catalog=%s, runtime=%s", rtRule.id, catRule.DefaultSeverity, rtRule.severity)
		}
		if string(catRule.Language) != "HTML" {
			t.Fatalf("language mismatch for %s: catalog=%s", rtRule.id, catRule.Language)
		}
	}
}

// 7.5 Determinism and caps

func TestHTMLFindingsDeterministic(t *testing.T) {
	hostileSrc := `<!doctype html>
<div id="a" id="a" class="c" class="c"></div>
<div id="a"></div>
<form><form></form></form>
<div />
<span id=""></span>
<span id="invalid whitespace"></span>
<html></html><html></html>
<head></head><head></head>
<body></body><body></body>
</div>
</img`

	var reference string
	for i := 0; i < 50; i++ {
		findings := scanHTMLFixture(hostileSrc)
		var current string
		for _, f := range findings {
			current += fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d\n", f.Rule, f.Kind, f.Severity, f.Title, f.Description, f.File, f.Line)
		}
		if i == 0 {
			reference = current
		} else if current != reference {
			t.Fatalf("nondeterministic findings output on iteration %d:\nFirst:\n%s\nGot:\n%s", i, reference, current)
		}
	}
}

func TestHTMLPerRuleFindingCap(t *testing.T) {
	src := "<!doctype html>\n"
	for i := 0; i < 30; i++ {
		src += "<div />\n"
	}
	findings := scanHTMLFixture(src)
	count := 0
	for _, f := range findings {
		if f.Rule == "html:nonvoid-self-closing" {
			count++
		}
	}
	if count != 20 {
		t.Fatalf("expected exactly 20 findings for per-rule cap, got %d", count)
	}
}

func TestHTMLGlobalFindingCap(t *testing.T) {
	src := "<!doctype html>\n"
	for i := 0; i < 150; i++ {
		src += fmt.Sprintf("<div id=\"item-%d\" id=\"dup-%d\" />\n", i, i)
	}
	findings := scanHTMLFixture(src)
	if len(findings) > 100 {
		t.Fatalf("expected at most 100 total findings for global cap, got %d", len(findings))
	}
}

func TestHTMLIDTrackingCapPreservesKnownDuplicates(t *testing.T) {
	src := "<!doctype html>\n"
	// Generate 4100 unique IDs to overflow the 4096 cap
	for i := 0; i < 4100; i++ {
		src += fmt.Sprintf("<div id=\"id-%d\"></div>\n", i)
	}
	// Re-use an ID from early in the document (within the first 4096)
	src += "<div id=\"id-5\"></div>\n"

	findings := scanHTMLFixture(src)
	foundDup := false
	for _, f := range findings {
		if f.Rule == "html:duplicate-id" {
			foundDup = true
			break
		}
	}
	if !foundDup {
		t.Fatalf("expected duplicate-id for known pre-cap ID after tracking map overflowed")
	}
}

// 7.6 Language isolation

func TestHTMLLanguageIsolation(t *testing.T) {
	nonHTMLFiles := map[string]string{
		"test.xhtml":  "<div />",
		"test.xml":    "<div />",
		"test.jsx":    "<div />",
		"test.tsx":    "<div />",
		"test.vue":    "<template><div /></template>",
		"test.svelte": "<div />",
	}

	tmpDir, err := os.MkdirTemp("", "htmllangtest-*")
	if err != nil {
		t.Fatalf("os.MkdirTemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	for name, content := range nonHTMLFiles {
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0644); err != nil {
			t.Fatalf("os.WriteFile(%s): %v", name, err)
		}
	}

	res, err := QualityFor(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}

	if len(res.Findings) != 0 {
		t.Fatalf("expected 0 findings for non-HTML files, got %d: %v", len(res.Findings), res.Findings)
	}
}
