//go:build cgo

package astwalk

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func TestCSSEmptyBlock(t *testing.T) {
	assertExactCSSRules(t, "a {}", "css:empty-block")
	assertExactCSSRules(t, "a { /* comment only */ }", "css:empty-block")
	assertExactCSSRules(t, "a { color: red; }")
	assertExactCSSRules(t, "@media print {}")
	assertExactCSSRules(t, "@supports (display: grid) {}")
	assertExactCSSRules(t, "@layer components {}")
	assertExactCSSRules(t, "@font-face { src: url(font.woff2); }")
}

func TestCSSMaintainabilityRecoversAfterSyntaxError(t *testing.T) {
	assertExactCSSRules(t, ".good { margin: 0px; }\n.broken { color:", "css:zero-with-unit")
}

func TestCSSImportantOveruse(t *testing.T) {
	assertExactCSSRules(t, "a { color: red !important; }", "css:important-overuse")
	assertExactCSSRules(t, "a { color: red !important; width: 1px !important; }", "css:important-overuse", "css:important-overuse")
	assertExactCSSRules(t, "a { content: \"!important\"; }")
	assertExactCSSRules(t, "a { --x: !important; }")
}

func TestCSSImportantDoesNotLeakIntoSemanticValues(t *testing.T) {
	assertExactCSSRules(t, "a { font-family: Inter, sans-serif !important; }", "css:important-overuse")
	assertExactCSSRules(t, "a { z-index: -1 !important; }", "css:important-overuse", "css:negative-zindex")
	assertExactCSSRules(t, "a { margin: 1rem 1rem !important; }", "css:important-overuse", "css:redundant-value-list")
}

func TestCSSDuplicateSelector(t *testing.T) {
	assertExactCSSRules(t, ".a { color: red; }\n.a { color: blue; }", "css:duplicate-selector")
	assertExactCSSRules(t, ".a, .b { color: red; }\n.a,.b { color: blue; }", "css:duplicate-selector")
	assertExactCSSRules(t, ".a { color: red; }\n@media all { .a { color: blue; } }")
	assertExactCSSRules(t, "@media (width > 1px) { .item { color: red; } }\n@container (width > 1px) { .item { color: blue; } }")
	assertExactCSSRules(t, ".A { color: red; }\n.a { color: blue; }")
	assertExactCSSRules(t, ".a>.b { color: red; }\n.a > .b { color: blue; }", "css:duplicate-selector")
}

func TestCSSZeroWithUnit(t *testing.T) {
	assertExactCSSRules(t, "a { margin: 0px; }", "css:zero-with-unit")
	assertExactCSSRules(t, "a { padding: 0rem 1rem; }", "css:zero-with-unit")
	assertExactCSSRules(t, "a { inset: 0vh; }", "css:zero-with-unit")
	assertExactCSSRules(t, "a { margin: 0px 0rem 0vh; }", "css:zero-with-unit", "css:zero-with-unit", "css:zero-with-unit")
	assertExactCSSRules(t, "a { animation-duration: 0s; }")
	assertExactCSSRules(t, "a { transform: rotate(0deg); }")
	assertExactCSSRules(t, "a { width: 0%; }")
	assertExactCSSRules(t, "a { --gap: 0px; }")
	assertExactCSSRules(t, "a { margin: /* 0px */ 1rem; }")
	assertExactCSSRules(t, "a { margin: calc(0px + 1rem); }", "css:zero-with-unit")
	assertExactCSSRules(t, "a { margin: -0px; }", "css:zero-with-unit")
	assertExactCSSRules(t, "a { margin: .0rem; }", "css:zero-with-unit")
	assertExactCSSRules(t, "a { margin: var(--gap, 0px); }")
	assertExactCSSRules(t, "a { margin: calc(var(--gap, 0px) + 0rem); }", "css:zero-with-unit")
	assertExactCSSRules(t, "a { margin: 10px; }")
	assertExactCSSRules(t, `a { content: "0px"; }`)
}

func TestCSSZeroWithUnitScannerBoundaries(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"0px", true},
		{"-0.0rem", true},
		{"calc(0px + 1rem)", true},
		{"calc(var(--gap, 0px) + 0rem)", true},
		{"/* 0px */ 1rem", false},
		{`"0px"`, false},
		{"var(--gap, 0px)", false},
		{"10px", false},
		{"0.px", false},
		{"#0px", false},
		{"0px-extra", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			if got := hasCSSZeroLengthDimension(tc.value); got != tc.want {
				t.Fatalf("hasCSSZeroLengthDimension(%q) = %t, want %t", tc.value, got, tc.want)
			}
		})
	}
}

func TestCSSZeroWithUnitTokenLines(t *testing.T) {
	findings := scanCSSFixture("a {\n  margin: 0px\n    0rem;\n}")
	var lines []int
	for _, finding := range findings {
		if finding.Rule == "css:zero-with-unit" {
			lines = append(lines, finding.Line)
		}
	}
	sort.Ints(lines)
	if len(lines) != 2 || lines[0] != 2 || lines[1] != 3 {
		t.Fatalf("zero-with-unit lines = %v, want [2 3]", lines)
	}
}

func TestCSSFontNoFallback(t *testing.T) {
	assertExactCSSRules(t, "a { font-family: Inter; }", "css:font-no-fallback")
	assertExactCSSRules(t, "a { font-family: \"Open Sans\", Arial; }", "css:font-no-fallback")
	assertExactCSSRules(t, "a { font-family: \"sans-serif\"; }", "css:font-no-fallback")
	assertExactCSSRules(t, "a { font-family: Inter, sans-serif; }")
	assertExactCSSRules(t, "a { font-family: serif; }")
	assertExactCSSRules(t, "a { font-family: inherit; }")
	assertExactCSSRules(t, "a { font-family: initial; }")
	assertExactCSSRules(t, "a { font-family: unset; }")
	assertExactCSSRules(t, "a { font-family: revert; }")
	assertExactCSSRules(t, "a { font-family: revert-layer; }")
	assertExactCSSRules(t, `a { font-family: "var(foo)"; }`, "css:font-no-fallback")
	assertExactCSSRules(t, `a { font-family: "env(test)"; }`, "css:font-no-fallback")
	assertExactCSSRules(t, "a { font-family: var(--font); }")
	assertExactCSSRules(t, "@font-face { font-family: Inter; }")
}

func TestCSSIDSelectorOveruse(t *testing.T) {
	assertExactCSSRules(t, "#app { color: red; }", "css:id-selector-overuse")
	assertExactCSSRules(t, "main #content .item { color: red; }", "css:id-selector-overuse")
	assertExactCSSRules(t, "[id=\"app\"] { color: red; }")
	assertExactCSSRules(t, ":where(#app) { color: red; }")
	assertExactCSSRules(t, ":WHERE(#app) { color: red; }")
	assertExactCSSRules(t, ":IS(#app) { color: red; }", "css:id-selector-overuse")
	assertExactCSSRules(t, `.foo\#bar { color: red; }`)
	assertExactCSSRules(t, `.foo\:hover { color: red; }`)
	assertExactCSSRules(t, `.foo\,bar { color: red; }`)
}

func TestCSSSelectorFindingLines(t *testing.T) {
	assertCSSRuleLine(t, ".normal,\n#target {\n  color: red;\n}", "css:id-selector-overuse", 2)
}

func TestCSSVendorPrefixNoStandard(t *testing.T) {
	assertExactCSSRules(t, "a { -webkit-transform: scale(1); }", "css:vendor-prefix-no-standard")
	assertExactCSSRules(t, "a { -webkit-transform: scale(1); transform: scale(1); }")
	assertExactCSSRules(t, "a { -webkit-line-clamp: 2; }")
	assertCSSRuleLine(t, "a {\n  color: red;\n  -webkit-transform: scale(1);\n}", "css:vendor-prefix-no-standard", 3)
}

func TestCSSShorthandRedundant(t *testing.T) {
	assertExactCSSRules(t, "a { margin-left: 1rem; margin: 2rem; }", "css:shorthand-redundant")
	assertExactCSSRules(t, "a { margin: 2rem; margin-left: 1rem; }")
	assertExactCSSRules(t, "a { margin-left: 1rem !important; margin: 2rem; }", "css:important-overuse")
}

func TestCSSNegativeZIndex(t *testing.T) {
	assertExactCSSRules(t, "a { z-index: -1; }", "css:negative-zindex")
	assertExactCSSRules(t, "a { z-index: -999; }", "css:negative-zindex")
	assertExactCSSRules(t, "a { z-index: 0; }")
	assertExactCSSRules(t, "a { z-index: -0; }")
	assertExactCSSRules(t, "a { z-index: -000; }")
	assertExactCSSRules(t, "a { z-index: auto; }")
	assertExactCSSRules(t, "a { z-index: var(--layer); }")
}

func TestCSSDuplicateFontFace(t *testing.T) {
	css := "@font-face { font-family: Demo; src: url(demo.woff2); }\n@font-face { src: url(demo.woff2); font-family: Demo; }"
	assertExactCSSRules(t, css, "css:duplicate-font-face")

	cssComments := "@font-face { font-family: Demo; src: url(demo.woff2); }\n@font-face { font-family: Demo /* same */; src: url(demo.woff2); }"
	assertExactCSSRules(t, cssComments, "css:duplicate-font-face")

	cssOk := "@font-face { font-family: Demo; src: url(demo-regular.woff2); }\n@font-face { font-family: Demo; src: url(demo-bold.woff2); font-weight: 700; }"
	assertExactCSSRules(t, cssOk)

	cssDifferentDescriptor := "@font-face { font-family: Demo; src: url(demo.woff2); ascent-override: 90%; }\n" +
		"@font-face { font-family: Demo; src: url(demo.woff2); ascent-override: 100%; }"
	assertExactCSSRules(t, cssDifferentDescriptor)

	oversized := strings.Repeat("a", cssMaxPreludeBytes+1)
	cssIncomplete := "@font-face { font-family: Demo; src: url(\"" + oversized + "\"); }\n" +
		"@font-face { font-family: Demo; src: url(\"" + oversized + "\"); }"
	assertExactCSSRules(t, cssIncomplete)
}

func TestCSSTodoMarker(t *testing.T) {
	assertExactCSSRules(t, "/* TODO: remove legacy rule */", "css:todo-marker")
	assertExactCSSRules(t, "/* FIXME broken on mobile */", "css:todo-marker")
	assertExactCSSRules(t, "/* TODO one\nTODO two */", "css:todo-marker", "css:todo-marker")
	assertCSSRuleLine(t, "/*\nTODO second line\n*/", "css:todo-marker", 2)
	assertExactCSSRules(t, "a { content: \"TODO\"; }")
	assertExactCSSRules(t, "/* todo is ordinary prose */")
}

func TestCSSSelectorSpecificityHigh(t *testing.T) {
	assertExactCSSRules(t, ".card.active[data-state=\"open\"]:hover { color: red; }", "css:selector-specificity-high")
	assertExactCSSRules(t, "main section article div p span { color: red; }", "css:selector-specificity-high", "css:selector-depth-high")
	assertExactCSSRules(t, ".card:hover { color: red; }")
	assertExactCSSRules(t, ":where(.page .content .card .title) { color: red; }")
	assertExactCSSRules(t, ":is(.a, .b, .c, .d) { color: red; }")
	assertExactCSSRules(t, ":not(.a, .b, .c, .d) { color: red; }")
	assertExactCSSRules(t, ":has(.a, .b, .c, .d) { color: red; }")
	assertExactCSSRules(t, ":is(.a, div div div div div) { color: red; }")
	assertExactCSSRules(t, ":is(#target div, .a.b.c.d) { color: red; }", "css:id-selector-overuse")
}

func TestCSSFunctionalPseudoSpecificityUsesLexicographicMaximum(t *testing.T) {
	for _, tc := range []struct {
		selector string
		classes  int
		types    int
	}{
		{":is(.a, .b, .c, .d)", 1, 0},
		{":not(.a, div div div)", 1, 0},
		{":has(.a, div div)", 1, 0},
		{":where(.a#target)", 0, 0},
		{":is(.a, div div div div div)", 1, 0},
		{":is([data-value=\")\"], div)", 1, 0},
		{":not(:is(.a, div div))", 1, 0},
		{"[data-value=\":is(.a)\"]", 1, 0},
	} {
		t.Run(tc.selector, func(t *testing.T) {
			classes, types := computeCSSSelectorSpecificity(tc.selector)
			if classes != tc.classes || types != tc.types {
				t.Fatalf("specificity for %q = (%d,%d), want (%d,%d)", tc.selector, classes, types, tc.classes, tc.types)
			}
		})
	}

	// An incomplete function must terminate without spinning.
	computeCSSSelectorSpecificity(":is(.a")
}

func TestCSSSelectorDepthHigh(t *testing.T) {
	assertExactCSSRules(t, "body main section article .card .title { color: red; }", "css:selector-depth-high")
	assertExactCSSRules(t, "main .card .title { color: red; }")
}

func TestCSSSelectorListTooLong(t *testing.T) {
	assertExactCSSRules(t, ".a,.b,.c,.d,.e,.f,.g,.h,.i { color: red; }", "css:selector-list-too-long")
	assertExactCSSRules(t, ".a,.b,.c,.d,.e,.f,.g,.h { color: red; }")
}

func TestCSSDeclarationBlockTooLarge(t *testing.T) {
	css := "a {\n" +
		"  color: red;\n  width: 1px;\n  height: 1px;\n  margin: 1px;\n  padding: 1px;\n" +
		"  display: block;\n  position: absolute;\n  top: 0;\n  left: 0;\n  right: 0;\n" +
		"  bottom: 0;\n  z-index: 1;\n  opacity: 1;\n  visibility: visible;\n  cursor: pointer;\n" +
		"  overflow: hidden;\n  float: left;\n  clear: both;\n  font-size: 14px;\n  line-height: 1.5;\n  background: blue;\n" +
		"}"
	assertExactCSSRules(t, css, "css:declaration-block-too-large")
}

func TestCSSOverqualifiedSelector(t *testing.T) {
	assertExactCSSRules(t, "div.card { color: red; }", "css:overqualified-selector")
	assertExactCSSRules(t, "a#home { color: red; }", "css:id-selector-overuse", "css:overqualified-selector")
	assertExactCSSRules(t, ".card { color: red; }")
	assertExactCSSRules(t, "div [class=\"card\"] { color: red; }")
	assertExactCSSRules(t, ":where(div.card) { color: red; }")
	assertExactCSSRules(t, ":where(a#home) { color: red; }")
}

func TestCSSKeyframeDeclarationBlockTooLarge(t *testing.T) {
	var css strings.Builder
	css.WriteString("@keyframes fade { 0% {")
	for i := 0; i < 21; i++ {
		css.WriteString("--step-")
		css.WriteString(strconv.Itoa(i))
		css.WriteString(": 0;\n")
	}
	css.WriteString("} }")

	assertExactCSSRules(t, css.String(), "css:declaration-block-too-large")
}

func TestCSSDuplicateKeyframes(t *testing.T) {
	assertExactCSSRules(t, "@keyframes Fade { 0% { opacity: 0; } }\n@keyframes Fade { 0% { opacity: 0; } }", "css:duplicate-keyframes")
	assertExactCSSRules(t, "@keyframes Fade { 0% { opacity: 0; } }\n@keyframes fade { 0% { opacity: 0; } }")
	assertExactCSSRules(t, "@keyframes Fade { 0% { opacity: 0; } }\n@-webkit-keyframes Fade { 0% { opacity: 0; } }")
}

func TestCSSDuplicateMediaQuery(t *testing.T) {
	assertExactCSSRules(t, "@media screen and (min-width: 800px) { a { color: red; } }\n@media screen  and  (min-width: 800px) { b { color: blue; } }", "css:duplicate-media-query")
}

func TestCSSDuplicateImport(t *testing.T) {
	assertExactCSSRules(t, "@import url(\"base.css\");\n@import url(\"base.css\");", "css:duplicate-import")
	assertExactCSSRules(t, "@import url(\"base.css\") screen;\n@import url(\"base.css\") print;")
}

func TestCSSLegacyProperty(t *testing.T) {
	assertExactCSSRules(t, "a { clip: rect(0, 0, 0, 0); }", "css:legacy-property")
	assertExactCSSRules(t, "@page { page-break-before: always; }", "css:legacy-property")
	assertExactCSSRules(t, "a { clip-path: inset(0); }")
}

func TestCSSPageContextIsolation(t *testing.T) {
	assertExactCSSRules(t, "@page {}")
	assertExactCSSRules(t, "@page { margin: 0px; }")
	assertExactCSSRules(t, "@page { /* TODO print layout */ margin: 0px; }", "css:todo-marker")
	assertExactCSSRules(t, "@page { page-break-before: always; }", "css:legacy-property")
}

func TestCSSLegacyPseudoElement(t *testing.T) {
	assertExactCSSRules(t, "a:before { content: \"\"; }", "css:legacy-pseudo-element")
	assertExactCSSRules(t, "a:after { content: \"\"; }", "css:legacy-pseudo-element")
	assertExactCSSRules(t, "a:beforex { color: red; }")
	assertExactCSSRules(t, "a:first-lineage { color: red; }")
	assertExactCSSRules(t, `[data-value=":before"] { color: red; }`)
	assertExactCSSRules(t, `a\:before { color: red; }`)
	assertExactCSSRules(t, "a::before { content: \"\"; }")
	assertExactCSSRules(t, "a:hover { color: red; }")
}

func TestCSSRedundantValueList(t *testing.T) {
	assertExactCSSRules(t, "a { margin: 1rem 1rem; }", "css:redundant-value-list")
	assertExactCSSRules(t, "a { margin: 1rem 2rem 1rem; }", "css:redundant-value-list")
	assertExactCSSRules(t, "a { margin: 1rem 2rem 1rem 2rem; }", "css:redundant-value-list")
	assertExactCSSRules(t, "a { margin: 1rem 2rem; }")
	assertExactCSSRules(t, "a { margin: var(--space) var(--space); }")
}

func TestCSSMaintainabilityRuntimeCatalogParity(t *testing.T) {
	// 1. Runtime keys
	runtimeKeys := make([]string, 0, len(cssRules))
	runtimeSeverities := make(map[string]string, len(cssRules))
	for k, r := range cssRules {
		runtimeKeys = append(runtimeKeys, r.id)
		runtimeSeverities[r.id] = r.severity
		if r.id != "css:"+k {
			t.Errorf("Mismatch in cssRules map key %q vs rule ID %q", k, r.id)
		}
	}
	sort.Strings(runtimeKeys)

	// 2. Catalog keys
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default catalog failed: %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("List catalog rules failed: %v", err)
	}
	catalogKeys := make([]string, 0)
	catalogSeverities := make(map[string]string)
	for _, r := range rules {
		if r.Language == "CSS" {
			catalogKeys = append(catalogKeys, string(r.Key))
			catalogSeverities[string(r.Key)] = string(r.DefaultSeverity)
		}
	}
	sort.Strings(catalogKeys)

	// 3. rule_keys.txt keys
	fileBytes, err := os.ReadFile("../../rulecatalog/testdata/rule_keys.txt")
	if err != nil {
		t.Fatalf("Read rule_keys.txt failed: %v", err)
	}
	lines := strings.Split(string(fileBytes), "\n")
	fileKeys := make([]string, 0)
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "css:") {
			fileKeys = append(fileKeys, l)
		}
	}
	sort.Strings(fileKeys)

	if len(runtimeKeys) != 30 || len(catalogKeys) != 30 || len(fileKeys) != 30 {
		t.Fatalf("Expected 30 CSS rules across all sets, got runtime=%d, catalog=%d, file=%d",
			len(runtimeKeys), len(catalogKeys), len(fileKeys))
	}

	for i := 0; i < 30; i++ {
		if runtimeKeys[i] != catalogKeys[i] || catalogKeys[i] != fileKeys[i] {
			t.Fatalf("Key mismatch at index %d: runtime=%q, catalog=%q, file=%q",
				i, runtimeKeys[i], catalogKeys[i], fileKeys[i])
		}
		if runtimeSeverities[runtimeKeys[i]] != catalogSeverities[runtimeKeys[i]] {
			t.Fatalf("Severity mismatch for %q: runtime=%q, catalog=%q", runtimeKeys[i], runtimeSeverities[runtimeKeys[i]], catalogSeverities[runtimeKeys[i]])
		}
	}
}

func TestCSSMaintainabilityDeterminism(t *testing.T) {
	fixture := "a { color: red !important; margin: 0px; z-index: -1; }\n" +
		".card.active[data-state=\"open\"]:hover { color: red; }\n" +
		"a:before { content: \"\"; }"

	var firstOutput string
	for i := 0; i < 50; i++ {
		res := scanCSSFixture(fixture)
		outputStr := formatCSSFindings(res)
		if i == 0 {
			firstOutput = outputStr
		} else if outputStr != firstOutput {
			t.Fatalf("Nondeterministic output at iteration %d:\nFirst:\n%s\nGot:\n%s", i, firstOutput, outputStr)
		}
	}
}

func TestCSSHostileSizeMemoryBounds(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(".correctness { color: red; color: red; }\n")
	for i := 0; i < 5000; i++ {
		sb.WriteString(".class_")
		sb.WriteString(strconv.Itoa(i))
		sb.WriteString(" { color: red !important; margin: 0px; }\n")
	}
	sb.WriteString(".class_0 { color: blue; }\n")

	src := sb.String()
	res := scanCSSFixture(src)

	if len(res) > 100 {
		t.Errorf("Expected findings count capped at <= 100, got %d", len(res))
	}

	ruleCounts := make(map[string]int)
	for _, f := range res {
		ruleCounts[f.Rule]++
		if ruleCounts[f.Rule] > 20 {
			t.Errorf("Per-rule count exceeded 20 for rule %q: %d", f.Rule, ruleCounts[f.Rule])
		}
	}
	if ruleCounts["css:duplicate-property"] != 1 {
		t.Fatalf("correctness finding was not prioritized before maintainability output: %+v", ruleCounts)
	}
	if ruleCounts["css:duplicate-selector"] != 1 {
		t.Fatalf("tracked duplicate was lost after the selector map reached its cap: %+v", ruleCounts)
	}

	root := parseCSS(src)
	if root == nil {
		t.Fatal("CSS parser unavailable")
	}
	collector := &cssCollector{counts: make(map[string]int)}
	ctx := newCSSMaintContext([]byte(src), "test.css", collector)
	ctx.walkMaintainabilityNode(root, nil, 0)
	if got := len(ctx.selectorOccurrences); got != cssMaxTrackedItems {
		t.Fatalf("tracked selector count = %d, want cap %d", got, cssMaxTrackedItems)
	}
	if got := len(ctx.mediaOccurrences) + len(ctx.importOccurrences) + len(ctx.keyframeOccurrences) + len(ctx.fontFaceOccurrences); got != 0 {
		t.Fatalf("unexpected non-selector tracked state: %d", got)
	}
}

func scanCSSFixture(src string) []QualityFinding {
	root := parseCSS(src)
	if root == nil {
		return nil
	}
	return cssFindings(root, []byte(src), "test.css")
}

func parseCSS(src string) *sitter.Node {
	spec, ok := specs["CSS"]
	if !ok {
		return nil
	}
	return parseRoot(context.Background(), spec, []byte(src))
}

func formatCSSFindings(findings []QualityFinding) string {
	var sb strings.Builder
	for _, f := range findings {
		sb.WriteString(f.Rule)
		sb.WriteString(":")
		sb.WriteString(f.Description)
		sb.WriteString("\n")
	}
	return sb.String()
}
