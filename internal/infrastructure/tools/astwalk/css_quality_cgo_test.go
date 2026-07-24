//go:build cgo

package astwalk

import (
	"bytes"
	"context"
	"sort"
	"strconv"
	"strings"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/css"
)

func assertExactCSSRules(t *testing.T, cssSource string, expected ...string) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "test.css", cssSource)

	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor error: %v", err)
	}

	var got []QualityFinding
	for _, f := range res.Findings {
		if strings.HasSuffix(f.File, "test.css") {
			if f.Line <= 0 {
				t.Errorf("Finding %q has invalid line %d", f.Rule, f.Line)
			}
			got = append(got, f)
		}
	}

	sort.Strings(expected)
	want := expected

	sort.Slice(got, func(i, j int) bool {
		return got[i].Rule < got[j].Rule
	})

	var gotRules []string
	for _, f := range got {
		gotRules = append(gotRules, f.Rule)
	}

	if len(got) != len(want) {
		t.Fatalf("Expected %d findings %v, got %d findings %v", len(want), want, len(got), gotRules)
	}

	for i := range got {
		if got[i].Rule != want[i] || got[i].Kind != "reliability" || got[i].Severity == "" || got[i].File == "" || got[i].Line <= 0 {
			t.Errorf("Finding %d: got %+v, want rule %q with full hygiene metadata", i, got[i], want[i])
		}
	}
}

func assertCSSRuleLine(t *testing.T, cssSource string, ruleID string, expectedLine int) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "test.css", cssSource)

	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor error: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if strings.HasSuffix(f.File, "test.css") && f.Rule == ruleID {
			if f.Line == expectedLine {
				found = true
			} else {
				t.Errorf("Expected %s at line %d, got line %d", ruleID, expectedLine, f.Line)
				found = true
			}
		}
	}

	if !found {
		t.Errorf("Expected to find %s at line %d, but no such finding occurred", ruleID, expectedLine)
	}
}

func TestCSSDoesNotScanSCSS(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "test.scss", "a { width: 10pzz; }")
	writeFile(t, root, "test.less", "a { width: 10pzz; }")
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	if len(res.Findings) > 0 {
		t.Errorf("Expected 0 findings for SCSS/Less, got %d", len(res.Findings))
	}
}

func TestCSSDuplicateProperty(t *testing.T) {
	assertExactCSSRules(t, "a { color: red; color: red; }", "css:duplicate-property")
	assertExactCSSRules(t, "a { COLOR: red; color: red; }", "css:duplicate-property")
	assertExactCSSRules(t, "a { color: red; color: blue; }")
	assertExactCSSRules(t, "a { color: red; color: red !important; }")
	assertExactCSSRules(t, "a { color: red; } b { color: red; }")
	assertExactCSSRules(t, "@keyframes fade { 0% { color: red; } 100% { color: red; } }")
	assertExactCSSRules(t, "a { --theme: red; --theme: red; }")
	assertExactCSSRules(t, "a { border: 1px solid red; border: 1px  solid  red; }", "css:duplicate-property")
	assertExactCSSRules(t, "a { color: red; color: red; color: red; }", "css:duplicate-property", "css:duplicate-property")
	assertExactCSSRules(t, `a { content: "First"; content: "Second"; }`)
	assertExactCSSRules(t, "a { width: var(--first); width: var(--second); }")
}

func TestCSSInvalidHexColor(t *testing.T) {
	assertExactCSSRules(t, "a { color: #12; }", "css:invalid-hex-color")
	assertExactCSSRules(t, "a { color: #12345; }", "css:invalid-hex-color")
	assertExactCSSRules(t, "a { color: #1234567; }", "css:invalid-hex-color")
	assertExactCSSRules(t, "a { color: #ggg; }", "css:invalid-hex-color")
	assertExactCSSRules(t, "a { color: #123456789; }", "css:invalid-hex-color")
	assertExactCSSRules(t, "a { color: #12; background: #ggg; }", "css:invalid-hex-color", "css:invalid-hex-color")
	assertExactCSSRules(t, "a { color: #123; }")
	assertExactCSSRules(t, "a { color: #1234; }")
	assertExactCSSRules(t, "a { color: #112233; }")
	assertExactCSSRules(t, "a { color: #11223344; }")
	assertExactCSSRules(t, "a { filter: url(#12); }")
	assertExactCSSRules(t, "a { color: var(--x, #12); }")
	assertExactCSSRules(t, "a { color: env(foo, #12); }")
	assertExactCSSRules(t, `a { content: "#12"; }`)
	assertExactCSSRules(t, "a { /* #12 */ color: red; }")
	assertExactCSSRules(t, "a { --x: #12; }")
	assertExactCSSRules(t, "a { color: #12 width: 10px; }")
	assertExactCSSRules(t, "a { color: #12: red; }")
	assertExactCSSRules(t, "a { color: #12 broken; width: 1px; }")

	assertCSSRuleLine(t, "a {\n  color: #12;\n}", "css:invalid-hex-color", 2)
	assertCSSRuleLine(t, "a {\r\n  color: #12;\r\n}", "css:invalid-hex-color", 2)
}

func TestCSSUnknownProperty(t *testing.T) {
	assertExactCSSRules(t, "a { colr: red; }", "css:unknown-property")
	assertExactCSSRules(t, "a { backgroud-color: red; }", "css:unknown-property") //nolint:misspell
	assertExactCSSRules(t, "a { widht: 10px; }", "css:unknown-property")
	assertExactCSSRules(t, "a { size: A4; }", "css:unknown-property")
	assertExactCSSRules(t, "a { color: red; }")
	assertExactCSSRules(t, "a { COLOR: red; }")
	assertExactCSSRules(t, "a { --custom-value: anything; }")
	assertExactCSSRules(t, "a { -webkit-line-clamp: 2; }")
	assertExactCSSRules(t, "a { -moz-box-sizing: border-box; }")
	assertExactCSSRules(t, "a { colr: url(https://example.com/image.png); }", "css:unknown-property")
	assertExactCSSRules(t, "@font-face { src: url(font.woff2); }")
	assertExactCSSRules(t, "@page { size: A4; }")
}

func TestCSSInvalidUnit(t *testing.T) {
	assertExactCSSRules(t, "a { width: 10pzz; }", "css:invalid-unit")
	assertExactCSSRules(t, "a { transform: rotate(1degrees); }", "css:invalid-unit")
	assertExactCSSRules(t, "a { animation-duration: 2sec; }", "css:invalid-unit")
	assertExactCSSRules(t, "a { margin: 3pixels; }", "css:invalid-unit")
	assertExactCSSRules(t, "a { width: 0; }")
	assertExactCSSRules(t, "a { width: 0px; }")
	assertExactCSSRules(t, "a { width: 10PX; }")
	assertExactCSSRules(t, "a { --size: 10pzz; }")
	assertExactCSSRules(t, "a { content: '10pzz'; }")
	assertExactCSSRules(t, "a { background: url(10pzz); }")
	assertExactCSSRules(t, "a { width: var(--size, 10rpx); }")
	assertExactCSSRules(t, "a { width: calc(100vw - 2rem); }")
}

func TestCSSInvalidKeyframeSelector(t *testing.T) {
	assertExactCSSRules(t, "@keyframes x { -1%, 101% { opacity: 0; } }", "css:invalid-keyframe-selector", "css:invalid-keyframe-selector")
	assertExactCSSRules(t, "@keyframes x { 0, 101% { opacity: 0; } }", "css:invalid-keyframe-selector", "css:invalid-keyframe-selector")
	assertExactCSSRules(t, "@keyframes fade { 0 { opacity: 0; } }", "css:invalid-keyframe-selector")
	assertExactCSSRules(t, "@keyframes fade { -1% { opacity: 0; } }", "css:invalid-keyframe-selector")
	assertExactCSSRules(t, "@keyframes fade { 101% { opacity: 0; } }", "css:invalid-keyframe-selector")
	assertExactCSSRules(t, "@keyframes fade { 100.01% { opacity: 0; } }", "css:invalid-keyframe-selector")

	assertExactCSSRules(t, "@keyframes fade { from { opacity: 0; } to { opacity: 1; } }")
	assertExactCSSRules(t, "@keyframes fade { 0% { opacity: 0; } 50% { opacity: 0.5; } 100% { opacity: 1; } }")
	assertExactCSSRules(t, "@keyframes fade { 0%, 50%, 100% { opacity: 1; } }")
	assertExactCSSRules(t, "@keyframes fade { entry 0% { opacity: 0; } }")
	assertExactCSSRules(t, "@-webkit-keyframes fade { 50% { opacity: 1; } }")
}

func TestCSSKeyframeStructuralRecovery(t *testing.T) {
	assertExactCSSRules(t, `
		@keyframes x {
			101% {
				opacity: 0;
	`)

	assertExactCSSRules(t, `
		@keyframes x {
			101% {
				opacity: 0;
			}
	`)

	assertExactCSSRules(
		t,
		`@keyframes x { 101% { opacity: 0; } }`,
		"css:invalid-keyframe-selector",
	)
}

func TestCSSNegativeAnimationDuration(t *testing.T) {
	assertExactCSSRules(t, "a { animation-duration: -1s; }", "css:negative-animation-duration")
	assertExactCSSRules(t, "a { animation-duration: -200ms; }", "css:negative-animation-duration")
	assertExactCSSRules(t, "a { animation-duration: 1s, -2s; }", "css:negative-animation-duration")

	assertExactCSSRules(t, "a { animation-duration: 0s; }")
	assertExactCSSRules(t, "a { animation-duration: -0s; }")
	assertExactCSSRules(t, "a { animation-duration: 1s; }")
	assertExactCSSRules(t, "a { animation-duration: var(--duration); }")
	assertExactCSSRules(t, "a { animation-duration: calc(2s - 1s); }")
	assertExactCSSRules(t, "a { animation-delay: -1s; }")
	assertExactCSSRules(t, "a { transition-duration: -1s; }")
}

func TestCSSInvalidFontWeight(t *testing.T) {
	assertExactCSSRules(t, "a { font-weight: 0; }", "css:invalid-font-weight")
	assertExactCSSRules(t, "a { font-weight: 1001; }", "css:invalid-font-weight")

	assertExactCSSRules(t, "a { font-weight: 1; }")
	assertExactCSSRules(t, "a { font-weight: 400; }")
	assertExactCSSRules(t, "a { font-weight: 1000; }")
	assertExactCSSRules(t, "a { font-weight: normal; }")
	assertExactCSSRules(t, "a { font-weight: bold; }")
	assertExactCSSRules(t, "a { font-weight: bolder; }")
	assertExactCSSRules(t, "a { font-weight: lighter; }")
	assertExactCSSRules(t, "a { font-weight: var(--weight); }")
	assertExactCSSRules(t, "a { font-weight: calc(400 + 100); }")
	assertExactCSSRules(t, "@font-face { font-weight: 100 900; }")
}

func TestCSSNegativeFlexFactor(t *testing.T) {
	assertExactCSSRules(t, "a { flex-grow: -1; }", "css:negative-flex-factor")
	assertExactCSSRules(t, "a { flex-shrink: -0.5; }", "css:negative-flex-factor")

	assertExactCSSRules(t, "a { flex-grow: -0; }")
	assertExactCSSRules(t, "a { flex-grow: 0; }")
	assertExactCSSRules(t, "a { flex-grow: 1; }")
	assertExactCSSRules(t, "a { order: -1; }")
}

func TestCSSKnownPropertiesInventory(t *testing.T) {
	if len(cssKnownPropertyNames) < 400 {
		t.Errorf("Expected at least 400 properties, got %d", len(cssKnownPropertyNames))
	}
	if !sort.StringsAreSorted(cssKnownPropertyNames) {
		t.Errorf("Property inventory is not sorted")
	}

	hasAccentColor := false
	for i, p := range cssKnownPropertyNames {
		if p == "accent-color" {
			hasAccentColor = true
		}
		if strings.ToLower(p) != p {
			t.Errorf("Property %q is not lowercase", p)
		}
		if i > 0 && cssKnownPropertyNames[i] == cssKnownPropertyNames[i-1] {
			t.Errorf("Duplicate property %q", p)
		}
		if p == "colr" || p == "widht" || p == "backgroud-color" || p == "size" { //nolint:misspell // intentional invalid-property sentinel
			t.Errorf("Property %q should not be in ordinary property inventory", p)
		}
	}
	if !hasAccentColor {
		t.Errorf("Missing modern property accent-color")
	}
}

func TestCSSKnownUnitsInventory(t *testing.T) {
	expected := []string{"em", "vw", "px", "deg", "s", "hz", "dpi", "fr"}
	for _, u := range expected {
		if !cssKnownUnits[u] {
			t.Errorf("Missing known unit %q", u)
		}
	}
}

func TestCSSRecoveryBarrier(t *testing.T) {
	assertExactCSSRules(t, "a { color: red;")
	assertExactCSSRules(t, "a { color red; }")
	assertExactCSSRules(t, "a >> b { color: red; }")
	assertExactCSSRules(t, "a { width: calc(10px; }")
	assertExactCSSRules(t, "a { $invalid; color: red; }")
	assertExactCSSRules(t, "a { color: red; $invalid }")
	assertExactCSSRules(t, "@keyframes foo { abc { color: red; } }")
	assertExactCSSRules(t, "@font-face { src url(font.woff); }")

	assertExactCSSRules(t, "a { color: #12 width: 10px; }")
	assertExactCSSRules(t, "a { color: #12: red; }")
	assertExactCSSRules(t, "a { color: #12 broken; width: 10px; }")
}

func TestCSSGrammarContract(t *testing.T) {
	src := []byte(`
		@font-face {
			font-family: 'MyFont';
		}
		@keyframes slidein {
			from { transform: translateX(0%); }
			to { transform: translateX(100%); }
		}
		.container {
			color: red;
			width: calc(100px);
			animation-duration: 2s;
			font-weight: 400;
			opacity: 0.5;
		}
	`)

	parser := sitter.NewParser()
	parser.SetLanguage(css.GetLanguage())
	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	foundNodes := make(map[string]bool)
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		foundNodes[n.Type()] = true
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i))
		}
	}
	walk(tree.RootNode())

	requiredTypes := []string{
		"at_rule",
		"at_keyword",
		"keyframes_statement",
		"keyframe_block",
		"block",
		"declaration",
		"property_name",
		"integer_value",
		"float_value",
		"unit",
		"call_expression",
	}

	for _, req := range requiredTypes {
		if !foundNodes[req] {
			t.Errorf("Missing required tree-sitter node type from grammar contract: %q", req)
		}
	}

	hasOpacityFloat := false
	walk = func(n *sitter.Node) {
		if n.Type() == "declaration" {
			hasOp := false
			hasVal := false
			for i := 0; i < int(n.ChildCount()); i++ {
				c := n.Child(i)
				if c.Type() == "property_name" && c.Content(src) == "opacity" {
					hasOp = true
				}
				if c.Type() == "float_value" && c.Content(src) == "0.5" {
					hasVal = true
				}
			}
			if hasOp && hasVal {
				hasOpacityFloat = true
			}
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i))
		}
	}
	walk(tree.RootNode())
	if !hasOpacityFloat {
		t.Errorf("Grammar contract failed: float_value '0.5' was not found as a child of opacity declaration")
	}
}

func TestCSSGlobalCap(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("a {\n")
	for i := 0; i < 25; i++ {
		buf.WriteString("  color: #xx;\n")
		buf.WriteString("  unknown-prop: 1;\n")
		buf.WriteString("  width: 1zz;\n")
		buf.WriteString("  font-weight: 2000;\n")
		buf.WriteString("  flex-grow: -1;\n")
		buf.WriteString("  animation-duration: -1s;\n")
	}
	buf.WriteString("}\n")

	parser := sitter.NewParser()
	parser.SetLanguage(css.GetLanguage())
	tree, err := parser.ParseCtx(context.Background(), nil, buf.Bytes())
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	findings := cssFindings(tree.RootNode(), buf.Bytes(), "test.css")
	if len(findings) != 100 {
		t.Fatalf("global cap = %d, want 100", len(findings))
	}
}

func TestCSSCapsAndDeterminism(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 30; i++ {
		sb.WriteString("a" + strconv.Itoa(i) + " { colr: red; width: 10pzz; color: #12; color: #12; }\n")
	}
	sb.WriteString(strings.Repeat("@media all { ", 100) + "a { width: 10px; }" + strings.Repeat(" }", 100) + "\n")

	root := t.TempDir()
	writeFile(t, root, "test.css", sb.String())

	res1, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor 1: %v", err)
	}

	for run := 0; run < 50; run++ {
		resRun, err := QualityFor(context.Background(), root)
		if err != nil {
			t.Fatalf("QualityFor run %d: %v", run, err)
		}
		if len(resRun.Findings) != len(res1.Findings) {
			t.Fatalf("Determinism fail on run %d: got %d findings, want %d", run, len(resRun.Findings), len(res1.Findings))
		}
		for idx := range resRun.Findings {
			if resRun.Findings[idx] != res1.Findings[idx] {
				t.Fatalf("Determinism mismatch on run %d item %d: got %+v, want %+v", run, idx, resRun.Findings[idx], res1.Findings[idx])
			}
		}
	}

	counts := make(map[string]int)
	for _, f := range res1.Findings {
		counts[f.Rule]++
	}

	for k, c := range counts {
		if c > 20 {
			t.Errorf("Rule %s exceeded cap 20: got %d", k, c)
		}
	}

	if len(res1.Findings) > 100 {
		t.Errorf("Total findings exceeded cap 100: got %d", len(res1.Findings))
	}
}

func TestCSSHostileSizeDeepNesting(t *testing.T) {
	depth := 5000
	var buf bytes.Buffer
	buf.WriteString("a {\n  width: ")
	for i := 0; i < depth; i++ {
		buf.WriteString("calc(")
	}
	buf.WriteString("1px")
	for i := 0; i < depth; i++ {
		buf.WriteString(")")
	}
	buf.WriteString(";\n}\n")

	largeBlock := "b { color: red; }\n"
	for buf.Len() < 4*1024*1024 {
		buf.WriteString(largeBlock)
	}

	src := buf.Bytes()
	parser := sitter.NewParser()
	parser.SetLanguage(css.GetLanguage())
	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	findings := cssFindings(tree.RootNode(), src, "test.css")
	_ = findings
}

func TestCSSInventoryFull(t *testing.T) {
	modernProps := []string{
		"accent-color", "anchor-name", "animation-timeline", "aspect-ratio",
		"backdrop-filter", "container-name", "container-type", "field-sizing",
		"font-palette", "interpolate-size", "offset-path", "overflow-clip-margin",
		"scroll-timeline-name", "text-wrap-mode", "view-transition-name",
	}
	for _, prop := range modernProps {
		if !cssKnownPropertySet[prop] {
			t.Errorf("Inventory missing modern property: %q", prop)
		}
	}

	representativeUnits := []string{
		"px", "em", "rem", "vh", "vw", "svh", "cqw", "deg", "ms", "hz", "dpi", "fr",
	}
	for _, unit := range representativeUnits {
		if !cssKnownUnits[unit] {
			t.Errorf("Inventory missing representative unit: %q", unit)
		}
	}
}

func TestCSSDepthCapSuppressesIncompleteFingerprint(t *testing.T) {
	depth := 300
	var buf bytes.Buffer
	buf.WriteString("a {\n  width: ")
	for i := 0; i < depth; i++ {
		buf.WriteString("calc(")
	}
	buf.WriteString("1px")
	for i := 0; i < depth; i++ {
		buf.WriteString(")")
	}
	buf.WriteString(";\n  width: ")
	for i := 0; i < depth; i++ {
		buf.WriteString("calc(")
	}
	buf.WriteString("2px")
	for i := 0; i < depth; i++ {
		buf.WriteString(")")
	}
	buf.WriteString(";\n}\n")

	assertExactCSSRules(t, buf.String())
}

func TestCSSRegressionCases(t *testing.T) {
	assertExactCSSRules(t, "a { animation-name: Fade; animation-name: fade; }")
	assertExactCSSRules(t, "a { width: var(--size, calc(10rpx)); }")
	assertExactCSSRules(t, "a { animation-duration: var(--duration, -1s); }")
	assertExactCSSRules(t, "a { animation-duration: calc(-1s); }")
	assertExactCSSRules(t, "a { animation-duration: -1px; }")
	assertExactCSSRules(t, "a { animation-duration: min(-1s, 2s); }")
	assertExactCSSRules(t, "a { animation-duration: -1; }")
}

func TestCSSDescriptorRegression(t *testing.T) {
	assertExactCSSRules(
		t,
		`@property --x { syntax: "<length>"; inherits: false; initial-value: 0px; }`,
	)

	assertExactCSSRules(
		t,
		`a { syntax: "<length>"; src: url(font.woff2); }`,
		"css:unknown-property",
		"css:unknown-property",
	)
}

func TestCSSDescriptorNamesAreNotOrdinaryProperties(t *testing.T) {
	assertExactCSSRules(t, "a { fallback: auto; }", "css:unknown-property")             //nolint:misspell
	assertExactCSSRules(t, "a { negative: '-'; }", "css:unknown-property")              //nolint:misspell
	assertExactCSSRules(t, "a { pad: 2 '0'; }", "css:unknown-property")                 //nolint:misspell
	assertExactCSSRules(t, "a { prefix: '('; }", "css:unknown-property")                //nolint:misspell
	assertExactCSSRules(t, "a { range: auto; }", "css:unknown-property")                //nolint:misspell
	assertExactCSSRules(t, "a { speak-as: normal; }", "css:unknown-property")           //nolint:misspell
	assertExactCSSRules(t, "a { suffix: ')'; }", "css:unknown-property")                //nolint:misspell
	assertExactCSSRules(t, "a { symbols: '*'; }", "css:unknown-property")               //nolint:misspell
	assertExactCSSRules(t, "a { system: cyclic; }", "css:unknown-property")             //nolint:misspell
	assertExactCSSRules(t, "a { font-display: auto; }", "css:unknown-property")         //nolint:misspell
	assertExactCSSRules(t, "a { src: url(font.woff); }", "css:unknown-property")        //nolint:misspell
	assertExactCSSRules(t, "a { unicode-range: U+0000-00FF; }", "css:unknown-property") //nolint:misspell
	assertExactCSSRules(t, "a { size-adjust: 100%; }", "css:unknown-property")          //nolint:misspell
	assertExactCSSRules(t, "a { syntax: '<length>'; }", "css:unknown-property")         //nolint:misspell
	assertExactCSSRules(t, "a { inherits: false; }", "css:unknown-property")            //nolint:misspell
	assertExactCSSRules(t, "a { initial-value: 0px; }", "css:unknown-property")         //nolint:misspell
}

func TestCSSDescriptorContexts(t *testing.T) {
	assertExactCSSRules(t, "@font-face { src: url(font.woff2); font-display: swap; unicode-range: U+000-5FF; size-adjust: 90%; }")
	assertExactCSSRules(t, "@property --my-color { syntax: '<color>'; inherits: false; initial-value: #c0ffee; }")
	assertExactCSSRules(t, "@counter-style x { system: cyclic; symbols: '*' '\\2020'; suffix: ' '; speak-as: normal; fallback: decimal; negative: '-'; pad: 2 '0'; range: infinite; prefix: ''; }")
	assertExactCSSRules(t, "@font-feature-values Font One { @swash { swash1: 1; } }")
	assertExactCSSRules(t, "@page { size: A4; margin: 1in; }")
	assertExactCSSRules(t, "@color-profile foo { src: url('profile.icc'); rendering-intent: relative-colorimetric; }")
	assertExactCSSRules(t, "@font-palette-values --Cool { font-family: Bungee; base-palette: 0; override-colors: 0 red, 1 blue; }")
}

func TestCSSGrammarContract_InvalidHexShapes(t *testing.T) {
	assertExactCSSRules(t, "a { color: #12345; }", "css:invalid-hex-color")
	assertExactCSSRules(t, "a { color /* test */ : #12; }", "css:invalid-hex-color")
}

func TestCSSGrammarContract_InvalidKeyframeShapes(t *testing.T) {
	assertExactCSSRules(t, "@keyframes x { 101% { opacity: 0; } }", "css:invalid-keyframe-selector")
}
