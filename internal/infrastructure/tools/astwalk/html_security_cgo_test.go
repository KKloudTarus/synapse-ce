//go:build cgo

package astwalk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func TestHTMLSchemePrefixRegressions(t *testing.T) {
	assertExactHTMLRules(t, `<!doctype html><form action="http:login"></form>`)
	assertExactHTMLRules(t, `<!doctype html><script src="https:cdn/app.js"></script>`)
	assertExactHTMLRules(t, `<!doctype html><script src="//cdn.example.com/app.js"></script>`)
}

func TestHTMLEntityDecodedAttributes(t *testing.T) {
	// Entity decoded rel suppressing target-blank-noopener
	assertExactHTMLRules(t, `<!doctype html><a href="https://example.test" target="_blank" rel="foo&#x20;noopener">Open</a>`)

	// Entity decoded target triggering target-blank-noopener
	assertExactHTMLRules(t, `<!doctype html><a href="https://example.test" target="_&#x62;lank">Open</a>`, "html:target-blank-noopener")

	// Decoded empty href does not count as usable href for target-blank-noopener
	assertExactHTMLRules(t, `<!doctype html><a href="&#x20;" target="_blank">Open</a>`)

	// Entity decoded sandbox triggering iframe-sandbox-escape
	assertExactHTMLRules(t, `<!doctype html><iframe src="page.html" sandbox="allow-scripts&#x20;allow-same-origin"></iframe>`, "html:iframe-sandbox-escape")

	// Entity decoded stylesheet rel
	assertExactHTMLRules(t, `<!doctype html><link rel="style&#x73;heet" href="http://cdn.example.test/app.css" integrity="sha384-xyz">`, "html:active-content-over-http")

	// Entity decoded whitespace integrity triggers external-resource-no-integrity
	assertExactHTMLRules(t, `<!doctype html><script src="https://cdn.example.test/app.js" integrity="&#x20;"></script>`, "html:external-resource-no-integrity")

	// Non-ASCII whitespace NBSP in inline handler still reports
	assertExactHTMLRules(t, `<!doctype html><button onclick="&#xA0;">Click</button>`, "html:inline-event-handler")
}

func TestHTMLFirstCompleteAttributeSelection(t *testing.T) {
	// First href is valueless; second href="javascript:alert(1)" is ignored for security rules, only duplicate-attribute is emitted
	assertExactHTMLRules(t, `<!doctype html><a href href="javascript:alert(1)">Run</a>`, "html:duplicate-attribute")

	// First integrity attribute is valueless; second integrity is ignored by security rule so external-resource-no-integrity IS emitted alongside duplicate-attribute
	assertExactHTMLRules(t, `<!doctype html><script src="https://cdn.example.test/app.js" integrity integrity="sha384-valid"></script>`, "html:duplicate-attribute", "html:external-resource-no-integrity")
}

func TestHTMLIframeSourceAttributeOrder(t *testing.T) {
	src := `<!doctype html>
<iframe
  srcdoc="<p>Hello</p>"
  src="/fallback">
</iframe>`
	assertHTMLRuleLine(t, src, "html:iframe-sandbox-missing", 3)
}

func TestHTMLMixedCorrectnessAndSecuritySourceOrder(t *testing.T) {
	src := `<!doctype html>
<a onclick="run()" class="a" class="b">Run</a>`
	ctx := context.Background()
	tree := parseRoot(ctx, specs["HTML"], []byte(src))
	findings := htmlFindings(tree, []byte(src), "test.html")

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %v", len(findings), findings)
	}

	expectedOrder := []string{"html:inline-event-handler", "html:duplicate-attribute"}
	for i, f := range findings {
		if f.Rule != expectedOrder[i] {
			t.Fatalf("expected rule at index %d to be %s, got %s", i, expectedOrder[i], f.Rule)
		}
	}
}

func TestHTMLSecuritySourceOrderEmission(t *testing.T) {
	src := `<!doctype html>
<a onclick="run()" href="javascript:run()" target="_blank">Run</a>`
	ctx := context.Background()
	tree := parseRoot(ctx, specs["HTML"], []byte(src))
	findings := htmlFindings(tree, []byte(src), "test.html")

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %v", len(findings), findings)
	}

	expectedOrder := []string{"html:inline-event-handler", "html:javascript-url", "html:target-blank-noopener"}
	for i, f := range findings {
		if f.Rule != expectedOrder[i] {
			t.Fatalf("expected rule at index %d to be %s, got %s", i, expectedOrder[i], f.Rule)
		}
	}
}

func TestHTMLTargetBlankNoopener(t *testing.T) {
	assertExactHTMLRules(t, `<!doctype html><a href="https://example.com" target="_blank">Link</a>`, "html:target-blank-noopener")
	assertExactHTMLRules(t, `<!doctype html><area href="https://example.com" target="_blank">`, "html:target-blank-noopener")
	assertExactHTMLRules(t, `<!doctype html><form target="_blank"></form>`, "html:target-blank-noopener")

	// Compliant / negative
	assertExactHTMLRules(t, `<!doctype html><a href="https://example.com" target="_blank" rel="noopener">Link</a>`)
	assertExactHTMLRules(t, `<!doctype html><a href="https://example.com" target="_blank" rel="noreferrer">Link</a>`)
	assertExactHTMLRules(t, `<!doctype html><a href="https://example.com" target="_blank" rel="NOOPENER">Link</a>`)
	assertExactHTMLRules(t, `<!doctype html><a href="https://example.com" target="_blank" rel="foo noopener bar">Link</a>`)
	assertExactHTMLRules(t, `<!doctype html><a href="https://example.com" target="_self">Link</a>`)
	assertExactHTMLRules(t, `<!doctype html><a href="" target="_blank">Link</a>`)
	assertExactHTMLRules(t, `<!doctype html><a target="_blank">No href</a>`)
	assertExactHTMLRules(t, `<!doctype html><button formtarget="_blank">Click</button>`)
	assertExactHTMLRules(t, `<!doctype html><input formtarget="_blank">`)
}

func TestHTMLInlineEventHandler(t *testing.T) {
	assertExactHTMLRules(t, `<!doctype html><button onclick="doSomething()">Click</button>`, "html:inline-event-handler")
	assertExactHTMLRules(t, `<!doctype html><body ONLOAD="init()"></body>`, "html:inline-event-handler")
	assertExactHTMLRules(t, `<!doctype html><div onmouseover="hover()"></div>`, "html:inline-event-handler")
	assertExactHTMLRules(t, `<!doctype html><button onclick="{{ handle() }}">Click</button>`, "html:inline-event-handler")

	// Compliant / negative
	assertExactHTMLRules(t, `<!doctype html><button on>Click</button>`)
	assertExactHTMLRules(t, `<!doctype html><button once>Click</button>`)
	assertExactHTMLRules(t, `<!doctype html><button onclick="">Click</button>`)
	assertExactHTMLRules(t, `<!doctype html><button onclick="   ">Click</button>`)
}

func TestHTMLJavascriptURL(t *testing.T) {
	assertExactHTMLRules(t, `<!doctype html><a href="javascript:alert(1)">Link</a>`, "html:javascript-url")
	assertExactHTMLRules(t, `<!doctype html><area href="java&#x73;cript:alert(1)">`, "html:javascript-url")
	assertExactHTMLRules(t, `<!doctype html><a href="&#x1F; javascript:alert(1)">Run</a>`, "html:javascript-url")
	assertExactHTMLRules(t, `<!doctype html><form action="JAVA&#x09;SCRIPT:submit()"></form>`, "html:javascript-url")
	assertExactHTMLRules(t, `<!doctype html><button formaction="javascript:void(0)">Submit</button>`, "html:javascript-url")
	assertExactHTMLRules(t, `<!doctype html><input formaction="javascript:doIt()">`, "html:javascript-url")
	assertExactHTMLRules(t, `<!doctype html><iframe src="javascript:run()"></iframe>`, "html:iframe-sandbox-missing", "html:javascript-url")

	// Compliant
	assertExactHTMLRules(t, `<!doctype html><a href="java&amp;#x73;cript:alert(1)">Run</a>`)
	assertExactHTMLRules(t, `<!doctype html><a href="/javascript/main.js">JS File</a>`)
	assertExactHTMLRules(t, `<!doctype html><a href="javascript.html">JS Doc</a>`)
	assertExactHTMLRules(t, `<!doctype html><a href="{{ jsURL }}">Template</a>`)
}

func TestHTMLIframeSandbox(t *testing.T) {
	// Missing sandbox
	assertExactHTMLRules(t, `<!doctype html><iframe src="https://example.com"></iframe>`, "html:iframe-sandbox-missing")
	assertExactHTMLRules(t, `<!doctype html><iframe srcdoc="<h1>Hello</h1>"></iframe>`, "html:iframe-sandbox-missing")
	assertExactHTMLRules(t, `<!doctype html><iframe src="{{ url }}"></iframe>`, "html:iframe-sandbox-missing")

	// Compliant sandbox
	assertExactHTMLRules(t, `<!doctype html><iframe src="https://example.com" sandbox></iframe>`)
	assertExactHTMLRules(t, `<!doctype html><iframe src="https://example.com" sandbox="allow-scripts"></iframe>`)

	// Substring negative
	assertExactHTMLRules(t, `<!doctype html><iframe src="https://example.com" sandbox="allow-scripts-foo allow-same-origin"></iframe>`)

	// Escape combination
	assertExactHTMLRules(t, `<!doctype html><iframe src="https://example.com" sandbox="allow-scripts allow-same-origin"></iframe>`, "html:iframe-sandbox-escape")
	assertExactHTMLRules(t, `<!doctype html><iframe src="https://example.com" sandbox="ALLOW-SCRIPTS allow-same-origin"></iframe>`, "html:iframe-sandbox-escape")
}

func TestHTMLInsecureFormAction(t *testing.T) {
	assertExactHTMLRules(t, `<!doctype html><form action="http://example.com/login"></form>`, "html:insecure-form-action")
	assertExactHTMLRules(t, `<!doctype html><button formaction="http://example.com/submit">Btn</button>`, "html:insecure-form-action")
	assertExactHTMLRules(t, `<!doctype html><input formaction="http://example.com/save">`, "html:insecure-form-action")

	// Compliant
	assertExactHTMLRules(t, `<!doctype html><form action="https://example.com/login"></form>`)
	assertExactHTMLRules(t, `<!doctype html><form action="/login"></form>`)
	assertExactHTMLRules(t, `<!doctype html><form action="//example.com/login"></form>`)
	assertExactHTMLRules(t, `<!doctype html><form action="javascript:alert(1)"></form>`, "html:javascript-url")
}

func TestHTMLActiveContentOverHTTP(t *testing.T) {
	assertExactHTMLRules(t, `<!doctype html><script src="http://example.com/app.js" integrity="sha256-xyz"></script>`, "html:active-content-over-http")
	assertExactHTMLRules(t, `<!doctype html><iframe src="http://example.com"></iframe>`, "html:iframe-sandbox-missing", "html:active-content-over-http")
	assertExactHTMLRules(t, `<!doctype html><object data="http://example.com/app.swf"></object>`, "html:active-content-over-http")
	assertExactHTMLRules(t, `<!doctype html><embed src="http://example.com/plugin">`, "html:active-content-over-http")
	assertExactHTMLRules(t, `<!doctype html><link rel="stylesheet" href="http://example.com/style.css" integrity="sha256-xyz">`, "html:active-content-over-http")

	// Passive media negative cases
	assertExactHTMLRules(t, `<!doctype html><img src="http://example.com/pic.jpg">`)
	assertExactHTMLRules(t, `<!doctype html><audio src="http://example.com/song.mp3"></audio>`)
	assertExactHTMLRules(t, `<!doctype html><video src="http://example.com/movie.mp4"></video>`)
	assertExactHTMLRules(t, `<!doctype html><video><source src="http://example.com/movie.mp4"></video>`)
	assertExactHTMLRules(t, `<!doctype html><video><track src="http://example.com/sub.vtt"></video>`)
}

func TestHTMLExternalResourceNoIntegrity(t *testing.T) {
	assertExactHTMLRules(t, `<!doctype html><script src="https://cdn.example.com/app.js"></script>`, "html:external-resource-no-integrity")
	assertExactHTMLRules(t, `<!doctype html><link rel="stylesheet" href="https://cdn.example.com/style.css">`, "html:external-resource-no-integrity")
	assertExactHTMLRules(t, `<!doctype html><script src="https://cdn.example.com/app.js" integrity=""></script>`, "html:external-resource-no-integrity")
	assertExactHTMLRules(t, `<!doctype html><script src="https://cdn.example.com/app.js" integrity></script>`, "html:external-resource-no-integrity")

	// Compliant
	assertExactHTMLRules(t, `<!doctype html><script src="https://cdn.example.com/app.js" integrity="sha384-xyz"></script>`)
	assertExactHTMLRules(t, `<!doctype html><script src="/local/app.js"></script>`)
	assertExactHTMLRules(t, `<!doctype html><script src="relative.js"></script>`)

	// Dual emission for HTTP active content without integrity
	assertExactHTMLRules(t, `<!doctype html><script src="http://example.com/app.js"></script>`, "html:active-content-over-http", "html:external-resource-no-integrity")
}

func TestHTMLSecurityLineAssertions(t *testing.T) {
	src := `<!doctype html>
<a href="https://example.com"
   target="_blank">Link</a>`
	assertHTMLRuleLine(t, src, "html:target-blank-noopener", 3)
}

func TestHTMLSecurityCommentsAndRawTextIsolation(t *testing.T) {
	src := `<!doctype html>
<!-- <a href="javascript:alert(1)" target="_blank"></a> -->
<script>
  var x = '<a href="javascript:alert(1)"></a>';
</script>
<style>
  div { content: '<a href="javascript:alert(1)"></a>'; }
</style>
<div></div>`
	assertExactHTMLRules(t, src)
}

func TestHTMLSecurityMalformedAttributesFailClosed(t *testing.T) {
	src := `<!doctype html>
<script src="http://example.com/app.js"`
	// Incomplete tag without closing > should fail closed without crashing or emitting false findings
	findings := scanHTMLFixture(src)
	for _, f := range findings {
		if f.Rule == "html:active-content-over-http" {
			t.Fatalf("unexpected finding on incomplete tag: %v", f)
		}
	}
}

func TestHTMLSecurityValidSiblingRecovery(t *testing.T) {
	src := `<!doctype html>
<script src="http://example.com/bad.js"` + "\n" +
		`<script src="http://example.com/good.js" integrity="sha256-xyz"></script>`
	findings := scanHTMLFixture(src)
	hasGood := false
	for _, f := range findings {
		if f.Rule == "html:active-content-over-http" && f.Line == 3 {
			hasGood = true
		}
	}
	if !hasGood {
		t.Fatalf("expected valid sibling finding on line 3 to be preserved, got: %v", findings)
	}
}

func TestHTMLSecurityCRLFLineMapping(t *testing.T) {
	src := "<!doctype html>\r\n<div>\r\n</div>\r\n<a href=\"javascript:alert(1)\">Link</a>"
	assertHTMLRuleLine(t, src, "html:javascript-url", 4)
}

func TestHTMLSecurityPerRuleFindingCap(t *testing.T) {
	src := "<!doctype html>\n"
	for i := 0; i < 30; i++ {
		src += "<a href=\"javascript:alert(1)\">Link</a>\n"
	}
	findings := scanHTMLFixture(src)
	count := 0
	for _, f := range findings {
		if f.Rule == "html:javascript-url" {
			count++
		}
	}
	if count != 20 {
		t.Fatalf("expected per-rule cap of 20 for html:javascript-url, got %d", count)
	}
}

func TestHTMLSecurityGlobalFindingCap(t *testing.T) {
	src := "<!doctype html>\n"
	// Generate 150 findings across 6 rules
	for i := 0; i < 30; i++ {
		src += fmt.Sprintf("<a id=\"dup\" href=\"javascript:alert(%d)\" target=\"_blank\" onclick=\"click()\" class=\"a\" class=\"b\">Link</a><button formaction=\"http://example.com/%d\">Btn</button>\n", i, i)
	}
	findings := scanHTMLFixture(src)
	if len(findings) != 100 {
		t.Fatalf("expected shared global finding cap of 100, got %d", len(findings))
	}
}

func TestHTMLSecurityFamilyCountsAndTypes(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default(): %v", err)
	}

	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("cat.List: %v", err)
	}

	var bugs, vulns, hotspots, smells int
	var htmlCount int
	for _, r := range rules {
		if r.Language == "HTML" {
			htmlCount++
			switch r.Type {
			case rule.TypeBug:
				bugs++
			case rule.TypeVulnerability:
				vulns++
			case rule.TypeSecurityHotspot:
				hotspots++
			case rule.TypeCodeSmell:
				smells++
			}
		}
	}

	if htmlCount != 50 {
		t.Fatalf("expected 50 HTML catalog rules, got %d", htmlCount)
	}
	if bugs != 10 {
		t.Fatalf("expected 10 bug rules for HTML, got %d", bugs)
	}
	if vulns != 2 {
		t.Fatalf("expected 2 vulnerability rules for HTML, got %d", vulns)
	}
	if hotspots != 6 {
		t.Fatalf("expected 6 security_hotspot rules for HTML, got %d", hotspots)
	}
	if smells != 32 {
		t.Fatalf("expected 32 code_smell rules for HTML, got %d", smells)
	}
}

func TestHTMLSecurityDeterminism(t *testing.T) {
	hostileSrc := `<!doctype html>
<a href="javascript:alert(1)" target="_blank">Link</a>
<iframe src="http://example.com/frame" sandbox="allow-scripts allow-same-origin"></iframe>
<form action="http://example.com/submit" target="_blank"><button onclick="click()"></button></form>
<script src="http://example.com/script.js"></script>
<link rel="stylesheet" href="https://example.com/style.css">`

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
			t.Fatalf("non-deterministic output at iteration %d:\nGOT:\n%s\nWANT:\n%s", i, current, reference)
		}
	}
}

func TestHTMLSecurityLanguageIsolation(t *testing.T) {
	nonHTMLFiles := map[string]string{
		"test.xhtml":  `<a href="javascript:alert(1)" target="_blank">Link</a>`,
		"test.xml":    `<a href="javascript:alert(1)" target="_blank">Link</a>`,
		"test.jsx":    `<a href="javascript:alert(1)" target="_blank">Link</a>`,
		"test.tsx":    `<a href="javascript:alert(1)" target="_blank">Link</a>`,
		"test.vue":    `<template><a href="javascript:alert(1)" target="_blank">Link</a></template>`,
		"test.svelte": `<a href="javascript:alert(1)" target="_blank">Link</a>`,
	}

	tmpDir, err := os.MkdirTemp("", "htmlseclangtest-*")
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
