package sast

import "testing"

// A single-file component is browser code by construction. Requiring a sighting of `window.` or
// `document.` left 20 SSRF findings on .vue files in one real repository, where the request is made by
// the reader's browser and server-side request forgery is not possible.
func TestClientComponentExtsAreBrowserContext(t *testing.T) {
	for _, ext := range []string{".vue", ".svelte", ".astro"} {
		if !clientComponentExts[ext] {
			t.Errorf("%s is a client component format", ext)
		}
		if !jsExts[ext] {
			t.Errorf("%s must stay in the JS rule set", ext)
		}
	}
	for _, ext := range []string{".js", ".ts", ".go"} {
		if clientComponentExts[ext] {
			t.Errorf("%s is not a single-file component; it needs the browser-global check", ext)
		}
	}
}

// The JavaScript in a template's <script> element runs in the browser, whatever the file's extension is.
// A Blade template is named .php, and 16 SSRF findings on one real repository came from axios calls in
// exactly that position.
func TestBrowserScriptHost(t *testing.T) {
	blade := []string{`<div>`, `<script>`, `  axios.post(window.location.href, {});`, `</script>`}
	if !browserScriptHost(".php", blade) {
		t.Error("a .php template carrying a <script> element is browser context")
	}
	if !browserScriptHost(".html", []string{`<script src="a.js"></script>`}) {
		t.Error("an html file carrying a <script> element is browser context")
	}

	// Server-side PHP with no script element stays server context, so SSRF still applies there.
	if browserScriptHost(".php", []string{`<?php $r = file_get_contents($_GET["u"]);`}) {
		t.Error("server-side PHP must not be treated as browser context")
	}
	// A non-markup file is never a script host, even if it writes markup into a string.
	if browserScriptHost(".go", []string{`w.Write([]byte("<script>alert(1)</script>"))`}) {
		t.Error("a Go file is not a script host")
	}
}
