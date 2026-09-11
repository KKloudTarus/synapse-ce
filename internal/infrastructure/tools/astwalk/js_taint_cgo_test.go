//go:build cgo

package astwalk

import (
	"context"
	"sort"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

// jsTaintRules extracts real semantic facts from the given JS/TS sources with the production extractor, runs
// the owned value-flow engine over the default catalog, and returns the set of taint rules proven. Driving
// the REAL extractor (not a hand-built document) is what makes the no-false-positive fixtures below
// trustworthy: they assert the pipeline a scan actually runs finds nothing.
func jsTaintRules(t *testing.T, files map[string]string) map[string]bool {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		writeFile(t, root, name, body)
	}
	doc, err := JsFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JsFactsFor: %v", err)
	}
	graph, err := taint.BuildJsValueGraph(doc, taint.DefaultJsCatalog())
	if err != nil {
		t.Fatalf("BuildJsValueGraph: %v", err)
	}
	rules := map[string]bool{}
	for _, finding := range graph.Vulnerabilities() {
		rules[finding.Rule] = true
	}
	return rules
}

func jsRuleList(rules map[string]bool) []string {
	out := make([]string, 0, len(rules))
	for rule := range rules {
		out = append(out, rule)
	}
	sort.Strings(out)
	return out
}

// TestJsTaintPositivePerClass proves each modeled class fires on a real source→sink flow.
func TestJsTaintPositivePerClass(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "command",
			body: "const cp = require('child_process');\n" +
				"app.get('/x', (req, res) => { cp.exec(req.query.cmd); });\n",
			want: "js-taint-command",
		},
		{
			name: "command_named_import",
			body: "import { execSync } from 'child_process';\n" +
				"app.get('/x', (req, res) => { execSync(req.query.cmd); });\n",
			want: "js-taint-command",
		},
		{
			name: "code_eval",
			body: "app.get('/x', (req, res) => { eval(req.query.expr); });\n",
			want: "js-taint-code",
		},
		{
			name: "code_vm",
			body: "const vm = require('vm');\n" +
				"app.get('/x', (req, res) => { vm.runInNewContext(req.query.src); });\n",
			want: "js-taint-code",
		},
		{
			name: "path",
			body: "const fs = require('fs');\n" +
				"app.get('/x', (req, res) => { fs.readFile(req.query.p, cb); });\n",
			want: "js-taint-path",
		},
		{
			name: "ssrf_axios",
			body: "const axios = require('axios');\n" +
				"app.get('/x', (req, res) => { axios.get(req.query.u); });\n",
			want: "js-taint-ssrf",
		},
		{
			name: "ssrf_fetch_global",
			body: "app.get('/x', (req, res) => { fetch(req.query.u); });\n",
			want: "js-taint-ssrf",
		},
		{
			name: "xss",
			body: "app.get('/x', (req, res) => { res.send(req.query.m); });\n",
			want: "js-taint-xss",
		},
		{
			name: "open_redirect",
			body: "app.get('/x', (req, res) => { res.redirect(req.query.to); });\n",
			want: "js-taint-open-redirect",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := jsTaintRules(t, map[string]string{"app.js": tc.body})
			if !rules[tc.want] {
				t.Fatalf("want rule %q, got %v", tc.want, jsRuleList(rules))
			}
		})
	}
}

// TestJsTaintSanitizedTwin proves the class-specific sanitizer walls stop the matching flow.
func TestJsTaintSanitizedTwin(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		clean string // the rule that must NOT appear
	}{
		{
			name: "xss_escape_html_default_call",
			body: "const escapeHtml = require('escape-html');\n" +
				"app.get('/x', (req, res) => { res.send(escapeHtml(req.query.m)); });\n",
			clean: "js-taint-xss",
		},
		{
			name: "xss_encodeuricomponent_global",
			body: "app.get('/x', (req, res) => { res.send(encodeURIComponent(req.query.m)); });\n",
			clean: "js-taint-xss",
		},
		{
			name: "path_basename",
			body: "const fs = require('fs');\nconst path = require('path');\n" +
				"app.get('/x', (req, res) => { fs.readFile(path.basename(req.query.p), cb); });\n",
			clean: "js-taint-path",
		},
		{
			name: "command_shell_quote",
			body: "const cp = require('child_process');\nconst sq = require('shell-quote');\n" +
				"app.get('/x', (req, res) => { cp.exec(sq.quote([req.query.cmd])); });\n",
			clean: "js-taint-command",
		},
		{
			name: "ssrf_number_coercion",
			body: "const axios = require('axios');\n" +
				"app.get('/x', (req, res) => { axios.get(Number(req.query.u)); });\n",
			clean: "js-taint-ssrf",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := jsTaintRules(t, map[string]string{"app.js": tc.body})
			if rules[tc.clean] {
				t.Fatalf("sanitized flow still reported %q: %v", tc.clean, jsRuleList(rules))
			}
		})
	}
}

// TestJsTaintCrossClassSanitizerDoesNotClean proves a class-specific sanitizer does not neutralize a
// different class: an HTML escaper on a command argument must leave the command-injection finding standing.
func TestJsTaintCrossClassSanitizerDoesNotClean(t *testing.T) {
	rules := jsTaintRules(t, map[string]string{"app.js": "" +
		"const cp = require('child_process');\n" +
		"const escapeHtml = require('escape-html');\n" +
		"app.get('/x', (req, res) => { cp.exec(escapeHtml(req.query.cmd)); });\n"})
	if !rules["js-taint-command"] {
		t.Fatalf("HTML escaper wrongly suppressed command injection: %v", jsRuleList(rules))
	}
}

// TestJsTaintInterprocedural proves taint crosses a call boundary: a request value passed into a local
// helper reaches a sink inside that helper.
func TestJsTaintInterprocedural(t *testing.T) {
	rules := jsTaintRules(t, map[string]string{"app.js": "" +
		"const cp = require('child_process');\n" +
		"function runIt(cmd) { cp.exec(cmd); }\n" +
		"app.get('/x', (req, res) => { runIt(req.query.cmd); });\n"})
	if !rules["js-taint-command"] {
		t.Fatalf("interprocedural command injection missed: %v", jsRuleList(rules))
	}
}

// TestJsTaintNoFalsePositive is the core soundness guard: every fixture is a shape the catalog DECLINES or a
// receiver the sink model must not match, so the pipeline must find NOTHING. A regression that widens a sink
// into a false positive fails here.
func TestJsTaintNoFalsePositive(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			// A bare .query on an array/ORM instance is DECLINED (SQLi needs receiver-value type resolution);
			// matching it would flag array.query.
			name: "bare_query_on_array",
			body: "app.get('/x', (req, res) => { const arr = []; arr.query(req.query.x); });\n",
		},
		{
			name: "bare_execute_on_object",
			body: "app.get('/x', (req, res) => { obj.execute(req.query.x); });\n",
		},
		{
			// axios(config): the URL is inside an object field the facts do not resolve.
			name: "axios_object_config",
			body: "const axios = require('axios');\n" +
				"app.get('/x', (req, res) => { axios({ url: req.query.u }); });\n",
		},
		{
			// fs.writeFile(PATH, DATA): only the PATH argument is a sink; a tainted DATA argument is not.
			name: "fs_writefile_data_arg",
			body: "const fs = require('fs');\nconst OUT = '/tmp/out';\n" +
				"app.get('/x', (req, res) => { fs.writeFile(OUT, req.query.data, cb); });\n",
		},
		{
			// setTimeout's first argument is normally a function; modeling its delay/callback as code would
			// flag the safe callback usage.
			name: "settimeout",
			body: "app.get('/x', (req, res) => { setTimeout(() => {}, req.query.t); });\n",
		},
		{
			// A dynamic attribute write is not a modeled sink.
			name: "computed_member_write",
			body: "app.get('/x', (req, res) => { const el = {}; el[req.query.k] = req.query.v; });\n",
		},
		{
			// res.render(view, locals): the template name is constant and locals are auto-escaped.
			name: "res_render_locals",
			body: "app.get('/x', (req, res) => { res.render('page', { name: req.query.name }); });\n",
		},
		{
			// A local parameter named exec shadows the child_process import, so the call is not the sink.
			name: "shadowed_import",
			body: "import { exec } from 'child_process';\n" +
				"function f(exec) { exec(req.query.cmd); }\n",
		},
		{
			// A constant argument is never a source, so a genuine sink with no tainted input reports nothing.
			name: "constant_argument",
			body: "const cp = require('child_process');\n" +
				"app.get('/x', (req, res) => { cp.exec('ls -la'); });\n",
		},
		{
			// A local `function fetch` (a Symbol, not a ValueBinding) shadows the global fetch SSRF sink.
			name: "local_function_shadows_global_fetch",
			body: "function fetch(id) { return cache.get(id); }\n" +
				"app.get('/x', (req, res) => { fetch(req.query.id); });\n",
		},
		{
			// A local `class Function` shadows the global Function code sink.
			name: "local_class_shadows_global_function",
			body: "class Function {}\n" +
				"app.get('/x', (req, res) => { return new Function(req.query.code); });\n",
		},
		{
			// A locally constructed `const res = { send }` is not the Express response parameter, so the
			// receiver-name XSS convention must not match it.
			name: "const_object_named_res_send",
			body: "function h(req) { const res = { send(v) { audit(v); } }; res.send(req.query.name); }\n",
		},
		{
			// widget.document.write is a nested object method, not the DOM document.write; the exact-path
			// receiver-name match must not fire.
			name: "deep_document_write",
			body: "app.get('/x', (req, res) => { const widget = { document: { write(v) {} } }; widget.document.write(req.query.x); });\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := jsTaintRules(t, map[string]string{"app.js": tc.body})
			if len(rules) != 0 {
				t.Fatalf("expected zero findings, got %v", jsRuleList(rules))
			}
		})
	}
}

// TestJsTaintReceiverNameConventionFloor PINS the accepted, documented residual of the receiver-name
// convention: a parameter named res in a request handler reaching res.send(req.query.x) is reported. This
// is the same convention the shipped Python catalog uses for cursor.execute, tightened here to an exact path
// and a non-constructed receiver. A parameter named res that is not a real Express response is a known
// name-collision limit accepted because findings are propose-only and separately verified; changing it (for
// example adding route-handler anchoring) must be a conscious change that updates this test.
func TestJsTaintReceiverNameConventionFloor(t *testing.T) {
	rules := jsTaintRules(t, map[string]string{
		"app.js": "app.get('/x', (req, res) => { res.send(req.query.name); });\n",
	})
	if !rules["js-taint-xss"] {
		t.Fatalf("res.send(req.query.name) in a handler is the accepted convention floor and must report XSS, got %v", jsRuleList(rules))
	}
}

// TestJsTaintImportEqualsRequireIsNotGlobal proves the TS `import x = require('m')` form binds a local name,
// so `import fetch = require('./local'); fetch(req.query.url)` resolves fetch to the local module and never
// reports the global-fetch SSRF sink. The file is .ts because import-equals is TypeScript syntax.
func TestJsTaintImportEqualsRequireIsNotGlobal(t *testing.T) {
	rules := jsTaintRules(t, map[string]string{
		"app.ts": "import fetch = require('./local');\n" +
			"app.get('/x', (req, res) => { fetch(req.query.url); });\n",
	})
	if len(rules) != 0 {
		t.Fatalf("import-equals fetch must not be the global SSRF sink, got %v", jsRuleList(rules))
	}
}

// TestJsTaintImportEqualsRequireDoesModelRealSink is the control: an import-equals of a REAL sink module
// still resolves to that module, so the sink fires (the binding is not a blanket suppression).
func TestJsTaintImportEqualsRealModuleStillSinks(t *testing.T) {
	rules := jsTaintRules(t, map[string]string{
		"app.ts": "import cp = require('child_process');\n" +
			"app.get('/x', (req, res) => { cp.exec(req.query.cmd); });\n",
	})
	if !rules["js-taint-command"] {
		t.Fatalf("import cp = require('child_process'); cp.exec(taint) should report command injection, got %v", jsRuleList(rules))
	}
}
