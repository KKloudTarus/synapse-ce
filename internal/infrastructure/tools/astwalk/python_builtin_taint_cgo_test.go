//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

// TestPythonBuiltinSourceSinkResolution guards that the taint catalog's bare-builtin source (input) and
// code-execution sinks (eval/exec/compile) are actually reachable end to end. They are modeled in
// DefaultPythonCatalog, but a bare call resolves to "builtins.<name>" only when the name is in the resolver's
// builtinCallables allowlist; input/eval/exec/compile were missing, so those source/sink models were dead.
func TestPythonBuiltinSourceSinkResolution(t *testing.T) {
	detect := func(t *testing.T, src string) []string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "m.py"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		doc, err := PythonFactsFor(context.Background(), dir)
		if err != nil {
			t.Fatalf("facts: %v", err)
		}
		res, err := pythonprogram.Resolve(doc)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		g, err := taint.BuildPythonValueGraph(doc, res, taint.DefaultPythonCatalog())
		if err != nil {
			t.Fatalf("graph: %v", err)
		}
		var cwes []string
		for _, p := range g.Vulnerabilities() {
			cwes = append(cwes, p.CWE)
		}
		return cwes
	}
	has := func(cwes []string, want string) bool {
		for _, c := range cwes {
			if c == want {
				return true
			}
		}
		return false
	}

	// input() source flowing into os.system -> command injection (CWE-78).
	if cwes := detect(t, "import os\ndef f():\n    x = input()\n    os.system(x)\n"); !has(cwes, "CWE-78") {
		t.Errorf("input() must be recognized as a taint source into os.system (CWE-78), got %v", cwes)
	}
	// eval() sink on tainted input -> code injection (CWE-94).
	if cwes := detect(t, "import os\ndef f():\n    x = os.getenv(\"X\")\n    eval(x)\n"); !has(cwes, "CWE-94") {
		t.Errorf("eval() must be recognized as a code-execution sink (CWE-94), got %v", cwes)
	}
	// exec() sink on tainted input -> code injection (CWE-94).
	if cwes := detect(t, "import os\ndef f():\n    x = os.getenv(\"X\")\n    exec(x)\n"); !has(cwes, "CWE-94") {
		t.Errorf("exec() must be recognized as a code-execution sink (CWE-94), got %v", cwes)
	}
	// A locally-shadowed builtin must NOT resolve to the builtin (no false source): a user eval() that is a
	// local function is not the code-execution sink.
	if cwes := detect(t, "import os\ndef eval(x):\n    return x\ndef f():\n    y = os.getenv(\"X\")\n    eval(y)\n"); has(cwes, "CWE-94") {
		t.Errorf("a locally-defined eval() must not be treated as the builtin sink, got %v", cwes)
	}
}

// TestPythonCrossFileInterprocedural proves the Python resolver already carries taint across a FILE boundary:
// app.py imports forward from helper.py and calls forward(input()); the os.system sink lives in helper.py.
// This pins the cross-file two-hop path (#1054) so a later refactor of the resolver cannot silently regress it.
func TestPythonCrossFileInterprocedural(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"helper.py": "import os\ndef forward(cmd):\n    os.system(cmd)\n",
		"app.py":    "from helper import forward\ndef handle():\n    forward(input())\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	doc, err := PythonFactsFor(context.Background(), dir)
	if err != nil {
		t.Fatalf("facts: %v", err)
	}
	res, err := pythonprogram.Resolve(doc)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	g, err := taint.BuildPythonValueGraph(doc, res, taint.DefaultPythonCatalog())
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	found := false
	for _, p := range g.Vulnerabilities() {
		if p.CWE == "CWE-78" {
			found = true
		}
	}
	if !found {
		t.Fatalf("cross-file command injection (input -> forward -> os.system) missed across app.py/helper.py")
	}
}

// A function-local binding that shadows an imported numeric converter must not inherit its wall.
func TestPythonShadowedSanitizerImportNotWalled(t *testing.T) {
	detect := func(t *testing.T, src string) []string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "m.py"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		doc, err := PythonFactsFor(context.Background(), dir)
		if err != nil {
			t.Fatalf("facts: %v", err)
		}
		res, err := pythonprogram.Resolve(doc)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		g, err := taint.BuildPythonValueGraph(doc, res, taint.DefaultPythonCatalog())
		if err != nil {
			t.Fatalf("graph: %v", err)
		}
		var cwes []string
		for _, p := range g.Vulnerabilities() {
			cwes = append(cwes, p.CWE)
		}
		return cwes
	}
	has := func(cwes []string, want string) bool {
		for _, c := range cwes {
			if c == want {
				return true
			}
		}
		return false
	}

	param := "from builtins import int as convert\nimport os\n" +
		"def f(convert):\n    x = input()\n    os.system(str(convert(x)))\n"
	if cwes := detect(t, param); !has(cwes, "CWE-78") {
		t.Errorf("a parameter shadowing numeric conversion must not wall command injection, got %v", cwes)
	}

	localAssign := "from builtins import int as convert\nimport os\n" +
		"def f(user_fn):\n    convert = user_fn\n    x = input()\n    os.system(str(convert(x)))\n"
	if cwes := detect(t, localAssign); !has(cwes, "CWE-78") {
		t.Errorf("a function-local assignment shadowing numeric conversion must not wall command injection, got %v", cwes)
	}

	moduleRebind := "from builtins import int as convert\nimport os\n" +
		"x = input()\nos.system(str(convert(x)))\nconvert = None\n"
	if cwes := detect(t, moduleRebind); has(cwes, "CWE-78") {
		t.Errorf("a later module-level rebind must not disable the earlier numeric wall, got %v", cwes)
	}

	control := "from builtins import int as convert\nimport os\n" +
		"def f():\n    x = input()\n    os.system(str(convert(x)))\n"
	if cwes := detect(t, control); has(cwes, "CWE-78") {
		t.Errorf("the unshadowed imported numeric conversion must neutralize command injection, got %v", cwes)
	}
}

func TestPythonShellQuotingDoesNotHideCommandInjection(t *testing.T) {
	src := "import os\nimport shlex\n" +
		"def f():\n    value = input()\n" +
		"    os.system('printf \"' + shlex.quote(value) + '\"')\n"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "m.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := PythonFactsFor(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := pythonprogram.Resolve(doc)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := taint.BuildPythonValueGraph(doc, resolved, taint.DefaultPythonCatalog())
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range graph.Vulnerabilities() {
		if finding.CWE == "CWE-78" {
			return
		}
	}
	t.Fatal("shell quoting inside double quotes must retain command injection")
}

func TestPythonBasenameAndSafeLoadRetainDangerousFlows(t *testing.T) {
	cases := []struct {
		name, source, want string
	}{
		{"basename_parent", "import os\ndef f():\n    name = input()\n    open('/srv/public/' + os.path.basename(name) + '/secret.txt')\n", "CWE-22"},
		{"safe_load_then_unsafe", "import yaml\ndef f():\n    value = input()\n    yaml.unsafe_load(yaml.safe_load(value))\n", "CWE-502"},
		{"safe_load_only", "import yaml\ndef f():\n    yaml.safe_load(input())\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "m.py"), []byte(tc.source), 0o644); err != nil {
				t.Fatal(err)
			}
			doc, err := PythonFactsFor(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := pythonprogram.Resolve(doc)
			if err != nil {
				t.Fatal(err)
			}
			graph, err := taint.BuildPythonValueGraph(doc, resolved, taint.DefaultPythonCatalog())
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, finding := range graph.Vulnerabilities() {
				found = found || finding.CWE == tc.want
				if tc.want == "" {
					t.Fatalf("safe parsing alone must not be a deserialization sink: %+v", finding)
				}
			}
			if tc.want != "" && !found {
				t.Fatalf("want %s finding after context-dependent helper", tc.want)
			}
		})
	}
}

func TestPythonEscapedRegexRetainsReDoS(t *testing.T) {
	source := "import re\ndef f():\n" +
		"    value = input()\n" +
		"    re.compile('(a|' + re.escape(value) + ')*$')\n"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "m.py"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := PythonFactsFor(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := pythonprogram.Resolve(doc)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := taint.BuildPythonValueGraph(doc, resolved, taint.DefaultPythonCatalog())
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range graph.Vulnerabilities() {
		if finding.CWE == "CWE-1333" {
			return
		}
	}
	t.Fatal("escaped text may overlap the surrounding regex alternatives")
}

// TestPythonFrameworkEscapersRetainUnknownContext proves HTML escaping cannot clear XSS without output context.
func TestPythonFrameworkEscapersRetainUnknownContext(t *testing.T) {
	detect := func(t *testing.T, src string) []string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "m.py"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		doc, err := PythonFactsFor(context.Background(), dir)
		if err != nil {
			t.Fatalf("facts: %v", err)
		}
		res, err := pythonprogram.Resolve(doc)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		g, err := taint.BuildPythonValueGraph(doc, res, taint.DefaultPythonCatalog())
		if err != nil {
			t.Fatalf("graph: %v", err)
		}
		var cwes []string
		for _, p := range g.Vulnerabilities() {
			cwes = append(cwes, p.CWE)
		}
		return cwes
	}
	has := func(cwes []string, want string) bool {
		for _, c := range cwes {
			if c == want {
				return true
			}
		}
		return false
	}

	// Baseline: an unsanitized tainted value into render_template_string is XSS (CWE-79).
	baseline := "from flask import render_template_string\ndef f():\n    x = input()\n    render_template_string(x)\n"
	if cwes := detect(t, baseline); !has(cwes, "CWE-79") {
		t.Fatalf("baseline unsanitized flow must report XSS (CWE-79), got %v", cwes)
	}

	// HTML text escaping leaves whitespace and equals signs usable in an unquoted attribute.
	unquoted := "from html import escape\nfrom django.http import HttpResponse\ndef f():\n    x = input()\n    return HttpResponse('<input value=' + escape(x) + '>')\n"
	if cwes := detect(t, unquoted); !has(cwes, "CWE-79") {
		t.Errorf("HTML escaping in an unquoted attribute must retain XSS, got %v", cwes)
	}

	// Django escape cannot prove the response context.
	django := "from django.utils.html import escape\nfrom flask import render_template_string\ndef f():\n    x = input()\n    render_template_string(escape(x))\n"
	if cwes := detect(t, django); !has(cwes, "CWE-79") {
		t.Errorf("django.utils.html.escape must retain unknown-context XSS, got %v", cwes)
	}

	// Flask escape has the same context limit.
	flaskEsc := "from flask import escape, render_template_string\ndef f():\n    x = input()\n    render_template_string(escape(x))\n"
	if cwes := detect(t, flaskEsc); !has(cwes, "CWE-79") {
		t.Errorf("flask.escape must retain unknown-context XSS, got %v", cwes)
	}

	markupsafe := "from markupsafe import escape\nfrom django.http import HttpResponse\ndef f():\n    x = input()\n    return HttpResponse('<input value=' + escape(x) + '>')\n"
	if cwes := detect(t, markupsafe); !has(cwes, "CWE-79") {
		t.Errorf("markupsafe.escape in an unquoted attribute must retain XSS, got %v", cwes)
	}

	bleach := "import bleach\nfrom django.http import HttpResponse\ndef f():\n    x = input()\n    return HttpResponse('<input value=' + bleach.clean(x) + '>')\n"
	if cwes := detect(t, bleach); !has(cwes, "CWE-79") {
		t.Errorf("bleach.clean in an unquoted attribute must retain XSS, got %v", cwes)
	}

	// Cross-class: an HTML escaper must NOT neutralize command injection (CWE-78).
	cross := "import os\nfrom django.utils.html import escape\ndef f():\n    x = input()\n    os.system(escape(x))\n"
	if cwes := detect(t, cross); !has(cwes, "CWE-78") {
		t.Errorf("an HTML escaper must not suppress command injection (CWE-78), got %v", cwes)
	}
}
