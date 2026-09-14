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

// TestPythonShadowedSanitizerImportNotWalled is the #1-bar guard for #1089: when a FUNCTION-LOCAL binding (a
// parameter or an assignment) shadows an imported sanitizer name, the taint engine must NOT apply the
// sanitizer wall to that call. Otherwise a local named `escape` is walled as if it were the real HTML escaper,
// hiding a real XSS. The suppression is scoped to sanitizers only, so it can only over-report, never touch
// sink/source resolution (which is why local-assignment shadowing needs no `global`/`nonlocal` tracking). A
// MODULE-level rebind is left alone (position-dependent, keeping the wall avoids a false positive).
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

	// A parameter named `escape` shadows the imported escaper: `escape(x)` is the parameter, not the sanitizer,
	// so the XSS flow must survive.
	param := "from flask import escape, render_template_string\n" +
		"def f(escape):\n    x = input()\n    render_template_string(escape(x))\n"
	if cwes := detect(t, param); !has(cwes, "CWE-79") {
		t.Errorf("a parameter shadowing the imported escaper must not wall XSS (CWE-79), got %v", cwes)
	}

	// A FUNCTION-LOCAL assignment named `escape` also shadows the import: inside f, `escape` is the local, so
	// the wall must not fire (it is not provably the real escaper).
	localAssign := "from flask import render_template_string\n" +
		"def f(user_fn):\n    escape = user_fn\n    x = input()\n    render_template_string(escape(x))\n"
	if cwes := detect(t, localAssign); !has(cwes, "CWE-79") {
		t.Errorf("a function-local assignment shadowing the escaper must not wall XSS (CWE-79), got %v", cwes)
	}

	// A MODULE-level reassignment of the imported name is NOT a shadow: a same-scope `escape = ...` after the
	// import is a position-dependent rebind, so keeping the wall avoids a false positive. The escaper stands.
	moduleRebind := "from flask import escape, render_template_string\n" +
		"x = input()\nrender_template_string(escape(x))\nescape = None\n"
	if cwes := detect(t, moduleRebind); has(cwes, "CWE-79") {
		t.Errorf("a module-level rebind (not a function-local shadow) must not disable the escaper wall, got %v", cwes)
	}

	// Control: with no shadow, the real imported escaper still neutralizes the XSS (the fix must not break the
	// legitimate sanitizer wall).
	control := "from flask import escape, render_template_string\n" +
		"def f():\n    x = input()\n    render_template_string(escape(x))\n"
	if cwes := detect(t, control); has(cwes, "CWE-79") {
		t.Errorf("the unshadowed imported escaper must still neutralize XSS, got %v", cwes)
	}
}

// TestPythonFrameworkEscapersSanitizeXSS proves the #1039 Django/Flask HTML escapers neutralize the XSS class
// (and only that class) end to end through the real extractor + engine.
func TestPythonFrameworkEscapersSanitizeXSS(t *testing.T) {
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

	// Django escape neutralizes the XSS flow.
	django := "from django.utils.html import escape\nfrom flask import render_template_string\ndef f():\n    x = input()\n    render_template_string(escape(x))\n"
	if cwes := detect(t, django); has(cwes, "CWE-79") {
		t.Errorf("django.utils.html.escape must neutralize XSS, got %v", cwes)
	}

	// Flask escape neutralizes the XSS flow.
	flaskEsc := "from flask import escape, render_template_string\ndef f():\n    x = input()\n    render_template_string(escape(x))\n"
	if cwes := detect(t, flaskEsc); has(cwes, "CWE-79") {
		t.Errorf("flask.escape must neutralize XSS, got %v", cwes)
	}

	// Cross-class: an HTML escaper must NOT neutralize command injection (CWE-78).
	cross := "import os\nfrom django.utils.html import escape\ndef f():\n    x = input()\n    os.system(escape(x))\n"
	if cwes := detect(t, cross); !has(cwes, "CWE-78") {
		t.Errorf("an HTML escaper must not suppress command injection (CWE-78), got %v", cwes)
	}
}
