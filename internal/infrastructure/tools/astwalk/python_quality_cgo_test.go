//go:build cgo

package astwalk

import (
	"context"
	"strings"
	"testing"
)

func TestQualityForPythonSeed(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "rules.py", `
import unused
import used
from package import *

assert value
if value == None: pass
if type(value) != str: pass
if len(items) == 0: pass
logger.info(f"value={value}")

def mutable(items=list()): pass

def eight(a, b, c, d, e, f, g, h): pass

def globals():
    global state

try:
    work()
except:
    pass

try:
    work()
finally:
    return

values = {'a': 1, "a": 2}
source = open(path)
raise Exception("bad")
used.dumps({})
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{
		"python-mutable-default-argument", "python-bare-except", "python-return-in-finally", "python-duplicate-dict-key",
		"python-assert-for-validation", "python-eq-none", "python-star-import", "python-open-no-context",
		"python-type-eq-vs-isinstance", "python-global-statement", "python-too-many-args", "python-f-string-logging",
		"python-len-eq-zero", "python-unused-import", "python-broad-raise",
	} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}

func TestQualityForPythonSeedRegressions(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "regressions.py", `
def seven(a: tuple[int, str], b, c, d, e, f, g): pass
with transaction():
    source = open(path)
import json
def outer(json):
    def inner():
        return json.loads("{}")
    return inner()
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	if got["python-too-many-args"] {
		t.Errorf("unexpected parameter finding: %+v", res.Findings)
	}
	if !got["python-unused-import"] {
		t.Errorf("shadowed import must be reported unused: %+v", res.Findings)
	}
	if !got["python-open-no-context"] {
		t.Errorf("open inside with body must be reported: %+v", res.Findings)
	}
}

func TestQualityForPythonMutableDefaultGuard(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "lambda_default.py", `
def callback(handler=lambda values=[]: values): pass
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	for _, f := range res.Findings {
		if f.Rule == "python-mutable-default-argument" {
			t.Errorf("lambda default must not be reported: %+v", res.Findings)
		}
	}
}

func TestQualityForPythonSeedGuards(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "clean.py", `
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import type_only

import used
__all__ = ["used"]

def seven(self, a, b, c, d, e, f, g, *args, **kwargs):
    with open(path) as source:
        return source.read()

try:
    work()
except ValueError:
    recover()

if value is None: pass
if isinstance(value, str): pass
if not items: pass
logger.info("value=%s", value)
raise ValueError("bad")
used.dumps({})
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("guard corpus produced findings: %+v", res.Findings)
	}
}

func TestQualityForPythonExtendedRules(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "extended.py", `
if status is 404:
    handle()

try:
    work()
except Exception:
    recover()

area = lambda r: r * r
import os, sys
message = f'ready'
subprocess.run(command, shell=True)
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{
		"python-is-literal", "python-broad-except", "python-lambda-assignment",
		"python-multiple-imports", "python-fstring-no-placeholder", "python-subprocess-shell",
	} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}

func TestQualityForPythonExtendedNoFalsePositives(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "clean.py", `
if value is None:
    return

try:
    work()
except ValueError:
    recover()

handler = compute
import os
message = f'hello {name}'
subprocess.run(['ls', '-la'])
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	for _, f := range res.Findings {
		switch f.Rule {
		case "python-is-literal", "python-broad-except", "python-lambda-assignment",
			"python-multiple-imports", "python-fstring-no-placeholder", "python-subprocess-shell":
			t.Errorf("false positive %s on clean code: %+v", f.Rule, f)
		}
	}
}

func TestQualityForPythonSecurityRules(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "sec.py", `
list = fetch()
assert (count > 0, "count must be positive")
sock.bind(("0.0.0.0", 8080))
path = tempfile.mktemp()
data = yaml.load(text)
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{
		"python-shadow-builtin", "python-assert-tuple", "python-bind-all-interfaces",
		"python-mktemp-insecure", "python-yaml-unsafe-load",
	} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}

func TestQualityForPythonSecurityNoFalsePositives(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "secclean.py", `
item_list = fetch()
assert count > 0, "count must be positive"
sock.bind(("127.0.0.1", 8080))
fd, path = tempfile.mkstemp()
data = yaml.safe_load(text)
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	for _, f := range res.Findings {
		switch f.Rule {
		case "python-shadow-builtin", "python-assert-tuple", "python-bind-all-interfaces",
			"python-mktemp-insecure", "python-yaml-unsafe-load":
			t.Errorf("false positive %s: %+v", f.Rule, f)
		}
	}
}

func TestQualityForJavaAST(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "App.java", `
class App {
    void empty() {}
    void handle(int state) {
        switch (state) {
            case 1: open(); break;
        }
    }
    void nested() {
        try {
            try { step1(); } finally { cleanup(); }
        } catch (Exception e) { log(e); }
    }
    void guard(boolean ready, boolean a, boolean b) {
        if (ready) {
        }
        if (a) {
            if (b) { run(); }
        }
    }
}
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{
		"java-ast-empty-method", "java-ast-missing-switch-default",
		"java-ast-nested-try", "java-ast-empty-if-block", "java-ast-collapsible-if",
	} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}

func TestQualityForJavaASTBatch2(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "B.java", `
class B {
    void loop(int n) {
        for (int i = 0; i < n; i++) {
        }
    }
    void many(String host, int port, int timeout, boolean tls, String user, String pass, int retries, int backoff) {
        connect(host, port);
    }
    void guard(boolean ready) {
        if (ready) {
            start();
        } else {
        }
        if (true) {
            run();
        }
    }
}
`)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{
		"java-ast-empty-loop-body", "java-ast-too-many-params",
		"java-ast-empty-else", "java-ast-constant-condition",
	} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}

func TestQualityForAstMetricsAndStructure(t *testing.T) {
	root := t.TempDir()
	// >50-statement bodies generated to exercise the length rules.
	javaStmts := strings.Repeat("        x++;\n", 55)
	pyStmts := strings.Repeat("    x += 1\n", 55)
	writeFile(t, root, "M.java", "class M {\n    int tier(boolean base, int score) { return base ? 1 : score > 90 ? 3 : 2; }\n    void big() {\n"+javaStmts+"    }\n}\n")
	writeFile(t, root, "m.py", "def __init__(self):\n    return self.value\n\ndef big():\n"+pyStmts+"    return 0\n")
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{
		"java-ast-nested-ternary", "java-ast-long-method",
		"python-return-in-init", "python-too-long-function",
	} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}
