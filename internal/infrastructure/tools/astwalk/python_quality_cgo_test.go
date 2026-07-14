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

func TestQualityForJavaASTBatch3(t *testing.T) {
	root := t.TempDir()
	methods := strings.Repeat("    void m%d() {}\n", 0)
	_ = methods
	var mb strings.Builder
	for i := 0; i < 25; i++ {
		mb.WriteString("    void m")
		mb.WriteByte(byte('a' + i%26))
		mb.WriteString("() { work(); }\n")
	}
	writeFile(t, root, "C.java", "class C {\n"+
		"    boolean check(boolean found) {\n        if (found) {\n            return true;\n        } else {\n            return false;\n        }\n    }\n"+
		"    void pick(boolean found) {\n        if (found) {\n            save();\n        } else {\n            save();\n        }\n    }\n"+
		mb.String()+
		"}\n")
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{"java-ast-identical-branches", "java-ast-if-return-boolean", "java-ast-large-class"} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}

func TestQualityForPythonASTStructure(t *testing.T) {
	root := t.TempDir()
	var big strings.Builder
	big.WriteString("class Big:\n")
	for i := 0; i < 25; i++ {
		big.WriteString("    def m")
		big.WriteByte(byte('a' + i%26))
		big.WriteString("(self):\n        return 1\n")
	}
	writeFile(t, root, "s.py", "class Cart:\n    items = []\n\n"+
		"grade = high if s > 90 else (mid if s > 70 else low)\n"+
		"if data == []:\n    stop()\n"+
		"try:\n    work()\nexcept ValueError:\n    pass\n\n"+
		big.String())
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{
		"python-mutable-class-attribute", "python-nested-conditional",
		"python-large-class", "python-compare-empty-collection", "python-except-pass",
	} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}

func TestQualityForJavaScriptAST(t *testing.T) {
	root := t.TempDir()
	var big strings.Builder
	big.WriteString("class Big {\n")
	for i := 0; i < 25; i++ {
		big.WriteString("  m")
		big.WriteByte(byte('a' + i%26))
		big.WriteString("() { return 1; }\n")
	}
	big.WriteString("}\n")
	writeFile(t, root, "a.js", "function empty() {}\n"+
		"function many(a, b, c, d, e, f, g, h) { return a; }\n"+
		"function pick(s) {\n  switch (s) {\n    case 1: return 1;\n  }\n}\n"+
		big.String())
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{"js-ast-empty-function", "js-ast-too-many-params", "js-ast-missing-switch-default", "js-ast-large-class"} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}

func TestQualityForJavaScriptASTBatch2(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "b.js", "function pick(found) {\n  if (found) {\n    save();\n  } else {\n    save();\n  }\n}\n"+
		"function risky() {\n  try {\n    return compute();\n  } finally {\n    return fallback();\n  }\n}\n")
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{"js-ast-identical-branches", "js-ast-return-in-finally"} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}

func TestQualityForTooManyReturns(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "r.py", "def classify(x):\n    if x == True:\n        return 0\n    if x == 1: return 1\n    if x == 2: return 2\n    if x == 3: return 3\n    if x == 4: return 4\n    if x == 5: return 5\n    if x == 6: return 6\n    return 7\n")
	writeFile(t, root, "R.java", "class R {\n  int classify(int x) {\n    if (x==1) return 1;\n    if (x==2) return 2;\n    if (x==3) return 3;\n    if (x==4) return 4;\n    if (x==5) return 5;\n    if (x==6) return 6;\n    if (x==7) return 7;\n    return 0;\n  }\n}\n")
	writeFile(t, root, "r.js", "function classify(x) {\n  if (x===1) return 1;\n  if (x===2) return 2;\n  if (x===3) return 3;\n  if (x===4) return 4;\n  if (x===5) return 5;\n  if (x===6) return 6;\n  if (x===7) return 7;\n  return 0;\n}\n")
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{"python-too-many-returns", "python-compare-bool-literal", "java-ast-too-many-returns", "js-ast-too-many-returns"} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}

func TestQualityForJavaASTStructural(t *testing.T) {
	root := t.TempDir()
	src := "class Big {\n" +
		"  int a1; int a2; int a3; int a4; int a5; int a6; int a7; int a8;\n" +
		"  int a9; int a10; int a11; int a12; int a13; int a14; int a15; int a16;\n" +
		"  void deep() {\n" +
		"    if (a) {\n" +
		"      for (int i = 0; i < n; i++) {\n" +
		"        while (b) {\n" +
		"          try {\n" +
		"            switch (c) { default: break; }\n" +
		"          } finally { cleanup(); }\n" +
		"        }\n" +
		"      }\n" +
		"    }\n" +
		"  }\n" +
		"  void loops() {\n" +
		"    for (int i = 0; i < n; i++) {\n" +
		"      for (int j = 0; j < n; j++) {\n" +
		"        for (int k = 0; k < n; k++) { sum += grid[i][j][k]; }\n" +
		"      }\n" +
		"    }\n" +
		"  }\n" +
		"  void cond() {\n" +
		"    if (a && b && c && d && e && f) { accept(); }\n" +
		"  }\n" +
		"}\n"
	writeFile(t, root, "Big.java", src)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{"java-ast-too-many-fields", "java-ast-deep-nesting", "java-ast-nested-loop", "java-ast-complex-condition"} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}

func TestQualityForPyJsStructural(t *testing.T) {
	root := t.TempDir()
	py := "def deep(x):\n" +
		"    if a:\n" +
		"        for i in items:\n" +
		"            while b:\n" +
		"                with lock:\n" +
		"                    if c:\n" +
		"                        run()\n" +
		"def loops():\n" +
		"    for i in rows:\n" +
		"        for j in cols:\n" +
		"            for k in depth:\n" +
		"                total += grid[i][j][k]\n" +
		"def cond():\n" +
		"    if a and b and c and d and e and f:\n" +
		"        accept()\n"
	writeFile(t, root, "m.py", py)
	js := "function deep(x) {\n" +
		"  if (a) {\n" +
		"    for (const i of items) {\n" +
		"      while (b) {\n" +
		"        try {\n" +
		"          if (c) { run(); }\n" +
		"        } finally { cleanup(); }\n" +
		"      }\n" +
		"    }\n" +
		"  }\n" +
		"}\n" +
		"function loops() {\n" +
		"  for (let i = 0; i < n; i++) {\n" +
		"    for (let j = 0; j < n; j++) {\n" +
		"      for (let k = 0; k < n; k++) { sum += g[i][j][k]; }\n" +
		"    }\n" +
		"  }\n" +
		"}\n" +
		"function cond() {\n" +
		"  if (a && b && c && d && e && f) { accept(); }\n" +
		"}\n"
	writeFile(t, root, "m.js", js)
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{"python-deep-nesting", "python-nested-loop", "python-complex-condition", "js-ast-deep-nesting", "js-ast-nested-loop", "js-ast-complex-condition"} {
		if !got[rule] {
			t.Errorf("missing %s in %+v", rule, res.Findings)
		}
	}
}

func TestQualityForComplexityMetrics(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "C.java", "class C {\n  int complex(int x) {\n    int sum = 0;\n    if (x == 0) sum++;\n    if (x == 1) sum++;\n    if (x == 2) sum++;\n    if (x == 3) sum++;\n    if (x == 4) sum++;\n    if (x == 5) sum++;\n    if (x == 6) sum++;\n    if (x == 7) sum++;\n    if (x == 8) sum++;\n    if (x == 9) sum++;\n    if (x == 10) sum++;\n    if (x == 11) sum++;\n    if (x == 12) sum++;\n    if (x == 13) sum++;\n    if (x == 14) sum++;\n    if (x == 15) sum++;\n    if (x == 16) sum++;\n    if (x == 17) sum++;\n    if (x == 18) sum++;\n    if (x == 19) sum++;\n    return sum;\n  }\n  int many(int status) {\n    switch (status) {\n      case 0: return 0;\n      case 1: return 1;\n      case 2: return 2;\n      case 3: return 3;\n      case 4: return 4;\n      case 5: return 5;\n      case 6: return 6;\n      case 7: return 7;\n      case 8: return 8;\n      case 9: return 9;\n      case 10: return 10;\n      case 11: return 11;\n      case 12: return 12;\n      case 13: return 13;\n      case 14: return 14;\n      case 15: return 15;\n      case 16: return 16;\n      case 17: return 17;\n      case 18: return 18;\n      case 19: return 19;\n      default: return -1;\n    }\n  }\n}\n")
	writeFile(t, root, "m.js", "function complex(x) {\n  let sum = 0;\n  if (x === 0) sum++;\n  if (x === 1) sum++;\n  if (x === 2) sum++;\n  if (x === 3) sum++;\n  if (x === 4) sum++;\n  if (x === 5) sum++;\n  if (x === 6) sum++;\n  if (x === 7) sum++;\n  if (x === 8) sum++;\n  if (x === 9) sum++;\n  if (x === 10) sum++;\n  if (x === 11) sum++;\n  if (x === 12) sum++;\n  if (x === 13) sum++;\n  if (x === 14) sum++;\n  if (x === 15) sum++;\n  if (x === 16) sum++;\n  if (x === 17) sum++;\n  if (x === 18) sum++;\n  if (x === 19) sum++;\n  return sum;\n}\nfunction many(status) {\n  switch (status) {\n    case 0: return 0;\n    case 1: return 1;\n    case 2: return 2;\n    case 3: return 3;\n    case 4: return 4;\n    case 5: return 5;\n    case 6: return 6;\n    case 7: return 7;\n    case 8: return 8;\n    case 9: return 9;\n    case 10: return 10;\n    case 11: return 11;\n    case 12: return 12;\n    case 13: return 13;\n    case 14: return 14;\n    case 15: return 15;\n    case 16: return 16;\n    case 17: return 17;\n    case 18: return 18;\n    case 19: return 19;\n    default: return -1;\n  }\n}\n")
	writeFile(t, root, "m.py", "def complex_fn(x):\n    total = 0\n    if x == 0:\n        total += 1\n    if x == 1:\n        total += 1\n    if x == 2:\n        total += 1\n    if x == 3:\n        total += 1\n    if x == 4:\n        total += 1\n    if x == 5:\n        total += 1\n    if x == 6:\n        total += 1\n    if x == 7:\n        total += 1\n    if x == 8:\n        total += 1\n    if x == 9:\n        total += 1\n    if x == 10:\n        total += 1\n    if x == 11:\n        total += 1\n    if x == 12:\n        total += 1\n    if x == 13:\n        total += 1\n    if x == 14:\n        total += 1\n    if x == 15:\n        total += 1\n    if x == 16:\n        total += 1\n    if x == 17:\n        total += 1\n    if x == 18:\n        total += 1\n    if x == 19:\n        total += 1\n    return total\n")
	res, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.Rule] = true
	}
	for _, rule := range []string{"java-ast-high-complexity", "java-ast-switch-many-cases", "js-ast-high-complexity", "js-ast-switch-many-cases", "python-high-complexity"} {
		if !got[rule] {
			t.Errorf("missing %s", rule)
		}
	}
}
