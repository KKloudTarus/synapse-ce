//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFunctionsForCGO(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "m.py", "def a():\n    pass\ndef b(x):\n    return x\n")           // 2
	writeFile(t, root, "a.js", "function f(){}\nconst g = () => 1;\nclass C { m(){} }\n") // 3
	writeFile(t, root, "D.java", "class D {\n  D(){}\n  int m(){ return 1; }\n}\n")       // 2 (ctor + method)
	writeFile(t, root, "node_modules/dep/x.js", "function ignored(){}\n")                 // vendored, skipped

	res, err := FunctionsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("FunctionsFor: %v", err)
	}
	want := map[string]int{"Python": 2, "JavaScript": 3, "Java": 2}
	for lang, n := range want {
		if res.Functions[lang] != n {
			t.Errorf("%s functions = %d, want %d (all: %v)", lang, res.Functions[lang], n, res.Functions)
		}
	}
}

func TestMetricsForCGO(t *testing.T) {
	root := t.TempDir()
	// Expected values are hand-computed per the documented algorithm (see parse_cgo.go package doc).
	writeFile(t, root, "m.py", "def f(x):\n"+
		"    if x and y:\n"+
		"        for i in z:\n"+
		"            pass\n"+
		"    elif w:\n"+
		"        pass\n"+
		"    else:\n"+
		"        pass\n"+
		"    return 1 if x else 2\n")
	writeFile(t, root, "a.js", "function g(x){\n"+
		"  if (x && y) { for (;;) {} } else if (z) {}\n"+
		"  switch (x) { case 1: break; }\n"+
		"  return x ? 1 : 2;\n"+
		"}\n")
	writeFile(t, root, "C.java", "class C {\n"+
		"  int m(int x) {\n"+
		"    if (x > 0 && y) { while (true) {} } else if (z) {}\n"+
		"    return x > 0 ? 1 : 2;\n"+
		"  }\n"+
		"}\n")

	m, err := MetricsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("MetricsFor: %v", err)
	}
	get := func(name string) (FunctionMetric, bool) {
		for _, f := range m.Functions {
			if f.Name == name {
				return f, true
			}
		}
		return FunctionMetric{}, false
	}
	for _, tc := range []struct {
		name     string
		cyc, cog int
		lang     string
	}{
		{"f", 6, 7, "Python"},
		{"g", 7, 10, "JavaScript"},
		{"m", 6, 7, "Java"},
	} {
		f, ok := get(tc.name)
		if !ok {
			t.Errorf("function %q not found (all: %+v)", tc.name, m.Functions)
			continue
		}
		if f.Cyclomatic != tc.cyc || f.Cognitive != tc.cog || f.Language != tc.lang {
			t.Errorf("%s: got cyc=%d cog=%d lang=%s, want cyc=%d cog=%d lang=%s", tc.name, f.Cyclomatic, f.Cognitive, f.Language, tc.cyc, tc.cog, tc.lang)
		}
	}
}
