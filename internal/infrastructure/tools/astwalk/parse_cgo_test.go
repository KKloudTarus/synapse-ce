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
