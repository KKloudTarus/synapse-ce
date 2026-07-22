//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestNewlyRegisteredGrammarsParse verifies that each grammar added to remove the "needs-grammar"
// prerequisite (#185/#186–#209) actually parses and — for function-bearing languages — counts functions
// via the spec's funcType node set. It is the empirical guard that the node-type names in specs match the
// bundled grammar, so a contributor authoring an AST rule pack can rely on the parser.
func TestNewlyRegisteredGrammarsParse(t *testing.T) {
	cases := []struct {
		lang, file, src string
		wantFuncs       int
	}{
		{"Go", "a.go", "package p\nfunc A() int { if true { return 1 }; return 0 }\nfunc (r R) B() {}\n", 2},
		{"C", "a.c", "#include <stdio.h>\nint main(void) { for (int i=0;i<3;i++){} return 0; }\n", 1},
		{"C++", "a.cpp", "#include <vector>\nclass K { public: int f() { return 1; } };\nint g(int x) { return x>0 ? 1 : 2; }\n", 2},
		{"C#", "a.cs", "namespace N { class C { public int F(int x) { if (x>0) return 1; return 0; } } }\n", 1},
		{"Rust", "a.rs", "fn main() { for _ in 0..3 { } }\nfn add(a: i32, b: i32) -> i32 { a + b }\n", 2},
		{"Ruby", "a.rb", "def greet(name)\n  if name\n    puts name\n  end\nend\n", 1},
		{"PHP", "a.php", "<?php\nfunction add($a, $b) { return $a + $b; }\n", 1},
		{"Scala", "a.scala", "object M {\n  def add(a: Int, b: Int): Int = a + b\n}\n", 1},
		{"Swift", "a.swift", "func greet(name: String) {\n  if name.isEmpty { return }\n}\n", 1},
		{"Kotlin", "a.kt", "fun add(a: Int, b: Int): Int {\n  return a + b\n}\n", 1},
	}

	for _, tc := range cases {
		t.Run(tc.lang, func(t *testing.T) {
			// A spec must be registered for the language.
			if _, ok := specs[tc.lang]; !ok {
				t.Fatalf("no spec registered for %q", tc.lang)
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.src), 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := FunctionsFor(context.Background(), dir)
			if err != nil {
				t.Fatalf("FunctionsFor: %v", err)
			}
			if got := res.Functions[tc.lang]; got != tc.wantFuncs {
				t.Fatalf("%s: function count = %d, want %d (funcType node types likely wrong for the bundled grammar, or enry mis-detected the language)", tc.lang, got, tc.wantFuncs)
			}
		})
	}
}

// TestMarkupGrammarsParse verifies the markup grammars (no functions) parse into a non-trivial tree, so
// AST rule authoring over selectors/elements is possible.
func TestMarkupGrammarsParse(t *testing.T) {
	cases := []struct{ lang, src string }{
		{"CSS", "a { color: red; }\n.b > .c { margin: 0; }\n"},
		{"HTML", "<!doctype html><html><body><div id=\"x\">hi</div></body></html>\n"},
	}
	for _, tc := range cases {
		t.Run(tc.lang, func(t *testing.T) {
			sp, ok := specs[tc.lang]
			if !ok {
				t.Fatalf("no spec registered for %q", tc.lang)
			}
			root := parseRoot(context.Background(), sp, []byte(tc.src))
			if root == nil {
				t.Fatalf("%s did not parse", tc.lang)
			}
			if root.ChildCount() == 0 {
				t.Fatalf("%s parsed to an empty tree", tc.lang)
			}
		})
	}
}
