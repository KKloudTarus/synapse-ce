//go:build cgo

package astwalk

import (
	"context"
	"testing"
)

func TestBugsForCGO(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.py", "def f(x):\n"+
		"    if x:\n"+
		"        return 1\n"+
		"        print(\"dead\")\n"+ // unreachable (after return)
		"    if True:\n"+ // constant condition
		"        return 2\n"+
		"    while True:\n"+ // idiomatic infinite loop: must NOT be flagged
		"        break\n"+
		"    return 3\n")
	writeFile(t, root, "b.js", "function g(x){\n"+
		"  if (x) { throw new Error('e'); doMore(); }\n"+ // unreachable (after throw)
		"  if (false) { neverRuns(); }\n"+ // constant condition
		"  while (true) { if (done()) break; }\n"+ // idiomatic: NOT flagged
		"  return 0;\n"+
		"}\n")

	res, err := BugsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("BugsFor: %v", err)
	}
	type key struct {
		file, rule string
	}
	got := map[key]bool{}
	for _, b := range res.Bugs {
		got[key{b.File, b.Rule}] = true
	}
	for _, want := range []key{
		{"a.py", "reliability-unreachable-code"},
		{"a.py", "reliability-constant-condition"},
		{"b.js", "reliability-unreachable-code"},
		{"b.js", "reliability-constant-condition"},
	} {
		if !got[want] {
			t.Errorf("missing bug %+v (all: %+v)", want, res.Bugs)
		}
	}
	// while(true)/while True must NOT produce a constant-condition bug (idiomatic infinite loop).
	if len(res.Bugs) != 4 {
		t.Errorf("want exactly 4 bugs (no while-true false positive), got %d: %+v", len(res.Bugs), res.Bugs)
	}
}

func TestBugsForNoFalsePositive(t *testing.T) {
	root := t.TempDir()
	// Clean code: a normal if, a normal return, a real infinite loop. No bugs.
	writeFile(t, root, "c.js", "function ok(x){\n  if (x > 0) { return 1; }\n  while (true) { if (stop()) return 2; }\n  return 0;\n}\n")
	res, err := BugsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("BugsFor: %v", err)
	}
	if len(res.Bugs) != 0 {
		t.Errorf("clean code must yield no bugs, got %+v", res.Bugs)
	}
}
