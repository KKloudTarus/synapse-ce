//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

// detectFieldSensitive runs the full owned Python pipeline (cgo extractor -> resolver -> taint value flow)
// on one source file and reports whether it produced the given CWE. It is the end-to-end harness for the
// D5.9b field-sensitivity refinement: precision cases must NOT produce the finding, soundness cases MUST.
func detectFieldSensitive(t *testing.T, src, wantCWE string) bool {
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
	for _, p := range g.Vulnerabilities() {
		if p.CWE == wantCWE {
			return true
		}
	}
	return false
}

// TestPythonFieldSensitivityRefinesFreshLocalContainer is the precision half of D5.9b: a tainted value
// stored under one literal key of a fresh, non-escaping local dict must NOT make a read of a DIFFERENT
// literal key look tainted, while a read of the SAME key still must. This removes a real false positive
// without hiding the real flow.
func TestPythonFieldSensitivityRefinesFreshLocalContainer(t *testing.T) {
	// Clean key read: d['role'] was assigned a constant, so it is not tainted even though d['user'] is.
	cleanRead := "import os\n" +
		"def f():\n" +
		"    d = {}\n" +
		"    d['user'] = input()\n" +
		"    d['role'] = 'guest'\n" +
		"    os.system(d['role'])\n"
	if detectFieldSensitive(t, cleanRead, "CWE-78") {
		t.Errorf("clean key read d['role'] of a fresh local dict must not be flagged (field-sensitivity false positive)")
	}

	// Tainted key read: d['user'] carries input(), so the same-key read IS the real command injection.
	taintedRead := "import os\n" +
		"def f():\n" +
		"    d = {}\n" +
		"    d['user'] = input()\n" +
		"    d['role'] = 'guest'\n" +
		"    os.system(d['user'])\n"
	if !detectFieldSensitive(t, taintedRead, "CWE-78") {
		t.Errorf("tainted key read d['user'] must remain flagged as CWE-78 (refinement must not hide the real flow)")
	}

	// Integer keys refine the same way: taint under key 0 must not surface at key 1.
	intKeys := "import os\n" +
		"def f():\n" +
		"    d = {}\n" +
		"    d[0] = input()\n" +
		"    d[1] = 'guest'\n" +
		"    os.system(d[1])\n"
	if detectFieldSensitive(t, intKeys, "CWE-78") {
		t.Errorf("clean integer-key read d[1] must not be flagged when only d[0] is tainted")
	}

	// Integer and string keys of the same text are DIFFERENT runtime keys: tainting d['0'] must not surface
	// at the integer read d[0].
	intVsStr := "import os\n" +
		"def f():\n" +
		"    d = {}\n" +
		"    d['0'] = input()\n" +
		"    d[0] = 'guest'\n" +
		"    os.system(d[0])\n"
	if detectFieldSensitive(t, intVsStr, "CWE-78") {
		t.Errorf("integer key d[0] must be distinct from string key d['0']; the clean int read must not be flagged")
	}

	// An EAGER list comprehension reads d['y'] at its textual position (before the tainted reassignment), so
	// its captured value is genuinely clean; refining it (not widening) is correct precision, not a false
	// negative. This guards that the generator-expression widening did not over-widen eager comprehensions.
	eagerComp := "import os\n" +
		"def f():\n" +
		"    d = {}\n" +
		"    d['y'] = 'safe'\n" +
		"    r = [d['y'] for _ in range(2)]\n" +
		"    d['y'] = input()\n" +
		"    os.system(r[0])\n"
	if detectFieldSensitive(t, eagerComp, "CWE-78") {
		t.Errorf("eager comprehension read of d['y'] before the tainted reassignment is genuinely clean and must not be flagged")
	}
}

// TestPythonFieldSensitivityWidensOnEscapeAndUncertainty is the soundness half of D5.9b: every case where
// the container could alias, escape, hold caller-controlled keys, be mutated out of view, or be reached
// through an unmodeled construct must fall back to whole-container taint, so the clean-key read that the
// precision case suppresses is flagged again here. A miss in any of these is a false negative, which the
// no-false-suppression bar forbids; the refinement therefore refines ONLY when it can prove none apply.
func TestPythonFieldSensitivityWidensOnEscapeAndUncertainty(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			// Bare use (alias): binding the container to another name means writes through the alias could
			// hit any key, so the container is no longer provably per-key. Widen -> the clean-key read fires.
			name: "bare_use_alias",
			src: "import os\n" +
				"def f():\n" +
				"    d = {}\n" +
				"    d['user'] = input()\n" +
				"    d['role'] = 'guest'\n" +
				"    alias = d\n" +
				"    os.system(d['role'])\n",
		},
		{
			// Dynamic-key write: d[k] could assign the key later read, so the whole container is tainted.
			name: "dynamic_key_write",
			src: "import os\n" +
				"def f(k):\n" +
				"    d = {}\n" +
				"    d[k] = input()\n" +
				"    d['role'] = 'guest'\n" +
				"    os.system(d['role'])\n",
		},
		{
			// Dynamic-key read at the sink: d[k] could read the tainted key, so it must be flagged.
			name: "dynamic_key_read",
			src: "import os\n" +
				"def f(k):\n" +
				"    d = {}\n" +
				"    d['user'] = input()\n" +
				"    os.system(d[k])\n",
		},
		{
			// Non-decimal integer key: 0x0/0o0/0b0 name the same runtime key as decimal 0 but with different
			// text, so they are treated as dynamic and widen (never split from the decimal slot).
			name: "hex_integer_key_widens",
			src: "import os\n" +
				"def f():\n" +
				"    d = {}\n" +
				"    d[0x0] = input()\n" +
				"    os.system(d[0])\n",
		},
		{
			// Non-empty init: the container is not a proven-empty fresh literal, so its starting keys are
			// unknown and it cannot be refined.
			name: "non_empty_init",
			src: "import os\n" +
				"def f():\n" +
				"    d = {'user': input()}\n" +
				"    os.system(d['role'])\n",
		},
		{
			// Nested scope: a closure could capture and mutate the container out of view, so a scope that
			// defines any nested callable refines nothing.
			name: "nested_scope_present",
			src: "import os\n" +
				"def f():\n" +
				"    d = {}\n" +
				"    d['user'] = input()\n" +
				"    d['role'] = 'guest'\n" +
				"    def inner():\n" +
				"        return 1\n" +
				"    os.system(d['role'])\n",
		},
		{
			// Escaped-string key: '\x61' is the escape for 'a', so d['\x61'] and d['a'] are the SAME runtime
			// key. The escape must widen (never a distinct refined slot) or the flow is dropped.
			name: "escaped_string_key_widens",
			src: "import os\n" +
				"def f():\n" +
				"    d = {}\n" +
				"    d['\\x61'] = input()\n" +
				"    os.system(d['a'])\n",
		},
		{
			// Reverse spelling: tainted under the plain key, read under the escaped spelling. Same key at
			// runtime; must still flag.
			name: "escaped_string_key_widens_reverse",
			src: "import os\n" +
				"def f():\n" +
				"    d = {}\n" +
				"    d['a'] = input()\n" +
				"    os.system(d['\\x61'])\n",
		},
		{
			// Loop-carried backward flow: d['y'] holds input() on the second iteration (the write is textually
			// after the read but executes before it in the next iteration). The position-gated per-key def-use
			// cannot see this, so a container touched by any subscript inside a loop must widen.
			name: "loop_carried_backward_flow",
			src: "import os\n" +
				"def f():\n" +
				"    d = {}\n" +
				"    d['x'] = input()\n" +
				"    d['y'] = 'safe'\n" +
				"    for i in range(2):\n" +
				"        os.system(d['y'])\n" +
				"        d['y'] = d['x']\n",
		},
		{
			// Overlong key: a key that would exceed the facts bound must widen at extraction, never be emitted
			// (which would fail the whole document's validation and drop ALL Python taint for the scan).
			name: "overlong_key_widens_not_fails",
			src: "import os\n" +
				"def f():\n" +
				"    d = {}\n" +
				"    d['" + strings.Repeat("k", 300) + "'] = input()\n" +
				"    os.system(d['" + strings.Repeat("k", 300) + "'])\n",
		},
		{
			// Non-empty dict literal initializer (Codex): the container is not a proven-empty fresh literal, so
			// tainted initializer contents must reach a same-key read.
			name: "non_empty_init_same_key",
			src: "import os\n" +
				"def f():\n" +
				"    d = {'cmd': input()}\n" +
				"    os.system(d['cmd'])\n",
		},
		{
			// Generator expression is LAZY: d['y'] is read when the generator is consumed, after d['y'] is
			// reassigned to the tainted value, so it must widen (a comprehension would read eagerly and be
			// clean, but a genexp defers).
			name: "generator_expression_deferred_read",
			src: "import os\n" +
				"def f():\n" +
				"    d = {}\n" +
				"    d['x'] = input()\n" +
				"    d['y'] = 'safe'\n" +
				"    g = (d['y'] for _ in range(2))\n" +
				"    d['y'] = d['x']\n" +
				"    os.system(list(g)[0])\n",
		},
		{
			// Sole-argument generator form f(x for x in r): the generator is the call's `arguments` node with no
			// argument_list, so it must still route through the generator widening. Consumed lazily (iter/next)
			// after the tainted reassignment, so the deferred read sees the tainted value.
			name: "sole_argument_generator_deferred",
			src: "import os\n" +
				"def f():\n" +
				"    d = {}\n" +
				"    d['x'] = input()\n" +
				"    d['y'] = 'safe'\n" +
				"    it = iter(d['y'] for _ in range(2))\n" +
				"    d['y'] = d['x']\n" +
				"    os.system(next(it))\n",
		},
		{
			// Comprehension with a dynamic key: comprehension bodies are analyzed in the enclosing scope, so a
			// non-literal subscript inside one still marks the container dynamic and widens.
			name: "comprehension_dynamic_key",
			src: "import os\n" +
				"def f(keys):\n" +
				"    d = {}\n" +
				"    d['x'] = input()\n" +
				"    vals = [d[k] for k in keys]\n" +
				"    os.system(vals[0])\n",
		},
		{
			// Interprocedural parameter: a dict passed whole into a callee has caller-controlled keys, so the
			// callee's parameter must not be refined (else the keyed read would find no local write and drop
			// the taint). This exercises both the bare-use guard (caller) and the parameter guard (callee).
			name: "parameter_container",
			src: "import os\n" +
				"def use(d):\n" +
				"    os.system(d['cmd'])\n" +
				"def f():\n" +
				"    payload = {}\n" +
				"    payload['cmd'] = input()\n" +
				"    use(payload)\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !detectFieldSensitive(t, tc.src, "CWE-78") {
				t.Errorf("%s: escaping/uncertain container must widen to whole-container taint and flag CWE-78 (false negative otherwise)", tc.name)
			}
		})
	}
}

// TestPythonFieldSensitivityExtractorTagsLiteralSubscripts checks the extractor half directly: a literal
// subscript on a simple name carries its key text, a dynamic subscript is marked dynamic, and a bare use of
// the same name carries neither. These tags are what the taint builder's refinability proof consumes.
func TestPythonFieldSensitivityExtractorTagsLiteralSubscripts(t *testing.T) {
	dir := t.TempDir()
	src := "def f(k):\n" +
		"    d = {}\n" +
		"    d['user'] = 1\n" +
		"    d[k] = 2\n" +
		"    x = d['role']\n" +
		"    y = d\n"
	if err := os.WriteFile(filepath.Join(dir, "m.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := PythonFactsFor(context.Background(), dir)
	if err != nil {
		t.Fatalf("facts: %v", err)
	}
	var litWriteUser, dynWrite, litReadRole, bareUse bool
	for _, v := range doc.Values {
		if v.Ref.Kind != pythonprogram.ReferenceName || len(v.Ref.Segments) != 1 || v.Ref.Segments[0] != "d" {
			continue
		}
		switch {
		case v.Kind == pythonprogram.ValueBinding && v.SubKey == "s:user":
			litWriteUser = true
		case v.Kind == pythonprogram.ValueBinding && v.SubDyn:
			dynWrite = true
		case v.Kind == pythonprogram.ValueReference && v.SubKey == "s:role":
			litReadRole = true
		case v.Kind == pythonprogram.ValueReference && v.SubKey == "" && !v.SubDyn:
			bareUse = true // the `y = d` right-hand side is a bare use of d
		}
	}
	if !litWriteUser {
		t.Errorf("write d['user'] must be tagged with SubKey=s:user")
	}
	if !dynWrite {
		t.Errorf("write d[k] must be tagged SubDyn")
	}
	if !litReadRole {
		t.Errorf("read d['role'] must be tagged with SubKey=s:role")
	}
	if !bareUse {
		t.Errorf("bare use `y = d` must leave d untagged (SubKey empty, SubDyn false)")
	}
}
