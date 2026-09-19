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
			// Non-empty dict literal initializer read at its OWN key: D5.9c desugars the display into a keyed
			// write d['cmd'] = input(), so a same-key read is the real command injection and must stay flagged.
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

// TestPythonDisplayFieldSensitivityRefinesDisplayLiteral is the precision half of D5.9c: a dict/list/tuple
// display literal whose keys/indices all decode is desugared into per-key writes, so a tainted entry does
// not make a read of a DIFFERENT literal key look tainted, while a same-key read still does. This is the
// headline `d = {'a': input(), 'b': 'safe'}` case: d['b'] clean, d['a'] flagged.
func TestPythonDisplayFieldSensitivityRefinesDisplayLiteral(t *testing.T) {
	precision := []struct {
		name string
		src  string
	}{
		{
			// Clean dict key: only 'a' holds input(), so a read of 'b' is not tainted.
			name: "dict_display_clean_key",
			src: "import os\n" +
				"def f():\n" +
				"    d = {'a': input(), 'b': 'safe'}\n" +
				"    os.system(d['b'])\n",
		},
		{
			// Clean list index: element 0 holds input(), so a read of index 1 is not tainted.
			name: "list_display_clean_index",
			src: "import os\n" +
				"def f():\n" +
				"    l = [input(), 'safe']\n" +
				"    os.system(l[1])\n",
		},
		{
			// Clean tuple index: element 0 holds input(), so a read of index 1 is not tainted.
			name: "tuple_display_clean_index",
			src: "import os\n" +
				"def f():\n" +
				"    t = (input(), 'safe')\n" +
				"    os.system(t[1])\n",
		},
		{
			// Integer dict keys decode the same way: taint under 0 must not surface at 1.
			name: "dict_display_integer_clean_key",
			src: "import os\n" +
				"def f():\n" +
				"    d = {0: input(), 1: 'safe'}\n" +
				"    os.system(d[1])\n",
		},
		{
			// Never-written key of a display literal is a runtime KeyError, so no tainted value reaches the
			// sink; refining `d = {'user': input()}` and reading the absent 'role' key must not be flagged.
			name: "dict_display_absent_key",
			src: "import os\n" +
				"def f():\n" +
				"    d = {'user': input()}\n" +
				"    os.system(d['role'])\n",
		},
		{
			// A comment between list elements is a tree-sitter named child but not an element: it must not
			// consume a positional index, so l[1] still resolves to the clean 'safe' element.
			name: "list_display_comment_between_elements",
			src: "import os\n" +
				"def f():\n" +
				"    l = [input(), # note\n" +
				"         'safe']\n" +
				"    os.system(l[1])\n",
		},
	}
	for _, tc := range precision {
		t.Run(tc.name, func(t *testing.T) {
			if detectFieldSensitive(t, tc.src, "CWE-78") {
				t.Errorf("%s: clean key/index of a refined display literal must not be flagged (false positive)", tc.name)
			}
		})
	}

	soundness := []struct {
		name string
		src  string
	}{
		{
			// Same dict key: d['a'] holds input(), so the same-key read is the real command injection.
			name: "dict_display_same_key",
			src: "import os\n" +
				"def f():\n" +
				"    d = {'a': input(), 'b': 'safe'}\n" +
				"    os.system(d['a'])\n",
		},
		{
			// Same list index: l[0] holds input(), so the same-index read must stay flagged.
			name: "list_display_same_index",
			src: "import os\n" +
				"def f():\n" +
				"    l = [input(), 'safe']\n" +
				"    os.system(l[0])\n",
		},
		{
			// Same tuple index: t[0] holds input(), so the same-index read must stay flagged.
			name: "tuple_display_same_index",
			src: "import os\n" +
				"def f():\n" +
				"    t = (input(), 'safe')\n" +
				"    os.system(t[0])\n",
		},
		{
			// Comment before the tainted element: the tainted value is element 1 at runtime (l[1]), and the
			// comment must not shift it to index 2. If the comment consumed a positional index, input() would be
			// filed under i:2 and the l[1] read would miss it: a hidden-taint false negative.
			name: "list_display_comment_shifts_tainted_index",
			src: "import os\n" +
				"def f():\n" +
				"    l = ['safe', # note\n" +
				"         input()]\n" +
				"    os.system(l[1])\n",
		},
	}
	for _, tc := range soundness {
		t.Run(tc.name, func(t *testing.T) {
			if !detectFieldSensitive(t, tc.src, "CWE-78") {
				t.Errorf("%s: same-key read of a refined display literal must stay flagged (refinement hid the real flow)", tc.name)
			}
		})
	}
}

// TestPythonDisplayFieldSensitivityWidensOnDisplayUncertainty is the soundness half of D5.9c: any display
// construct that defeats exact per-key reasoning (a splat that shifts positions, a nested display value, a
// key whose text does not identify one runtime key, a key that collides with another under Python's key
// equality, a rebinding, or a nested scope) must fall back to whole-container taint, so a clean-looking
// read is flagged. Each entry here would be a false negative if the display were refined instead of widened.
func TestPythonDisplayFieldSensitivityWidensOnDisplayUncertainty(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			// Dict splat: **base injects unknown keys, so the display cannot be enumerated. base is tainted, so
			// whole-container widening must flag even a read of the literal key 'x'.
			name: "dict_splat_widens",
			src: "import os\n" +
				"def f():\n" +
				"    base = {}\n" +
				"    base['y'] = input()\n" +
				"    d = {**base, 'x': 'safe'}\n" +
				"    os.system(d['x'])\n",
		},
		{
			// List splat: *rest shifts every following index, so positions are no longer exact. rest is tainted,
			// so widening must flag a read of index 0.
			name: "list_splat_widens",
			src: "import os\n" +
				"def f():\n" +
				"    rest = [input()]\n" +
				"    l = [*rest, 'safe']\n" +
				"    os.system(l[0])\n",
		},
		{
			// Nested display value: a nested list holds input(), so the outer display must widen; reading the
			// sibling literal key 'b' must flag because the container is tainted as a whole.
			name: "nested_display_value_widens",
			src: "import os\n" +
				"def f():\n" +
				"    d = {'a': [input()], 'b': 'safe'}\n" +
				"    os.system(d['b'])\n",
		},
		{
			// Duplicate literal key, tainted last: `{'a': 'safe', 'a': input()}` leaves d['a'] holding input()
			// at runtime (the second entry wins). The two entries share one refined slot (s:a) rather than
			// widening; the same-key read binds to every prior write, so the tainted last write still flows.
			name: "duplicate_key_last_tainted",
			src: "import os\n" +
				"def f():\n" +
				"    d = {'a': 'safe', 'a': input()}\n" +
				"    os.system(d['a'])\n",
		},
		{
			// Bare-use escape of a display-born container: D5.9c makes the container freshInit (a new way to
			// reach the refinable state), so this guards that passing it whole into a call still widens and the
			// clean-key read flags. A regression that stopped counting bare uses would only be caught here.
			name: "display_container_escapes_to_call",
			src: "import os\n" +
				"def g(x):\n" +
				"    return x\n" +
				"def f():\n" +
				"    d = {'a': input(), 'b': 'safe'}\n" +
				"    g(d)\n" +
				"    os.system(d['b'])\n",
		},
		{
			// Parenthesized tainted element: the element node is a parenthesized_expression, not a bare call, so
			// this confirms per-position taint survives a non-trivial element node at its own index.
			name: "list_parenthesized_element_taint",
			src: "import os\n" +
				"def f():\n" +
				"    l = [(input()), 'safe']\n" +
				"    os.system(l[0])\n",
		},
		{
			// Conditional-expression element: element 0 may evaluate to input(), so the same-index read must
			// flag; the ternary is one named child at index 0 and its taint must reach the keyed write.
			name: "list_conditional_element_taint",
			src: "import os\n" +
				"def f(p):\n" +
				"    l = [input() if p else 'x', 'safe']\n" +
				"    os.system(l[0])\n",
		},
		{
			// bool/int key collision: True and 1 are the same runtime dict key (True == 1), so `{1: input(),
			// True: 'safe'}` leaves d[1] == 'safe' but the bool key is treated as dynamic and widens, flagging
			// the read rather than risk splitting the shared slot.
			name: "bool_key_collision_widens",
			src: "import os\n" +
				"def f():\n" +
				"    d = {1: input(), True: 'safe'}\n" +
				"    os.system(d[1])\n",
		},
		{
			// float/int key collision: 1.0 and 1 are the same runtime dict key, so a float key is dynamic and
			// the display widens.
			name: "float_key_collision_widens",
			src: "import os\n" +
				"def f():\n" +
				"    d = {1: input(), 1.0: 'safe'}\n" +
				"    os.system(d[1])\n",
		},
		{
			// Byte-string key: b'cmd' is decoded as dynamic (prefix), so the display widens; the same-key read
			// carries the real flow and must flag.
			name: "byte_string_key_widens",
			src: "import os\n" +
				"def f():\n" +
				"    d = {b'cmd': input()}\n" +
				"    os.system(d[b'cmd'])\n",
		},
		{
			// Tuple key: a tuple is a valid but non-scalar dict key, decoded as dynamic, so the display widens.
			name: "tuple_key_widens",
			src: "import os\n" +
				"def f():\n" +
				"    d = {('a', 'b'): input()}\n" +
				"    os.system(d[('a', 'b')])\n",
		},
		{
			// f-string key: an interpolated key is not a static literal, so it is dynamic and the display widens.
			name: "fstring_key_widens",
			src: "import os\n" +
				"def f(x):\n" +
				"    d = {f'{x}': input()}\n" +
				"    os.system(d['a'])\n",
		},
		{
			// Rebinding to a tainted display: the latest binding of d holds input() under 'a', so the read must
			// resolve to the tainted write and flag.
			name: "rebind_to_tainted",
			src: "import os\n" +
				"def f():\n" +
				"    d = {'a': 'safe'}\n" +
				"    d = {'a': input()}\n" +
				"    os.system(d['a'])\n",
		},
		{
			// Nested scope present: a closure could mutate the container out of view, so a scope that defines a
			// nested callable refines nothing; the clean-key read of the display must widen and flag.
			name: "display_nested_scope_present",
			src: "import os\n" +
				"def f():\n" +
				"    d = {'a': input(), 'b': 'safe'}\n" +
				"    def inner():\n" +
				"        return 1\n" +
				"    os.system(d['b'])\n",
		},
		{
			// Augmented assignment does not freshly bind: `d = {...}` then `d |= {...}` mutates d, so the second
			// display is not desugared and a bare-use/merge keeps the container widened; the same-key read flags.
			name: "augmented_merge_not_desugared",
			src: "import os\n" +
				"def f():\n" +
				"    d = {}\n" +
				"    d['a'] = input()\n" +
				"    d |= {'a': 'safe'}\n" +
				"    os.system(d['a'])\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !detectFieldSensitive(t, tc.src, "CWE-78") {
				t.Errorf("%s: uncertain display must widen to whole-container taint and flag CWE-78 (false negative otherwise)", tc.name)
			}
		})
	}
}

// TestPythonDisplayFieldSensitivityExtractorDesugars checks the extractor half of D5.9c directly: a display
// literal assigned to a bare local is desugared into a born-empty whole binding (a ValueLiteral RHS) plus
// one keyed ValueBinding per entry, keyed by the same normalized subscript key a read would decode.
func TestPythonDisplayFieldSensitivityExtractorDesugars(t *testing.T) {
	dir := t.TempDir()
	src := "def f():\n" +
		"    d = {'a': 1, 'b': 2}\n" +
		"    l = [10, 20]\n"
	if err := os.WriteFile(filepath.Join(dir, "m.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := PythonFactsFor(context.Background(), dir)
	if err != nil {
		t.Fatalf("facts: %v", err)
	}
	var dictKeyA, dictKeyB, dictWhole, listIdx0, listIdx1 bool
	for _, v := range doc.Values {
		if v.Ref.Kind != pythonprogram.ReferenceName || len(v.Ref.Segments) != 1 {
			continue
		}
		name := v.Ref.Segments[0]
		switch {
		case name == "d" && v.Kind == pythonprogram.ValueBinding && v.SubKey == "s:a":
			dictKeyA = true
		case name == "d" && v.Kind == pythonprogram.ValueBinding && v.SubKey == "s:b":
			dictKeyB = true
		case name == "d" && v.Kind == pythonprogram.ValueBinding && v.SubKey == "" && !v.SubDyn:
			dictWhole = true
		case name == "l" && v.Kind == pythonprogram.ValueBinding && v.SubKey == "i:0":
			listIdx0 = true
		case name == "l" && v.Kind == pythonprogram.ValueBinding && v.SubKey == "i:1":
			listIdx1 = true
		}
	}
	if !dictKeyA || !dictKeyB {
		t.Errorf("dict display must emit keyed bindings s:a and s:b (got a=%v b=%v)", dictKeyA, dictKeyB)
	}
	if !dictWhole {
		t.Errorf("dict display must emit a whole (born-empty) binding for d")
	}
	if !listIdx0 || !listIdx1 {
		t.Errorf("list display must emit positional keyed bindings i:0 and i:1 (got 0=%v 1=%v)", listIdx0, listIdx1)
	}
	// The desugared whole binding must have a ValueLiteral RHS so refinableContainers counts it as freshInit.
	var sawLiteralBirth bool
	for _, a := range doc.Assignments {
		if len(a.Targets) == 1 && a.Targets[0].Kind == pythonprogram.ReferenceName &&
			len(a.Targets[0].Segments) == 1 && a.Targets[0].Segments[0] == "d" &&
			a.Value.Kind == pythonprogram.ReferenceLiteral {
			sawLiteralBirth = true
		}
	}
	if !sawLiteralBirth {
		t.Errorf("desugared dict binding must record a ValueLiteral (born-empty) assignment for d")
	}
}
