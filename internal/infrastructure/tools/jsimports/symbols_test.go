package jsimports

import (
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
)

// usesFor indexes a module's local references by local name.
func usesFor(graph modulegraph.Graph, module string) map[string][]modulegraph.LocalUse {
	out := map[string][]modulegraph.LocalUse{}
	for _, use := range graph.LocalUses {
		if use.Module == module {
			out[use.Local] = append(out[use.Local], use)
		}
	}
	return out
}

func hasProperty(uses []modulegraph.LocalUse, property string) bool {
	for _, use := range uses {
		if use.Kind == modulegraph.LocalUseProperty && use.Property == property {
			return true
		}
	}
	return false
}

func hasOpaque(uses []modulegraph.LocalUse) bool {
	for _, use := range uses {
		if use.Kind == modulegraph.LocalUseOpaque {
			return true
		}
	}
	return false
}

// TestNamespaceMemberReadsAreObserved is the positive case Tier-2 depends on: a whole-module binding
// whose every reference is a plain property read tells us exactly which exports are reached.
func TestNamespaceMemberReadsAreObserved(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "src", "a.ts"), `
import * as lodash from "lodash";

export function render(input) {
  const compiled = lodash.template(input);
  return lodash.escape(compiled);
}
`)
	graph := scan(t, root)
	uses := usesFor(graph, "src/a.ts")["lodash"]
	if !hasProperty(uses, "template") || !hasProperty(uses, "escape") {
		t.Fatalf("both property reads must be observed, got %+v", uses)
	}
	if hasOpaque(uses) {
		t.Fatalf("a namespace used only through property reads must not be opaque, got %+v", uses)
	}
}

// TestEscapingBindingsAreOpaque is the safety case: every one of these can reach ANY export, so none of
// them may leave the analysis able to conclude a symbol is unused.
func TestEscapingBindingsAreOpaque(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{"passed as an argument", `register(lodash);`},
		{"spread into an object", `const all = { ...lodash };`},
		{"indexed with a computed key", `const fn = lodash[name];`},
		{"returned", `export function get() { return lodash; }`},
		{"assigned to another binding", `const alias = lodash;`},
		{"invoked directly", `lodash();`},
		{"awaited", `await lodash;`},
		{"compared", `if (lodash) { report(); }`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "src", "a.ts"), "import * as lodash from \"lodash\";\n"+test.body+"\n")
			graph := scan(t, root)
			uses := usesFor(graph, "src/a.ts")["lodash"]
			if !hasOpaque(uses) {
				t.Fatalf("%s must make the binding opaque, got %+v", test.name, uses)
			}
		})
	}
}

// TestCommonJSDestructuringYieldsNamedBindings locks the CommonJS half: `const {template} = require(...)`
// names one export exactly, the same as an ESM named import.
func TestCommonJSDestructuringYieldsNamedBindings(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "src", "a.js"), `
const { template, escape: esc } = require("lodash");
module.exports = { template, esc };
`)
	graph := scan(t, root)
	edge := mustEdge(t, graph, "src/a.js", "lodash")
	got := map[string]string{}
	for _, binding := range edge.Bindings {
		got[binding.Imported] = binding.Local
	}
	if got["template"] != "template" || got["escape"] != "esc" {
		t.Fatalf("destructured bindings = %+v, want template->template and escape->esc", edge.Bindings)
	}
	for _, binding := range edge.Bindings {
		if binding.Namespace {
			t.Fatalf("a destructured binding is not a namespace binding: %+v", binding)
		}
	}
}

func TestCommonJSWholeModuleBindingIsANamespace(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "src", "a.js"), `
const lodash = require("lodash");
exports.run = (x) => lodash.template(x);
`)
	graph := scan(t, root)
	edge := mustEdge(t, graph, "src/a.js", "lodash")
	if len(edge.Bindings) != 1 || !edge.Bindings[0].Namespace || edge.Bindings[0].Local != "lodash" {
		t.Fatalf("bindings = %+v, want one namespace binding for lodash", edge.Bindings)
	}
	if !hasProperty(usesFor(graph, "src/a.js")["lodash"], "template") {
		t.Fatalf("the property read must be observed, got %+v", usesFor(graph, "src/a.js")["lodash"])
	}
}

// A binding pattern this scanner does not model must yield NO bindings, which downstream reads as a
// whole-module binding — never as "these are all the exports that are used".
func TestUnmodelledCommonJSPatternsYieldNoBindings(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, source string }{
		{"rest element", `const { template, ...rest } = require("lodash");`},
		{"default value", `const { template = fallback } = require("lodash");`},
		{"nested pattern", `const { a: { b } } = require("lodash");`},
		{"immediately invoked", `require("lodash")();`},
		{"member read on the call", `const t = require("lodash").template;`},
		{"passed straight on", `register(require("lodash"));`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "src", "a.js"), test.source+"\n")
			graph := scan(t, root)
			edge := mustEdge(t, graph, "src/a.js", "lodash")
			for _, binding := range edge.Bindings {
				if binding.Imported != "" {
					t.Fatalf("%s must not produce a named binding, got %+v", test.name, edge.Bindings)
				}
			}
		})
	}
}

// A property name must never be recorded as a reference to a local of the same name: `config.template`
// says nothing about a local called template.
func TestPropertyNamesAreNotLocalReferences(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "src", "a.ts"), `
import { template } from "lodash";
const config = { template: 1 };
report(config.template);
`)
	graph := scan(t, root)
	for _, use := range graph.LocalUses {
		if use.Local == "template" && use.Kind == modulegraph.LocalUseOpaque && use.Detail == "referenced without a property access" {
			// `report(config.template)` must not have produced this; the only legitimate opaque use of
			// `template` here would come from a bare reference, and there is none.
			t.Fatalf("a property name was recorded as a local reference: %+v", use)
		}
	}
}

// Declaration sites introduce a name; they are not uses of it. Without this the local of every
// `const x = require(...)` would immediately look like an escaping reference.
func TestDeclarationSitesAreNotUses(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "src", "a.js"), `
const lodash = require("lodash");
lodash.template("x");
`)
	graph := scan(t, root)
	uses := usesFor(graph, "src/a.js")["lodash"]
	if hasOpaque(uses) {
		t.Fatalf("the declaration site must not count as an escaping use, got %+v", uses)
	}
	if !hasProperty(uses, "template") {
		t.Fatalf("the property read must still be observed, got %+v", uses)
	}
}

// Symbol observation must not disturb import extraction: the same file's edges are still found.
func TestSymbolObservationDoesNotDisturbImportExtraction(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "src", "a.tsx"), `
import * as lodash from "lodash";
import React from "react";
import { helper } from "./helper";

export const App = () => <div onClick={() => lodash.template(helper())} />;
`)
	writeFile(t, filepath.Join(root, "src", "helper.ts"), `export function helper() { return "x"; }`)
	graph := scan(t, root)
	for _, specifier := range []string{"lodash", "react", "./helper"} {
		mustEdge(t, graph, "src/a.tsx", specifier)
	}
	if len(graph.Coverage) != 0 {
		t.Fatalf("this file has no unobservable construct, got coverage %+v", graph.Coverage)
	}
}

// mustEdge returns the edge for a specifier, failing the test when it is absent.
func mustEdge(t *testing.T, graph modulegraph.Graph, from, specifier string) modulegraph.Edge {
	t.Helper()
	edge, ok := edgeFor(graph, from, specifier)
	if !ok {
		t.Fatalf("no edge from %s for %q", from, specifier)
	}
	return edge
}
