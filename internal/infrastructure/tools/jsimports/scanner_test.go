package jsimports

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func writeFile(t *testing.T, file, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(file), err)
	}
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", file, err)
	}
}

func scan(t *testing.T, root string) modulegraph.Graph {
	t.Helper()
	graph, err := New().Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("scan %s: %v", root, err)
	}
	return graph
}

// coverageKinds indexes a graph's coverage issues by kind.
func coverageKinds(graph modulegraph.Graph) map[modulegraph.CoverageIssueKind]bool {
	out := map[modulegraph.CoverageIssueKind]bool{}
	for _, issue := range graph.Coverage {
		out[issue.Kind] = true
	}
	return out
}

// edgeFor returns the first edge with the given source and specifier.
func edgeFor(graph modulegraph.Graph, from, specifier string) (modulegraph.Edge, bool) {
	for _, edge := range graph.Edges {
		if edge.From == from && edge.Specifier == specifier {
			return edge, true
		}
	}
	return modulegraph.Edge{}, false
}

func TestScanBuildsFirstPartyGraph(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "src", "index.ts"), `
import { service } from "./service";
import lodash from "lodash";
`)
	writeFile(t, filepath.Join(root, "src", "service.ts"), `
import { helper } from "./util/helper";
export const service = helper;
`)
	writeFile(t, filepath.Join(root, "src", "util", "helper.ts"), `export const helper = 1;`)

	graph := scan(t, root)

	wantModules := []string{"src/index.ts", "src/service.ts", "src/util/helper.ts"}
	gotModules := make([]string, 0, len(graph.Modules))
	for _, m := range graph.Modules {
		gotModules = append(gotModules, m.Path)
	}
	if !reflect.DeepEqual(gotModules, wantModules) {
		t.Fatalf("modules = %v, want %v", gotModules, wantModules)
	}

	// A relative import resolves to a first-party module; an external one deliberately leaves To empty
	// because package identity belongs to the resolver, not the scanner.
	local, ok := edgeFor(graph, "src/index.ts", "./service")
	if !ok || local.To != "src/service.ts" {
		t.Fatalf("relative edge did not resolve: %+v (ok=%v)", local, ok)
	}
	external, ok := edgeFor(graph, "src/index.ts", "lodash")
	if !ok || external.To != "" {
		t.Fatalf("external edge must have an empty target: %+v (ok=%v)", external, ok)
	}

	if len(graph.Coverage) != 0 {
		t.Fatalf("a fully observable project must have no coverage issues, got %+v", graph.Coverage)
	}
	if graph.FilesScanned != 3 {
		t.Fatalf("FilesScanned = %d, want 3", graph.FilesScanned)
	}
	// index.ts is the only module with no incoming resolved edge.
	if !reflect.DeepEqual(graph.Roots, []string{"src/index.ts"}) {
		t.Fatalf("Roots = %v, want [src/index.ts]", graph.Roots)
	}
}

func TestScanRelativeResolution(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "app.ts"), `
import a from "./plain";
import b from "./dir";
import c from "./emitted.js";
import d from "./explicit.ts";
import e from "./styles.css";
import f from "./data.json";
`)
	writeFile(t, filepath.Join(root, "plain.ts"), `export default 1;`)
	writeFile(t, filepath.Join(root, "dir", "index.ts"), `export default 1;`)
	// A TypeScript ESM project writes the EMITTED extension: "./emitted.js" is authored as emitted.ts.
	writeFile(t, filepath.Join(root, "emitted.ts"), `export default 1;`)
	writeFile(t, filepath.Join(root, "explicit.ts"), `export default 1;`)
	writeFile(t, filepath.Join(root, "styles.css"), `body{}`)
	writeFile(t, filepath.Join(root, "data.json"), `{}`)

	graph := scan(t, root)

	wantTargets := map[string]string{
		"./plain":       "plain.ts",
		"./dir":         "dir/index.ts",
		"./emitted.js":  "emitted.ts",
		"./explicit.ts": "explicit.ts",
		// Asset imports carry no JavaScript, so they resolve to no module WITHOUT degrading coverage.
		"./styles.css": "",
		"./data.json":  "",
	}
	for specifier, want := range wantTargets {
		edge, ok := edgeFor(graph, "app.ts", specifier)
		if !ok {
			t.Fatalf("no edge for specifier %q", specifier)
		}
		if edge.To != want {
			t.Errorf("specifier %q resolved to %q, want %q", specifier, edge.To, want)
		}
	}
	if len(graph.Coverage) != 0 {
		t.Fatalf("asset imports must not degrade coverage, got %+v", graph.Coverage)
	}
}

// TestScanUnresolvedRelativeImportDegradesCoverageAtTheEdgeLine locks the contract the package resolver
// depends on: an unresolved relative edge must carry a coverage issue whose Line equals the edge's line.
func TestScanUnresolvedRelativeImportDegradesCoverageAtTheEdgeLine(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "app.ts"), "import a from \"lodash\";\nimport b from \"./missing\";\n")

	graph := scan(t, root)

	edge, ok := edgeFor(graph, "app.ts", "./missing")
	if !ok {
		t.Fatal("expected an edge for the unresolved relative specifier")
	}
	if edge.To != "" {
		t.Fatalf("unresolved relative edge must have no target, got %q", edge.To)
	}
	var matched bool
	for _, issue := range graph.Coverage {
		if issue.Kind == modulegraph.CoverageUnresolvedRelativeImport && issue.Path == "app.ts" && issue.Line == edge.Position.Line {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("expected an unresolved-relative-import issue at line %d, got %+v", edge.Position.Line, graph.Coverage)
	}
}

func TestScanRelativeImportEscapingRootDegradesCoverage(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "app.ts"), `import a from "../outside/secret";`)

	graph := scan(t, root)

	if !coverageKinds(graph)[modulegraph.CoverageRelativeImportEscapesRoot] {
		t.Fatalf("a root-escaping relative import must degrade coverage, got %+v", graph.Coverage)
	}
	edge, ok := edgeFor(graph, "app.ts", "../outside/secret")
	if !ok || edge.To != "" {
		t.Fatalf("root-escaping edge must exist with no target: %+v (ok=%v)", edge, ok)
	}
}

func TestScanCaseOnlyMatchIsAmbiguous(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	// "./Helper" matches helper.ts only on a case-insensitive filesystem, so the build is
	// platform-dependent: honest output is ambiguous, never a clean resolution or a clean miss.
	writeFile(t, filepath.Join(root, "app.ts"), `import h from "./Helper";`)
	writeFile(t, filepath.Join(root, "helper.ts"), `export default 1;`)

	graph := scan(t, root)

	if !coverageKinds(graph)[modulegraph.CoverageAmbiguousRelativeImport] {
		t.Fatalf("a case-only relative match must be ambiguous, got %+v", graph.Coverage)
	}
}

func TestScanUnparsedComponentImportDegradesCoverage(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	// A .vue/.svelte body contains JavaScript this scanner cannot parse, so it can hide package
	// imports — unlike a stylesheet, it must degrade coverage.
	writeFile(t, filepath.Join(root, "app.ts"), `import C from "./Widget.vue";`)
	writeFile(t, filepath.Join(root, "Widget.vue"), `<script>import axios from "axios";</script>`)

	graph := scan(t, root)

	if !coverageKinds(graph)[modulegraph.CoverageUnsupportedSyntax] {
		t.Fatalf("importing an unparsed component must degrade coverage, got %+v", graph.Coverage)
	}
	for _, m := range graph.Modules {
		if strings.HasSuffix(m.Path, ".vue") {
			t.Fatalf("a .vue file must not become a graph module: %+v", graph.Modules)
		}
	}
}

func TestScanHazardsDegradeCoverage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		want modulegraph.CoverageIssueKind
	}{
		{name: "dynamic require", src: `const m = require(name);`, want: modulegraph.CoverageDynamicRequire},
		{name: "dynamic import", src: `await import(spec);`, want: modulegraph.CoverageDynamicImport},
		{name: "eval", src: `eval("code");`, want: modulegraph.CoverageEval},
		{name: "new Function", src: `new Function("x")();`, want: modulegraph.CoverageNewFunction},
		{name: "require.context", src: `require.context("./x", true);`, want: modulegraph.CoverageRequireContext},
		{name: "import.meta.glob", src: `import.meta.glob("./x/*.ts");`, want: modulegraph.CoverageImportMetaGlob},
		{name: "createRequire", src: `const r = createRequire(import.meta.url);`, want: modulegraph.CoverageModuleCreateRequire},
		{name: "malformed source", src: `import a from "unterminated`, want: modulegraph.CoverageMalformedSource},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "app.ts"), test.src)

			graph := scan(t, root)
			if !coverageKinds(graph)[test.want] {
				t.Fatalf("expected coverage kind %q, got %+v", test.want, graph.Coverage)
			}
		})
	}
}

func TestScanSkipsDependencyAndBuildDirectories(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "src", "app.ts"), `import a from "lodash";`)
	// A dependency's own imports are not evidence that FIRST-PARTY code uses it.
	writeFile(t, filepath.Join(root, "node_modules", "lodash", "index.js"), `require("hidden-transitive");`)
	writeFile(t, filepath.Join(root, "dist", "bundle.js"), `require("built-artifact");`)
	writeFile(t, filepath.Join(root, ".git", "hook.js"), `require("git-internal");`)

	graph := scan(t, root)

	if len(graph.Modules) != 1 || graph.Modules[0].Path != "src/app.ts" {
		t.Fatalf("only first-party source may be scanned, got %+v", graph.Modules)
	}
	for _, edge := range graph.Edges {
		if edge.Specifier == "hidden-transitive" || edge.Specifier == "built-artifact" || edge.Specifier == "git-internal" {
			t.Fatalf("edge from an excluded directory leaked into the graph: %+v", edge)
		}
	}
}

func TestScanDeclarationOnlyModules(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "types.d.ts"), `import type { T } from "some-types";`)
	writeFile(t, filepath.Join(root, "app.ts"), `export const x = 1;`)

	graph := scan(t, root)

	var declaration *modulegraph.Module
	for i := range graph.Modules {
		if graph.Modules[i].Path == "types.d.ts" {
			declaration = &graph.Modules[i]
		}
	}
	if declaration == nil || !declaration.DeclarationOnly {
		t.Fatalf("types.d.ts must be flagged declaration-only, got %+v", graph.Modules)
	}
	// The edge is preserved for provenance and marked type-only; a later analyzer decides it is not
	// runtime evidence.
	edge, ok := edgeFor(graph, "types.d.ts", "some-types")
	if !ok || !edge.TypeOnly {
		t.Fatalf("declaration import must be recorded type-only: %+v (ok=%v)", edge, ok)
	}
}

func TestScanSymlinksAreNeverFollowed(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is restricted on windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.ts"), `import a from "exfiltrated";`)
	writeFile(t, filepath.Join(root, "app.ts"), `export const x = 1;`)
	if err := os.Symlink(filepath.Join(outside, "secret.ts"), filepath.Join(root, "linked.ts")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	graph := scan(t, root)

	for _, m := range graph.Modules {
		if m.Path == "linked.ts" {
			t.Fatal("a symlinked file must never be scanned as a module")
		}
	}
	for _, edge := range graph.Edges {
		if edge.Specifier == "exfiltrated" {
			t.Fatal("a symlink was followed outside the scan root")
		}
	}
	if !coverageKinds(graph)[modulegraph.CoverageSymlink] {
		t.Fatalf("an unfollowed symlink must be recorded as coverage, got %+v", graph.Coverage)
	}
}

func TestScanInvalidUTF8DegradesCoverage(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "app.ts"), `export const x = 1;`)
	if err := os.WriteFile(filepath.Join(root, "broken.ts"), []byte{0xff, 0xfe, 'i', 'm', 'p', 0x80}, 0o600); err != nil {
		t.Fatalf("write invalid utf-8: %v", err)
	}

	graph := scan(t, root)

	if !coverageKinds(graph)[modulegraph.CoverageInvalidUTF8] {
		t.Fatalf("non-UTF-8 source must degrade coverage, got %+v", graph.Coverage)
	}
}

func TestScanBudgets(t *testing.T) {
	t.Parallel()

	t.Run("file count budget", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		for _, name := range []string{"a.ts", "b.ts", "c.ts"} {
			writeFile(t, filepath.Join(root, name), `import x from "pkg";`)
		}
		limits := defaultLimits()
		limits.maxFiles = 2
		scanner, err := newWithLimits(limits)
		if err != nil {
			t.Fatalf("newWithLimits: %v", err)
		}
		graph, err := scanner.Scan(context.Background(), root)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !coverageKinds(graph)[modulegraph.CoverageFileCountBudgetExceeded] {
			t.Fatalf("exceeding the file budget must degrade coverage, got %+v", graph.Coverage)
		}
	})

	t.Run("per-file byte budget", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "small.ts"), `import x from "pkg";`)
		writeFile(t, filepath.Join(root, "big.ts"), strings.Repeat("// padding\n", 200))
		limits := defaultLimits()
		limits.maxFileBytes = 64
		scanner, err := newWithLimits(limits)
		if err != nil {
			t.Fatalf("newWithLimits: %v", err)
		}
		graph, err := scanner.Scan(context.Background(), root)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !coverageKinds(graph)[modulegraph.CoverageFileTooLarge] {
			t.Fatalf("an oversized file must degrade coverage, got %+v", graph.Coverage)
		}
	})

	t.Run("total byte budget", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		for _, name := range []string{"a.ts", "b.ts", "c.ts"} {
			writeFile(t, filepath.Join(root, name), strings.Repeat("// pad\n", 20))
		}
		limits := defaultLimits()
		limits.maxTotalBytes = 100
		scanner, err := newWithLimits(limits)
		if err != nil {
			t.Fatalf("newWithLimits: %v", err)
		}
		graph, err := scanner.Scan(context.Background(), root)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !coverageKinds(graph)[modulegraph.CoverageTotalByteBudgetExceeded] {
			t.Fatalf("exceeding the total byte budget must degrade coverage, got %+v", graph.Coverage)
		}
		// The unparsed modules are still reported as modules: they exist, their imports are unknown.
		if len(graph.Modules) != 3 {
			t.Fatalf("modules beyond the byte budget must still be listed, got %d", len(graph.Modules))
		}
	})

	t.Run("invalid limits are rejected", func(t *testing.T) {
		t.Parallel()
		limits := defaultLimits()
		limits.maxFiles = 0
		if _, err := newWithLimits(limits); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation for non-positive limits, got %v", err)
		}
	})
}

func TestScanHardNoCoverageConditions(t *testing.T) {
	t.Parallel()

	t.Run("empty root", func(t *testing.T) {
		t.Parallel()
		if _, err := New().Scan(context.Background(), "  "); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation for a blank root, got %v", err)
		}
	})

	t.Run("nil context", func(t *testing.T) {
		t.Parallel()
		//lint:ignore SA1012 deliberately asserting the nil-context guard
		if _, err := New().Scan(nil, t.TempDir()); !errors.Is(err, shared.ErrValidation) { //nolint:staticcheck
			t.Fatalf("expected ErrValidation for a nil context, got %v", err)
		}
	})

	t.Run("missing root", func(t *testing.T) {
		t.Parallel()
		if _, err := New().Scan(context.Background(), filepath.Join(t.TempDir(), "absent")); err == nil {
			t.Fatal("expected an error for a missing root")
		}
	})

	t.Run("file as root", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		file := filepath.Join(root, "app.ts")
		writeFile(t, file, `export const x = 1;`)
		if _, err := New().Scan(context.Background(), file); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("expected ErrValidation when the root is a file, got %v", err)
		}
	})

	t.Run("no javascript source", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "main.go"), `package main`)
		// No JS/TS at all is NO COVERAGE (not a JavaScript project), never an empty clean graph that a
		// later analyzer could read as "nothing is imported".
		if _, err := New().Scan(context.Background(), root); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("expected ErrNotFound when there is no JS/TS source, got %v", err)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "app.ts"), `export const x = 1;`)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := New().Scan(ctx, root); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	})
}

func TestScanIsDeterministic(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "src", "a.ts"), `import x from "pkg-a"; import "./b";`)
	writeFile(t, filepath.Join(root, "src", "b.ts"), `import y from "pkg-b"; import "./c";`)
	writeFile(t, filepath.Join(root, "src", "c.ts"), `import z from "pkg-c"; require(dynamic);`)
	writeFile(t, filepath.Join(root, "src", "z.tsx"), `import w from "pkg-d";`)

	first := scan(t, root)
	second := scan(t, root)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("repeated scans of the same tree must produce identical graphs")
	}
}

func TestScanCycleIsRepresentable(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.ts"), `import "./b"; import x from "pkg";`)
	writeFile(t, filepath.Join(root, "b.ts"), `import "./a";`)

	graph := scan(t, root)

	// Every module in a cycle has an incoming edge, so a cyclic project has no structural roots. This
	// must not crash or loop; a later analyzer handles rootless graphs.
	if len(graph.Roots) != 0 {
		t.Fatalf("a pure cycle has no structural roots, got %v", graph.Roots)
	}
	if len(graph.Edges) != 3 {
		t.Fatalf("expected 3 edges (a→b, b→a, a→pkg), got %d: %+v", len(graph.Edges), graph.Edges)
	}
}
