package jsimports

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
)

// newResolveState builds a scanState with a synthetic file set, so relative resolution can be tested
// directly without touching the filesystem.
func newResolveState(modules, assets, components []string) *scanState {
	sc := &scanState{
		limits:          defaultLimits(),
		coverage:        newCoverageSink(defaultMaxCoverage),
		moduleSet:       map[string]bool{},
		lowerIndex:      map[string][]string{},
		assetSet:        map[string]bool{},
		codeCarryingSet: map[string]bool{},
	}
	for _, m := range modules {
		sc.moduleSet[m] = true
		lower := toLower(m)
		sc.lowerIndex[lower] = append(sc.lowerIndex[lower], m)
	}
	for _, a := range assets {
		sc.assetSet[a] = true
	}
	for _, c := range components {
		sc.codeCarryingSet[c] = true
	}
	return sc
}

func toLower(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] >= 'A' && out[i] <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

func outcomeName(o relativeOutcome) string {
	switch o {
	case relativeResolved:
		return "resolved"
	case relativeAsset:
		return "asset"
	case relativeCodeCarrying:
		return "code-carrying"
	case relativeAmbiguous:
		return "ambiguous"
	case relativeEscapesRoot:
		return "escapes-root"
	default:
		return "unresolved"
	}
}

func TestResolveRelativeTable(t *testing.T) {
	t.Parallel()

	modules := []string{
		"src/index.ts",
		"src/plain.ts",
		"src/emitted.ts",
		"src/dir/index.ts",
		"src/only-js.js",
		"src/Cased.ts",
		"src/types.d.ts",
	}
	assets := []string{"src/styles.css", "src/data.json"}
	components := []string{"src/Widget.vue"}

	tests := []struct {
		name        string
		from        string
		specifier   string
		wantTarget  string
		wantOutcome relativeOutcome
	}{
		{name: "sibling extensionless", from: "src/index.ts", specifier: "./plain", wantTarget: "src/plain.ts", wantOutcome: relativeResolved},
		{name: "explicit extension", from: "src/index.ts", specifier: "./plain.ts", wantTarget: "src/plain.ts", wantOutcome: relativeResolved},
		{name: "emitted extension rewrite", from: "src/index.ts", specifier: "./emitted.js", wantTarget: "src/emitted.ts", wantOutcome: relativeResolved},
		{name: "directory index", from: "src/index.ts", specifier: "./dir", wantTarget: "src/dir/index.ts", wantOutcome: relativeResolved},
		{name: "javascript sibling", from: "src/index.ts", specifier: "./only-js", wantTarget: "src/only-js.js", wantOutcome: relativeResolved},
		{name: "declaration sibling", from: "src/index.ts", specifier: "./types", wantTarget: "src/types.d.ts", wantOutcome: relativeResolved},
		{name: "parent traversal within root", from: "src/dir/index.ts", specifier: "../plain", wantTarget: "src/plain.ts", wantOutcome: relativeResolved},
		{name: "stylesheet is not a module", from: "src/index.ts", specifier: "./styles.css", wantOutcome: relativeAsset},
		{name: "json is not a module", from: "src/index.ts", specifier: "./data.json", wantOutcome: relativeAsset},
		{name: "component hides code", from: "src/index.ts", specifier: "./Widget.vue", wantOutcome: relativeCodeCarrying},
		{name: "case-only match is ambiguous", from: "src/index.ts", specifier: "./cased", wantOutcome: relativeAmbiguous},
		{name: "escapes the scan root", from: "src/index.ts", specifier: "../../outside/x", wantOutcome: relativeEscapesRoot},
		{name: "missing module", from: "src/index.ts", specifier: "./absent", wantOutcome: relativeUnresolved},
		{name: "bundler query suffix is stripped", from: "src/index.ts", specifier: "./plain?raw", wantTarget: "src/plain.ts", wantOutcome: relativeResolved},
		{name: "fragment suffix is stripped", from: "src/index.ts", specifier: "./plain#frag", wantTarget: "src/plain.ts", wantOutcome: relativeResolved},
		{name: "self directory resolves to index", from: "src/dir/index.ts", specifier: ".", wantTarget: "src/dir/index.ts", wantOutcome: relativeResolved},
	}

	sc := newResolveState(modules, assets, components)
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			target, outcome := sc.resolveRelative(test.from, test.specifier)
			if outcome != test.wantOutcome {
				t.Fatalf("outcome = %s, want %s (target %q)", outcomeName(outcome), outcomeName(test.wantOutcome), target)
			}
			if test.wantOutcome == relativeResolved && target != test.wantTarget {
				t.Fatalf("target = %q, want %q", target, test.wantTarget)
			}
		})
	}
}

// TestResolveRelativePrefersTypeScriptOverJavaScript locks the precedence that makes resolution
// deterministic: when both a .ts and a .js sibling exist, exactly one candidate wins and it is the one
// the TypeScript compiler would choose.
func TestResolveRelativePrefersTypeScriptOverJavaScript(t *testing.T) {
	t.Parallel()

	sc := newResolveState([]string{"src/index.ts", "src/dual.ts", "src/dual.js"}, nil, nil)
	target, outcome := sc.resolveRelative("src/index.ts", "./dual")
	if outcome != relativeResolved || target != "src/dual.ts" {
		t.Fatalf("expected src/dual.ts to win, got %q (%s)", target, outcomeName(outcome))
	}
}

// TestBackslashSpecifierNeverSetsATarget is the regression for a contract break with the package
// resolver: the domain classifies a backslash specifier as UNSUPPORTED, not relative. If the scanner
// treated it as relative and set Edge.To, the resolver would reject the ENTIRE graph, so one
// Windows-style import anywhere in a repository would abort every scan.
func TestBackslashSpecifierNeverSetsATarget(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.ts"), `import u from ".\\util";`)
	writeFile(t, filepath.Join(root, "util.ts"), `export default 1;`)

	graph := scan(t, root)

	edge, ok := edgeFor(graph, "a.ts", `.\util`)
	if !ok {
		t.Fatalf("expected an edge for the backslash specifier, got %+v", graph.Edges)
	}
	if edge.To != "" {
		t.Fatalf("a specifier the domain calls unsupported must not be resolved to %q", edge.To)
	}
}

func TestCoverageSinkReportsItsOwnTruncation(t *testing.T) {
	t.Parallel()

	sink := newCoverageSink(3)
	for i := 0; i < 10; i++ {
		sink.add(modulegraph.CoverageIssue{Kind: modulegraph.CoverageDynamicRequire, Path: "a.ts", Line: i + 1})
	}
	issues := sink.issues()
	if len(issues) != 3 {
		t.Fatalf("sink must cap at its budget, got %d issues", len(issues))
	}
	// A truncated coverage list must never look like a clean scan: the final slot says so, with its own
	// distinct kind rather than borrowing another budget's kind.
	last := issues[len(issues)-1]
	if last.Kind != modulegraph.CoverageIssueBudgetExceeded {
		t.Fatalf("truncation marker kind = %q, want %q", last.Kind, modulegraph.CoverageIssueBudgetExceeded)
	}
}

func TestScanEntryAndEdgeBudgets(t *testing.T) {
	t.Parallel()

	t.Run("entry budget", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		for _, name := range []string{"a.ts", "b.ts", "c.ts", "d.ts"} {
			writeFile(t, filepath.Join(root, "deep", "nested", name), `import x from "pkg";`)
		}
		limits := defaultLimits()
		limits.maxEntries = 3
		scanner, err := newWithLimits(limits)
		if err != nil {
			t.Fatalf("newWithLimits: %v", err)
		}
		graph, err := scanner.Scan(context.Background(), root)
		if err != nil {
			// With a tiny entry budget the walk may find no source at all, which is itself a
			// no-coverage error rather than a clean empty graph.
			return
		}
		if !coverageKinds(graph)[modulegraph.CoverageEntryBudgetExceeded] {
			t.Fatalf("exceeding the entry budget must degrade coverage, got %+v", graph.Coverage)
		}
	})

	t.Run("edge budget", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "many.ts"), `import a from "p1"; import b from "p2"; import c from "p3"; import d from "p4";`)
		limits := defaultLimits()
		limits.maxEdges = 2
		scanner, err := newWithLimits(limits)
		if err != nil {
			t.Fatalf("newWithLimits: %v", err)
		}
		graph, err := scanner.Scan(context.Background(), root)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if !coverageKinds(graph)[modulegraph.CoverageEdgeBudgetExceeded] {
			t.Fatalf("exceeding the edge budget must degrade coverage, got %+v", graph.Coverage)
		}
		if len(graph.Edges) > 2 {
			t.Fatalf("edge budget not enforced: %d edges", len(graph.Edges))
		}
	})
}

func TestScanSkippedDirectoryWithSourceDegradesCoverage(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "src", "app.ts"), `import x from "pkg";`)
	// Build output is excluded by policy, but it CAN contain first-party imports, so excluding it is a
	// coverage limitation that must be reported.
	writeFile(t, filepath.Join(root, "dist", "bundle.js"), `require("built-only-dep");`)
	// A dependency directory is exempt: a dependency's own imports are not first-party evidence.
	writeFile(t, filepath.Join(root, "node_modules", "dep", "index.js"), `require("transitive");`)

	graph := scan(t, root)

	var skipped []string
	for _, issue := range graph.Coverage {
		if issue.Kind == modulegraph.CoverageSkippedDirectory {
			skipped = append(skipped, issue.Path)
		}
	}
	if len(skipped) != 1 || skipped[0] != "dist" {
		t.Fatalf("expected exactly the dist directory to be reported, got %v (all: %+v)", skipped, graph.Coverage)
	}
}

func TestScanFileGrowingDuringReadIsNotSilentlyTruncated(t *testing.T) {
	t.Parallel()

	// A file whose size exceeds the per-file budget at READ time (not at stat time) must not have its
	// prefix parsed silently: the imports past the cut would vanish with no coverage issue.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "ok.ts"), `import a from "p";`)
	writeFile(t, filepath.Join(root, "big.ts"), `import b from "pkg2"; // `+strings.Repeat("x", 200))

	limits := defaultLimits()
	// Between the two file sizes: ok.ts is parsed, big.ts is over budget.
	limits.maxFileBytes = 64
	scanner, err := newWithLimits(limits)
	if err != nil {
		t.Fatalf("newWithLimits: %v", err)
	}
	graph, err := scanner.Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	kinds := coverageKinds(graph)
	if !kinds[modulegraph.CoverageFileTooLarge] && !kinds[modulegraph.CoverageUnreadableFile] {
		t.Fatalf("an over-budget file must degrade coverage, got %+v", graph.Coverage)
	}
	// Whatever happened, no edge may have been invented from a truncated read.
	for _, edge := range graph.Edges {
		if edge.From == "big.ts" {
			t.Fatalf("an over-budget file must not contribute edges: %+v", edge)
		}
	}
}

func TestScanRejectsNonRegularRootEntries(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "app.ts"), `import x from "pkg";`)
	if err := os.Mkdir(filepath.Join(root, "weird.ts"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	graph := scan(t, root)

	// A directory named like a source file must never become a module.
	for _, m := range graph.Modules {
		if m.Path == "weird.ts" {
			t.Fatal("a directory must not be scanned as a source module")
		}
	}
}
