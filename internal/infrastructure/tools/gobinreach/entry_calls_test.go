package gobinreach

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/gobinsubject"
)

const xNetFixtureGoSum = `golang.org/x/net v0.59.0 h1:5zfYln+w5XCxwrnMMJPufRgNoXEaGxl0wo5GqPXyues=
golang.org/x/net v0.59.0/go.mod h1:2DA/G1UfVbCpQPeWTmMPGY7Cs2PkBkwu743bVX5PIVg=
golang.org/x/text v0.42.0 h1:JbOZXgfeCPU9gacVtYliJqOhD+zhrEqK4LfdpmlUZqI=
golang.org/x/text v0.42.0/go.mod h1:ojzP1Z+2QtioaF8DTtO8K5q7JWVVYwZKenzujK0Zd0E=
`

func buildEntryCallFixture(t *testing.T, ldflags string, preserveFunctions bool) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	source := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.invalid/entry-call-fixture\n\ngo 1.27\n\nrequire (\n\tgolang.org/x/net v0.59.0\n\tgolang.org/x/text v0.42.0 // indirect\n)\n",
		"go.sum": xNetFixtureGoSum,
		"main.go": `package main

import (
    "os"

    "golang.org/x/net/idna"
)

var retainedControls = []func(){controlUnreachable}

func main() {
    entry()
    if len(retainedControls) == 0 {
        panic("retain controls")
    }
    opaqueDispatch(os.Getenv("ENTRY_CALL_CONTROL"))
}

//go:noinline
func entry() { _, _ = idna.ToASCII("example.test") }

//go:noinline
func controlUnreachable() {}

//go:noinline
func controlOpaque() {}

func opaqueDispatch(name string) {
    if handler, ok := map[string]func(){"opaque": controlOpaque}[name]; ok {
        handler()
    }
}
`,
	}
	if !preserveFunctions {
		for name, contents := range files {
			files[name] = strings.ReplaceAll(contents, "//go:noinline\n", "")
		}
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(source, filepath.FromSlash(name)), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	args := []string{"build", "-o", filepath.Join(out, "app")}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, ".")
	command := exec.Command("go", args...)
	command.Dir = source
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Linux/amd64 call fixture: %v: %s", err, output)
	}
	return out
}

func TestEntryCallAnalyzerFindsDirectPCLNTABPathAndExcludesRetainedControl(t *testing.T) {
	dir := buildEntryCallFixture(t, "", true)
	analysis, err := NewEntryCallAnalyzer().Analyze(context.Background(), dir, []string{
		encodedGoSubject(t, "pkg:golang/golang.org/x/net@v0.59.0", "golang.org/x/net/idna.ToASCII"),
		encodedGoSubject(t, "pkg:golang/golang.org/x/net@v0.59.0", "golang.org/x/net/idna.controlUnreachable"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Entrypoints) != 1 || analysis.Entrypoints[0] != "main.main" {
		t.Fatalf("entrypoints = %v, want main.main", analysis.Entrypoints)
	}
	if len(analysis.Results) != 1 || analysis.Results[0].Symbol != encodedGoSubject(t, "pkg:golang/golang.org/x/net@v0.59.0", "golang.org/x/net/idna.ToASCII") || !analysis.Results[0].Reachable {
		t.Fatalf("results = %#v, want only reached full dependency symbol", analysis.Results)
	}
	if got := analysis.Results[0].Path; len(got) < 3 || got[0] != "main.main" || got[1] != "main.entry" || got[len(got)-1] != "golang.org/x/net/idna.ToASCII" {
		t.Fatalf("direct-call witness = %v, want main.main -> main.entry -> idna.ToASCII", got)
	}
}

func TestEntryCallAnalyzerSupportsStrippedPCLNTAB(t *testing.T) {
	dir := buildEntryCallFixture(t, "-s -w", true)
	analysis, err := NewEntryCallAnalyzer().Analyze(context.Background(), dir, []string{encodedGoSubject(t, "pkg:golang/golang.org/x/net@v0.59.0", "golang.org/x/net/idna.ToASCII")})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 1 || !analysis.Results[0].Reachable {
		t.Fatalf("stripped PCLNTAB result = %#v, want reached dependency", analysis.Results)
	}
}

func TestEntryCallAnalyzerUsesPCLNTABInlineCallMetadata(t *testing.T) {
	dir := buildEntryCallFixture(t, "-s -w", false)
	analysis, err := NewEntryCallAnalyzer().Analyze(context.Background(), dir, []string{
		encodedGoSubject(t, "pkg:golang/golang.org/x/net@v0.59.0", "golang.org/x/net/idna.ToASCII"),
		encodedGoSubject(t, "pkg:golang/golang.org/x/net@v0.59.0", "golang.org/x/net/idna.controlUnreachable"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 1 || analysis.Results[0].Symbol != encodedGoSubject(t, "pkg:golang/golang.org/x/net@v0.59.0", "golang.org/x/net/idna.ToASCII") || !analysis.Results[0].Reachable {
		t.Fatalf("inlined PCLNTAB result = %#v, want only reached full dependency symbol", analysis.Results)
	}
	if got := analysis.Results[0].Path; len(got) < 3 || got[0] != "main.main" || got[1] != "main.entry" || got[len(got)-1] != "golang.org/x/net/idna.ToASCII" {
		t.Fatalf("inlined call witness = %v, want main.main -> main.entry -> idna.ToASCII", got)
	}
}

func TestEntryCallAnalyzerMalformedAndUnsupportedBinariesProvideNoCoverage(t *testing.T) {
	dir := t.TempDir()
	for name, contents := range map[string][]byte{
		"malformed-elf":  append([]byte("\x7fELF"), make([]byte, 4096)...),
		"unsupported-pe": []byte("MZ not a Linux amd64 ELF"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), contents, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	analysis, err := NewEntryCallAnalyzer().Analyze(context.Background(), dir, []string{
		encodedGoSubject(t, "pkg:golang/example.invalid/library@v1.0.0", "example.invalid/library/pkg.Target"),
	})
	if err != nil {
		t.Fatalf("unsupported binary analysis must not error: %v", err)
	}
	if len(analysis.Results) != 0 || len(analysis.Entrypoints) != 0 {
		t.Fatalf("unsupported binaries must provide no coverage, got %#v", analysis)
	}
}

func TestEntryCallAnalyzerCancellationPropagates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	analysis, err := NewEntryCallAnalyzer().Analyze(ctx, t.TempDir(), []string{"package.Target"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("entry-call cancellation error = %v, want context.Canceled", err)
	}
	if analysis != nil {
		t.Fatalf("canceled entry-call analysis = %#v, want nil", analysis)
	}
}

func TestGoSymbolKeyPreservesImportPathAndNormalizesOnlyGenericAndPointerReceiver(t *testing.T) {
	for name, test := range map[string]struct {
		raw  string
		want goSymbolKey
	}{
		"generic pointer receiver": {
			raw:  "example.com/acme/v2/pkg.(*Server[example.com/acme/v2/pkg.Value]).Handle",
			want: "example.com/acme/v2/pkg.Server.Handle",
		},
		"generic function": {
			raw:  "example.com/acme/v2/pkg.Transform[go.shape.int]",
			want: "example.com/acme/v2/pkg.Transform",
		},
		"semantic import version remains": {
			raw:  "example.com/acme/v2/pkg.Call",
			want: "example.com/acme/v2/pkg.Call",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, valid := goSymbolKeyFor(test.raw)
			if !valid || got != test.want {
				t.Fatalf("goSymbolKeyFor(%q) = (%q, %t), want (%q, true)", test.raw, got, valid, test.want)
			}
		})
	}
	for name, test := range map[string]struct {
		left  string
		right string
	}{
		"dot slash boundary": {
			left:  "example.com/a/b.Func",
			right: "example.com/a.b.Func",
		},
		"semantic import version": {
			left:  "example.com/acme/v2/pkg.Call",
			right: "example.com/acme/v3/pkg.Call",
		},
		"vendor prefix": {
			left:  "example.com/acme/vendor/pkg.Call",
			right: "example.com/acme/pkg.Call",
		},
	} {
		t.Run(name, func(t *testing.T) {
			left, leftValid := goSymbolKeyFor(test.left)
			right, rightValid := goSymbolKeyFor(test.right)
			if !leftValid || !rightValid || left == right {
				t.Fatalf("unrelated Go symbols collapsed: %q => %q, %q => %q", test.left, left, test.right, right)
			}
		})
	}
}

func TestDirectCallMatchingRejectsSameTailFromDifferentModule(t *testing.T) {
	const (
		textAddress = uint64(0x400000)
		targetAddr  = textAddress + 5
	)
	functions := map[uint64]pclntabFunction{
		textAddress: {name: "main.main", entry: textAddress, end: targetAddr},
		targetAddr:  {name: "example.invalid/upstream/dependency.GenericReach[go.shape.int]", entry: targetAddr, end: targetAddr + 1},
	}
	wanted := map[string]goSymbolKey{
		"example.invalid/upstream/dependency.GenericReach":           mustGoSymbolKey(t, "example.invalid/upstream/dependency.GenericReach"),
		"github.com/advisory/module/dependency.GenericReach":         mustGoSymbolKey(t, "github.com/advisory/module/dependency.GenericReach"),
		"example.invalid/upstream/dependency/v2.GenericReach":        mustGoSymbolKey(t, "example.invalid/upstream/dependency/v2.GenericReach"),
		"example.invalid/upstream/dependency.GenericReach[go.shape]": mustGoSymbolKey(t, "example.invalid/upstream/dependency.GenericReach[go.shape.int]"),
	}
	paths, complete := walkDirectCalls(context.Background(), []byte{0xe8, 0, 0, 0, 0, 0xc3}, textAddress, functions, functions[textAddress], inlineWantedIndex(wanted))
	if !complete {
		t.Fatal("direct-call fixture must decode completely")
	}
	if len(paths) != 2 {
		t.Fatalf("direct-call matches = %#v, want only exact generic-key aliases", paths)
	}
	for subject := range wanted {
		_, matched := paths[subject]
		if strings.Contains(subject, "advisory/") || strings.Contains(subject, "/v2.") {
			if matched {
				t.Fatalf("unrelated direct subject %q matched %#v", subject, paths[subject])
			}
			continue
		}
		if !matched {
			t.Fatalf("exact direct subject %q did not match", subject)
		}
	}
}

func TestInlineCallMatchingRejectsSameTailFromDifferentModule(t *testing.T) {
	calls := []inlineCall{{name: "example.invalid/upstream/dependency.GenericReach[go.shape.int]", parent: -1}}
	wanted := inlineWantedIndex(map[string]goSymbolKey{
		"example.invalid/upstream/dependency.GenericReach":    mustGoSymbolKey(t, "example.invalid/upstream/dependency.GenericReach"),
		"github.com/advisory/module/dependency.GenericReach":  mustGoSymbolKey(t, "github.com/advisory/module/dependency.GenericReach"),
		"example.invalid/upstream/dependency/v2.GenericReach": mustGoSymbolKey(t, "example.invalid/upstream/dependency/v2.GenericReach"),
	})
	matches, valid := inlineCallMatches(context.Background(), calls, wanted)
	if !valid {
		t.Fatal("valid inline metadata was rejected")
	}
	if len(matches) != 1 || matches["example.invalid/upstream/dependency.GenericReach"] != 0 {
		t.Fatalf("inline matches = %#v, want only exact module-path generic match", matches)
	}
}

func TestBoundSubjectsForBinaryRequiresExactLongestVersionedOwner(t *testing.T) {
	queries := map[string]wantedSubject{}
	add := func(purl, symbol string) string {
		subject := encodedGoSubject(t, purl, symbol)
		parsed, raw, ok := gobinsubject.Parse(subject)
		if !ok {
			t.Fatal("test subject did not parse")
		}
		queries[subject] = wantedSubject{purl: parsed, symbol: mustGoSymbolKey(t, raw)}
		return subject
	}
	nested := add("pkg:golang/example.invalid/library/nested@v0.2.0", "example.invalid/library/nested/pkg.Call")
	parent := add("pkg:golang/example.invalid/library@v1.0.0", "example.invalid/library/nested/pkg.Call")
	replaced := add("pkg:golang/example.invalid/replaced@v1.0.0", "example.invalid/replaced/pkg.Call")
	info := &debug.BuildInfo{Main: debug.Module{Path: "example.invalid/app", Version: "(devel)"}, Deps: []*debug.Module{
		{Path: "example.invalid/library", Version: "v1.0.0"},
		{Path: "example.invalid/library/nested", Version: "v0.2.0"},
		{Path: "example.invalid/replaced", Version: "v1.0.0", Replace: &debug.Module{Path: "example.invalid/local", Version: "v1.0.0"}},
	}}
	bound := boundSubjectsForBinary(info, queries)
	if len(bound) != 1 || bound[nested] == "" || bound[parent] != "" || bound[replaced] != "" {
		t.Fatalf("bound subjects = %#v, want only exact longest non-replaced owner", bound)
	}
	if got := boundSubjectsForBinary(nil, queries); got != nil {
		t.Fatalf("missing build info bound subjects = %#v, want nil", got)
	}
}

func TestBoundSubjectsForBinaryRejectsConflictingAndRootPackageOwners(t *testing.T) {
	queries := map[string]wantedSubject{}
	add := func(purl, symbol string) string {
		subject := encodedGoSubject(t, purl, symbol)
		parsed, raw, ok := gobinsubject.Parse(subject)
		if !ok {
			t.Fatal("test subject did not parse")
		}
		queries[subject] = wantedSubject{purl: parsed, symbol: mustGoSymbolKey(t, raw)}
		return subject
	}
	conflicted := add("pkg:golang/example.invalid/conflict@v1.0.0", "example.invalid/conflict/pkg.Call")
	root := add("pkg:golang/example.invalid/parent@v1.0.0", "example.invalid/parent/nested.Call")
	valid := add("pkg:golang/example.invalid/valid@v1.0.0", "example.invalid/valid/pkg.Call")
	info := &debug.BuildInfo{Deps: []*debug.Module{
		{Path: "example.invalid/conflict", Version: "v1.0.0"},
		{Path: "example.invalid/conflict", Version: "v2.0.0"},
		{Path: "example.invalid/parent", Version: "v1.0.0"},
		{Path: "example.invalid/parent/nested", Version: "v1.0.0"},
		{Path: "example.invalid/valid", Version: "v1.0.0"},
	}}
	bound := boundSubjectsForBinary(info, queries)
	if len(bound) != 1 || bound[valid] == "" || bound[conflicted] != "" || bound[root] != "" {
		t.Fatalf("bound subjects = %#v, want only unambiguous subpackage owner", bound)
	}
}

func TestBoundSubjectsForBinaryRejectsRootFunctionMethodAmbiguity(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		parent string
		decoy  string
		symbol string
	}{
		{
			name:   "subpackage method",
			parent: "example.invalid/parent",
			decoy:  "example.invalid/parent/pkg.target",
			symbol: "example.invalid/parent/pkg.target.Method",
		},
		{
			name:   "root method",
			parent: "example.invalid/library",
			decoy:  "example.invalid/library.target",
			symbol: "example.invalid/library.target.Method",
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			subject := encodedGoSubject(t, "pkg:golang/"+scenario.decoy+"@v1.0.0", scenario.symbol)
			purl, raw, ok := gobinsubject.Parse(subject)
			if !ok {
				t.Fatal("test subject did not parse")
			}
			info := &debug.BuildInfo{Deps: []*debug.Module{
				{Path: scenario.parent, Version: "v1.0.0"},
				{Path: scenario.decoy, Version: "v1.0.0"},
			}}
			bound := boundSubjectsForBinary(info, map[string]wantedSubject{
				subject: {purl: purl, symbol: mustGoSymbolKey(t, raw)},
			})
			if len(bound) != 0 {
				t.Fatalf("ambiguous method matched decoy module: %#v", bound)
			}
		})
	}
}

func TestEntryCallAnalyzerSubjectBudgetProvidesNoCoverage(t *testing.T) {
	subjects := make([]string, maxEntryCallSubjects+1)
	for index := range subjects {
		subjects[index] = "pkg:golang/example.invalid/library@v1.0.0#example.invalid/library/pkg.Target"
	}
	analysis, err := NewEntryCallAnalyzer().Analyze(context.Background(), t.TempDir(), subjects)
	if err != nil || len(analysis.Results) != 0 || len(analysis.Entrypoints) != 0 {
		t.Fatalf("over-budget subject result = %#v, %v; want no coverage", analysis, err)
	}
}

func TestGoModuleOwnershipRequiresPackageBoundary(t *testing.T) {
	if !goModuleOwnsSymbol("example.invalid/library", "example.invalid/library/pkg.Target") ||
		!goModuleOwnsSymbol("example.invalid/library", "example.invalid/library.Root") {
		t.Fatal("subpackage or root free function was not owned")
	}
	if goModuleOwnsSymbol("example.invalid/library", "example.invalid/library.Target.Method") ||
		goModuleOwnsSymbol("example.invalid/library", "example.invalid/library.v2/pkg.Target") {
		t.Fatal("root method or dotted sibling symbol was incorrectly owned")
	}
}

func mustGoSymbolKey(t *testing.T, raw string) goSymbolKey {
	t.Helper()
	key, valid := goSymbolKeyFor(raw)
	if !valid {
		t.Fatalf("goSymbolKeyFor(%q) rejected test symbol", raw)
	}
	return key
}

func encodedGoSubject(t *testing.T, purl, symbol string) string {
	t.Helper()
	encoded, ok := gobinsubject.Encode(purl, symbol)
	if !ok {
		t.Fatalf("gobinsubject.Encode(%q, %q) rejected test subject", purl, symbol)
	}
	return encoded
}

func TestDirectCallTargetsRejectUnsupportedVectorPrefixes(t *testing.T) {
	const address = uint64(0x400000)
	for name, code := range map[string][]byte{
		"VEX3": {0xc4, 0xe2, 0x79, 0x90, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3},
		"VEX2": {0xc5, 0xf8, 0x90, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3},
		"EVEX": {0x62, 0xf1, 0x7c, 0x48, 0x90, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3},
	} {
		t.Run(name, func(t *testing.T) {
			targets, complete := directCallTargets(context.Background(), code, address)
			if complete || len(targets) != 0 {
				t.Fatalf("vector-prefixed encoding yielded targets=%#v complete=%t, want no decoded call", targets, complete)
			}
		})
	}
}

func TestDirectCallTargetsContinuesPastSupportedExtendedEncoding(t *testing.T) {
	const address = uint64(0x400000)
	code := []byte{0x0f, 0x3a, 0x0f, 0xc0, 0xe8, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3}
	targets, complete := directCallTargets(context.Background(), code, address)
	if !complete {
		t.Fatal("supported 0F 3A encoding left decoding incomplete")
	}
	if len(targets) != 1 || targets[0] != address+10 {
		t.Fatalf("direct targets = %#v, want [%#x]", targets, address+10)
	}
}

func TestPCLNTABInlinePathsHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	metadata, valid := pclntabInlinePaths(ctx, nil, 0, nil, nil)
	if valid || metadata != nil {
		t.Fatalf("canceled PCLNTAB parse = (%#v, %t), want no result", metadata, valid)
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("context error = %v, want context.Canceled", ctx.Err())
	}
}

func TestDirectCallTargetsHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	targets, complete := directCallTargets(ctx, []byte{0x90, 0xc3}, 0x400000)
	if complete || len(targets) != 0 {
		t.Fatalf("canceled instruction decode = (%#v, %t), want no result", targets, complete)
	}
}

func TestInlineCallMatchingScalesLinearly(t *testing.T) {
	wanted := inlineWantedIndex(map[string]goSymbolKey{
		"package.Target": "package.Target",
	})
	small := inlineCallLadder(256, "package.Target")
	large := inlineCallLadder(512, "package.Target")
	smallAllocs := testing.AllocsPerRun(5, func() {
		matches, valid := inlineCallMatches(context.Background(), small, wanted)
		if !valid || matches["package.Target"] != len(small)-1 {
			t.Fatal("small inline call ladder did not find its target")
		}
	})
	largeAllocs := testing.AllocsPerRun(5, func() {
		matches, valid := inlineCallMatches(context.Background(), large, wanted)
		if !valid || matches["package.Target"] != len(large)-1 {
			t.Fatal("large inline call ladder did not find its target")
		}
	})
	if largeAllocs > smallAllocs*2.5+16 {
		t.Fatalf("inline-match allocations grew faster than linearly: 256 calls=%0.f, 512 calls=%0.f", smallAllocs, largeAllocs)
	}
}

func TestInlineCallParentValidationRejectsMalformedGraphs(t *testing.T) {
	for name, calls := range map[string][]inlineCall{
		"cycle":        {{name: "package.First", parent: 1}, {name: "package.Second", parent: 0}},
		"out-of-range": {{name: "package.First", parent: 1}},
	} {
		t.Run(name, func(t *testing.T) {
			if validInlineCallParents(context.Background(), calls) {
				t.Fatal("malformed inline parents were accepted")
			}
		})
	}
}

func TestInlineCallPathReconstructsTheMatchedAncestorChain(t *testing.T) {
	calls := inlineCallLadder(3, "package.Target")
	path, valid := inlineCallPath(context.Background(), calls, 2)
	if !valid {
		t.Fatal("valid inline ancestor chain was rejected")
	}
	want := []string{"package.Frame", "package.Frame", "package.Target"}
	if len(path) != len(want) {
		t.Fatalf("inline path = %v, want %v", path, want)
	}
	for index := range want {
		if path[index] != want[index] {
			t.Fatalf("inline path = %v, want %v", path, want)
		}
	}
}

func BenchmarkInlineCallMatches(b *testing.B) {
	wanted := inlineWantedIndex(map[string]goSymbolKey{
		"package.Target": "package.Target",
	})
	for _, size := range []int{256, 4096} {
		b.Run(fmt.Sprintf("calls=%d", size), func(b *testing.B) {
			calls := inlineCallLadder(size, "package.Target")
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				matches, valid := inlineCallMatches(context.Background(), calls, wanted)
				if !valid || matches["package.Target"] != len(calls)-1 {
					b.Fatal("inline call ladder did not find its target")
				}
			}
		})
	}
}

func BenchmarkInlineParentIndex(b *testing.B) {
	for _, size := range []int{256, 4096} {
		b.Run(fmt.Sprintf("ranges=%d", size), func(b *testing.B) {
			ranges := make([]pcDataRange, size)
			for index := range ranges {
				ranges[index] = pcDataRange{end: uint64(index + 1), value: index % 17}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				parent, valid := inlineParentIndex(ranges, uint64(size-1), 17)
				if !valid || parent != (size-1)%17 {
					b.Fatal("inline parent index lookup was invalid")
				}
			}
		})
	}
}

func inlineCallLadder(count int, target string) []inlineCall {
	calls := make([]inlineCall, count)
	for index := range calls {
		calls[index] = inlineCall{name: "package.Frame", parent: index - 1}
	}
	calls[len(calls)-1].name = target
	return calls
}
