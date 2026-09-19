package gobinreach

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/symbolcanon"
)

func buildEntryCallFixture(t *testing.T, ldflags string, preserveFunctions bool) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	source := t.TempDir()
	if err := os.MkdirAll(filepath.Join(source, "internal", "dependency"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod": "module example.invalid/entry-call-fixture\n\ngo 1.21\n",
		"internal/dependency/dependency.go": `package dependency

var Calls int

//go:noinline
func Reachable() { Calls++ }
`,
		"main.go": `package main

import (
    "os"

    "example.invalid/entry-call-fixture/internal/dependency"
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
func entry() { dependency.Reachable() }

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
		t.Skipf("build Linux/amd64 call fixture: %v: %s", err, output)
	}
	return out
}

func TestEntryCallAnalyzerFindsDirectPCLNTABPathAndExcludesRetainedControl(t *testing.T) {
	dir := buildEntryCallFixture(t, "", true)
	analysis, err := NewEntryCallAnalyzer().Analyze(context.Background(), dir, []string{"dependency.Reachable", "controlUnreachable"})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Entrypoints) != 1 || analysis.Entrypoints[0] != "main.main" {
		t.Fatalf("entrypoints = %v, want main.main", analysis.Entrypoints)
	}
	if len(analysis.Results) != 1 || analysis.Results[0].Symbol != "dependency.Reachable" || !analysis.Results[0].Reachable {
		t.Fatalf("results = %#v, want only reached dependency.Reachable", analysis.Results)
	}
	if got := analysis.Results[0].Path; len(got) < 3 || got[0] != "main.main" || got[1] != "main.entry" || got[len(got)-1] != "example.invalid/entry-call-fixture/internal/dependency.Reachable" {
		t.Fatalf("direct-call witness = %v, want main.main -> main.entry -> dependency.Reachable", got)
	}
}

func TestEntryCallAnalyzerSupportsStrippedPCLNTAB(t *testing.T) {
	dir := buildEntryCallFixture(t, "-s -w", true)
	analysis, err := NewEntryCallAnalyzer().Analyze(context.Background(), dir, []string{"dependency.Reachable"})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 1 || !analysis.Results[0].Reachable {
		t.Fatalf("stripped PCLNTAB result = %#v, want reached dependency", analysis.Results)
	}
}

func TestEntryCallAnalyzerUsesPCLNTABInlineCallMetadata(t *testing.T) {
	dir := buildEntryCallFixture(t, "-s -w", false)
	analysis, err := NewEntryCallAnalyzer().Analyze(context.Background(), dir, []string{"dependency.Reachable", "controlUnreachable"})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 1 || analysis.Results[0].Symbol != "dependency.Reachable" || !analysis.Results[0].Reachable {
		t.Fatalf("inlined PCLNTAB result = %#v, want only reached dependency.Reachable", analysis.Results)
	}
	if got := analysis.Results[0].Path; len(got) < 3 || got[0] != "main.main" || got[1] != "main.entry" || got[len(got)-1] != "example.invalid/entry-call-fixture/internal/dependency.Reachable" {
		t.Fatalf("inlined call witness = %v, want main.main -> main.entry -> dependency.Reachable", got)
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
	analysis, err := NewEntryCallAnalyzer().Analyze(context.Background(), dir, []string{"dependency.Reachable"})
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
	wanted := inlineWantedIndex(map[string]symbolcanon.Symbol{
		"package.Target": symbolcanon.Canonicalize(symbolcanon.Go, "package.Target"),
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
	wanted := inlineWantedIndex(map[string]symbolcanon.Symbol{
		"package.Target": symbolcanon.Canonicalize(symbolcanon.Go, "package.Target"),
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
