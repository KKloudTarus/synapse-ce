package gobinreach

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
