package gobinreach

import (
	"context"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func buildLinuxAMD64GoFixture(t *testing.T, files map[string]string, args ...string) string {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("fixture exercises Linux/amd64 Go binary metadata")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	source := t.TempDir()
	for name, contents := range files {
		path := filepath.Join(source, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	command := exec.Command("go", append([]string{"build", "-o", filepath.Join(out, "artifact")}, args...)...)
	command.Dir = source
	command.Env = append(os.Environ(), "CGO_ENABLED=1", "GOOS=linux", "GOARCH=amd64")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Linux/amd64 fixture: %v: %s", err, output)
	}
	return out
}

func TestEntryCallAnalyzerMatchesVendoredGenericFunctionByExactModulePath(t *testing.T) {
	dir := buildLinuxAMD64GoFixture(t, map[string]string{
		"go.mod":             "module example.invalid/generic-fixture\n\ngo 1.27\n\nrequire example.invalid/upstream v0.0.0\n",
		"vendor/modules.txt": "# example.invalid/upstream v0.0.0\n## explicit; go 1.27\nexample.invalid/upstream/dependency\n",
		"vendor/example.invalid/upstream/dependency/dependency.go": `package dependency

//go:noinline
func GenericReach[T any](value T) { println(value) }
`,
		"main.go": `package main

import "example.invalid/upstream/dependency"

//go:noinline
func entry() { dependency.GenericReach(7) }

func main() { entry() }
`,
	})

	analysis, err := NewEntryCallAnalyzer().Analyze(context.Background(), dir, []string{
		encodedGoSubject(t, "pkg:golang/example.invalid/upstream@v0.0.0", "example.invalid/upstream/dependency.GenericReach"),
		encodedGoSubject(t, "pkg:golang/github.com/advisory/module@v1.2.3", "github.com/advisory/module/dependency.GenericReach"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 1 || !analysis.Results[0].Reachable ||
		analysis.Results[0].Symbol != encodedGoSubject(t, "pkg:golang/example.invalid/upstream@v0.0.0", "example.invalid/upstream/dependency.GenericReach") {
		t.Fatalf("vendored generic module-path result = %#v, want only the exact reachable dependency symbol", analysis.Results)
	}
	if got := analysis.Results[0].Path; len(got) < 3 || got[0] != "main.main" ||
		!strings.Contains(got[len(got)-1], "dependency.GenericReach[") {
		t.Fatalf("generic witness = %v, want main.main path ending at instantiated dependency.GenericReach", got)
	}
}

func TestEntryCallAnalyzerMatchesVersionedModuleRootFunction(t *testing.T) {
	dir := buildLinuxAMD64GoFixture(t, map[string]string{
		"go.mod":             "module example.invalid/app\n\ngo 1.27\n\nrequire example.invalid/library v1.0.0\n",
		"vendor/modules.txt": "# example.invalid/library v1.0.0\n## explicit; go 1.27\nexample.invalid/library\n",
		"vendor/example.invalid/library/library.go": `package library

//go:noinline
func RootReach() { println("root") }
`,
		"main.go": `package main

import "example.invalid/library"

func main() { library.RootReach() }
`,
	})
	correct := encodedGoSubject(t, "pkg:golang/example.invalid/library@v1.0.0", "example.invalid/library.RootReach")
	wrongVersion := encodedGoSubject(t, "pkg:golang/example.invalid/library@v1.1.0", "example.invalid/library.RootReach")
	analysis, err := NewEntryCallAnalyzer().Analyze(context.Background(), dir, []string{correct, wrongVersion})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 1 || analysis.Results[0].Symbol != correct || !analysis.Results[0].Reachable {
		t.Fatalf("root function result = %#v, want only exact module version", analysis.Results)
	}
}

func TestSymbolScannerFindsGenericInstantiationInStrippedBinary(t *testing.T) {
	dir := buildLinuxAMD64GoFixture(t, map[string]string{
		"go.mod": "module example.invalid/generic-symbol-fixture\n\ngo 1.27\n",
		"main.go": `package main

//go:noinline
func GenericReach[T any](value T) { println(value) }

func main() { GenericReach(7) }
`,
	}, "-ldflags=-s -w", ".")
	refs, err := New().ScanSymbolRefs(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		if strings.HasPrefix(ref, "main.GenericReach[") {
			return
		}
	}
	t.Fatalf("stripped generic binary symbols = %v, want instantiated main.GenericReach", firstN(refs, 16))
}

func TestEntryCallAnalyzerSharedObjectProvidesNoEntrypointProof(t *testing.T) {
	dir := buildLinuxAMD64GoFixture(t, map[string]string{
		"go.mod": "module example.invalid/shared-fixture\n\ngo 1.27\n",
		"main.go": `package main

import "C"

//export SharedReachable
func SharedReachable() {}

func main() {}
`,
	}, "-buildmode=c-shared", ".")
	assertNoProcessImage(t, filepath.Join(dir, "artifact"))
}

func TestEntryCallAnalyzerPluginProvidesNoEntrypointProof(t *testing.T) {
	dir := buildLinuxAMD64GoFixture(t, map[string]string{
		"go.mod": "module example.invalid/plugin-fixture\n\ngo 1.27\n",
		"main.go": `package main

//go:noinline
func PluginReachable() {}
`,
	}, "-buildmode=plugin", ".")
	assertNoProcessImage(t, filepath.Join(dir, "artifact"))
}

func TestEntryCallAnalyzerSupportsPIEProcessImage(t *testing.T) {
	dir := buildLinuxAMD64GoFixture(t, map[string]string{
		"go.mod": "module example.invalid/pie-fixture\n\ngo 1.27\n\nrequire (\n\tgolang.org/x/net v0.59.0\n\tgolang.org/x/text v0.42.0 // indirect\n)\n",
		"go.sum": xNetFixtureGoSum,
		"main.go": `package main

import "golang.org/x/net/idna"

//go:noinline
func entry() { _, _ = idna.ToASCII("example.test") }

func main() { entry() }
`,
	}, "-buildmode=pie", ".")
	analysis, err := NewEntryCallAnalyzer().Analyze(context.Background(), dir, []string{encodedGoSubject(t, "pkg:golang/golang.org/x/net@v0.59.0", "golang.org/x/net/idna.ToASCII")})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 1 || !analysis.Results[0].Reachable {
		t.Fatalf("PIE process-image result = %#v, want reachable dependency", analysis.Results)
	}
}

func TestSymbolScannerNoPCLNTABELFProvidesNoCoverage(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires a Linux system ELF without Go metadata")
	}
	path, err := exec.LookPath("true")
	if err != nil {
		t.Skip("system true unavailable")
	}
	dir := t.TempDir()
	artifact := filepath.Join(dir, "no-pclntab")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("read system true: %v", err)
	}
	if err := os.WriteFile(artifact, contents, 0o755); err != nil {
		t.Fatal(err)
	}
	refs, err := New().ScanSymbolRefs(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("ELF without .gopclntab returned symbols = %v, want no coverage", firstN(refs, 8))
	}
	analysis, err := NewEntryCallAnalyzer().Analyze(context.Background(), dir, []string{encodedGoSubject(t, "pkg:golang/example.invalid/library@v1.0.0", "example.invalid/library/pkg.Target")})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 0 || len(analysis.Entrypoints) != 0 {
		t.Fatalf("ELF without .gopclntab established reachability = %#v", analysis)
	}
}

func TestEntryCallAnalyzerBindsEachPositiveToItsOwnBinaryVersion(t *testing.T) {
	workspace := t.TempDir()
	build := func(version, name, main string) {
		dir := buildLinuxAMD64GoFixture(t, map[string]string{
			"go.mod":             "module example.invalid/app\n\ngo 1.27\n\nrequire example.invalid/library " + version + "\n",
			"vendor/modules.txt": "# example.invalid/library " + version + "\n## explicit; go 1.27\nexample.invalid/library/pkg\n",
			"vendor/example.invalid/library/pkg/pkg.go": `package pkg

func Target() { println("target") }
`,
			"main.go": main,
		})
		contents, err := os.ReadFile(filepath.Join(dir, "artifact"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(workspace, name), contents, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	build("v1.0.0", "v1", `package main
import _ "example.invalid/library/pkg"
func main() {}`)
	// The v2 call deliberately has no noinline directive, so the optimized binary exercises inline metadata.
	build("v1.1.0", "v2", `package main
import "example.invalid/library/pkg"
func main() { pkg.Target() }`)
	v1 := encodedGoSubject(t, "pkg:golang/example.invalid/library@v1.0.0", "example.invalid/library/pkg.Target")
	v2 := encodedGoSubject(t, "pkg:golang/example.invalid/library@v1.1.0", "example.invalid/library/pkg.Target")
	analysis, err := NewEntryCallAnalyzer().Analyze(context.Background(), workspace, []string{v1, v2})
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Results) != 1 || analysis.Results[0].Symbol != v2 || !analysis.Results[0].Reachable {
		t.Fatalf("mixed-version results = %#v, want only v2 positive from its own binary", analysis.Results)
	}
	if got := analysis.Results[0].Path; len(got) < 2 || got[len(got)-1] != "example.invalid/library/pkg.Target" {
		t.Fatalf("mixed-version v2 witness = %v, want inlined Target path", got)
	}
}

func assertNoProcessImage(t *testing.T, path string) {
	t.Helper()
	file, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if file.Type != elf.ET_DYN {
		t.Fatalf("shared fixture type = %v, want ET_DYN", file.Type)
	}
	if linuxAMD64ProcessImage(file) {
		t.Fatalf("shared fixture %q was accepted as process image", path)
	}
}
