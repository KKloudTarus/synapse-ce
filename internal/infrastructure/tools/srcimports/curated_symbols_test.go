package srcimports

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/symreach"
)

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPHPSymbolScanner(t *testing.T) {
	dir := writeTemp(t, "x.php", `<?php
// a comment mentioning Ignored\Class::method should be stripped
# a hash comment mentioning Hashed\Class::method should be stripped
#[Route("/x")]
$h = new \Monolog\Handler\StreamHandler("php://stderr");
\Monolog\Handler\StreamHandler::write($record);
$quoted = "StringOnly\\Class::method()";
$local = foo(); // unqualified -> omitted
`)
	refs, err := NewPHPSymbolScanner().ScanSymbolRefs(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(refs, `Monolog\Handler\StreamHandler::write`) || !contains(refs, `Monolog\Handler\StreamHandler`) {
		t.Fatalf("php refs missing expected qualified symbols: %v", refs)
	}
	if contains(refs, `Ignored\Class::method`) || contains(refs, `Hashed\Class::method`) || contains(refs, `StringOnly\Class::method`) {
		t.Fatalf("comments and strings must not become php evidence: %v", refs)
	}
}

func TestPHPSymbolScannerLocalProvenanceIsDeclarationOnly(t *testing.T) {
	dir := writeTemp(t, "main.php", `<?php
function beta(): void {}
function local_target(): void {}
// local_target();
local_target();
"local_target();";
$handler = "local_target";
$handler();
call_user_func(local_target);
new ReflectionFunction("local_target");
missing_target();
beta();
`)
	scanner := NewPHPSymbolScanner()
	refs, provenance, err := scanner.ScanSymbolRefsWithProvenance(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("unexpected qualified php refs: %v", refs)
	}
	want := []symreach.SymbolReference{
		{Symbol: "beta", ModulePath: "main.php", Line: 2},
		{Symbol: "local_target", ModulePath: "main.php", Line: 3},
	}
	if !reflect.DeepEqual(provenance, want) {
		t.Fatalf("php declaration provenance = %#v, want %#v", provenance, want)
	}
	_, again, err := scanner.ScanSymbolRefsWithProvenance(context.Background(), dir)
	if err != nil || !reflect.DeepEqual(again, provenance) {
		t.Fatalf("php provenance must be deterministic: %#v, %v", again, err)
	}
}

func TestPHPSymbolScannerRejectsDuplicateLocalDeclarations(t *testing.T) {
	dir := writeTemp(t, "main.php", "<?php\nfunction target(): void {}\ntarget();\n")
	if err := os.WriteFile(filepath.Join(dir, "other.php"), []byte("<?php\nfunction target(): void {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, provenance, err := NewPHPSymbolScanner().ScanSymbolRefsWithProvenance(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(provenance) != 0 {
		t.Fatalf("duplicate local declarations must remain unresolved: %#v", provenance)
	}
}

func TestRubySymbolScanner(t *testing.T) {
	dir := writeTemp(t, "x.rb", `# Foo::Commented.method is a comment
=begin
Foo::Blocked.method should be stripped as a block comment
=end
obj = Foo::Bar.new
Foo::Bar.baz(arg)
message = "Foo::Quoted.method"
plain_call(x)
`)
	refs, err := NewRubySymbolScanner().ScanSymbolRefs(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(refs, "Foo::Bar#baz") || !contains(refs, "Foo::Bar") {
		t.Fatalf("ruby refs missing expected qualified symbols (# member form): %v", refs)
	}
	if contains(refs, "Foo::Commented#method") || contains(refs, "Foo::Blocked#method") || contains(refs, "Foo::Quoted#method") {
		t.Fatalf("comments and strings must not become ruby evidence: %v", refs)
	}
}

func TestRubySymbolScannerLocalProvenanceIsDeclarationOnly(t *testing.T) {
	dir := writeTemp(t, "main.rb", `def beta; end
def local_target; end
# local_target
local_target
local_target()
message = "local_target"
send(:local_target)
public_send(local_target)
method(:local_target)
missing_target
beta
`)
	scanner := NewRubySymbolScanner()
	refs, provenance, err := scanner.ScanSymbolRefsWithProvenance(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("unexpected qualified ruby refs: %v", refs)
	}
	want := []symreach.SymbolReference{
		{Symbol: "beta", ModulePath: "main.rb", Line: 1},
		{Symbol: "local_target", ModulePath: "main.rb", Line: 2},
	}
	if !reflect.DeepEqual(provenance, want) {
		t.Fatalf("ruby declaration provenance = %#v, want %#v", provenance, want)
	}
	_, again, err := scanner.ScanSymbolRefsWithProvenance(context.Background(), dir)
	if err != nil || !reflect.DeepEqual(again, provenance) {
		t.Fatalf("ruby provenance must be deterministic: %#v, %v", again, err)
	}
}

func TestRubySymbolScannerRejectsDuplicateLocalDeclarations(t *testing.T) {
	dir := writeTemp(t, "main.rb", "def target; end\ntarget\n")
	if err := os.WriteFile(filepath.Join(dir, "other.rb"), []byte("def target; end\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, provenance, err := NewRubySymbolScanner().ScanSymbolRefsWithProvenance(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(provenance) != 0 {
		t.Fatalf("duplicate local declarations must remain unresolved: %#v", provenance)
	}
}

func TestDotNetSymbolScanner(t *testing.T) {
	dir := writeTemp(t, "x.cs", `// System.Commented.Member() is a comment
var c = new System.Net.WebClient();
var s = System.IO.File.ReadAllText(path);
Helper(x);
`)
	refs, err := NewDotNetSymbolScanner().ScanSymbolRefs(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(refs, "System.IO.File.ReadAllText") || !contains(refs, "System.Net.WebClient") {
		t.Fatalf("dotnet refs missing expected qualified symbols: %v", refs)
	}
	if contains(refs, "System.Commented.Member") {
		t.Fatalf("a commented reference must be stripped: %v", refs)
	}
}

func TestSourceWalkerBoundsAggregateSourceBytes(t *testing.T) {
	const body = "<?php\n// bounded source\n"
	dir := t.TempDir()
	for _, name := range []string{"a.php", "b.php", "c.php"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	walker := newSourceWalker(scanLimits{
		maxFiles:       3,
		maxFileBytes:   int64(len(body)),
		maxSourceBytes: int64(len(body) * 2),
		maxEntries:     10,
	}, []string{".php"}, nil)
	var visited []string
	out, err := walker.walk(context.Background(), dir, func(path string, _ []byte, _ *scanAccumulator) {
		visited = append(visited, path)
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a.php", "b.php"}; !reflect.DeepEqual(visited, want) {
		t.Fatalf("accepted source files = %v, want %v", visited, want)
	}
	if got, want := out.sourceBytes, int64(len(body)*2); got != want {
		t.Fatalf("accepted source bytes = %d, want %d", got, want)
	}
	if !out.reasons["aggregate source byte budget exceeded; traversal stopped"] {
		t.Fatalf("aggregate byte cap was not recorded: %#v", out.reasons)
	}
}

func TestSourceWalkerHonorsCancellationDuringFirstPass(t *testing.T) {
	const body = "<?php\nfunction target(): void {}\ntarget();\n"
	dir := writeTemp(t, "main.php", body)
	walker := newSourceWalker(scanLimits{
		maxFiles:       1,
		maxFileBytes:   int64(len(body)),
		maxSourceBytes: int64(len(body)),
		maxEntries:     2,
	}, []string{".php"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	visited := false
	_, err := walker.walk(ctx, dir, func(string, []byte, *scanAccumulator) {
		visited = true
		cancel()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during first pass error = %v, want context cancellation", err)
	}
	if !visited {
		t.Fatal("first-pass visitor did not run")
	}
}

func TestLocalSymbolScannersHonorCancelledFirstPassContext(t *testing.T) {
	dir := writeTemp(t, "main.php", "<?php\nfunction target(): void {}\ntarget();\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, scanner := range []struct {
		name string
		scan func(context.Context, string) ([]string, []symreach.SymbolReference, error)
	}{
		{name: "php", scan: NewPHPSymbolScanner().ScanSymbolRefsWithProvenance},
		{name: "ruby", scan: NewRubySymbolScanner().ScanSymbolRefsWithProvenance},
	} {
		t.Run(scanner.name, func(t *testing.T) {
			_, _, err := scanner.scan(ctx, dir)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled first pass error = %v, want context cancellation", err)
			}
		})
	}
}

func TestSourceWalkerHonorsCancellationDuringSecondPass(t *testing.T) {
	const body = "<?php\nfunction target(): void {}\ntarget();\n"
	dir := writeTemp(t, "main.php", body)
	walker := newSourceWalker(scanLimits{
		maxFiles:       1,
		maxFileBytes:   int64(len(body)),
		maxSourceBytes: int64(len(body)),
		maxEntries:     2,
	}, []string{".php"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	visited := false
	err := walker.rescan(ctx, dir, []sourceFile{{path: "main.php", bytes: int64(len(body))}}, func(string, []byte) error {
		visited = true
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during second pass error = %v, want context cancellation", err)
	}
	if !visited {
		t.Fatal("second-pass visitor did not run")
	}
}

func BenchmarkPHPSymbolScannerProvenance(b *testing.B) {
	benchmarkLocalSymbolScanner(b, ".php", "//", func(index int) string {
		return fmt.Sprintf("function target_%d(): void {}\ntarget_%d();\n", index, index)
	}, NewPHPSymbolScanner().ScanSymbolRefsWithProvenance)
}

func BenchmarkRubySymbolScannerProvenance(b *testing.B) {
	benchmarkLocalSymbolScanner(b, ".rb", "#", func(index int) string {
		return fmt.Sprintf("def target_%d; end\ntarget_%d\n", index, index)
	}, NewRubySymbolScanner().ScanSymbolRefsWithProvenance)
}

func benchmarkLocalSymbolScanner(
	b *testing.B,
	extension, comment string,
	declarations func(int) string,
	scan func(context.Context, string) ([]string, []symreach.SymbolReference, error),
) {
	b.Helper()
	dir := b.TempDir()
	padding := comment + " benchmark padding\n" + strings.Repeat(comment+" padding\n", 256)
	var sourceBytes int64
	for index := range 64 {
		body := declarations(index) + padding
		sourceBytes += int64(len(body))
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("source_%03d%s", index, extension)), []byte(body), 0o600); err != nil {
			b.Fatal(err)
		}
	}
	b.SetBytes(sourceBytes)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, _, err := scan(context.Background(), dir); err != nil {
			b.Fatal(err)
		}
	}
}
