package srcimports

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
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
