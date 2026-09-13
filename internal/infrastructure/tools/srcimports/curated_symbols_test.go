package srcimports

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
$local = foo(); // unqualified -> omitted
`)
	refs, err := NewPHPSymbolScanner().ScanSymbolRefs(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(refs, `Monolog\Handler\StreamHandler::write`) || !contains(refs, `Monolog\Handler\StreamHandler`) {
		t.Fatalf("php refs missing expected qualified symbols: %v", refs)
	}
	if contains(refs, `Ignored\Class::method`) || contains(refs, `Hashed\Class::method`) {
		t.Fatalf("a commented reference (// or #) must be stripped: %v", refs)
	}
}

func TestRubySymbolScanner(t *testing.T) {
	dir := writeTemp(t, "x.rb", `# Foo::Commented.method is a comment
=begin
Foo::Blocked.method should be stripped as a block comment
=end
obj = Foo::Bar.new
Foo::Bar.baz(arg)
plain_call(x)
`)
	refs, err := NewRubySymbolScanner().ScanSymbolRefs(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(refs, "Foo::Bar#baz") || !contains(refs, "Foo::Bar") {
		t.Fatalf("ruby refs missing expected qualified symbols (# member form): %v", refs)
	}
	if contains(refs, "Foo::Commented#method") || contains(refs, "Foo::Blocked#method") {
		t.Fatalf("a commented reference (# line or =begin/=end block) must be stripped: %v", refs)
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
