package srcimports

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCppSymbolScanner(t *testing.T) {
	dir := writeTemp(t, "main.cpp", `#include <string>
// a comment mentioning Ignored::Class::method should be stripped
/* block comment mentioning Blocked::Class::method */
namespace app {
  void run() {
    curl::easy::Curl c;                       // declaration, not a call -> omitted
    curl::easy::perform(c);                   // qualified call -> curl::easy::perform
    auto v = std::vector<int>();              // template -> std::vector
    auto h = new nginx::http::Handler();      // instantiation -> nginx::http::Handler
    boost::regex::match<char>(s);             // templated qualified call -> boost::regex::match
    local();                                  // unqualified -> omitted
    obj.method();                             // member call, no scope -> omitted
    obj->ptrmethod();                         // member call, no scope -> omitted
  }
}
`)
	refs, err := NewCppSymbolScanner().ScanSymbolRefs(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"curl::easy::perform", "nginx::http::Handler", "boost::regex::match", "std::vector"} {
		if !contains(refs, want) {
			t.Fatalf("missing expected qualified ref %q in %v", want, refs)
		}
	}
	for _, bad := range []string{"Ignored::Class::method", "Blocked::Class::method"} {
		if contains(refs, bad) {
			t.Fatalf("a commented reference must be stripped: %q in %v", bad, refs)
		}
	}
	// unqualified / member calls are omitted (raise-only tolerates the miss)
	for _, bad := range []string{"local", "method", "ptrmethod"} {
		if contains(refs, bad) {
			t.Fatalf("an unqualified/member call must be omitted: %q in %v", bad, refs)
		}
	}
}

// A build/third-party directory must be skipped (it holds dependency source, not first-party).
func TestCppSymbolScannerSkipsBuildDirs(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "build"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "build", "gen.cpp"), []byte("void f(){ vendor::internal::secret(); }"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.cpp"), []byte("void g(){ app::mod::use(); }"), 0o600); err != nil {
		t.Fatal(err)
	}
	refs, err := NewCppSymbolScanner().ScanSymbolRefs(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(refs, "app::mod::use") {
		t.Fatalf("first-party ref missing: %v", refs)
	}
	if contains(refs, "vendor::internal::secret") {
		t.Fatalf("a build/ directory must be skipped: %v", refs)
	}
}
