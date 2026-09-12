package rustsymreach

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func reach(t *testing.T, src string, symbols []string) map[string]bool {
	t.Helper()
	dir := write(t, map[string]string{"src/main.rs": src, "Cargo.toml": "[package]\nname=\"x\"\n"})
	a, err := New(newScanner())
	if err != nil {
		t.Fatal(err)
	}
	an, err := a.Analyze(context.Background(), dir, symbols)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	out := map[string]bool{}
	for _, r := range an.Results {
		out[r.Symbol] = r.Reachable
	}
	return out
}

func newScanner() symbolScanner { return rustSymbolScannerAdapter{} }

func TestQualifiedReferenceIsReachable(t *testing.T) {
	src := "use time;\nfn main() {\n    let t = time::at(0);\n}\n"
	got := reach(t, src, []string{"time::at"})
	if !got["time::at"] {
		t.Errorf("a qualified time::at(...) call must be reachable, got %v", got)
	}
}

func TestTypeQualifiedMethodPathIsReachable(t *testing.T) {
	// RustSec form crate::Type::method, called in fully-qualified form.
	src := "fn f() {\n    smallvec::SmallVec::insert_many(&mut v, 0, xs);\n}\n"
	got := reach(t, src, []string{"smallvec::SmallVec::insert_many"})
	if !got["smallvec::SmallVec::insert_many"] {
		t.Errorf("a qualified SmallVec::insert_many call must be reachable, got %v", got)
	}
}

func TestUseAndCallIsReachable(t *testing.T) {
	src := "use time::at;\nfn main() { let t = at(0); }\n"
	got := reach(t, src, []string{"time::at"})
	if !got["time::at"] {
		t.Errorf("use time::at + at() must be reachable, got %v", got)
	}
}

func TestAliasedUseAndCallIsReachable(t *testing.T) {
	src := "use time::at as now;\nfn main() { let t = now(0); }\n"
	got := reach(t, src, []string{"time::at"})
	if !got["time::at"] {
		t.Errorf("use time::at as now + now() must be reachable, got %v", got)
	}
}

func TestUnreferencedIsNotReachable(t *testing.T) {
	src := "use serde;\nfn main() { let v = serde::to_string(&x); }\n"
	got := reach(t, src, []string{"time::at"})
	if got["time::at"] {
		t.Error("time::at not referenced anywhere must NOT be reachable")
	}
}

func TestBareSameNamedLocalDoesNotMatch(t *testing.T) {
	// A local function named `at` with no use/qualification of time::at must NOT match (needs the qualifier).
	src := "fn at(x: i32) -> i32 { x }\nfn main() { let t = at(0); }\n"
	got := reach(t, src, []string{"time::at"})
	if got["time::at"] {
		t.Error("a same-named local at() with no time qualifier/use must NOT be reachable (raise-only precision)")
	}
}

func TestHyphenatedCrateNormalizes(t *testing.T) {
	// RustSec may name the crate with a hyphen; Rust source uses the underscore form.
	src := "fn f() { serde_json::from_str(x); }\n"
	got := reach(t, src, []string{"serde-json::from_str"})
	if !got["serde-json::from_str"] {
		t.Errorf("a hyphenated advisory crate must match the underscore source form, got %v", got)
	}
}
