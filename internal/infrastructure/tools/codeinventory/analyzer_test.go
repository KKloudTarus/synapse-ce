package codeinventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func byLang(inv measure.Inventory) map[string]measure.LanguageInventory {
	m := map[string]measure.LanguageInventory{}
	for _, li := range inv.Languages {
		m[li.Language] = li
	}
	return m
}

func TestInventoryMixedTree(t *testing.T) {
	root := t.TempDir()

	// Go: 2 functions (a func + a method), 1 line comment, 1 block-comment line, 1 blank.
	write(t, root, "main.go", "package main\n"+ // code
		"\n"+ // blank
		"// entry point\n"+ // comment (line)
		"func main() { println(hello()) }\n"+ // code + func
		"/* helper */\n"+ // comment (block, single line)
		"func hello() string { return \"hi\" }\n") // code + func

	// Python: 1 line comment (#), 1 code, 1 blank.
	write(t, root, "app.py", "# a comment\n"+
		"x = 1\n"+
		"\n")

	// JavaScript: 1 block comment spanning 2 lines, 1 code.
	write(t, root, "web/app.js", "/* multi\n"+
		"line */\n"+
		"const a = 1;\n")

	// Vendored dir must be skipped entirely.
	write(t, root, "node_modules/dep/index.js", "var ignored = true;\n")

	inv, err := New().Inventory(context.Background(), root)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	m := byLang(inv)

	g, ok := m["Go"]
	if !ok {
		t.Fatalf("Go not detected; got %+v", inv.Languages)
	}
	if g.Files != 1 || g.CodeLines != 3 || g.CommentLines != 2 || g.BlankLines != 1 {
		t.Errorf("Go lines wrong: %+v", g)
	}
	if !g.FunctionsKnown || g.Functions != 2 {
		t.Errorf("Go functions wrong: want 2 known, got %d known=%v", g.Functions, g.FunctionsKnown)
	}

	py, ok := m["Python"]
	if !ok {
		t.Fatalf("Python not detected; got %+v", inv.Languages)
	}
	if py.CodeLines != 1 || py.CommentLines != 1 || py.BlankLines != 1 {
		t.Errorf("Python lines wrong: %+v", py)
	}
	if py.FunctionsKnown {
		t.Errorf("Python functions must be reported not-known (no parser yet): %+v", py)
	}

	js, ok := m["JavaScript"]
	if !ok {
		t.Fatalf("JavaScript not detected; got %+v", inv.Languages)
	}
	if js.CommentLines != 2 || js.CodeLines != 1 {
		t.Errorf("JS block-comment classification wrong: %+v", js)
	}

	// Vendored file excluded from every language tally.
	for _, li := range inv.Languages {
		if li.Language == "JavaScript" && li.Files != 1 {
			t.Errorf("node_modules must be skipped; JS files = %d", li.Files)
		}
	}

	// Totals: FunctionsKnown false because Python/JS have no parser yet.
	tot := inv.Totals()
	if tot.FunctionsKnown {
		t.Errorf("totals FunctionsKnown must be false when a language lacks a parser: %+v", tot)
	}
	if tot.Files != 3 {
		t.Errorf("total files want 3 (vendored skipped), got %d", tot.Files)
	}
}

func TestInventoryGoParseFailureDowngrades(t *testing.T) {
	// A parser-supported language (Go) with even one unparseable file must report FunctionsKnown=false
	// for that language, so a reported count is never a silent undercount.
	root := t.TempDir()
	write(t, root, "ok.go", "package a\nfunc F() {}\nfunc G() {}\n")
	write(t, root, "broken.go", "package a\nfunc H( {\n") // syntactically invalid
	inv, err := New().Inventory(context.Background(), root)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	g := byLang(inv)["Go"]
	if g.Files != 2 {
		t.Fatalf("want 2 Go files, got %d", g.Files)
	}
	if g.FunctionsKnown {
		t.Errorf("a Go file that fails to parse must downgrade FunctionsKnown to false; got %+v", g)
	}
}

// fakeProvider is an in-memory ports.ASTProvider so the wiring is testable without the sidecar binary.
type fakeProvider struct {
	counts    map[string]int
	available bool
}

func (f fakeProvider) FunctionCounts(_ context.Context, _ string) (map[string]int, bool, error) {
	return f.counts, f.available, nil
}

func TestInventoryASTProviderFillsNonGoFunctions(t *testing.T) {
	root := t.TempDir()
	write(t, root, "main.go", "package a\nfunc F() {}\n") // Go: counted in-process
	write(t, root, "app.py", "x = 1\n")                   // Python: not counted in-process

	// Provider reports Python functions + a stale Go count that must be ignored (Go is already accurate).
	prov := fakeProvider{available: true, counts: map[string]int{"Python": 7, "Go": 999, "Ruby": 3}}
	inv, err := New(WithASTProvider(prov)).Inventory(context.Background(), root)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	m := byLang(inv)
	if py := m["Python"]; !py.FunctionsKnown || py.Functions != 7 {
		t.Errorf("provider must fill Python functions: got %+v", py)
	}
	if g := m["Go"]; g.Functions != 1 {
		t.Errorf("provider must NOT override the in-process Go count: got %+v", g)
	}
	if _, ok := m["Ruby"]; ok {
		t.Errorf("provider must not invent a language the walk did not see (Ruby)")
	}
}

func TestInventoryASTProviderUnavailableIsNoop(t *testing.T) {
	root := t.TempDir()
	write(t, root, "app.py", "x = 1\n")
	prov := fakeProvider{available: false, counts: map[string]int{"Python": 7}}
	inv, err := New(WithASTProvider(prov)).Inventory(context.Background(), root)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if py := byLang(inv)["Python"]; py.FunctionsKnown {
		t.Errorf("unavailable provider must not fill counts: got %+v", py)
	}
}

func TestInventoryEmptyRoot(t *testing.T) {
	inv, err := New().Inventory(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if len(inv.Languages) != 0 {
		t.Errorf("empty tree should yield no languages, got %+v", inv.Languages)
	}
}

func TestInventoryDeterministicSort(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.go", "package a\nfunc F() {}\n")
	write(t, root, "b.py", "x = 1\n")
	i1, _ := New().Inventory(context.Background(), root)
	i2, _ := New().Inventory(context.Background(), root)
	if len(i1.Languages) != len(i2.Languages) {
		t.Fatalf("length mismatch")
	}
	for i := range i1.Languages {
		if i1.Languages[i].Language != i2.Languages[i].Language {
			t.Errorf("order not deterministic at %d: %q vs %q", i, i1.Languages[i].Language, i2.Languages[i].Language)
		}
	}
}
