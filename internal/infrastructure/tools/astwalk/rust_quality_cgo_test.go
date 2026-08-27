//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func rustFixtureFindings(t *testing.T, source string) []QualityFinding {
	t.Helper()
	root := parseRoot(context.Background(), specs["Rust"], []byte(source))
	if root == nil || root.HasError() {
		t.Fatalf("Rust fixture is not syntactically complete: %q", source)
	}
	findings, _ := rustFindingsLimit(root, []byte(source), "fixture.rs", 100)
	return findings
}

func rustHasRule(findings []QualityFinding, wantKey string) bool {
	for _, f := range findings {
		if f.Rule == wantKey {
			return true
		}
	}
	return false
}

func TestRustGrammarContractReachability(t *testing.T) {
	const source = `
pub struct Buffer;
impl Buffer {
    pub fn new() -> Self { Buffer }
}
fn main() {
    let mut x = 42;
    if x > 0 {
        x += 1;
    }
}
`
	root := parseRoot(context.Background(), specs["Rust"], []byte(source))
	if root == nil || root.HasError() {
		t.Fatal("Rust grammar did not parse contract fixture")
	}
	seen := map[string]bool{}
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		seen[n.Type()] = true
		for i := 0; i < int(n.ChildCount()); i++ {
			stack = append(stack, n.Child(i))
		}
	}
	for _, want := range []string{"struct_item", "impl_item", "function_item", "let_declaration", "if_expression", "block"} {
		if !seen[want] {
			t.Errorf("bundled Rust grammar lacks reachable %q: %v", want, seen)
		}
	}
}

func TestRustRuntimeKeyRegistryCompleteness(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default(): %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("cat.List(): %v", err)
	}
	rustCount := 0
	for _, r := range rules {
		if r.Language == "Rust" && r.Detection == rule.DetectionAST {
			rustCount++
			shortKey := strings.TrimPrefix(string(r.Key), "rust:")
			if _, ok := rustRuntimeRules[shortKey]; !ok {
				t.Errorf("Rust runtime registry missing key for catalog rule %q", r.Key)
			}
		}
	}
	if rustCount != len(rustRuntimeRules) {
		t.Errorf("Rust catalog AST rule count (%d) != runtime rule count (%d)", rustCount, len(rustRuntimeRules))
	}
}

func TestRustASTCatalogExamples(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default(): %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("cat.List(): %v", err)
	}

	for _, r := range rules {
		if r.Language != "Rust" || r.Detection != rule.DetectionAST {
			continue
		}
		key := string(r.Key)
		t.Run(strings.TrimPrefix(key, "rust:"), func(t *testing.T) {
			noncompliant := rustExampleProgram(r.NoncompliantExample)
			findings := rustFixtureFindings(t, noncompliant)
			if !rustHasRule(findings, key) {
				t.Fatalf("noncompliant catalog example did not emit %s: %q (got findings: %+v)", key, r.NoncompliantExample, findings)
			}

			compliant := rustExampleProgram(r.CompliantExample)
			compliantFindings := rustFixtureFindings(t, compliant)
			if rustHasRule(compliantFindings, key) {
				t.Fatalf("compliant catalog example emitted %s: %q", key, r.CompliantExample)
			}
		})
	}
}

func rustExampleProgram(example string) string {
	trimmed := strings.TrimSpace(example)
	if strings.HasPrefix(trimmed, "fn ") || strings.HasPrefix(trimmed, "pub fn ") || strings.HasPrefix(trimmed, "pub unsafe fn ") || strings.HasPrefix(trimmed, "extern \"C\"") || strings.HasPrefix(trimmed, "struct ") || strings.HasPrefix(trimmed, "pub struct ") || strings.HasPrefix(trimmed, "enum ") || strings.HasPrefix(trimmed, "pub enum ") || strings.HasPrefix(trimmed, "impl ") || strings.HasPrefix(trimmed, "unsafe impl") || strings.HasPrefix(trimmed, "static ") || strings.HasPrefix(trimmed, "///") || strings.HasPrefix(trimmed, "#[") {
		if strings.HasPrefix(trimmed, "///") && !strings.Contains(trimmed, "fn ") {
			return trimmed + "\npub fn fixture() {}"
		}
		return trimmed
	}
	return "fn fixture() {\n" + trimmed + "\n}"
}

func TestRustQualityForDispatch(t *testing.T) {
	dir := t.TempDir()
	src := `
fn test_leak() {
    let b = Box::new(42);
    let _ = Box::into_raw(b);
}
`
	if err := os.WriteFile(filepath.Join(dir, "leak.rs"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := QualityFor(context.Background(), dir)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	found := false
	for _, f := range got.Findings {
		if f.Rule == "rust:leaked-raw-box" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("QualityFor did not find rust:leaked-raw-box in Rust file: %+v", got.Findings)
	}
}
