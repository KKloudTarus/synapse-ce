//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func cppFixtureFindings(t *testing.T, source string) []QualityFinding {
	t.Helper()
	root := parseRoot(context.Background(), specs["C++"], []byte(source))
	if root == nil {
		t.Fatalf("C++ fixture failed to parse: %q", source)
	}
	findings, _ := cppFindingsLimit(root, []byte(source), "fixture.cpp", 100)
	return findings
}

func cppHasRule(findings []QualityFinding, wantKey string) bool {
	for _, f := range findings {
		if f.Rule == wantKey {
			return true
		}
	}
	return false
}

func TestCPPGrammarContractReachability(t *testing.T) {
	const source = `
#include <vector>
#include <memory>
class Base {
public:
    virtual ~Base() = default;
};
int main() {
    auto p = std::make_unique<Base>();
    return 0;
}
`
	root := parseRoot(context.Background(), specs["C++"], []byte(source))
	if root == nil || root.HasError() {
		t.Fatal("C++ grammar did not parse contract fixture")
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
	for _, want := range []string{"class_specifier", "function_definition", "declaration", "return_statement"} {
		if !seen[want] {
			t.Errorf("bundled C++ grammar lacks reachable %q: %v", want, seen)
		}
	}
}

func TestCPPRuntimeKeyRegistryCompleteness(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default(): %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("cat.List(): %v", err)
	}
	cppCount := 0
	for _, r := range rules {
		if r.Language == "C++" && r.Detection == rule.DetectionAST {
			cppCount++
			shortKey := strings.TrimPrefix(string(r.Key), "cpp:")
			if _, ok := cppRuntimeRules[shortKey]; !ok {
				t.Errorf("C++ runtime registry missing key for catalog rule %q", r.Key)
			}
		}
	}
	if cppCount != len(cppRuntimeRules) {
		t.Errorf("C++ catalog AST rule count (%d) != runtime rule count (%d)", cppCount, len(cppRuntimeRules))
	}
}

func TestCPPASTCatalogExamples(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default(): %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("cat.List(): %v", err)
	}

	for _, r := range rules {
		if r.Language != "C++" || r.Detection != rule.DetectionAST {
			continue
		}
		key := string(r.Key)
		t.Run(strings.TrimPrefix(key, "cpp:"), func(t *testing.T) {
			noncompliant := cppExampleProgram(r.NoncompliantExample)
			findings := cppFixtureFindings(t, noncompliant)
			if !cppHasRule(findings, key) {
				t.Fatalf("noncompliant catalog example did not emit %s: %q (got findings: %+v)", key, r.NoncompliantExample, findings)
			}

			compliant := cppExampleProgram(r.CompliantExample)
			compliantFindings := cppFixtureFindings(t, compliant)
			if cppHasRule(compliantFindings, key) {
				t.Fatalf("compliant catalog example emitted %s: %q", key, r.CompliantExample)
			}
		})
	}
}

func cppExampleProgram(example string) string {
	trimmed := strings.TrimSpace(example)
	if strings.HasPrefix(trimmed, "class ") || strings.HasPrefix(trimmed, "struct ") || strings.HasPrefix(trimmed, "template<") || strings.HasPrefix(trimmed, "export template") || strings.HasPrefix(trimmed, "enum ") || strings.HasPrefix(trimmed, "typedef ") || strings.HasPrefix(trimmed, "using ") {
		return trimmed + "\n"
	}
	if strings.HasPrefix(trimmed, "void ") || strings.HasPrefix(trimmed, "int ") {
		if strings.Contains(trimmed, "{") {
			return trimmed + "\n"
		}
		if strings.Contains(trimmed, ";") && strings.Contains(trimmed, "(") {
			return trimmed + "\nvoid fixture() {}\n"
		}
	}
	if strings.HasPrefix(trimmed, "~") {
		return "class Fixture {\npublic:\n" + trimmed + "\n};\n"
	}
	return "void fixture() {\n" + trimmed + "\n}\n"
}

func TestCPPQualityForDispatch(t *testing.T) {
	dir := t.TempDir()
	src := `
#include <iostream>
void test_throw() {
    throw new std::runtime_error("error");
}
`
	if err := os.WriteFile(filepath.Join(dir, "throw.cpp"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := QualityFor(context.Background(), dir)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	found := false
	for _, f := range got.Findings {
		if f.Rule == "cpp:throw-raw-pointer" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("QualityFor did not find cpp:throw-raw-pointer in C++ file: %+v", got.Findings)
	}
}
