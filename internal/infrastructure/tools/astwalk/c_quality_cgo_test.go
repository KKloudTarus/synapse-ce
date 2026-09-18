//go:build cgo

package astwalk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func cFixtureFindings(t *testing.T, source string) []QualityFinding {
	t.Helper()
	root := parseRoot(context.Background(), specs["C"], []byte(source))
	if root == nil || root.HasError() {
		t.Fatalf("C fixture is not syntactically complete: %q", source)
	}
	findings, _ := cFindingsLimit(context.Background(), root, []byte(source), "fixture.c", 100)
	return findings
}

func cHasRule(findings []QualityFinding, wantKey string) bool {
	for _, f := range findings {
		if f.Rule == wantKey {
			return true
		}
	}
	return false
}

func TestCGrammarContractReachability(t *testing.T) {
	const source = `
#include <stdio.h>
struct Point { int x; int y; };
int main(void) {
    int val = 10;
    if (val > 0) {
        val++;
    }
    return 0;
}
`
	root := parseRoot(context.Background(), specs["C"], []byte(source))
	if root == nil || root.HasError() {
		t.Fatal("C grammar did not parse contract fixture")
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
	for _, want := range []string{"function_definition", "declaration", "if_statement", "compound_statement", "return_statement"} {
		if !seen[want] {
			t.Errorf("bundled C grammar lacks reachable %q: %v", want, seen)
		}
	}
}

func TestCRuntimeKeyRegistryCompleteness(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default(): %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("cat.List(): %v", err)
	}
	cCount := 0
	for _, r := range rules {
		if r.Language == "C" && r.Detection == rule.DetectionAST {
			cCount++
			shortKey := strings.TrimPrefix(string(r.Key), "c:")
			if _, ok := cRuntimeRules[shortKey]; !ok {
				t.Errorf("C runtime registry missing key for catalog rule %q", r.Key)
			}
		}
	}
	if cCount != len(cRuntimeRules) {
		t.Errorf("C catalog AST rule count (%d) != runtime rule count (%d)", cCount, len(cRuntimeRules))
	}
}

func TestCASTCatalogExamples(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default(): %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("cat.List(): %v", err)
	}

	for _, r := range rules {
		if r.Language != "C" || r.Detection != rule.DetectionAST {
			continue
		}
		key := string(r.Key)
		t.Run(strings.TrimPrefix(key, "c:"), func(t *testing.T) {
			noncompliant := cExampleProgram(r.NoncompliantExample)
			findings := cFixtureFindings(t, noncompliant)
			if !cHasRule(findings, key) {
				t.Fatalf("noncompliant catalog example did not emit %s: %q (got findings: %+v)", key, r.NoncompliantExample, findings)
			}

			compliant := cExampleProgram(r.CompliantExample)
			compliantFindings := cFixtureFindings(t, compliant)
			if cHasRule(compliantFindings, key) {
				t.Fatalf("compliant catalog example emitted %s: %q", key, r.CompliantExample)
			}
		})
	}
}

func cExampleProgram(example string) string {
	trimmed := strings.TrimSpace(example)
	if strings.HasPrefix(trimmed, "#define") {
		return trimmed + "\nvoid fixture(void) {}\n"
	}
	if strings.HasPrefix(trimmed, "__attribute__") {
		return trimmed + "\nvoid fixture(void) {}\n"
	}
	if (strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "//")) && !strings.Contains(trimmed, "void ") {
		return trimmed + "\nvoid fixture(void) {}\n"
	}
	if strings.HasPrefix(trimmed, "void ") || strings.HasPrefix(trimmed, "int ") || strings.HasPrefix(trimmed, "char ") || strings.HasPrefix(trimmed, "struct ") || strings.HasPrefix(trimmed, "static ") || strings.HasPrefix(trimmed, "FILE ") {
		if strings.Contains(trimmed, ";") && !strings.Contains(trimmed, "{") && (strings.HasPrefix(trimmed, "void ") || strings.HasPrefix(trimmed, "int ")) {
			return trimmed + "\nvoid fixture(void) {}\n"
		}
		if strings.Contains(trimmed, "{") {
			return trimmed + "\n"
		}
	}
	return "void fixture(void) {\n" + trimmed + "\n}\n"
}

func TestCQualityForDispatch(t *testing.T) {
	dir := t.TempDir()
	src := `
#include <stdio.h>
void test_vla(int len) {
    char buf[len];
}
`
	if err := os.WriteFile(filepath.Join(dir, "vla.c"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := QualityFor(context.Background(), dir)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	found := false
	for _, f := range got.Findings {
		if f.Rule == "c:vla-stack-allocation" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("QualityFor did not find c:vla-stack-allocation in C file: %+v", got.Findings)
	}
}

// TestCTypeAwareDetectors pins the type-aware fixes to two C detectors: dangling-stack-pointer-return now
// resolves the returned name against the function's own declarations (so an initialized local and a bare
// local-array return are caught, while a global, a static, and a scalar returned by value are not), and
// signed-unsigned-comparison resolves operand signedness from the declarations (so `if (a < b)` with a
// unsigned and b signed is caught, while a same-signedness comparison is not).
func TestCTypeAwareDetectors(t *testing.T) {
	src := `int global_v = 5;

int *dangle_scalar(void) {
    int local = 42;
    return &local;
}

char *dangle_array(void) {
    char buf[64];
    return buf;
}

int ok_scalar_by_value(void) {
    int local = 42;
    return local;
}

int *ok_global(void) {
    return &global_v;
}

int *ok_static(void) {
    static int s = 1;
    return &s;
}

int cmp_signed_unsigned(unsigned int a, int b) {
    if (a < b) {
        return 1;
    }
    return 0;
}

int cmp_same_sign(int a, int b) {
    if (a < b) {
        return 1;
    }
    return 0;
}
`
	findings := cFixtureFindings(t, src)
	lines := func(rule string) []int {
		var ls []int
		for _, f := range findings {
			if f.Rule == rule {
				ls = append(ls, f.Line)
			}
		}
		return ls
	}
	has := func(ls []int, want int) bool {
		for _, l := range ls {
			if l == want {
				return true
			}
		}
		return false
	}

	dangling := lines("c:dangling-stack-pointer-return")
	if !has(dangling, 5) {
		t.Errorf("initialized-local address return not caught (line 5); got %v", dangling)
	}
	if !has(dangling, 10) {
		t.Errorf("local-array return not caught (line 10); got %v", dangling)
	}
	for _, bad := range dangling {
		if bad != 5 && bad != 10 {
			t.Errorf("false-positive dangling return at line %d (scalar-by-value/global/static must not fire)", bad)
		}
	}

	su := lines("c:signed-unsigned-comparison")
	if !has(su, 28) {
		t.Errorf("signed/unsigned comparison `if (a < b)` not caught (line 28); got %v", su)
	}
	for _, bad := range su {
		if bad != 28 {
			t.Errorf("false-positive signed-unsigned comparison at line %d (same-signedness must not fire)", bad)
		}
	}
}

// TestCSignedUnsignedGuardIsLocal pins that the `>= 0` range-check guard for signed-unsigned-comparison is
// scoped to the comparison's own control-flow construct, not the whole file: an unrelated `>= 0` in another
// function must not suppress a genuine unsigned/signed comparison.
func TestCSignedUnsignedGuardIsLocal(t *testing.T) {
	src := `int f(unsigned int a, int b) {
    if (a < b) {
        return 1;
    }
    return 0;
}

int g(int z) {
    if (z >= 0) {
        return 1;
    }
    return 0;
}
`
	findings := cFixtureFindings(t, src)
	n := 0
	for _, f := range findings {
		if f.Rule == "c:signed-unsigned-comparison" {
			n++
			if f.Line != 2 {
				t.Errorf("signed-unsigned finding at line %d, want 2", f.Line)
			}
		}
	}
	if n != 1 {
		t.Fatalf("want exactly 1 signed-unsigned finding despite the unrelated `>= 0` in g(), got %d", n)
	}
}

// TestCFunctionVarsBounded pins that resolving variable types over a function with a very large
// comma-declarator list stays fast (the type text is read once per declaration, not per declarator), so an
// adversarial single declaration cannot make the walk quadratic.
func TestCFunctionVarsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("void f(void) {\n unsigned int u = 0; int s = 0; if (u < s) { s++; }\n long ")
	for i := 0; i < 8000; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "v%d", i)
	}
	b.WriteString(";\n}\n")
	src := b.String()
	done := make(chan struct{})
	go func() {
		root := parseRoot(context.Background(), specs["C"], []byte(src))
		_, _ = cFindingsLimit(context.Background(), root, []byte(src), "f.c", 100)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("cFunctionVars did not complete in time on a large declarator list (possible O(n^2) regression)")
	}
}
