//go:build cgo

package astwalk

import (
	"context"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/javaprogram"
	sitter "github.com/smacker/go-tree-sitter"
)

func javaDeadBranchFacts(t *testing.T, body string) javaprogram.Document {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "Dead.java", `import javax.servlet.http.HttpServletRequest;
public class Dead {
  void run(HttpServletRequest request, boolean predicate) throws Exception {
`+body+`
  }
}
`)
	doc, err := JavaFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JavaFactsFor: %v", err)
	}
	return doc
}

func javaDeadBranchExecFacts(doc javaprogram.Document) int {
	count := 0
	for _, call := range doc.Calls {
		if len(call.Callee.Segments) > 0 && call.Callee.Segments[len(call.Callee.Segments)-1] == "exec" {
			count++
		}
	}
	return count
}

// TestJavaExactFalseConsequenceOmitted proves the one allowed suppression: a bare false literal makes its
// ordinary statement consequence unreachable. The end-to-end assertion guards both extraction and taint.
func TestJavaExactFalseConsequenceOmitted(t *testing.T) {
	body := `    if (false) {
      Runtime.getRuntime().exec(request.getParameter("cmd"));
    }`
	doc := javaDeadBranchFacts(t, body)
	if got := javaDeadBranchExecFacts(doc); got != 0 {
		t.Fatalf("exact false consequence must emit no exec facts, got %d", got)
	}
	rules := javaTaintRules(t, map[string]string{"Dead.java": `import javax.servlet.http.HttpServletRequest;
public class Dead {
  void run(HttpServletRequest request) throws Exception {
` + body + `
  }
}
`})
	if rules["java-taint-command-exec"] {
		t.Fatalf("exact false consequence must not produce command-exec taint: %v", javaRuleList(rules))
	}
}

// TestJavaExactFalseConsequenceRetainsConservativeCases keeps extraction conservative whenever
// the condition is not the grammar's bare false literal, parsing is malformed, the consequence owns a
// callable body, or the bounded eligibility scan cannot finish.
func TestJavaExactFalseConsequenceRetainsConservativeCases(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"else", `    if (false) { harmless(); } else { Runtime.getRuntime().exec(request.getParameter("cmd")); }`},
		{"following_statement", `    if (false) { harmless(); }
    Runtime.getRuntime().exec(request.getParameter("cmd"));`},
		{"true", `    if (true) { Runtime.getRuntime().exec(request.getParameter("cmd")); }`},
		{"variable", `    boolean disabled = false;
    if (disabled) { Runtime.getRuntime().exec(request.getParameter("cmd")); }`},
		{"false_or_predicate", `    if (false || predicate) { Runtime.getRuntime().exec(request.getParameter("cmd")); }`},
		{"parenthesized_false", `    if ((false)) { Runtime.getRuntime().exec(request.getParameter("cmd")); }`},
		{"local_type", `    if (false) { class Local { void execute() throws Exception { Runtime.getRuntime().exec(request.getParameter("cmd")); } } }`},
		{"lambda", `    if (false) { Runnable task = () -> { Runtime.getRuntime().exec(request.getParameter("cmd")); }; }`},
		{"anonymous_class", `    if (false) { Runnable task = new Runnable() { public void run() { Runtime.getRuntime().exec(request.getParameter("cmd")); } }; }`},
		{"eligibility_budget", "    if (false) {\n" + strings.Repeat("      {\n", maxJavaDeadBranchEligibilityNodes+1) +
			strings.Repeat("      }\n", maxJavaDeadBranchEligibilityNodes+1) + "      Runtime.getRuntime().exec(request.getParameter(\"cmd\"));\n    }"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := javaDeadBranchFacts(t, tc.body)
			if got := javaDeadBranchExecFacts(doc); got == 0 {
				t.Fatalf("%s must retain exec facts", tc.name)
			}
		})
	}
}

func javaFirstIfStatement(node *sitter.Node) *sitter.Node {
	if node == nil {
		return nil
	}
	if node.Type() == "if_statement" {
		return node
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if found := javaFirstIfStatement(node.Child(i)); found != nil {
			return found
		}
	}
	return nil
}

func TestJavaExactFalseConsequenceMalformedConditionIsRetained(t *testing.T) {
	source := []byte(`class Dead { void run() { if (false { Runtime.getRuntime().exec("cmd"); } } }`)
	ifNode := javaFirstIfStatement(parseRoot(context.Background(), specs["Java"], source))
	if ifNode == nil {
		t.Fatal("malformed fixture must retain an if_statement recovery node")
	}
	extractor := javaFactExtractor{source: source}
	if extractor.skipExactFalseConsequence(ifNode) {
		t.Fatal("malformed if_statement must retain its consequence")
	}
}

// TestJavaExactFalseConsequenceKeepsReachableTaint proves the optimization does not hide reachable sinks in
// the adjacent alternative, following statement, or any condition whose value is not syntactically exact.
func TestJavaExactFalseConsequenceKeepsReachableTaint(t *testing.T) {
	cases := map[string]string{
		"else": `if (false) { harmless(); } else { Runtime.getRuntime().exec(request.getParameter("cmd")); }`,
		"following": `if (false) { harmless(); }
Runtime.getRuntime().exec(request.getParameter("cmd"));`,
		"true": `if (true) { Runtime.getRuntime().exec(request.getParameter("cmd")); }`,
		"variable": `boolean disabled = false;
if (disabled) { Runtime.getRuntime().exec(request.getParameter("cmd")); }`,
		"false_or_predicate": `if (false || predicate) { Runtime.getRuntime().exec(request.getParameter("cmd")); }`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rules := javaTaintRules(t, map[string]string{"Dead.java": `import javax.servlet.http.HttpServletRequest;
public class Dead {
  void run(HttpServletRequest request, boolean predicate) throws Exception {
` + body + `
  }
}
`})
			if !rules["java-taint-command-exec"] {
				t.Fatalf("reachable command-exec taint was hidden: %v", javaRuleList(rules))
			}
		})
	}
}
