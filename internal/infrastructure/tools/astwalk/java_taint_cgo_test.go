//go:build cgo

package astwalk

import (
	"context"
	"sort"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

// javaTaintRules extracts real semantic facts from the given Java sources with the production extractor,
// runs the owned value-flow engine over the default catalog, and returns the set of taint rules proven.
// Driving the REAL extractor (not a hand-built document) is what makes the no-false-positive fixtures
// trustworthy: they assert the pipeline a scan actually runs finds nothing.
func javaTaintRules(t *testing.T, files map[string]string) map[string]bool {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		writeFile(t, root, name, body)
	}
	doc, err := JavaFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JavaFactsFor: %v", err)
	}
	graph, err := taint.BuildJavaValueGraph(doc, taint.DefaultJavaCatalog())
	if err != nil {
		t.Fatalf("BuildJavaValueGraph: %v", err)
	}
	rules := map[string]bool{}
	for _, finding := range graph.Vulnerabilities() {
		rules[finding.Rule] = true
	}
	return rules
}

func javaRuleList(rules map[string]bool) []string {
	out := make([]string, 0, len(rules))
	for rule := range rules {
		out = append(out, rule)
	}
	sort.Strings(out)
	return out
}

// TestJavaTaintPositivePerClass proves each modeled sink class fires on a real source->sink flow.
func TestJavaTaintPositivePerClass(t *testing.T) {
	cases := []struct {
		name string
		file string
		body string
		want string
	}{
		{
			name: "sql_statement",
			file: "SqlController.java",
			body: `import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class SqlController {
  public void run(HttpServletRequest request, Statement stmt) throws Exception {
    String id = request.getParameter("id");
    String q = "SELECT * FROM users WHERE id = " + id;
    stmt.executeQuery(q);
  }
}
`,
			want: "java-taint-sql-statement",
		},
		{
			name: "command_exec",
			file: "CmdController.java",
			body: `import javax.servlet.http.HttpServletRequest;

public class CmdController {
  public void run(HttpServletRequest request) throws Exception {
    String cmd = request.getParameter("cmd");
    Runtime.getRuntime().exec(cmd);
  }
}
`,
			want: "java-taint-command-exec",
		},
		{
			name: "path_file",
			file: "PathController.java",
			body: `import java.io.File;
import javax.servlet.http.HttpServletRequest;

public class PathController {
  public void run(HttpServletRequest request) throws Exception {
    String name = request.getParameter("f");
    File f = new File(name);
  }
}
`,
			want: "java-taint-path-file",
		},
		{
			name: "ssrf_url",
			file: "SsrfController.java",
			body: `import java.net.URL;
import javax.servlet.http.HttpServletRequest;

public class SsrfController {
  public void run(HttpServletRequest request) throws Exception {
    String u = request.getParameter("u");
    URL url = new URL(u);
  }
}
`,
			want: "java-taint-ssrf-url",
		},
		{
			name: "deser_ois",
			file: "DeserController.java",
			body: `import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;

public class DeserController {
  public void run(HttpServletRequest request) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
    Object o = ois.readObject();
  }
}
`,
			want: "java-taint-deser-ois",
		},
		{
			name: "code_scripteval",
			file: "CodeController.java",
			body: `import javax.script.ScriptEngine;
import javax.servlet.http.HttpServletRequest;

public class CodeController {
  public void run(HttpServletRequest request, ScriptEngine engine) throws Exception {
    String expr = request.getParameter("expr");
    engine.eval(expr);
  }
}
`,
			want: "java-taint-code-scripteval",
		},
		{
			name: "command_processbuilder",
			file: "PbController.java",
			body: `import javax.servlet.http.HttpServletRequest;

public class PbController {
  public void run(HttpServletRequest request) throws Exception {
    String cmd = request.getParameter("cmd");
    new ProcessBuilder(cmd).start();
  }
}
`,
			want: "java-taint-command-processbuilder",
		},
		{
			name: "spring_requestparam_annotation",
			file: "SpringController.java",
			body: `import java.sql.Statement;

public class SpringController {
  public void search(@RequestParam String q, Statement stmt) throws Exception {
    stmt.executeQuery(q);
  }
}
`,
			want: "java-taint-sql-statement",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := javaTaintRules(t, map[string]string{tc.file: tc.body})
			if !rules[tc.want] {
				t.Fatalf("want rule %q, got %v", tc.want, javaRuleList(rules))
			}
		})
	}
}

// TestJavaTaintCanonicalizeIsNotASanitizer pins a DELIBERATE catalog decision (DefaultJavaCatalog models no
// sanitizers): getCanonicalPath()/normalize() alone is NOT a sound path-traversal wall, because a
// canonicalized path can still resolve to /etc/passwd; the sound neutralization is a base-directory
// containment check, which is not a single call result. So routing a tainted value through
// getCanonicalPath before a File constructor is only an unmodeled transformer that PROPAGATES taint, and
// the path-traversal finding must still fire. A future change that re-adds a canonicalizer sanitizer (a
// false suppression of a real traversal) must fail here consciously. This is the e2e counterpart of the JS
// sanitizer twin, inverted to match the Java catalog's explicit no-sanitizer contract.
func TestJavaTaintCanonicalizeIsNotASanitizer(t *testing.T) {
	rules := javaTaintRules(t, map[string]string{
		"PathController.java": `import java.io.File;
import javax.servlet.http.HttpServletRequest;

public class PathController {
  public void read(HttpServletRequest request) throws Exception {
    String name = request.getParameter("f");
    File f = fileFor(name);
    String safe = f.getCanonicalPath();
    File out = new File(safe);
  }
}
`,
	})
	if !rules["java-taint-path-file"] {
		t.Fatalf("canonicalize is not a modeled sanitizer, so path traversal must still fire, got %v", javaRuleList(rules))
	}
}

// TestJavaTaintNoFalsePositive is the soundness guard: a constant query and a benign program must find
// nothing. A regression that widens a sink into a false positive fails here.
func TestJavaTaintNoFalsePositive(t *testing.T) {
	cases := []struct {
		name string
		file string
		body string
	}{
		{
			name: "constant_query",
			file: "SqlController.java",
			body: `import java.sql.Statement;

public class SqlController {
  public void run(Statement stmt) throws Exception {
    stmt.executeQuery("SELECT 1");
  }
}
`,
		},
		{
			name: "benign_program",
			file: "Hello.java",
			body: `public class Hello {
  public static void main(String[] args) {
    System.out.println("hello, world");
    int total = 0;
    for (int i = 0; i < args.length; i++) {
      total += args[i].length();
    }
    System.out.println(total);
  }
}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := javaTaintRules(t, map[string]string{tc.file: tc.body})
			if len(rules) != 0 {
				t.Fatalf("expected zero findings, got %v", javaRuleList(rules))
			}
		})
	}
}

// TestJavaFactsBoundedOnDeepExpression feeds a pathologically deep expression (nested parentheses and a long
// binary chain) that would overflow the stack if the expression-lowering helpers recursed unbounded. The
// extractor must return without panicking; the deep subtree is truncated rather than modeled.
func TestJavaFactsBoundedOnDeepExpression(t *testing.T) {
	const depth = 20000
	deep := make([]byte, 0, depth*2+64)
	deep = append(deep, []byte("package a; class A { void m() { int x = ")...)
	for i := 0; i < depth; i++ {
		deep = append(deep, '(')
	}
	deep = append(deep, '1')
	for i := 0; i < depth; i++ {
		deep = append(deep, ')')
	}
	deep = append(deep, []byte("; } }")...)

	chain := "package b; class B { int f() { return x" + repeatJava("+x", depth) + "; } }"

	for name, src := range map[string]string{"a/A.java": string(deep), "b/B.java": chain} {
		root := t.TempDir()
		writeFile(t, root, name, src)
		doc, err := JavaFactsFor(context.Background(), root) // must not panic / stack-overflow
		if err != nil {
			t.Fatalf("%s: JavaFactsFor errored instead of bounding: %v", name, err)
		}
		if !doc.Truncated {
			t.Errorf("%s: a %d-deep expression must mark the document truncated", name, depth)
		}
	}
}

func repeatJava(s string, n int) string {
	b := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		b = append(b, s...)
	}
	return string(b)
}
