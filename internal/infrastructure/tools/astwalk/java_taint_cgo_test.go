//go:build cgo

package astwalk

import (
	"context"
	"sort"
	"strings"
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

func TestJavaHTMLTextOutputProofIsCallsiteScoped(t *testing.T) {
	safeBody := `import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
class Example {
  private java.io.PrintWriter writer;
  void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String name = req.getParameter("name");
    String clean = clean(name);
    writer = resp.getWriter();
    resp.setContentType("text/html");
    writer.println("<html>" + clean + "</html>");
  }
  private static String clean(String name) {
    StringBuffer buf = new StringBuffer();
    for (int i = 0; i < name.length(); i++) {
      char ch = name.charAt(i);
      if (Character.isLetter(ch) || Character.isDigit(ch) || ch == '_') { buf.append(ch); } else { buf.append('?'); }
    }
    return buf.toString();
  }
}`
	unsafeBodies := map[string]string{
		"script_context":   strings.Replace(safeBody, `"<html>" + clean + "</html>"`, `"<script>" + clean + "</script>"`, 1),
		"raw_write_before": strings.Replace(safeBody, `writer.println("<html>" + clean + "</html>");`, "writer.println(name);\n    writer.println(\"<html>\" + clean + \"</html>\");", 1),
		"partial_encoder":  strings.Replace(safeBody, "else { buf.append('?'); }", "else { buf.append(ch); }", 1),
		"bypass_return":    strings.Replace(safeBody, "return buf.toString();", "if (name == null) return name; return buf.toString();", 1),
		"shadowed_result":  strings.Replace(safeBody, "String clean = clean(name);", "{ String clean = clean(name); }\n    String clean = name;", 1),
		"unicode_escape":   strings.Replace(safeBody, "return buf.toString();", "// \\u000a if (name != null) return name;\n    return buf.toString();", 1),
		"inner_shadow": strings.Replace(safeBody, `writer.println("<html>" + clean + "</html>");`,
			`{ String clean = name; writer.println("<html>" + clean + "</html>"); }`, 1),
		"for_initializer": strings.Replace(
			strings.Replace(safeBody, "String clean = clean(name);", "for (String clean = clean(name); true;) {", 1),
			`writer.println("<html>" + clean + "</html>");`, `writer.println("<html>" + clean + "</html>"); break; }`, 1),
		"class_field": strings.Replace(safeBody, "private java.io.PrintWriter writer;", "private java.io.PrintWriter writer;\n  private String clean;", 1),
	}
	cases := map[string]struct {
		body      string
		wantProof bool
		wantRule  bool
	}{
		"safe_html_text": {body: safeBody, wantProof: true},
	}
	for name, body := range unsafeBodies {
		cases[name] = struct {
			body      string
			wantProof bool
			wantRule  bool
		}{body: body, wantRule: true}
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "Example.java", tc.body)
			doc, err := JavaFactsFor(context.Background(), root)
			if err != nil {
				t.Fatalf("JavaFactsFor: %v", err)
			}
			proof := false
			for _, call := range doc.Calls {
				if call.OutputProof == "html_text" {
					proof = true
				}
			}
			if proof != tc.wantProof {
				t.Fatalf("HTML-text proof = %v, want %v", proof, tc.wantProof)
			}
			graph, err := taint.BuildJavaValueGraph(doc, taint.DefaultJavaCatalog())
			if err != nil {
				t.Fatalf("BuildJavaValueGraph: %v", err)
			}
			found := false
			for _, finding := range graph.Vulnerabilities() {
				if finding.Rule == "java-taint-xss-writer" {
					found = true
				}
			}
			if found != tc.wantRule {
				t.Fatalf("XSS writer finding = %v, want %v", found, tc.wantRule)
			}
		})
	}
}

func TestJavaHTMLTextOutputProofRejectsCommentDelimiterInsideEscapedLiteral(t *testing.T) {
	escapedHelper := `private String clean(String name) {
    StringBuffer buf = new StringBuffer();
    for (int i = 0; i < name.length(); i++) {
      char ch = name.charAt(i);
      switch (ch) {
        case '<': buf.append("&lt;"); break;
        case '>': buf.append("&gt;"); break;
        case '&': buf.append("&amp;"); break;
        default: if (Character.isLetter(ch) || Character.isDigit(ch) || ch == '_') { buf.append(ch); } else { buf.append('?'); }
      }
    }
    return buf.toString();
  }`
	body := `import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
class Example {
  private java.io.PrintWriter writer;
  void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String name = req.getParameter("name");
    String clean = clean(name);
    writer = resp.getWriter();
    resp.setContentType("text/html");
    writer.println("<html>" + clean + "</html>");
  }
  ` + escapedHelper + `
}`
	for name, tc := range map[string]struct {
		body      string
		wantProof bool
		wantRule  bool
	}{
		"ordinary_entities": {body: body, wantProof: true},
		"delimiter_in_literal": {
			body:     strings.Replace(body, `"&lt;"`, `"&lt;/*<script>alert(1)</script>*/"`, 1),
			wantRule: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "Example.java", tc.body)
			doc, err := JavaFactsFor(context.Background(), root)
			if err != nil {
				t.Fatalf("JavaFactsFor: %v", err)
			}
			proof := false
			for _, call := range doc.Calls {
				proof = proof || call.OutputProof == "html_text"
			}
			if proof != tc.wantProof {
				t.Fatalf("HTML-text proof = %v, want %v", proof, tc.wantProof)
			}
			graph, err := taint.BuildJavaValueGraph(doc, taint.DefaultJavaCatalog())
			if err != nil {
				t.Fatalf("BuildJavaValueGraph: %v", err)
			}
			found := false
			for _, finding := range graph.Vulnerabilities() {
				found = found || finding.Rule == "java-taint-xss-writer"
			}
			if found != tc.wantRule {
				t.Fatalf("XSS writer finding = %v, want %v", found, tc.wantRule)
			}
		})
	}
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

// TestJavaTaintCrossFileStaticImport proves taint crosses a FILE boundary through a first-party STATIC import
// (#1054): a request value passed into a helper imported by `import static <fqn>.run` reaches a command-exec
// sink inside that helper's own file. The router file holds the source and the call; the helper file (a
// different package) holds the sink, resolved by matching the import FQN to the in-document class + method.
func TestJavaTaintCrossFileStaticImport(t *testing.T) {
	files := map[string]string{
		"Router.java": `package com.example.web;

import javax.servlet.http.HttpServletRequest;
import static com.example.cmd.Helper.run;

public class Router {
  public void handle(HttpServletRequest request) throws Exception {
    run(request.getParameter("cmd"));
  }
}
`,
		"Helper.java": `package com.example.cmd;

public class Helper {
  public static void run(String cmd) throws Exception {
    Runtime.getRuntime().exec(cmd);
  }
}
`,
	}
	if rules := javaTaintRules(t, files); !rules["java-taint-command-exec"] {
		t.Fatalf("cross-file static-import command injection missed: %v", javaRuleList(rules))
	}
}

// TestJavaTaintCrossFileNonFirstPartyStaticImportNotBound is the soundness guard for the cross-file resolver:
// a static import of a type NOT in the scanned document (a third-party library) must not be bound to some
// same-named in-tree method. Here the only `run` in the document is the safe local one; the third-party
// import must not fabricate a command finding from the wrong method.
func TestJavaTaintCrossFileNonFirstPartyStaticImportNotBound(t *testing.T) {
	files := map[string]string{
		"Router.java": `package com.example.web;

import javax.servlet.http.HttpServletRequest;
import static com.thirdparty.Vendor.run;

public class Router {
  public void handle(HttpServletRequest request) throws Exception {
    run(request.getParameter("cmd"));
  }
}
`,
		"Local.java": `package com.example.local;

public class Local {
  public static void run(String cmd) throws Exception {
    Runtime.getRuntime().exec(cmd);
  }
}
`,
	}
	if rules := javaTaintRules(t, files); rules["java-taint-command-exec"] {
		t.Fatalf("a third-party static import must not bind to a same-named in-tree method: %v", javaRuleList(rules))
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

func TestJavaStrongUpdatesRespectControlFlow(t *testing.T) {
	const header = `import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class Controller {
  void run(HttpServletRequest request, HttpServletResponse response, boolean overwrite) throws Exception {
`
	const footer = `  }
}
`
	cases := []struct {
		name          string
		body          string
		markerLine    int
		strong        bool
		wantSinkLines []int
	}{
		{
			name: "straight_line_constant_overwrite",
			body: `    String name = request.getParameter("name");
    name = "safe";
    PrintWriter writer = response.getWriter();
    writer.println(name);
`,
			markerLine: 7, strong: true,
		},
		{
			name: "conditional_overwrite_keeps_prior_taint",
			body: `    String name = request.getParameter("name");
    if (overwrite) {
      name = "safe";
    }
    PrintWriter writer = response.getWriter();
    writer.println(name);
`,
			markerLine: 8, strong: false, wantSinkLines: []int{11},
		},
		{
			name: "nonliteral_assignment_retains_prior_taint_when_value_flow_is_incomplete",
			body: `    String name = request.getParameter("name");
    String clean = "safe";
    name = clean;
    PrintWriter writer = response.getWriter();
    writer.println(name);
`,
			markerLine: 8, strong: false, wantSinkLines: []int{10},
		},
		{
			name: "unicode_escaped_literal_is_not_proof_of_strong_update",
			body: `    String name = request.getParameter("name");
    name = "\u0061";
    PrintWriter writer = response.getWriter();
    writer.println(name);
`,
			markerLine: 7, strong: false, wantSinkLines: []int{9},
		},
		{
			name: "short_circuit_overwrite_keeps_prior_taint",
			body: `    String name = request.getParameter("name");
    boolean observed = overwrite && ((name = "safe") != null);
    PrintWriter writer = response.getWriter();
    writer.println(name);
`,
			markerLine: 7, strong: false, wantSinkLines: []int{9},
		},
		{
			name: "labeled_break_can_skip_overwrite",
			body: `    String name = request.getParameter("name");
    label: {
      if (overwrite) break label;
      name = "safe";
    }
    PrintWriter writer = response.getWriter();
    writer.println(name);
`,
			markerLine: 9, strong: false, wantSinkLines: []int{12},
		},
		{
			name: "sink_before_overwrite_remains",
			body: `    String name = request.getParameter("name");
    PrintWriter writer = response.getWriter();
    writer.println(name);
    name = "safe";
    writer.println(name);
`,
			markerLine: 9, strong: true, wantSinkLines: []int{8},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "Controller.java", header+tc.body+footer)
			doc, err := JavaFactsFor(context.Background(), root)
			if err != nil {
				t.Fatalf("JavaFactsFor: %v", err)
			}
			foundMarker := false
			for _, assignment := range doc.Assignments {
				if assignment.Pos.Line == tc.markerLine {
					foundMarker = true
					if assignment.StrongUpdate != tc.strong {
						t.Fatalf("assignment at line %d StrongUpdate=%t, want %t", tc.markerLine, assignment.StrongUpdate, tc.strong)
					}
				}
			}
			if !foundMarker {
				t.Fatalf("no assignment fact at line %d: %#v", tc.markerLine, doc.Assignments)
			}
			graph, err := taint.BuildJavaValueGraph(doc, taint.DefaultJavaCatalog())
			if err != nil {
				t.Fatalf("BuildJavaValueGraph: %v", err)
			}
			gotSinkLines := map[int]bool{}
			for _, path := range graph.Vulnerabilities() {
				if path.Rule == "java-taint-xss-writer" {
					gotSinkLines[path.SinkPos.Line] = true
				}
			}
			wantSinkLines := map[int]bool{}
			for _, line := range tc.wantSinkLines {
				wantSinkLines[line] = true
			}
			if len(gotSinkLines) != len(wantSinkLines) {
				t.Fatalf("XSS sink lines=%v, want %v", gotSinkLines, wantSinkLines)
			}
			for line := range wantSinkLines {
				if !gotSinkLines[line] {
					t.Fatalf("XSS sink lines=%v, want %v", gotSinkLines, wantSinkLines)
				}
			}
		})
	}
}

func TestJavaStrongUpdateSharedFieldRetainsTaint(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "Controller.java", `import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class Controller {
  private String name;
  void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
    name = request.getParameter("name");
    name = "safe";
    PrintWriter writer = response.getWriter();
    writer.println(name);
  }
}
`)
	doc, err := JavaFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JavaFactsFor: %v", err)
	}
	foundMarker := false
	marker := false
	for _, assignment := range doc.Assignments {
		if assignment.Pos.Line == 8 {
			foundMarker = true
			marker = assignment.StrongUpdate
		}
	}
	if !foundMarker {
		t.Fatalf("missing field overwrite assignment: %#v", doc.Assignments)
	}
	if marker {
		t.Fatalf("a shared field overwrite must not be a strong update: %#v", doc.Assignments)
	}
	graph, err := taint.BuildJavaValueGraph(doc, taint.DefaultJavaCatalog())
	if err != nil {
		t.Fatalf("BuildJavaValueGraph: %v", err)
	}
	for _, path := range graph.Vulnerabilities() {
		if path.Rule == "java-taint-xss-writer" {
			return
		}
	}
	t.Fatalf("a shared field may be changed by another request before the sink, got no XSS finding")
}

func TestJavaNestedLocalStrongUpdateDoesNotHideOuterValue(t *testing.T) {
	const header = `import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class Controller {
  private String name;
  void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
`
	const footer = `  }
}
`
	cases := []struct {
		name  string
		outer string
	}{
		{"shared_field", `    name = request.getParameter("name");`},
		{"outer_local", `    String name = request.getParameter("name");`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "Controller.java", header+tc.outer+`
    {
      String name = "inner";
      name = "safe";
    }
    PrintWriter writer = response.getWriter();
    writer.println(name);
`+footer)
			doc, err := JavaFactsFor(context.Background(), root)
			if err != nil {
				t.Fatalf("JavaFactsFor: %v", err)
			}
			foundInnerAssignment := false
			for _, assignment := range doc.Assignments {
				if assignment.Pos.Line == 10 && assignment.StrongUpdate {
					t.Fatalf("an inner-block local must not be a strong update: %#v", doc.Assignments)
				}
				if assignment.Pos.Line == 10 {
					foundInnerAssignment = true
				}
			}
			if !foundInnerAssignment {
				t.Fatalf("missing inner-block assignment: %#v", doc.Assignments)
			}
			graph, err := taint.BuildJavaValueGraph(doc, taint.DefaultJavaCatalog())
			if err != nil {
				t.Fatalf("BuildJavaValueGraph: %v", err)
			}
			for _, path := range graph.Vulnerabilities() {
				if path.Rule == "java-taint-xss-writer" {
					return
				}
			}
			t.Fatalf("an inner local must not hide the outer tainted value")
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
