//go:build cgo

package astwalk

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// TestJavaInlineFQNSatisfiesImportGate proves the extractor lowers an inline fully-qualified type reference
// to a file-scoped on-demand import, so a RequiresImport-gated sink (LDAP search, XPath evaluate) fires on
// source that spells the API fully qualified instead of writing an import. This is the exact shape OWASP
// BenchmarkJava uses, where an import-statement-only gate scored zero recall. The unrelated-package case is
// the over-widen guard: an inline java.util reference must not satisfy the javax.naming anchor.
func TestJavaInlineFQNSatisfiesImportGate(t *testing.T) {
	cases := []struct {
		name string
		file string
		body string
		rule string
		want bool
	}{
		{
			name: "ldap_inline_fqn",
			file: "LdapController.java",
			body: `public class LdapController {
    public void handle(javax.servlet.http.HttpServletRequest request) throws Exception {
        String filter = request.getParameter("q");
        javax.naming.directory.DirContext ctx = makeCtx();
        javax.naming.directory.InitialDirContext idc = (javax.naming.directory.InitialDirContext) ctx;
        idc.search("ou=users", filter, new Object[]{}, new javax.naming.directory.SearchControls());
    }
    javax.naming.directory.DirContext makeCtx() { return null; }
}`,
			rule: "java-taint-ldap-search",
			want: true,
		},
		{
			name: "xpath_inline_fqn",
			file: "XpathController.java",
			body: `public class XpathController {
    public void handle(javax.servlet.http.HttpServletRequest request) throws Exception {
        String expr = request.getParameter("q");
        javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
        String result = xp.evaluate(expr, someNode());
    }
    Object someNode() { return null; }
}`,
			rule: "java-taint-xpath-expression",
			want: true,
		},
		{
			// The sink receiver's fully-qualified type is only in the method parameter list, which walkMethod
			// does not descend into for facts; the signature must still feed the inline-FQN gate.
			name: "param_type_fqn_fires_ldap",
			file: "ParamController.java",
			body: `public class ParamController {
    public void handle(javax.naming.directory.InitialDirContext idc, javax.servlet.http.HttpServletRequest request) throws Exception {
        String filter = request.getParameter("q");
        idc.search("ou=users", filter, new Object[]{}, null);
    }
}`,
			rule: "java-taint-ldap-search",
			want: true,
		},
		{
			name: "unrelated_inline_fqn_does_not_gate_ldap",
			file: "ListController.java",
			body: `public class ListController {
    public void handle(javax.servlet.http.HttpServletRequest request) {
        String q = request.getParameter("q");
        java.util.Stack<String> stack = makeStack();
        stack.search(q);
    }
    java.util.Stack<String> makeStack() { return null; }
}`,
			rule: "java-taint-ldap-search",
			want: false,
		},
		{
			// The synthetic import is type-granular (the full FQN), so a type in the PARENT package of an
			// anchor (javax.xml.XMLConstants vs the javax.xml.xpath anchor) must not gate the XPath sink. A
			// package-granular import would falsely match through javaMatchesModule's reverse-prefix branch.
			name: "parent_package_type_does_not_gate_xpath",
			file: "XmlConstController.java",
			body: `public class XmlConstController {
    public void handle(javax.servlet.http.HttpServletRequest request) throws Exception {
        String expr = request.getParameter("q");
        javax.xml.XMLConstants marker = constant();
        Object ev = evaluator();
        String out = ev.evaluate(expr, marker);
    }
    javax.xml.XMLConstants constant() { return null; }
    Object evaluator() { return null; }
}`,
			rule: "java-taint-xpath-expression",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := javaTaintRules(t, map[string]string{tc.file: tc.body})
			if rules[tc.rule] != tc.want {
				t.Errorf("%s: rule %q present=%v, want %v (all: %v)", tc.name, tc.rule, rules[tc.rule], tc.want, javaRuleList(rules))
			}
		})
	}
}

// TestJavaInlineFQNHostileInputDoesNotPoisonDocument proves a crafted over-long inline fully-qualified type
// reference is dropped at record time, not emitted as an over-long import specifier that would fail document
// validation and discard every fact for the whole target. The real LDAP flow in a sibling file must still be
// proven, which it can only be if the parse succeeded.
func TestJavaInlineFQNHostileInputDoesNotPoisonDocument(t *testing.T) {
	// A single inline type whose name far exceeds the domain's 4096-byte specifier cap. Emitting it would
	// fail Document.Validate and drop the whole document; the length guard must drop it silently instead.
	oversized := "a.b." + strings.Repeat("C", 5000)
	files := map[string]string{
		"Poison.java": "public class Poison { " + oversized + " field; }",
		"LdapController.java": `public class LdapController {
    public void handle(javax.servlet.http.HttpServletRequest request) throws Exception {
        String filter = request.getParameter("q");
        javax.naming.directory.InitialDirContext idc = context();
        idc.search("ou=users", filter, new Object[]{}, null);
    }
    javax.naming.directory.InitialDirContext context() { return null; }
}`,
	}
	rules := javaTaintRules(t, files)
	if !rules["java-taint-ldap-search"] {
		t.Errorf("hostile over-long FQN poisoned the document: the real LDAP flow was not proven (rules: %v)", javaRuleList(rules))
	}
}

// TestJavaInlineFQNCountCapMarksTruncated proves that once a file exceeds the per-file synthetic-import cap,
// the extractor marks the document truncated instead of silently dropping later fully-qualified types. A
// silent drop would suppress an import-gated sink and read as a proven-clean result, violating the EPIC's
// no-false-suppression guardrail.
func TestJavaInlineFQNCountCapMarksTruncated(t *testing.T) {
	var b strings.Builder
	b.WriteString("public class C {\n  void m() {\n")
	for i := 0; i < maxSyntheticFQNTypes+8; i++ {
		fmt.Fprintf(&b, "    a.b.T%d v%d = null;\n", i, i)
	}
	b.WriteString("  }\n}\n")
	root := t.TempDir()
	writeFile(t, root, "C.java", b.String())
	doc, err := JavaFactsFor(context.Background(), root)
	if err != nil {
		t.Fatalf("JavaFactsFor: %v", err)
	}
	if !doc.Truncated {
		t.Error("exceeding the synthetic-import cap must mark the document truncated, not silently drop types")
	}
}
