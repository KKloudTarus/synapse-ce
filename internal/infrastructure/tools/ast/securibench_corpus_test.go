package ast

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSecuribench(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "securibench", "micro", "basic")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "package securibench.micro.basic;\n" +
		"class Basic1 {\n" +
		"  void doGet(HttpServletRequest req, HttpServletResponse resp) {\n" +
		"    String s = req.getParameter(\"name\");\n" +
		"    writer.println(s);            /* BAD */\n" + // line 5: XSS true
		"    writer.println(clean(s));     /* OK */\n" + // line 6: XSS safe
		"    stmt.executeQuery(\"...\" + s); /* BAD */\n" + // line 7: SQL true
		"    resp.sendRedirect(s);         /* BAD */\n" + // line 8: unmodeled sink -> unclassified
		"    int x = s.length();\n" + // line 9: no marker
		"  }\n" +
		"}\n"
	if err := os.WriteFile(filepath.Join(pkg, "Basic1.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	corpus, err := loadSecuribench(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if corpus.Unclassified != 1 {
		t.Errorf("sendRedirect marker must count as unclassified (unmodeled sink); got %d", corpus.Unclassified)
	}
	if len(corpus.Cases) != 3 {
		t.Fatalf("want 3 classified cases (XSS true, XSS safe, SQL true); got %d: %+v", len(corpus.Cases), corpus.Cases)
	}
	want := map[string]struct {
		cwe  string
		real bool
	}{
		"securibench/micro/basic/Basic1.java:5": {"CWE-79", true},
		"securibench/micro/basic/Basic1.java:6": {"CWE-79", false},
		"securibench/micro/basic/Basic1.java:7": {"CWE-89", true},
	}
	for _, c := range corpus.Cases {
		w, ok := want[c.Name]
		if !ok {
			t.Errorf("unexpected case %q", c.Name)
			continue
		}
		if c.CWE != w.cwe || c.Real != w.real {
			t.Errorf("case %q: got cwe=%s real=%v, want cwe=%s real=%v", c.Name, c.CWE, c.Real, w.cwe, w.real)
		}
	}
}
