package ownadvisory

import "testing"

func TestCPEToEcosystem(t *testing.T) {
	cases := []struct {
		name, cpe     string
		eco, pkg, ver string
		ok            bool
	}{
		{"python/django", "cpe:2.3:a:djangoproject:django:3.2.1:*:*:*:*:python:*:*", "PyPI", "django", "3.2.1", true},
		{"npm via node.js", "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*", "npm", "lodash", "4.17.20", true},
		{"version ANY", "cpe:2.3:a:x:flask:*:*:*:*:*:python:*:*", "PyPI", "flask", "*", true},
		{"PyPI canonicalized", "cpe:2.3:a:x:Django_REST:1.0:*:*:*:*:python:*:*", "PyPI", "django-rest", "1.0", true},
		{"unmapped target_sw (apache http)", "cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*", "", "", "", false},
		// Go + Maven are deliberately NOT mapped: their package key (module path / groupId:artifactId) is not
		// the CPE product, so a mapping would mis-key – and Go's comparator would amplify it (security HIGH).
		{"go module not keyed by CPE product", "cpe:2.3:a:etcd-io:etcd:3.5.0:*:*:*:*:go:*:*", "", "", "", false},
		{"maven not keyed by CPE product", "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:maven:*:*", "", "", "", false},
		{"rubygems has no range comparator yet", "cpe:2.3:a:x:rails:6.0.0:*:*:*:*:ruby:*:*", "", "", "", false},
		{"OS part is not a package", "cpe:2.3:o:linux:linux_kernel:5.0:*:*:*:*:*:*:*", "", "", "", false},
		{"cpe 2.2 URI form", "cpe:/a:vendor:product", "", "", "", false},
		{"too few components", "cpe:2.3:a:vendor:product", "", "", "", false},
		{"empty", "", "", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eco, pkg, ver, ok := cpeToEcosystem(c.cpe)
			if ok != c.ok || eco != c.eco || pkg != c.pkg || ver != c.ver {
				t.Errorf("cpeToEcosystem(%q) = (%q,%q,%q,%v), want (%q,%q,%q,%v)", c.cpe, eco, pkg, ver, ok, c.eco, c.pkg, c.ver, c.ok)
			}
		})
	}
}

func TestSplitCPEHandlesEscapedColon(t *testing.T) {
	// CPE 2.3 escapes ':' as "\:" inside a component – a naive split would over-split.
	parts := splitCPE(`cpe:2.3:a:ven\:dor:prod:1.0:*:*:*:*:python:*:*`)
	if len(parts) != 13 {
		t.Fatalf("escaped colon must not over-split: want 13 components, got %d (%v)", len(parts), parts)
	}
	if parts[3] != `ven\:dor` {
		t.Errorf("the escaped colon must stay within the vendor field, got %q", parts[3])
	}
	if got := unescapeCPE(parts[3]); got != "ven:dor" {
		t.Errorf("unescapeCPE must restore the literal colon, got %q", got)
	}
}

func TestUnescapeCPE(t *testing.T) {
	for in, want := range map[string]string{
		`django`:       "django",
		`django\-rest`: "django-rest",
		`a\\b`:         `a\b`,
		`x\:y`:         "x:y",
	} {
		if got := unescapeCPE(in); got != want {
			t.Errorf("unescapeCPE(%q) = %q, want %q", in, got, want)
		}
	}
}
