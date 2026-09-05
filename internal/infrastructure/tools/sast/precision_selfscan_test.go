package sast

import "testing"

// TestRulePrecisionSelfScan pins the false positives a full scan of this repository produced (623
// findings, 140 high SAST, most of them noise) and the true positives each tightened rule must keep.
func TestRulePrecisionSelfScan(t *testing.T) {
	handler := "package h\n\nimport (\n\t\"fmt\"\n\t\"net/http\"\n\t\"os\"\n)\n\n"
	for _, tc := range []struct {
		name    string
		rule    string
		file    string
		content string
		want    bool
	}{
		// reflected-response-write: a CLI printing an error to stderr is not an HTTP response.
		{name: "cli error to stderr", rule: "reflected-response-write", file: "cmd/tool/main.go", want: false,
			content: "package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\nfunc main() {\n\terr := run()\n\tfmt.Fprintln(os.Stderr, \"tool:\", err)\n}\n"},
		{name: "cli formatted stdout", rule: "reflected-response-write", file: "cmd/tool/report.go", want: false,
			content: "package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\nfunc report(n int, name string) {\n\tfmt.Fprintf(os.Stdout, \"%d %s\\n\", n, name)\n}\n"},
		{name: "handler fprintf request value", rule: "reflected-response-write", file: "h.go", want: true,
			content: handler + "func h(w http.ResponseWriter, r *http.Request) {\n\tname := r.URL.Query().Get(\"n\")\n\tfmt.Fprintf(w, \"hello %s\", name)\n}\n"},
		{name: "handler fprintln variable", rule: "reflected-response-write", file: "h2.go", want: true,
			content: handler + "func h(w http.ResponseWriter, r *http.Request) {\n\tname := r.FormValue(\"n\")\n\tfmt.Fprintln(w, name)\n}\n"},
		{name: "handler write to a strings builder", rule: "reflected-response-write", file: "h3.go", want: false,
			content: handler + "func h(w http.ResponseWriter, r *http.Request, sb *strings.Builder) {\n\tname := r.FormValue(\"n\")\n\tfmt.Fprintln(sb, name)\n\t_ = os.Stdout\n}\n"},

		// path-traversal-file-access: a variable named path is only evidence where a request exists.
		{name: "test reads a fixture path", rule: "path-traversal-file-access", file: "api/coverage_test.go", want: false,
			content: "package api\n\nimport \"os\"\n\nfunc load(path string) ([]byte, error) {\n\treturn os.ReadFile(path)\n}\n"},
		{name: "cli reads a configured path", rule: "path-traversal-file-access", file: "cmd/agent/journal.go", want: false,
			content: "package main\n\nimport \"os\"\n\nfunc open(path string) (*os.File, error) {\n\treturn os.Open(path)\n}\n"},
		{name: "handler opens a request path", rule: "path-traversal-file-access", file: "files.go", want: true,
			content: handler + "func h(w http.ResponseWriter, r *http.Request) {\n\tf, _ := os.Open(r.URL.Query().Get(\"file\"))\n\tfmt.Fprintln(w, f.Name())\n}\n"},
		{name: "express sendFile request param", rule: "path-traversal-file-access", file: "src/files.js", want: true,
			content: "const express = require('express')\nfunction h(req, res) {\n  res.sendFile(req.params.name)\n}\n"},

		// go-sql-dynamic-query: the request URL's Query() is not database/sql.
		{name: "url query getter", rule: "go-sql-dynamic-query", file: "handler.go", want: false,
			content: handler + "func h(w http.ResponseWriter, r *http.Request) {\n\tq := r.URL.Query().Get(\"q\") + \"\"\n\tfmt.Fprintln(w, len(q))\n}\n"},
		{name: "db query with url query value", rule: "go-sql-dynamic-query", file: "repo.go", want: true,
			content: handler + "func h(w http.ResponseWriter, r *http.Request, db interface{ Query(string) error }) {\n\t_ = db.Query(\"SELECT 1 WHERE a='\" + r.URL.Query().Get(\"q\") + \"'\")\n}\n"},

		// hardcoded-credential: labels that name the concept are not credentials.
		{name: "metric label", rule: "hardcoded-credential", file: "metrics.go", want: false,
			content: "package m\n\nconst MetricNewSecret = \"new_secret\"\n"},
		{name: "pattern set id", rule: "hardcoded-credential", file: "digest.go", want: false,
			content: "package m\n\nconst secretPatternSetID = \"secret-patterns:v2\"\n"},
		{name: "real password literal", rule: "hardcoded-credential", file: "cfg.go", want: true,
			content: "package m\n\nvar dbPassword = \"Tr0ub4dor&3xyzQ9\"\n"},
		{name: "api key literal", rule: "hardcoded-credential", file: "cfg.py", want: true,
			content: "API_KEY = \"AKfj39dKq2LmZp8Rt5\"\n"},

		// jwt-hardcoded-secret-or-none: an identifier ending in Algorithm is not a JWT setting.
		{name: "sampling algorithm none", rule: "jwt-hardcoded-secret-or-none", file: "policy.go", want: false,
			content: "package p\n\nconst NoSamplingAlgorithm = \"none\"\n"},
		{name: "jwt algorithm none", rule: "jwt-hardcoded-secret-or-none", file: "auth.js", want: true,
			content: "const token = jwt.sign(payload, key, { algorithm: \"none\" })\n"},

		// redos-vulnerable-regex: a separator-led nested group repeats unambiguously.
		{name: "version segments", rule: "redos-vulnerable-regex", file: "pep440.go", want: false,
			content: "package v\n\nimport \"regexp\"\n\nvar re = regexp.MustCompile(`^v?([0-9]+(?:\\.[0-9]+)*)$`)\n"},
		{name: "classic nested quantifier", rule: "redos-vulnerable-regex", file: "bad.go", want: true,
			content: "package v\n\nimport \"regexp\"\n\nvar re = regexp.MustCompile(`^(a+)+$`)\n"},
		{name: "wildcard nested quantifier", rule: "redos-vulnerable-regex", file: "bad2.js", want: true,
			content: "const re = new RegExp('^(.*a)*$')\n"},

		// Test code stays reported (the gate classifies it as background scope); prose is not source.
		{name: "test file command still reported", rule: "go-command-dynamic", file: "run_test.go", want: true,
			content: "package m\n\nimport \"os/exec\"\n\nfunc run(userVar string) {\n\texec.Command(\"sh\", userVar)\n}\n"},
		{name: "changelog snippet", rule: "go-command-dynamic", file: "CHANGELOG.md", want: false,
			content: "# Changelog\n\n- `exec.Command(args[0], args[1:]...)` no longer matches.\n"},
		{name: "text file secret still reported", rule: "hardcoded-aws-access-key", file: "creds.txt", want: true,
			content: "AKIAIOSFODNN7QZX4BQ2\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, tc.file, tc.content)
			got := findingsByRule(t, root)[tc.rule]
			if (len(got) > 0) != tc.want {
				t.Errorf("%s fired = %v, want %v (%+v)", tc.rule, len(got) > 0, tc.want, got)
			}
		})
	}
}
