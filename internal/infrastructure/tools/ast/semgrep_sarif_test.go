package ast

import (
	"strings"
	"testing"
)

const sampleSemgrepSARIF = `{
  "runs": [{
    "tool": {"driver": {"rules": [
      {"id": "java.xss.rule", "properties": {"tags": ["CWE-79: Cross-site Scripting", "security"]}},
      {"id": "java.sqli.rule", "properties": {"tags": ["OWASP-A03", "CWE-89: SQL Injection"]}},
      {"id": "java.style.rule", "properties": {"tags": ["maintainability"]}}
    ]}},
    "results": [
      {"ruleId": "java.xss.rule", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "securibench/micro/basic/Basic1.java"}, "region": {"startLine": 39}}}]},
      {"ruleId": "java.sqli.rule", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a/b/Basic21.java"}, "region": {"startLine": 50}}}]},
      {"ruleId": "java.style.rule", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "x/Style.java"}, "region": {"startLine": 3}}}]},
      {"ruleId": "java.xss.rule", "locations": []},
      {"ruleId": "rule.not.in.table", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "y/Ghost.java"}, "region": {"startLine": 7}}}]}
    ]
  }]
}`

func TestParseSemgrepSARIF(t *testing.T) {
	findings, skipped, err := parseSemgrepSARIF(strings.NewReader(sampleSemgrepSARIF))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Skipped: the style rule (no CWE tag), the locationless result, and the result whose ruleId is absent
	// from the rules table (a lookup miss must not be misclassified as a finding).
	if skipped != 3 {
		t.Errorf("want 3 skipped (no-CWE rule + locationless result + unknown ruleId); got %d", skipped)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings; got %d: %+v", len(findings), findings)
	}
	// Findings are keyed by base filename with the CWE from the matched rule's tags.
	got := map[string]sarifFinding{}
	for _, f := range findings {
		got[f.File] = sarifFinding{f.CWE, f.Line}
	}
	if g := got["Basic1.java"]; g.cwe != "CWE-79" || g.line != 39 {
		t.Errorf("Basic1.java: got %+v, want CWE-79 line 39", g)
	}
	if g := got["Basic21.java"]; g.cwe != "CWE-89" || g.line != 50 {
		t.Errorf("Basic21.java (base of a/b/Basic21.java): got %+v, want CWE-89 line 50", g)
	}
}

type sarifFinding struct {
	cwe  string
	line int
}

func TestCWEFromTags(t *testing.T) {
	cases := []struct {
		tags []string
		want string
	}{
		{[]string{"CWE-79: Cross-site Scripting", "security"}, "CWE-79"},
		{[]string{"OWASP-A03", "CWE-89: SQL Injection"}, "CWE-89"},
		{[]string{"maintainability", "MEDIUM CONFIDENCE"}, ""},
		{[]string{"SomethingCWE-79"}, ""}, // unanchored: must not match mid-string
		{[]string{"CWE-"}, ""},            // no digits: must not match
		{[]string{"  CWE-1234: padded"}, "CWE-1234"},
		{nil, ""},
	}
	for _, tc := range cases {
		if got := cweFromTags(tc.tags); got != tc.want {
			t.Errorf("cweFromTags(%v) = %q, want %q", tc.tags, got, tc.want)
		}
	}
}
