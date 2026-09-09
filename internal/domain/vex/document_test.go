package vex

import "testing"

const sampleVEX = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements": [
    {"vulnerability": {"name": "CVE-2024-1"}, "products": [{"@id": "pkg:npm/lodash@4.17.21"}], "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"},
    {"vulnerability": {"name": "CVE-2024-2"}, "products": [{"@id": "pkg:npm/express"}], "status": "fixed"},
    {"vulnerability": {"name": "CVE-2024-3"}, "products": [{"@id": "pkg:npm/foo@1.0"}], "status": "affected"}
  ]
}`

func TestParse(t *testing.T) {
	doc, err := Parse([]byte(sampleVEX))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(doc.Statements) != 3 {
		t.Fatalf("want 3 statements, got %d", len(doc.Statements))
	}
	if doc.Statements[0].Vulnerability != "CVE-2024-1" || doc.Statements[0].Justification == "" {
		t.Errorf("statement 0 mis-parsed: %+v", doc.Statements[0])
	}
}

func TestParseRejectsJunk(t *testing.T) {
	if _, err := Parse([]byte(`{"not": "vex"}`)); err == nil {
		t.Error("a non-OpenVEX document must error")
	}
	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Error("invalid JSON must error")
	}
	if _, err := Parse([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`)); err == nil {
		t.Error("an empty-statements OpenVEX doc must error")
	}
}

func TestSuppresses(t *testing.T) {
	cases := map[string]bool{"not_affected": true, "fixed": true, "affected": false, "under_investigation": false, "": false}
	for status, want := range cases {
		if got := (Statement{Status: status}).Suppresses(); got != want {
			t.Errorf("Suppresses(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestMatchesFinding(t *testing.T) {
	doc, _ := Parse([]byte(sampleVEX))
	notAffected, fixed := doc.Statements[0], doc.Statements[1]

	// versioned product: matches the exact component+version, and by PURL name.
	if !notAffected.MatchesFinding("CVE-2024-1", "lodash", "4.17.21") {
		t.Error("versioned product must match the exact finding (by PURL name)")
	}
	if notAffected.MatchesFinding("CVE-2024-1", "lodash", "3.0.0") {
		t.Error("a different version must NOT match a versioned product")
	}
	if notAffected.MatchesFinding("CVE-2024-9", "lodash", "4.17.21") {
		t.Error("a different advisory must NOT match")
	}
	// versionless product: matches any version of the component.
	if !fixed.MatchesFinding("CVE-2024-2", "express", "4.18.0") {
		t.Error("a versionless product must match any version")
	}
	if !fixed.MatchesFinding("CVE-2024-2", "express", "3.0.0") {
		t.Error("a versionless product must match any version (2)")
	}
	// wrong component must not match.
	if fixed.MatchesFinding("CVE-2024-2", "koa", "1.0.0") {
		t.Error("a different component must NOT match")
	}
}

func TestComponentMatchScopeAware(t *testing.T) {
	// A scoped npm product must match its own scoped finding and NOT collapse onto a different unscoped one.
	st := Statement{Vulnerability: "CVE-1", Status: "not_affected", Products: []string{"pkg:npm/%40safe/lodash@4.17.21"}}
	if st.MatchesFinding("CVE-1", "lodash", "4.17.21") {
		t.Error("scoped @safe/lodash must NOT match unscoped lodash (false suppression)")
	}
	if !st.MatchesFinding("CVE-1", "@safe/lodash", "4.17.21") {
		t.Error("scoped product must match its own @safe/lodash finding")
	}
	// A literal-@ scope (non-percent-encoded, e.g. from an OpenVEX doc) behaves the same.
	st2 := Statement{Vulnerability: "CVE-1", Status: "not_affected", Products: []string{"pkg:npm/@acme/util@1.0.0"}}
	if st2.MatchesFinding("CVE-1", "util", "1.0.0") {
		t.Error("scoped @acme/util must NOT match unscoped util")
	}
	// A non-scoped namespaced purl (Go, Debian) still collapses to its bare leaf, as findings are keyed.
	st3 := Statement{Vulnerability: "CVE-1", Status: "fixed", Products: []string{"pkg:golang/github.com/gin-gonic/gin@v1.9.1"}}
	if !st3.MatchesFinding("CVE-1", "gin", "v1.9.1") {
		t.Error("Go module must still match its bare-name finding")
	}
	// Scope reconstruction is npm-ONLY: a %40 segment under a non-npm type is an ordinary namespace and
	// must collapse to the bare leaf, never matching an npm scoped finding.
	st4 := Statement{Vulnerability: "CVE-1", Status: "not_affected", Products: []string{"pkg:generic/%40safe/lodash@4.17.21"}}
	if st4.MatchesFinding("CVE-1", "@safe/lodash", "4.17.21") {
		t.Error("a non-npm purl must NOT reconstruct an @scope name and match an npm scoped finding")
	}
	if !st4.MatchesFinding("CVE-1", "lodash", "4.17.21") {
		t.Error("a non-npm namespaced purl still collapses to its bare leaf")
	}
}
