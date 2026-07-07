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
