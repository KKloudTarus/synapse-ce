package taintrules

import (
	"os"
	"path/filepath"
	"testing"
)

const validYAML = `
python:
  sources:
    - modules: ["myframework"]
      names: ["read_body"]
  sinks:
    - modules: ["myorm"]
      names: ["raw_query"]
      class: "sql"
      cwe: "CWE-89"
      rule: "myorm-sqli"
      argument: 0
`

func TestLoadBytesValid(t *testing.T) {
	rules, err := LoadBytes([]byte(validYAML))
	if err != nil {
		t.Fatalf("valid rules must load: %v", err)
	}
	if len(rules.Python.Sources) != 1 || len(rules.Python.Sinks) != 1 {
		t.Fatalf("parsed rules wrong: %+v", rules)
	}
	if rules.Python.Sinks[0].Rule != "myorm-sqli" || rules.Python.Sinks[0].Class != "sql" {
		t.Errorf("sink fields wrong: %+v", rules.Python.Sinks[0])
	}
}

func TestLoadBytesRejectsUnknownField(t *testing.T) {
	// A misspelled key must be an error, not a silently-empty ruleset.
	bad := `
python:
  sinks:
    - modules: ["m"]
      names: ["n"]
      clas: "sql"
      cwe: "CWE-89"
      rule: "r"
`
	if _, err := LoadBytes([]byte(bad)); err == nil {
		t.Error("a misspelled field (clas) must fail to parse")
	}
}

func TestLoadBytesRejectsInvalidRule(t *testing.T) {
	bad := `
python:
  sinks:
    - modules: ["m"]
      names: ["n"]
      class: "bogus"
      cwe: "CWE-1"
      rule: "r"
`
	if _, err := LoadBytes([]byte(bad)); err == nil {
		t.Error("an unknown taint class must fail validation")
	}
}

func TestLoadEmptyPathIsNoRules(t *testing.T) {
	// No path configured means "use built-ins only", not an error.
	if _, found, err := Load(""); found || err != nil {
		t.Errorf("empty path: found=%v err=%v", found, err)
	}
}

func TestLoadConfiguredMissingFileErrors(t *testing.T) {
	// A configured-but-missing file is an operator error: it must NOT silently drop their rules.
	missing := filepath.Join(t.TempDir(), "nope.yaml")
	if _, found, err := Load(missing); err == nil || found {
		t.Errorf("a configured missing file must error, got found=%v err=%v", found, err)
	}
}

func TestLoadBytesRejectsMultiDocument(t *testing.T) {
	// A trailing YAML document must not be silently ignored (its rules would be dropped).
	multi := validYAML + "\n---\npython:\n  sinks:\n    - modules: [\"m\"]\n      names: [\"n\"]\n      class: \"sql\"\n      cwe: \"CWE-89\"\n      rule: \"r\"\n"
	if _, err := LoadBytes([]byte(multi)); err == nil {
		t.Error("a multi-document rule file must be rejected")
	}
}

func TestLoadBytesRejectsBadCWEFormat(t *testing.T) {
	bad := `
python:
  sinks:
    - modules: ["m"]
      names: ["n"]
      class: "sql"
      cwe: "CWE-not-a-number"
      rule: "r"
`
	if _, err := LoadBytes([]byte(bad)); err == nil {
		t.Error("a non-numeric CWE must fail validation")
	}
}

func TestLoadFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(p, []byte(validYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, found, err := Load(p)
	if err != nil || !found {
		t.Fatalf("load: found=%v err=%v", found, err)
	}
	if len(rules.Python.Sinks) != 1 {
		t.Errorf("loaded rules wrong: %+v", rules)
	}
}
