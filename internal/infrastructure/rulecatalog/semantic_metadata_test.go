package rulecatalog

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
)

func TestAuditRuleMetadataDisambiguatesReviewedDisplayNames(t *testing.T) {
	entries := []rule.Rule{
		{Key: "cpp:empty-catch-clause", Name: "Empty catch block"},
		{Key: "csharp-ast-empty-catch", Name: "Empty catch block"},
		{Key: "js-ast-ternary-boolean", Name: "Ternary returning boolean literals"},
		{Key: "js-node-domain-module", Name: "Deprecated domain module"},
		{Key: "js-node-punycode-module", Name: "Deprecated punycode module"},
		{Key: "js-node-sys-module", Name: "Removed sys module"},
		{Key: "js-no-process-exit", Name: "process.exit() in library code"},
		{Key: "php:get-magic-quotes", Name: "Removed magic quotes API"},
		{Key: "php:set-magic-quotes", Name: "Removed magic quotes API"},
		{Key: "rust:swallowed-error-let-underscore", Name: "Result discarded with let _"},
		{Key: "vb:process-start-variable", Name: "Process.Start receives a variable command"},
	}
	want := []string{
		"Structurally empty catch clause",
		"Structurally empty catch clause",
		"Redundant boolean-literal ternary expression",
		"Deprecated domain module import",
		"Deprecated built-in punycode module import",
		"Removed sys module import",
		"Abrupt process.exit() termination",
		"Removed get_magic_quotes_gpc API",
		"Removed set_magic_quotes_runtime API",
		"Result discarded by wildcard assignment",
		"Process.Start first argument is a variable",
	}

	got, err := auditRuleMetadata(entries)
	if err != nil {
		t.Fatalf("auditRuleMetadata() error: %v", err)
	}
	for i := range want {
		if got[i].Name != want[i] {
			t.Errorf("rule %s name = %q, want %q", got[i].Key, got[i].Name, want[i])
		}
		if entries[i].Name == got[i].Name {
			t.Errorf("fixture for %s did not exercise a display-name override", got[i].Key)
		}
	}
}
