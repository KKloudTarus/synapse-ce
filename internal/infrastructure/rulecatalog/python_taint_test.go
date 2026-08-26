package rulecatalog

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

func TestPythonTaintCatalogRulesHaveCompleteFirstPartyMetadata(t *testing.T) {
	metadata := map[string]bool{}
	for _, item := range pythonTaintRules() {
		if err := item.Validate(); err != nil {
			t.Fatalf("rule %s: %v", item.Key, err)
		}
		metadata[string(item.Key)] = true
	}
	if len(metadata) != 7 {
		t.Fatalf("metadata rules = %d, want seven taint classes", len(metadata))
	}
	used := map[string]bool{}
	for _, sink := range taint.DefaultPythonCatalog().Sinks {
		if !metadata[sink.Rule] {
			t.Errorf("sink rule %q has no first-party metadata", sink.Rule)
		}
		used[sink.Rule] = true
	}
	for key := range metadata {
		if !used[key] {
			t.Errorf("documented Python taint rule %q has no sink model", key)
		}
	}
}
