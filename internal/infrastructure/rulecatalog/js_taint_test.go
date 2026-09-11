package rulecatalog

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

// TestJsTaintCatalogRulesHaveCompleteFirstPartyMetadata pins the JS taint rule metadata to the sinks the
// value-flow catalog actually emits: every documented rule must back a sink, and every sink rule must be
// documented, so a new sink cannot ship without operator-facing metadata (and vice versa).
func TestJsTaintCatalogRulesHaveCompleteFirstPartyMetadata(t *testing.T) {
	metadata := map[string]bool{}
	for _, item := range jsTaintRules() {
		if err := item.Validate(); err != nil {
			t.Fatalf("rule %s: %v", item.Key, err)
		}
		metadata[string(item.Key)] = true
	}
	if len(metadata) != 9 {
		t.Fatalf("metadata rules = %d, want nine JS taint classes", len(metadata))
	}
	used := map[string]bool{}
	for _, sink := range taint.DefaultJsCatalog().Sinks {
		if !metadata[sink.Rule] {
			t.Errorf("sink rule %q has no first-party metadata", sink.Rule)
		}
		used[sink.Rule] = true
	}
	for key := range metadata {
		if !used[key] {
			t.Errorf("documented JS taint rule %q has no sink model", key)
		}
	}
}
