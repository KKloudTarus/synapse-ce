package scabench

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestRunFalsifierSpecMaterializesEveryHistoricalRecipe(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve falsifier spec path")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "..", "usecase", "scabench", "testdata", "semantic-comparison-falsifiers.json"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := bench.DecodeFalsifierSpec(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	results, err := RunFalsifierSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 41 {
		t.Fatalf("result count = %d, want 41", len(results))
	}
	for _, result := range results {
		if result.BaselineDigest == result.MutationDigest || result.BaselineDigest == "" || result.MutationDigest == "" {
			t.Fatalf("result %q did not retain distinct generated roots: %+v", result.ID, result)
		}
		if result.ObservedOutcome != result.ExpectedOutcome || result.Operation != "semantic_bundle_comparator" || result.ReasonCode == "" {
			t.Fatalf("result %q is incomplete or unexpected: %+v", result.ID, result)
		}
		if result.ObservedOutcome == "rejected" && result.Reason == "" {
			t.Fatalf("rejected result %q lacks an actual stable reason", result.ID)
		}
	}
}

func TestRunFalsifierSpecRejectsAlteredRecipeMetadata(t *testing.T) {
	entry := historicalFalsifierRecipes["grype_allowed_metadata_change_accepted"]
	spec := bench.FalsifierSpec{SchemaVersion: bench.FalsifierSpecSchemaVersion, Entries: []bench.FalsifierEntry{{ID: "grype_allowed_metadata_change_accepted", Capability: "semantic-full-bundle-comparator", Engine: entry.Engine, Baseline: entry.Baseline, Mutation: "wrong-mutation", ExpectedOutcome: entry.ExpectedOutcome, Operation: "semantic_bundle_comparator"}}}
	if _, err := RunFalsifierSpec(spec); err == nil {
		t.Fatal("falsifier runner accepted altered recipe metadata")
	}
}
