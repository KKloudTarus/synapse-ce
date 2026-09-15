package scabench

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSemanticComparisonFalsifierSpecMatchesHistoricalComparisonKeys(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve falsifier spec path")
	}
	root := filepath.Dir(source)
	specBody, err := os.ReadFile(filepath.Join(root, "testdata", "semantic-comparison-falsifiers.json"))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := DecodeFalsifierSpec(bytes.NewReader(specBody))
	if err != nil {
		t.Fatalf("decode falsifier spec: %v", err)
	}
	comparisonBody, err := os.ReadFile(filepath.Join(root, "testdata", "reference", "comparison.json"))
	if err != nil {
		t.Fatal(err)
	}
	var comparison struct {
		Falsifiers map[string]bool `json:"falsifiers"`
	}
	if err := json.Unmarshal(comparisonBody, &comparison); err != nil {
		t.Fatal(err)
	}
	if len(spec.Entries) != len(comparison.Falsifiers) {
		t.Fatalf("falsifier entry count = %d, historical comparison key count = %d", len(spec.Entries), len(comparison.Falsifiers))
	}
	for _, entry := range spec.Entries {
		if _, exists := comparison.Falsifiers[entry.ID]; !exists {
			t.Errorf("falsifier spec adds non-historical key %q", entry.ID)
		}
	}
	for id := range comparison.Falsifiers {
		found := false
		for _, entry := range spec.Entries {
			if entry.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("falsifier spec omits historical key %q", id)
		}
	}
}
