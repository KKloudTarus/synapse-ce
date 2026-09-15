package scabench

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

type historicalReferenceInventory struct {
	SchemaVersion                   string `json:"schema_version"`
	Classification                  string `json:"classification"`
	CaseCount                       int    `json:"case_count"`
	InaccessibleHistoricalCitations int    `json:"inaccessible_historical_citation_count"`
	NativeReplayRequired            bool   `json:"native_replay_required"`
	ReconstructableEvidence         struct {
		Capture     bool `json:"capture"`
		Review      bool `json:"review"`
		Bundle      bool `json:"bundle"`
		Environment bool `json:"environment"`
	} `json:"reconstructable_evidence"`
	ControlDigest string             `json:"control_digest"`
	Files         []ContentReference `json:"files"`
}

func TestHistoricalReferenceInventoryControlsEveryFixturePathAndByte(t *testing.T) {
	inventory := readHistoricalReferenceInventory(t)
	root := historicalReferenceFixtureRoot(t)
	if inventory.SchemaVersion != "synapse-sca-benchmark-historical-reference-inventory-v1" || inventory.Classification != "historical_reducer_regression_evidence_only" {
		t.Fatalf("historical inventory classification = %q/%q", inventory.SchemaVersion, inventory.Classification)
	}
	if inventory.CaseCount != 628 || inventory.InaccessibleHistoricalCitations != 698 || !inventory.NativeReplayRequired {
		t.Fatalf("historical inventory limitations = %+v", inventory)
	}
	if inventory.ReconstructableEvidence.Capture || inventory.ReconstructableEvidence.Review || inventory.ReconstructableEvidence.Bundle || inventory.ReconstructableEvidence.Environment {
		t.Fatalf("historical inventory claimed reconstructable evidence: %+v", inventory.ReconstructableEvidence)
	}
	oracleBody, err := os.ReadFile(filepath.Join(root, "oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	oracle, err := DecodeOracle(bytes.NewReader(oracleBody))
	if err != nil {
		t.Fatal(err)
	}
	inaccessibleCitations := make(map[string]struct{})
	for _, item := range oracle.Cases {
		for _, citation := range item.Citations {
			if strings.HasPrefix(citation.Reference, "file://") {
				inaccessibleCitations[citation.Reference] = struct{}{}
			}
		}
	}
	if len(oracle.Cases) != inventory.CaseCount || len(inaccessibleCitations) != inventory.InaccessibleHistoricalCitations {
		t.Fatalf("historical oracle cases/distinct inaccessible citations = %d/%d, want %d/%d", len(oracle.Cases), len(inaccessibleCitations), inventory.CaseCount, inventory.InaccessibleHistoricalCitations)
	}
	control, err := CanonicalJSON(inventory.Files)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.ControlDigest != SHA256Digest(control) {
		t.Fatalf("historical inventory control digest = %q", inventory.ControlDigest)
	}

	actual := make(map[string]ContentReference)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("historical fixture contains a symlink: %s", relative)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("historical fixture contains a non-regular file: %s", relative)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		actual[relative] = ContentReference{Locator: relative, Digest: SHA256Digest(body), Size: int64(len(body))}
		return nil
	}); err != nil {
		t.Fatalf("walk historical fixture: %v", err)
	}
	wanted := make(map[string]ContentReference, len(inventory.Files))
	for _, file := range inventory.Files {
		if err := file.Validate(); err != nil {
			t.Fatalf("inventory file %q: %v", file.Locator, err)
		}
		if _, duplicate := wanted[file.Locator]; duplicate {
			t.Fatalf("inventory contains duplicate locator %q", file.Locator)
		}
		wanted[file.Locator] = file
	}
	assertHistoricalNames(t, actual, wanted)
	for locator, expected := range wanted {
		if actual[locator] != expected {
			t.Errorf("historical fixture %q identity = %+v, want %+v", locator, actual[locator], expected)
		}
	}
}

func readHistoricalReferenceInventory(t *testing.T) historicalReferenceInventory {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve historical inventory path")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(source), "testdata", "historical-reference-inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inventory historicalReferenceInventory
	if err := strictDecode(bytes.NewReader(body), &inventory); err != nil {
		t.Fatalf("decode historical inventory: %v", err)
	}
	return inventory
}

func historicalReferenceFixtureRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve historical fixture path")
	}
	return filepath.Join(filepath.Dir(source), "testdata", "reference")
}

func assertHistoricalNames(t *testing.T, actual, expected map[string]ContentReference) {
	t.Helper()
	actualNames := make([]string, 0, len(actual))
	for name := range actual {
		actualNames = append(actualNames, name)
	}
	expectedNames := make([]string, 0, len(expected))
	for name := range expected {
		expectedNames = append(expectedNames, name)
	}
	sort.Strings(actualNames)
	sort.Strings(expectedNames)
	if len(actualNames) != len(expectedNames) {
		t.Fatalf("historical fixture path count = %d, want %d", len(actualNames), len(expectedNames))
	}
	for index := range actualNames {
		if actualNames[index] != expectedNames[index] {
			t.Fatalf("historical fixture paths differ: got %v, want %v", actualNames, expectedNames)
		}
	}
}
