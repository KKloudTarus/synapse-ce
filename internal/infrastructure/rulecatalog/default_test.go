package rulecatalog_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
	"gopkg.in/yaml.v3"
)

func TestDefault_Validation(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default() failed validation: %v", err)
	}
	if cat == nil {
		t.Fatal("expected catalog, got nil")
	}
}

func TestDefault_GoldenInventory(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}

	goldenBytes, err := os.ReadFile(filepath.Join("testdata", "rule_keys.txt"))
	if err != nil {
		t.Fatalf("Failed to read golden file: %v", err)
	}

	goldenRaw := strings.ReplaceAll(string(goldenBytes), "\r\n", "\n")
	if !strings.HasSuffix(goldenRaw, "\n") {
		t.Errorf("Golden file missing final newline")
	}

	lines := strings.Split(goldenRaw, "\n")
	// Drop the final empty line resulting from the trailing newline
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	expectedKeys := make(map[string]bool)
	var prev string
	for i, line := range lines {
		if line == "" {
			t.Errorf("Golden file has blank line at index %d", i)
		}
		if strings.TrimSpace(line) != line {
			t.Errorf("Golden file line %d has surrounding whitespace: %q", i, line)
		}
		if expectedKeys[line] {
			t.Errorf("Golden file has duplicate key: %s", line)
		}
		if i > 0 && line < prev {
			t.Errorf("Golden file not sorted: %q comes after %q", line, prev)
		}
		prev = line
		expectedKeys[line] = true
	}

	if len(expectedKeys) != 212 {
		t.Errorf("Golden file must have exactly 212 rules, found %d", len(expectedKeys))
	}

	actualRules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	actualMap := make(map[string]bool)
	for _, r := range actualRules {
		actualMap[string(r.Key)] = true
	}

	// Report missing keys
	for k := range expectedKeys {
		if !actualMap[k] {
			t.Errorf("Rule %q in golden file but missing from catalog", k)
		}
	}

	// Report extra keys
	for k := range actualMap {
		if !expectedKeys[k] {
			t.Errorf("Rule %q in catalog but not in golden file", k)
		}
	}

	// Test deterministic order
	var actualKeys []string
	for _, r := range actualRules {
		actualKeys = append(actualKeys, string(r.Key))
	}
	if !sort.IsSorted(sort.StringSlice(actualKeys)) {
		t.Errorf("Catalog List() does not return rules in sorted order")
	}
}

func TestDefault_Deterministic(t *testing.T) {
	cat1, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}
	cat2, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}

	list1, err := cat1.List(context.Background())
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}
	list2, err := cat2.List(context.Background())
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	if len(list1) != len(list2) {
		t.Fatalf("Length mismatch: %d vs %d", len(list1), len(list2))
	}

	for i := range list1 {
		if !reflect.DeepEqual(list1[i], list2[i]) {
			t.Fatalf("Non-deterministic rule at index %d: %+v vs %+v", i, list1[i], list2[i])
		}
	}
}

func TestDefault_NoDuplicates(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}

	list, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	seen := make(map[string]bool)
	for _, r := range list {
		if seen[string(r.Key)] {
			t.Fatalf("Duplicate key found in default catalog: %s", r.Key)
		}
		seen[string(r.Key)] = true
	}

	if len(seen) != len(list) {
		t.Fatalf("Length mismatch: %d unique keys vs %d listed rules", len(seen), len(list))
	}
}

func TestDefault_DetectionValuesDocumentedInOpenAPI(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}

	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Enum []rule.Detection `yaml:"enum"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI spec: %v", err)
	}

	enum := spec.Components.Schemas["RuleDetection"].Enum
	if len(enum) == 0 {
		t.Fatal("OpenAPI RuleDetection enum is missing or empty")
	}
	allowed := make(map[rule.Detection]bool, len(enum))
	for _, detection := range enum {
		allowed[detection] = true
	}

	for _, r := range rules {
		if !allowed[r.Detection] {
			t.Errorf("rule %s uses detection %q missing from OpenAPI RuleDetection enum", r.Key, r.Detection)
		}
	}
}

func TestDefault_Isolation(t *testing.T) {
	cat1, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}

	list1, err := cat1.List(context.Background())
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	list1[0].Name = "HACKED"
	list1[0].Qualities[0] = rule.QualityMaintainability
	list1[0].Tags = append(list1[0].Tags, "hacked-tag")
	list1[0].CWE[0] = "CWE-999"
	// OWASP might be empty, so we must safely assign it
	list1[0].OWASP = []string{"A99:2025"}

	cat2, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default() failed: %v", err)
	}

	list2, err := cat2.List(context.Background())
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	if list2[0].Name == "HACKED" || list2[0].Qualities[0] == rule.QualityMaintainability || list2[0].CWE[0] == "CWE-999" {
		t.Fatal("Modifying one Default() result corrupted another")
	}
	if len(list2[0].OWASP) > 0 && list2[0].OWASP[0] == "A99:2025" {
		t.Fatal("OWASP slice isolation failure")
	}
	for _, tag := range list2[0].Tags {
		if tag == "hacked-tag" {
			t.Fatal("Modifying one Default() result corrupted another (tags)")
		}
	}
}
