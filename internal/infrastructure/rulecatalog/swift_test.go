package rulecatalog

import (
	"context"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
)

func TestSwiftRuleInventory(t *testing.T) {
	rules := swiftRules()
	if len(rules) != 120 {
		t.Fatalf("Swift rules = %d, want 120", len(rules))
	}
	wantFamilies := map[string]int{"bugs": 25, "err": 6, "res": 8, "conc": 10, "inj": 8, "crypto": 6, "hotspot": 8, "api": 15, "types": 15, "perf": 8, "maint": 11}
	families := map[string]int{}
	seen := map[rule.Key]bool{}
	for _, r := range rules {
		if !strings.HasPrefix(string(r.Key), "swift:") || r.Language != "Swift" {
			t.Fatalf("invalid Swift catalog rule: %+v", r)
		}
		if seen[r.Key] {
			t.Fatalf("duplicate rule %q", r.Key)
		}
		seen[r.Key] = true
		if err := r.Validate(); err != nil {
			t.Fatalf("invalid rule %q: %v", r.Key, err)
		}
		for _, tag := range r.Tags {
			if strings.HasPrefix(tag, "swift-") && wantFamilies[strings.TrimPrefix(tag, "swift-")] > 0 {
				families[strings.TrimPrefix(tag, "swift-")]++
			}
		}
		if strings.Contains(r.Description, "rule's bounded detection shape") || strings.Contains(r.Description, "Reports . It") || !strings.Contains(r.Description, "does not prove") {
			t.Fatalf("generic or incomplete Swift description for %q: %q", r.Key, r.Description)
		}
		if !strings.Contains(r.Rationale, "\n\nSource: https://") {
			t.Fatalf("Swift rationale lacks concrete HTTPS source for %q: %q", r.Key, r.Rationale)
		}
	}
	for family, want := range wantFamilies {
		if got := families[family]; got != want {
			t.Errorf("Swift %s rules = %d, want %d", family, got, want)
		}
	}
	if got := rules[len(rules)-1]; got.Key != "swift:redundant-self" {
		t.Fatalf("last frozen Swift rule = %q", got.Key)
	}
	profile, ok := qualityprofile.BuiltIn("Swift", rules)
	if !ok || len(profile.ActivatedRules) != len(rules) {
		t.Fatalf("Swift built-in profile activates %d rules, want %d", len(profile.ActivatedRules), len(rules))
	}
}

func TestSwiftCatalogRuntimeMetadata(t *testing.T) {
	catalog, err := Default()
	if err != nil {
		t.Fatalf("Default(): %v", err)
	}
	rules, err := catalog.List(context.Background())
	if err != nil {
		t.Fatalf("List(): %v", err)
	}
	byKey := map[rule.Key]rule.Rule{}
	for _, r := range rules {
		if r.Language == "Swift" {
			byKey[r.Key] = r
		}
	}
	if len(byKey) != 120 {
		t.Fatalf("Swift catalog entries = %d, want 120", len(byKey))
	}
	for _, key := range []string{"swift:ats-disabled", "swift:cognitive-complexity"} {
		if _, ok := byKey[rule.Key(key)]; !ok {
			t.Errorf("missing non-AST Swift metadata for %s", key)
		}
	}
}
