package rulecatalog_test

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func TestKotlinRuleFamilyInventory(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default(): %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("List(): %v", err)
	}
	want := map[string]int{
		"bugs": 22, "err": 8, "res": 6, "conc": 12, "inj": 8, "crypto": 6,
		"authz": 3, "hotspot": 8, "api": 15, "types": 12, "perf": 8, "maint": 22,
	}
	got := map[string]int{}
	kotlin := 0
	for _, r := range rules {
		if r.Language != "Kotlin" {
			continue
		}
		kotlin++
		for family := range want {
			for _, tag := range r.Tags {
				if tag == family {
					got[family]++
				}
			}
		}
	}
	if kotlin != 130 {
		t.Fatalf("Kotlin catalog has %d rules, want 130", kotlin)
	}
	for family, count := range want {
		if got[family] != count {
			t.Errorf("family %s has %d rules, want %d", family, got[family], count)
		}
	}
	profile, ok := qualityprofile.BuiltIn("Kotlin", rules)
	if !ok || len(profile.ActivatedRules) != 130 {
		t.Fatalf("Kotlin built-in profile activates %d rules, ok=%v", len(profile.ActivatedRules), ok)
	}
}
