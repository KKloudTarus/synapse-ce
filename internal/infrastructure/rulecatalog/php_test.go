package rulecatalog_test

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func TestPHPRuleFamilyInventory(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default(): %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("List(): %v", err)
	}
	want := map[string]int{
		"bugs": 30, "err": 10, "res": 6, "inj": 25, "crypto": 12,
		"authz": 10, "hotspot": 15, "api": 30, "types": 12, "perf": 8, "maint": 22,
	}
	required := map[string]bool{
		"php:sql-concat": false, "php:echo-unescaped": false, "php:eval-usage": false,
		"php:command-exec": false, "php:dynamic-include": false, "php:unserialize-untrusted": false,
		"php:weak-password-hash": false, "php:loose-comparison": false, "php:unvalidated-upload": false,
		"php:header-injection": false, "php:display-errors-on": false, "php:cognitive-complexity": false,
	}
	got := map[string]int{}
	php := 0
	for _, r := range rules {
		if r.Language != "PHP" {
			continue
		}
		php++
		if _, ok := required[string(r.Key)]; ok {
			required[string(r.Key)] = true
		}
		for _, tag := range r.Tags {
			if _, ok := want[tag]; ok {
				got[tag]++
			}
		}
	}
	if php != 180 {
		t.Fatalf("PHP catalog has %d rules, want 180", php)
	}
	for family, count := range want {
		if got[family] != count {
			t.Errorf("family %s has %d rules, want %d", family, got[family], count)
		}
	}
	for key, found := range required {
		if !found {
			t.Errorf("required seed rule %s is missing", key)
		}
	}
	profile, ok := qualityprofile.BuiltIn("PHP", rules)
	if !ok || len(profile.ActivatedRules) != 180 {
		t.Fatalf("PHP built-in profile activates %d rules, ok=%v", len(profile.ActivatedRules), ok)
	}
}
