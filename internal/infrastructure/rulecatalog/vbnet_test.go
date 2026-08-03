package rulecatalog_test

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

func TestVBNetRulePackContract(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default(): %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("List(): %v", err)
	}

	wantFamilies := map[string]int{
		"bugs": 25, "err": 12, "res": 10, "conc": 8, "inj": 15, "crypto": 10,
		"authz": 6, "hotspot": 12, "api": 20, "types": 10, "perf": 6, "maint": 6,
	}
	gotFamilies := make(map[string]int, len(wantFamilies))
	var vbRules []rule.Rule
	for _, entry := range rules {
		if entry.Language != "VB.NET" {
			continue
		}
		vbRules = append(vbRules, entry)
		if entry.Detection != rule.DetectionPattern {
			t.Errorf("rule %s detection = %q, want pattern", entry.Key, entry.Detection)
		}
		families := 0
		for _, tag := range entry.Tags {
			if _, ok := wantFamilies[tag]; ok {
				gotFamilies[tag]++
				families++
			}
		}
		if families != 1 {
			t.Errorf("rule %s has %d family tags, want 1", entry.Key, families)
		}
	}
	if len(vbRules) != 140 {
		t.Fatalf("VB.NET catalog has %d rules, want 140", len(vbRules))
	}
	for family, want := range wantFamilies {
		if got := gotFamilies[family]; got != want {
			t.Errorf("family %s has %d rules, want %d", family, got, want)
		}
	}

	seeds := map[rule.Key]struct {
		type_    rule.Type
		severity shared.Severity
	}{
		"vb:on-error-resume-next":     {rule.TypeBug, shared.SeverityHigh},
		"vb:option-strict-off":        {rule.TypeCodeSmell, shared.SeverityMedium},
		"vb:empty-catch":              {rule.TypeBug, shared.SeverityMedium},
		"vb:sql-concat":               {rule.TypeVulnerability, shared.SeverityHigh},
		"vb:process-start-var":        {rule.TypeSecurityHotspot, shared.SeverityHigh},
		"vb:weak-hash":                {rule.TypeSecurityHotspot, shared.SeverityMedium},
		"vb:idisposable-not-disposed": {rule.TypeBug, shared.SeverityMedium},
		"vb:hardcoded-conn-string":    {rule.TypeSecurityHotspot, shared.SeverityHigh},
	}
	for key, want := range seeds {
		entry, err := cat.Get(context.Background(), key)
		if err != nil {
			t.Errorf("seed rule %s missing: %v", key, err)
			continue
		}
		if entry.Type != want.type_ || entry.DefaultSeverity != want.severity {
			t.Errorf("seed rule %s contract = %s/%s, want %s/%s", key, entry.Type, entry.DefaultSeverity, want.type_, want.severity)
		}
	}

	profile, ok := qualityprofile.BuiltIn("VB.NET", rules)
	if !ok {
		t.Fatal("VB.NET built-in profile missing")
	}
	if profile.Key != "synapse-way-vbnet" || len(profile.ActivatedRules) != 140 {
		t.Fatalf("VB.NET built-in profile = key %q, %d rules", profile.Key, len(profile.ActivatedRules))
	}
}
