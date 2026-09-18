package qualityprofile

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func presetRules() []rule.Rule {
	return []rule.Rule{
		{Key: "go-crit", Language: "Go", DefaultSeverity: shared.SeverityCritical},
		{Key: "go-med", Language: "Go", DefaultSeverity: shared.SeverityMedium},
		{Key: "go-info", Language: "Go", DefaultSeverity: shared.SeverityInfo},
		{Key: "py-low", Language: "Python", DefaultSeverity: shared.SeverityLow},
	}
}

func TestRecommendedDropsInfoRules(t *testing.T) {
	p, ok := Recommended("Go", presetRules())
	if !ok || p.Key != "recommended-go" || !p.BuiltIn {
		t.Fatalf("recommended = %+v ok=%v", p, ok)
	}
	if !p.Active("go-crit") || !p.Active("go-med") {
		t.Fatal("recommended must keep low-and-above rules")
	}
	if p.Active("go-info") {
		t.Fatal("recommended must drop info-level rules")
	}
	if p.ActivatedRules["go-crit"].Severity != "" {
		t.Fatal("recommended keeps default severities")
	}
}

func TestStrictEscalatesEveryRule(t *testing.T) {
	p, ok := Strict("Go", presetRules())
	if !ok || p.Key != "strict-go" {
		t.Fatalf("strict = %+v ok=%v", p, ok)
	}
	// info -> low, medium -> high, critical stays critical; every rule stays active.
	if p.ActivatedRules["go-info"].Severity != shared.SeverityLow {
		t.Fatalf("go-info escalated to %q, want low", p.ActivatedRules["go-info"].Severity)
	}
	if p.ActivatedRules["go-med"].Severity != shared.SeverityHigh {
		t.Fatalf("go-med escalated to %q, want high", p.ActivatedRules["go-med"].Severity)
	}
	if p.ActivatedRules["go-crit"].Severity != shared.SeverityCritical {
		t.Fatalf("go-crit escalated to %q, want critical", p.ActivatedRules["go-crit"].Severity)
	}
	if len(p.ActivatedRules) != 3 {
		t.Fatalf("strict must keep every Go rule active, got %d", len(p.ActivatedRules))
	}
}

func TestPresetsOrderAndLanguageScope(t *testing.T) {
	presets := Presets("Go", presetRules())
	if len(presets) != 3 {
		t.Fatalf("want 3 Go presets, got %d", len(presets))
	}
	if presets[0].Key != "synapse-way-go" || presets[1].Key != "recommended-go" || presets[2].Key != "strict-go" {
		t.Fatalf("preset order = %v", []string{presets[0].Key, presets[1].Key, presets[2].Key})
	}
	// A language with no rules yields no presets.
	if got := Presets("Rust", presetRules()); len(got) != 0 {
		t.Fatalf("Rust presets = %d, want 0", len(got))
	}
}

func TestLanguageSlugIsInjectiveOverCFamily(t *testing.T) {
	got := map[string]string{}
	for _, lang := range []string{"C", "C#", "C++", "F#", "Go"} {
		got[lang] = LanguageSlug(lang)
	}
	want := map[string]string{"C": "c", "C#": "csharp", "C++": "cpp", "F#": "fsharp", "Go": "go"}
	for lang, w := range want {
		if got[lang] != w {
			t.Errorf("LanguageSlug(%q) = %q, want %q", lang, got[lang], w)
		}
	}
	// No two of these languages may share a slug (a collision merges their built-in profile keys).
	seen := map[string]string{}
	for lang, slug := range got {
		if other, dup := seen[slug]; dup {
			t.Fatalf("slug collision: %q and %q both slug to %q", other, lang, slug)
		}
		seen[slug] = lang
	}
}

func TestRecommendedDroppedWhenEveryRuleIsInfo(t *testing.T) {
	rules := []rule.Rule{
		{Key: "sh-a", Language: "Shell", DefaultSeverity: shared.SeverityInfo},
		{Key: "sh-b", Language: "Shell", DefaultSeverity: shared.SeverityInfo},
	}
	if _, ok := Recommended("Shell", rules); ok {
		t.Fatal("Recommended must be dropped (ok=false) when no rule is Low or above, not emit an all-disabling profile")
	}
	// Presets then offers only Synapse way and Strict for such a language.
	presets := Presets("Shell", rules)
	if len(presets) != 2 || presets[0].Key != "synapse-way-shell" || presets[1].Key != "strict-shell" {
		t.Fatalf("presets = %+v, want synapse-way-shell and strict-shell only", presets)
	}
}
