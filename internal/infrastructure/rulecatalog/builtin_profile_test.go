package rulecatalog_test

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/rulecatalog"
)

// TestEveryShippedLanguageHasBuiltInProfile enforces the #185 acceptance criterion at the code level:
// every language present in the shipped rule catalog produces a non-empty built-in "Synapse way"
// profile (P9, #183), so the built-in profile is browsable in the Rules explorer (#182), assignable via
// Quality Profiles (#183), and gate-eligible (#184). Adding a rule for a new language automatically
// gives that language a built-in profile — this test guards that invariant against regressions.
func TestEveryShippedLanguageHasBuiltInProfile(t *testing.T) {
	cat, err := rulecatalog.Default()
	if err != nil {
		t.Fatalf("Default(): %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("List(): %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("the shipped rule catalog is empty")
	}

	byLang := map[string][]rule.Rule{}
	for _, r := range rules {
		byLang[r.Language] = append(byLang[r.Language], r)
	}

	for lang, langRules := range byLang {
		profile, ok := qualityprofile.BuiltIn(lang, rules)
		if !ok {
			t.Errorf("language %q ships %d rule(s) but has no built-in profile", lang, len(langRules))
			continue
		}
		if profile.Key != qualityprofile.BuiltInKey(lang) || !profile.BuiltIn || profile.Language != lang {
			t.Errorf("language %q built-in profile is malformed: %+v", lang, profile)
		}
		// Every catalog rule for the language is activated in the built-in default (the "Synapse way").
		if len(profile.ActivatedRules) != len(langRules) {
			t.Errorf("language %q: built-in activates %d rules, catalog has %d", lang, len(profile.ActivatedRules), len(langRules))
		}
		if err := profile.Validate(); err != nil {
			t.Errorf("language %q built-in profile invalid: %v", lang, err)
		}
	}

	// The core shipped packs (per docs/guide/code-quality-rules.md) must each have a built-in profile.
	for _, lang := range []string{"Go", "Python", "Java", "JavaScript/TypeScript", "Secrets"} {
		if _, ok := qualityprofile.BuiltIn(lang, rules); !ok {
			t.Errorf("expected a shipped built-in profile for %q", lang)
		}
	}
}
