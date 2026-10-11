package sast

import "testing"

// A translation catalogue holds UI text keyed by identifier, so `"Password": "<translated word>"` is a
// label. Reporting it as a hardcoded credential turned one UI string into 26 HIGH findings on one real
// repository, one per language it ships.
func TestIsLocalizationCatalogue(t *testing.T) {
	cases := []struct {
		rel  string
		want bool
	}{
		{"lang/en.json", true},
		{"lang/bn.json", true},
		{"resources/lang/en/auth.php", true},
		{"src/locales/de.yaml", true},
		{"web/src/i18n/messages.json", true},
		{"translations/messages.fr.xlf", true},
		{"app/intl/en.properties", true},

		// A source file is still scanned, whatever directory it sits in.
		{"internal/intl/format.go", false},
		{"web/src/i18n/index.ts", false},
		{"app/Services/Auth.php", false},
		{"config/database.yml", false},
		{"lang/README.md", false},
		{".env", false},
	}
	for _, c := range cases {
		if got := isLocalizationCatalogue(c.rel); got != c.want {
			t.Errorf("isLocalizationCatalogue(%q) = %v, want %v", c.rel, got, c.want)
		}
	}
}

// The guard covers exactly the credential-shaped rules; it must not silence the rest of the ruleset on a
// catalogue file.
func TestCredentialShapedRuleIDsIsNarrow(t *testing.T) {
	if !credentialShapedRuleIDs["hardcoded-credential"] {
		t.Error("hardcoded-credential is the rule this guard exists for")
	}
	for _, id := range []string{"weak-hash-md5", "php:eval-usage", "generic-command-injection-sink"} {
		if credentialShapedRuleIDs[id] {
			t.Errorf("%s must stay active in a localization catalogue", id)
		}
	}
}
