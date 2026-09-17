package qualityprofile

import (
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// RecommendedKey is the deterministic key of the built-in "Recommended" preset for a language.
func RecommendedKey(language string) string { return "recommended-" + LanguageSlug(language) }

// StrictKey is the deterministic key of the built-in "Strict" preset for a language.
func StrictKey(language string) string { return "strict-" + LanguageSlug(language) }

// Recommended generates the lower-noise built-in preset for a language: every rule whose default
// severity is Low or higher is activated at its default severity, and info-level rules are left
// deactivated to reduce noise. It mirrors BuiltIn's rule-filtering and language contract. Returns a
// zero Profile with ok=false when no rule targets the language.
func Recommended(language string, rules []rule.Rule) (Profile, bool) {
	language = strings.TrimSpace(language)
	if language == "" {
		return Profile{}, false
	}
	activated := map[string]RuleActivation{}
	floor := shared.SeverityRank(shared.SeverityLow)
	for _, r := range rules {
		if r.Language != language {
			continue
		}
		if shared.SeverityRank(r.DefaultSeverity) >= floor {
			activated[string(r.Key)] = RuleActivation{} // active at the rule's default severity
		}
	}
	// No rule at Low or above: there is no meaningful lower-noise set, so drop the preset (consistent
	// with BuiltIn/Strict) rather than emit a profile that would disable every rule in the overlay.
	if len(activated) == 0 {
		return Profile{}, false
	}
	return Profile{
		Key:            RecommendedKey(language),
		Name:           "Recommended (" + language + ")",
		Language:       language,
		ActivatedRules: activated,
		BuiltIn:        true,
	}, true
}

// Strict generates the strictest built-in preset for a language: every rule is activated with its
// default severity escalated one level (info→low→medium→high→critical; critical stays critical), so a
// project on this profile gates its issues more seriously than the default. Returns ok=false when no
// rule targets the language.
func Strict(language string, rules []rule.Rule) (Profile, bool) {
	language = strings.TrimSpace(language)
	if language == "" {
		return Profile{}, false
	}
	activated := map[string]RuleActivation{}
	for _, r := range rules {
		if r.Language != language {
			continue
		}
		activated[string(r.Key)] = RuleActivation{Severity: escalateSeverity(r.DefaultSeverity)}
	}
	if len(activated) == 0 {
		return Profile{}, false
	}
	return Profile{
		Key:            StrictKey(language),
		Name:           "Strict (" + language + ")",
		Language:       language,
		ActivatedRules: activated,
		BuiltIn:        true,
	}, true
}

// escalateSeverity raises a severity one level toward critical, capping at critical. An unknown or
// invalid default is treated as the lowest actionable level (low), so a strict profile never leaves a
// rule at unknown severity.
func escalateSeverity(s shared.Severity) shared.Severity {
	switch s {
	case shared.SeverityLow:
		return shared.SeverityMedium
	case shared.SeverityMedium:
		return shared.SeverityHigh
	case shared.SeverityHigh, shared.SeverityCritical:
		return shared.SeverityCritical
	default: // info or unknown
		return shared.SeverityLow
	}
}

// Presets returns the built-in profiles for a language in a stable order: the default (Synapse way),
// Recommended, then Strict. A preset with no applicable rules is omitted.
func Presets(language string, rules []rule.Rule) []Profile {
	out := make([]Profile, 0, 3)
	if p, ok := BuiltIn(language, rules); ok {
		out = append(out, p)
	}
	if p, ok := Recommended(language, rules); ok {
		out = append(out, p)
	}
	if p, ok := Strict(language, rules); ok {
		out = append(out, p)
	}
	return out
}
