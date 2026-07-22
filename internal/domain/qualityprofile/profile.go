// Package qualityprofile models named, per-language rule sets — the industry-standard "Quality
// Profile". A built-in default profile per language is generated from the rule catalog (every rule for
// that language, at its default severity) and is immutable; a user copies a built-in into a custom
// profile and then activates/deactivates rules and overrides severities. A profile is assigned per
// language per project (domain/project.DefaultProfileByLang); analyses honor it by translating the
// assigned profiles into the deterministic qualitygate.Profile overlay applied to findings.
//
// It is pure domain: types + operations, no I/O and no LLM. The overlay bridge (ToOverlay) is the single
// point where a managed profile becomes the serverless .synapse-rules.yaml equivalent.
package qualityprofile

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// RuleActivation is a rule's state inside a profile: it is active, optionally with a severity that
// overrides the rule's catalog default. A rule absent from a profile's ActivatedRules is deactivated.
type RuleActivation struct {
	// Severity overrides the rule's default severity when non-empty; "" keeps the catalog default.
	Severity shared.Severity `json:"severity,omitempty"`
}

// Profile is a named, per-language set of activated rules. BuiltIn profiles are generated from the
// catalog and immutable (no store row); custom profiles copy a Parent and are persisted per tenant.
type Profile struct {
	Key            string                    `json:"key"`
	Name           string                    `json:"name"`
	Language       string                    `json:"language"`
	Parent         string                    `json:"parent,omitempty"` // key the custom profile was copied from ("" for a built-in)
	ActivatedRules map[string]RuleActivation `json:"activated_rules"`  // keyed by rule.Key; absence = deactivated
	BuiltIn        bool                      `json:"built_in"`
}

var keyPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// LanguageSlug lowercases a language into a key-safe slug (e.g. "JavaScript/TypeScript" → "javascripttypescript").
func LanguageSlug(language string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(language)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// BuiltInKey is the deterministic key of the built-in default profile for a language.
func BuiltInKey(language string) string { return "synapse-way-" + LanguageSlug(language) }

// BuiltIn generates the built-in default profile for a language from its catalog rules: every rule is
// activated at its default severity (no override). Rules whose Language differs are ignored, so callers
// can pass the whole catalog. Returns a zero Profile with ok=false when no rule targets the language.
func BuiltIn(language string, rules []rule.Rule) (Profile, bool) {
	language = strings.TrimSpace(language)
	if language == "" {
		return Profile{}, false
	}
	activated := map[string]RuleActivation{}
	for _, r := range rules {
		if r.Language != language {
			continue
		}
		activated[string(r.Key)] = RuleActivation{} // active at the rule's default severity
	}
	if len(activated) == 0 {
		return Profile{}, false
	}
	return Profile{
		Key:            BuiltInKey(language),
		Name:           "Synapse way (" + language + ")",
		Language:       language,
		ActivatedRules: activated,
		BuiltIn:        true,
	}, true
}

// Copy produces an independent custom profile from p (a built-in or another custom profile), carrying
// its activated rules and recording p as the parent. The result is validated and never built-in.
func (p Profile) Copy(key, name string) (Profile, error) {
	c := Profile{
		Key:            strings.TrimSpace(key),
		Name:           strings.TrimSpace(name),
		Language:       p.Language,
		Parent:         p.Key,
		ActivatedRules: cloneActivations(p.ActivatedRules),
		BuiltIn:        false,
	}
	return c.Normalize()
}

// Clone returns an independent deep copy.
func (p Profile) Clone() Profile {
	p.ActivatedRules = cloneActivations(p.ActivatedRules)
	return p
}

func cloneActivations(in map[string]RuleActivation) map[string]RuleActivation {
	out := make(map[string]RuleActivation, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Active reports whether a rule is enabled in this profile.
func (p Profile) Active(ruleKey string) bool {
	_, ok := p.ActivatedRules[ruleKey]
	return ok
}

// Activate enables a rule (adding it if absent) with an optional severity override. A built-in profile
// is immutable, so mutating it is an error. Returns a modified copy; the receiver is never mutated.
func (p Profile) Activate(ruleKey string, severity shared.Severity) (Profile, error) {
	if p.BuiltIn {
		return Profile{}, fmt.Errorf("%w: cannot modify a built-in profile", shared.ErrValidation)
	}
	ruleKey = strings.TrimSpace(ruleKey)
	if ruleKey == "" {
		return Profile{}, fmt.Errorf("%w: rule key is required", shared.ErrValidation)
	}
	if severity != "" && !severity.Valid() {
		return Profile{}, fmt.Errorf("%w: invalid severity %q", shared.ErrValidation, severity)
	}
	out := p.Clone()
	out.ActivatedRules[ruleKey] = RuleActivation{Severity: severity}
	return out, nil
}

// Deactivate disables a rule (removing it from the active set). Built-in profiles are immutable.
func (p Profile) Deactivate(ruleKey string) (Profile, error) {
	if p.BuiltIn {
		return Profile{}, fmt.Errorf("%w: cannot modify a built-in profile", shared.ErrValidation)
	}
	ruleKey = strings.TrimSpace(ruleKey)
	if _, ok := p.ActivatedRules[ruleKey]; !ok {
		return Profile{}, fmt.Errorf("%w: rule %q is not active in this profile", shared.ErrNotFound, ruleKey)
	}
	out := p.Clone()
	delete(out.ActivatedRules, ruleKey)
	return out, nil
}

// SetSeverity overrides (or clears, with "") the severity of an already-active rule. Built-in profiles
// are immutable.
func (p Profile) SetSeverity(ruleKey string, severity shared.Severity) (Profile, error) {
	if p.BuiltIn {
		return Profile{}, fmt.Errorf("%w: cannot modify a built-in profile", shared.ErrValidation)
	}
	ruleKey = strings.TrimSpace(ruleKey)
	if _, ok := p.ActivatedRules[ruleKey]; !ok {
		return Profile{}, fmt.Errorf("%w: rule %q is not active in this profile", shared.ErrNotFound, ruleKey)
	}
	if severity != "" && !severity.Valid() {
		return Profile{}, fmt.Errorf("%w: invalid severity %q", shared.ErrValidation, severity)
	}
	out := p.Clone()
	out.ActivatedRules[ruleKey] = RuleActivation{Severity: severity}
	return out, nil
}

// Normalize validates and normalizes a custom profile (trimming, key/name/language required, valid
// severity overrides). It never returns a built-in.
func (p Profile) Normalize() (Profile, error) {
	p.Key, p.Name, p.Language = strings.TrimSpace(p.Key), strings.TrimSpace(p.Name), strings.TrimSpace(p.Language)
	p.BuiltIn = false
	if p.ActivatedRules == nil {
		p.ActivatedRules = map[string]RuleActivation{}
	}
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// Validate enforces the fields required for a safe profile.
func (p Profile) Validate() error {
	if !keyPattern.MatchString(p.Key) {
		return fmt.Errorf("%w: profile key must be a lowercase hyphenated slug", shared.ErrValidation)
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("%w: profile name is required", shared.ErrValidation)
	}
	if strings.TrimSpace(p.Language) == "" {
		return fmt.Errorf("%w: profile language is required", shared.ErrValidation)
	}
	for k, a := range p.ActivatedRules {
		if strings.TrimSpace(k) == "" {
			return fmt.Errorf("%w: profile has an empty rule key", shared.ErrValidation)
		}
		if a.Severity != "" && !a.Severity.Valid() {
			return fmt.Errorf("%w: invalid severity %q for rule %q", shared.ErrValidation, a.Severity, k)
		}
	}
	return nil
}

// SortedRuleKeys returns the activated rule keys in deterministic order (for stable API output).
func (p Profile) SortedRuleKeys() []string {
	keys := make([]string, 0, len(p.ActivatedRules))
	for k := range p.ActivatedRules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ToOverlay translates the profile into the deterministic qualitygate.Profile overlay applied to
// findings, given the full set of the language's catalog rules: a rule not activated is disabled
// (dropped from results), and an activated rule with a severity override carries that severity. An
// activated rule at its default severity produces no overlay entry (it passes through unchanged). This
// is the single bridge that makes a managed profile behave exactly like the .synapse-rules.yaml overlay.
func (p Profile) ToOverlay(languageRules []rule.Key) qualitygate.Profile {
	overlay := qualitygate.Profile{Rules: map[string]qualitygate.RuleConfig{}}
	for _, rk := range languageRules {
		key := string(rk)
		act, ok := p.ActivatedRules[key]
		if !ok {
			off := false
			overlay.Rules[key] = qualitygate.RuleConfig{Enabled: &off}
			continue
		}
		if act.Severity != "" {
			overlay.Rules[key] = qualitygate.RuleConfig{Severity: string(act.Severity)}
		}
	}
	return overlay
}
