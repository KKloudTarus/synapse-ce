// Package suppression models .synapseignore: operator-declared suppressions that hide known/accepted
// findings, each REQUIRING a reason and an expiry date. Expiry is the point — a suppression stops
// applying after its date so the finding reappears and the suppression gets periodically re-justified,
// unlike an open-ended ignore list that silently rots. The parsing/IO lives in the caller (YAML); this
// package is the pure, deterministic matcher + validator.
package suppression

import (
	"fmt"
	"path"
	"strings"
	"time"
)

// Rule is one suppression entry. At least one of RuleKey / Path must be set; Reason and Expires are
// mandatory.
type Rule struct {
	RuleKey string    // match a finding's rule key / advisory id (e.g. "generic-secret", "CVE-2024-1"); empty = any
	Path    string    // match the finding's file with a glob (path.Match semantics); empty = any
	Reason  string    // why this is accepted — mandatory (accountability)
	Expires time.Time // last day the suppression applies (inclusive); after it, the finding reappears
}

// Validate enforces the mandatory fields and a usable matcher.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.RuleKey) == "" && strings.TrimSpace(r.Path) == "" {
		return fmt.Errorf("suppression needs a rule or a path to match")
	}
	if strings.TrimSpace(r.Reason) == "" {
		return fmt.Errorf("suppression needs a reason")
	}
	if r.Expires.IsZero() {
		return fmt.Errorf("suppression needs an expiry date")
	}
	if r.Path != "" {
		if _, err := path.Match(r.Path, "x"); err != nil {
			return fmt.Errorf("suppression path %q is not a valid glob: %w", r.Path, err)
		}
	}
	return nil
}

// active reports whether the suppression still applies on the given day (inclusive of the expiry date).
func (r Rule) active(now time.Time) bool {
	return !dayOf(now).After(dayOf(r.Expires))
}

func dayOf(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// Ruleset is a parsed .synapseignore.
type Ruleset []Rule

// Suppress reports the first ACTIVE rule that matches a finding identified by its rule keys (rule key,
// advisory id, …) and its source file (empty for non-file findings). An expired rule never matches.
func (rs Ruleset) Suppress(ruleKeys []string, file string, now time.Time) (Rule, bool) {
	for _, r := range rs {
		if !r.active(now) {
			continue
		}
		if !r.matchesRule(ruleKeys) || !r.matchesPath(file) {
			continue
		}
		return r, true
	}
	return Rule{}, false
}

// Expired returns the rules that are no longer active — surfaced so a stale suppression is visible, not
// silently dropped.
func (rs Ruleset) Expired(now time.Time) []Rule {
	var out []Rule
	for _, r := range rs {
		if !r.active(now) {
			out = append(out, r)
		}
	}
	return out
}

func (r Rule) matchesRule(ruleKeys []string) bool {
	if r.RuleKey == "" {
		return true
	}
	for _, k := range ruleKeys {
		if k != "" && strings.EqualFold(k, r.RuleKey) {
			return true
		}
	}
	return false
}

func (r Rule) matchesPath(file string) bool {
	if r.Path == "" {
		return true
	}
	if file == "" {
		return false
	}
	file = strings.ReplaceAll(file, "\\", "/")
	if ok, _ := path.Match(r.Path, file); ok {
		return true
	}
	// A trailing "/**" (or bare dir prefix) matches everything under the directory, which path.Match
	// does not do across separators on its own.
	if prefix, ok := strings.CutSuffix(r.Path, "/**"); ok {
		return file == prefix || strings.HasPrefix(file, prefix+"/")
	}
	return false
}
