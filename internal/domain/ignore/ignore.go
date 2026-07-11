// Package ignore models a repo-committed, declarative finding-suppression policy: the accepted-risk
// decisions a team version-controls alongside its code – Synapse's take on Trivy's .trivyignore, made
// governance-first. A rule may carry a reason and an expiry; an expired rule never suppresses (accepted
// risk is revisited, not permanent); and – enforced by the caller – a suppressed finding is RETAINED and
// surfaced, never silently dropped. This package is pure (bytes in, decisions out): reading the file and
// applying the decisions live in the infrastructure + usecase layers.
package ignore

import (
	"strings"
	"time"
)

// Rule is one suppression: an advisory id (CVE/GHSA) or an exact finding dedup key to accept, with an
// optional human reason and an optional expiry (zero = never expires).
type Rule struct {
	ID      string
	Reason  string
	Expires time.Time // zero = never; the rule stops suppressing on this UTC date
	// Malformed marks a rule whose exp: token was present but unparseable. Such a rule NEVER suppresses
	// (fail-safe: a date typo must not silently become a permanent acceptance) and is surfaced so it's fixed.
	Malformed bool
}

// Set is a parsed suppression policy.
type Set []Rule

// Parse reads the .synapseignore text format: one rule per line, '#' begins a comment. A rule line is
//
//	<id> [exp:YYYY-MM-DD] [# free-text reason]
//
// Unparseable lines are skipped (lenient, like Trivy) so a single typo can neither hide a whole policy nor
// fail a scan. Parsing never errors.
func Parse(data []byte) Set {
	var out Set
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		reason := ""
		if h := strings.IndexByte(line, '#'); h >= 0 { // an inline "# reason"
			reason = strings.TrimSpace(line[h+1:])
			line = strings.TrimSpace(line[:h])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		r := Rule{ID: fields[0], Reason: reason}
		for _, f := range fields[1:] {
			if v, ok := strings.CutPrefix(f, "exp:"); ok {
				if t, err := time.Parse("2006-01-02", v); err == nil {
					r.Expires = t
				} else {
					r.Malformed = true // a present-but-invalid expiry must NOT default to permanent suppression
				}
			}
		}
		out = append(out, r)
	}
	return out
}

// Match returns the first ACTIVE rule whose id equals any of the given identifiers (case-insensitive), and
// true. An expired OR malformed rule never matches, so the finding re-surfaces. now is the comparison time.
func (s Set) Match(ids []string, now time.Time) (Rule, bool) {
	for _, r := range s {
		if r.Malformed || r.expired(now) {
			continue
		}
		for _, id := range ids {
			if strings.EqualFold(strings.TrimSpace(id), r.ID) {
				return r, true
			}
		}
	}
	return Rule{}, false
}

// Expired returns the rules that have lapsed as of now, so an operator can be told which accepted-risk
// decisions need refreshing (surfacing them is the caller's job – this never hides anything).
func (s Set) Expired(now time.Time) Set {
	var out Set
	for _, r := range s {
		if r.expired(now) {
			out = append(out, r)
		}
	}
	return out
}

// Malformed returns the rules with an unparseable expiry, so an operator can be told to fix them (they are
// treated as non-suppressing until fixed).
func (s Set) Malformed() Set {
	var out Set
	for _, r := range s {
		if r.Malformed {
			out = append(out, r)
		}
	}
	return out
}

func (r Rule) expired(now time.Time) bool {
	return !r.Expires.IsZero() && !now.Before(r.Expires)
}
