package qualitygate

import (
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// RuleConfig overrides a single rule/advisory: disable it, and/or override its severity. A nil Enabled
// leaves the rule enabled.
type RuleConfig struct {
	Enabled  *bool  `yaml:"enabled" json:"enabled"`
	Severity string `yaml:"severity" json:"severity"`
}

// Profile is a per-project rule overlay (.synapse-rules.yaml): enable/disable rules and override
// severities without changing the built-in engines. Keyed by rule id (first-party rules) or advisory id
// (SCA).
type Profile struct {
	Rules map[string]RuleConfig `yaml:"rules" json:"rules"`
}

// Apply drops findings whose rule is disabled and overrides severities per the profile. A finding whose
// rule is not in the profile passes through unchanged. Returns the input as-is when the profile is empty.
//
// For rule-based findings the stable catalog RuleKey is preferred over
// DedupKey parsing: RuleKey is a direct catalog key and avoids any
// ambiguity introduced by the cq:<kind>: prefix or file:line suffix.
func (p Profile) Apply(findings []finding.Finding) []finding.Finding {
	if len(p.Rules) == 0 {
		return findings
	}
	out := make([]finding.Finding, 0, len(findings)) // fresh slice: never mutate the caller's backing array
	for _, f := range findings {
		ruleID := RuleIDOf(f.DedupKey)
		if f.Kind.IsRuleBased() && f.RuleKey != "" {
			ruleID = f.RuleKey
		}
		cfg, ok := p.Rules[ruleID]
		if !ok {
			out = append(out, f)
			continue
		}
		if cfg.Enabled != nil && !*cfg.Enabled {
			continue // rule disabled: drop the finding
		}
		if cfg.Severity != "" {
			f.Severity = shared.Severity(cfg.Severity)
		}
		out = append(out, f)
	}
	return out
}

// knownKinds are the first-party dedup-key prefixes whose rule id follows the kind.
var knownKinds = map[string]bool{"sast": true, "secret": true, "misconfig": true, "quality": true, "reliability": true}

// firstPartyParts returns the rule and path fields for legacy <kind>:<rule>:<file>:<line> keys and
// Code Quality's collision-safe cq:<kind>:<rule>:<file>:<line> keys.
func firstPartyParts(dedupKey string) (parts []string, offset int, ok bool) {
	parts = strings.Split(dedupKey, ":")
	if len(parts) >= 5 && parts[0] == "cq" && knownKinds[parts[1]] {
		return parts, 2, true
	}
	if len(parts) >= 4 && knownKinds[parts[0]] {
		return parts, 1, true
	}
	return nil, 0, false
}

// RuleIDOf extracts the rule/advisory identifier a profile keys on from a first-party dedup key, or the
// first field of an SCA advisory key.
func RuleIDOf(dedupKey string) string {
	parts, offset, ok := firstPartyParts(dedupKey)
	if ok {
		return parts[offset]
	}
	parts = strings.Split(dedupKey, ":")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// FileLineOf extracts the source file and 1-based line from a first-party dedup key. ok=false for a key
// that is not line-anchored (e.g. an SCA advisory key), so a caller can decide how to treat it under
// new-code gating.
func FileLineOf(dedupKey string) (file string, line int, ok bool) {
	parts, offset, ok := firstPartyParts(dedupKey)
	if !ok {
		return "", 0, false
	}
	n, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil || n < 1 {
		return "", 0, false
	}
	file = strings.Join(parts[offset+1:len(parts)-1], ":") // rejoin a Windows-y path that contained colons
	if file == "" {
		return "", 0, false
	}
	return file, n, true
}
