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
func (p Profile) Apply(findings []finding.Finding) []finding.Finding {
	if len(p.Rules) == 0 {
		return findings
	}
	out := make([]finding.Finding, 0, len(findings)) // fresh slice: never mutate the caller's backing array
	for _, f := range findings {
		cfg, ok := p.Rules[RuleIDOf(f.DedupKey)]
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

// knownKinds are the dedup-key prefixes whose rule id is the SECOND field (<kind>:<rule>:<file>:<line>).
var knownKinds = map[string]bool{"sast": true, "secret": true, "misconfig": true, "quality": true, "reliability": true}

// RuleIDOf extracts the rule/advisory identifier a profile keys on from a finding's dedup key: the second
// field for first-party kinds (<kind>:<rule>:...), else the first field (an SCA advisory id).
func RuleIDOf(dedupKey string) string {
	parts := strings.Split(dedupKey, ":")
	if len(parts) == 0 {
		return ""
	}
	if len(parts) >= 2 && knownKinds[parts[0]] {
		return parts[1]
	}
	return parts[0]
}

// FileLineOf extracts the source file and 1-based line from a first-party dedup key
// (<kind>:<rule>:<file>:<line>). ok=false for a key that is not line-anchored (e.g. an SCA advisory key),
// so a caller can decide how to treat non-line-anchored findings under new-code gating.
func FileLineOf(dedupKey string) (file string, line int, ok bool) {
	parts := strings.Split(dedupKey, ":")
	if len(parts) < 4 || !knownKinds[parts[0]] {
		return "", 0, false
	}
	n, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil || n < 1 {
		return "", 0, false
	}
	file = strings.Join(parts[2:len(parts)-1], ":") // rejoin a Windows-y path that contained colons
	if file == "" {
		return "", 0, false
	}
	return file, n, true
}
