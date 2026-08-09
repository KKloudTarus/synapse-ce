package sarifingest

import (
	"math"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Severity mapping is explicit and documented, and an unmappable severity becomes UNKNOWN.
//
// It must never default to medium. A defaulted severity is indistinguishable from a measured one, so it
// would silently invent a risk level for a finding nobody assessed — and that level then flows into
// prioritisation and the CI gate.
//
// Three sources are consulted, in decreasing order of specificity:
//
//  1. a tool-specific severity property, because SARIF's four levels are too coarse for most scanners;
//  2. the CVSS-style `security-severity` score GitHub's ecosystem popularised;
//  3. the SARIF `level`, which is the only field the specification guarantees.
func MapSeverity(toolName string, result sarifResult, rule sarifRule) shared.Severity {
	if severity := mapToolSpecific(toolName, result, rule); severity != shared.SeverityUnknown {
		return severity
	}
	if severity := mapSecuritySeverity(firstNonEmpty(result.Properties.Severity, rule.Properties.Severity)); severity != shared.SeverityUnknown {
		return severity
	}
	level := firstNonEmpty(result.Level, rule.DefaultConfig.Level)
	return mapSARIFLevel(level)
}

// mapToolSpecific applies the per-tool mappings that SARIF's levels cannot express. Each entry is a
// documented decision about one tool's own vocabulary.
func mapToolSpecific(toolName string, result sarifResult, rule sarifRule) shared.Severity {
	raw := firstNonEmpty(result.Properties.ProblemSeverity, rule.Properties.ProblemSeverity)
	if raw == "" {
		// Several tools express severity as a tag rather than a property.
		raw = severityFromTags(append(append([]string(nil), result.Properties.Tags...), rule.Properties.Tags...))
	}
	if raw == "" {
		return shared.SeverityUnknown
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "blocker":
		return shared.SeverityCritical
	case "high", "error":
		return shared.SeverityHigh
	case "medium", "moderate", "warning":
		return shared.SeverityMedium
	case "low", "minor":
		return shared.SeverityLow
	case "info", "informational", "note", "recommendation":
		return shared.SeverityInfo
	default:
		// An unrecognised vocabulary is unknown, not a guess.
		return shared.SeverityUnknown
	}
}

// severityTagPrefixes are the tag namespaces tools use to carry severity.
var severityTagPrefixes = []string{"severity/", "security-severity/", "priority/"}

func severityFromTags(tags []string) string {
	for _, tag := range tags {
		lower := strings.ToLower(strings.TrimSpace(tag))
		for _, prefix := range severityTagPrefixes {
			if strings.HasPrefix(lower, prefix) {
				return strings.TrimPrefix(lower, prefix)
			}
		}
	}
	return ""
}

// mapSecuritySeverity maps a CVSS-style numeric score using the standard CVSS v3 bands.
func mapSecuritySeverity(raw string) shared.Severity {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return shared.SeverityUnknown
	}
	score, err := strconv.ParseFloat(trimmed, 64)
	// NaN must be excluded explicitly: ParseFloat accepts "NaN", and BOTH `score < 0` and `score > 10`
	// are false for it, so a range test alone would let an unassessable value fall through the bands to
	// a concrete severity — exactly the invented risk level this file forbids.
	if err != nil || math.IsNaN(score) || score < 0 || score > 10 {
		return shared.SeverityUnknown
	}
	switch {
	case score >= 9.0:
		return shared.SeverityCritical
	case score >= 7.0:
		return shared.SeverityHigh
	case score >= 4.0:
		return shared.SeverityMedium
	case score > 0:
		return shared.SeverityLow
	default:
		return shared.SeverityInfo
	}
}

// mapSARIFLevel maps the four levels the SARIF specification defines.
//
// "warning" deliberately maps to MEDIUM because that is the specification's own meaning, not a default:
// a result that carries no level at all returns unknown instead.
func mapSARIFLevel(level string) shared.Severity {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return shared.SeverityHigh
	case "warning":
		return shared.SeverityMedium
	case "note":
		return shared.SeverityLow
	case "none":
		return shared.SeverityInfo
	default:
		return shared.SeverityUnknown
	}
}
