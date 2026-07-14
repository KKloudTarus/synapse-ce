package rule_test

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestTypeValid(t *testing.T) {
	tests := []struct {
		typ  rule.Type
		want bool
	}{
		{rule.TypeBug, true},
		{rule.TypeVulnerability, true},
		{rule.TypeCodeSmell, true},
		{rule.TypeSecurityHotspot, true},
		{"", false},
		{"unknown", false},
	}
	for _, tt := range tests {
		if got := tt.typ.Valid(); got != tt.want {
			t.Errorf("Type(%q).Valid() = %v, want %v", tt.typ, got, tt.want)
		}
	}
}

func TestQualityValid(t *testing.T) {
	tests := []struct {
		qual rule.Quality
		want bool
	}{
		{rule.QualitySecurity, true},
		{rule.QualityReliability, true},
		{rule.QualityMaintainability, true},
		{"", false},
		{"unknown", false},
	}
	for _, tt := range tests {
		if got := tt.qual.Valid(); got != tt.want {
			t.Errorf("Quality(%q).Valid() = %v, want %v", tt.qual, got, tt.want)
		}
	}
}

func TestDetectionValid(t *testing.T) {
	tests := []struct {
		det  rule.Detection
		want bool
	}{
		{rule.DetectionAST, true},
		{rule.DetectionPattern, true},
		{rule.DetectionParse, true},
		{rule.DetectionMetric, true},
		{"", false},
		{"unknown", false},
	}
	for _, tt := range tests {
		if got := tt.det.Valid(); got != tt.want {
			t.Errorf("Detection(%q).Valid() = %v, want %v", tt.det, got, tt.want)
		}
	}
}

func validRule() rule.Rule {
	return rule.Rule{
		Key:                 "valid-key",
		Name:                "Valid Rule",
		Language:            "General",
		Type:                rule.TypeVulnerability,
		Qualities:           []rule.Quality{rule.QualitySecurity},
		DefaultSeverity:     shared.SeverityHigh,
		Tags:                []string{"tag1", "tag2"},
		CWE:                 []string{"CWE-79"},
		OWASP:               []string{"A1"},
		Description:         "desc",
		Rationale:           "rat",
		Remediation:         "rem",
		CompliantExample:    "comp",
		NoncompliantExample: "noncomp",
		RemediationEffort:   5,
		Detection:           rule.DetectionPattern,
	}
}

func TestRuleValidateComplete(t *testing.T) {
	r := validRule()
	if err := r.Validate(); err != nil {
		t.Errorf("expected valid rule to have no error, got %v", err)
	}
}

func TestRuleValidateRequiredFields(t *testing.T) {
	tests := []struct {
		name     string
		modifier func(*rule.Rule)
	}{
		{"empty key", func(r *rule.Rule) { r.Key = "" }},
		{"whitespace key", func(r *rule.Rule) { r.Key = "  " }},
		{"empty name", func(r *rule.Rule) { r.Name = "  " }},
		{"empty language", func(r *rule.Rule) { r.Language = "  " }},
		{"empty type", func(r *rule.Rule) { r.Type = "" }},
		{"no qualities", func(r *rule.Rule) { r.Qualities = nil }},
		{"unknown severity", func(r *rule.Rule) { r.DefaultSeverity = "unknown" }},
		{"empty description", func(r *rule.Rule) { r.Description = "  " }},
		{"empty rationale", func(r *rule.Rule) { r.Rationale = "  " }},
		{"empty remediation", func(r *rule.Rule) { r.Remediation = "  " }},
		{"empty compliant example", func(r *rule.Rule) { r.CompliantExample = "  " }},
		{"empty non-compliant example", func(r *rule.Rule) { r.NoncompliantExample = "  " }},
		{"zero remediation effort", func(r *rule.Rule) { r.RemediationEffort = 0 }},
		{"negative remediation effort", func(r *rule.Rule) { r.RemediationEffort = -5 }},
		{"empty detection", func(r *rule.Rule) { r.Detection = "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validRule()
			tt.modifier(&r)
			if err := r.Validate(); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func TestRuleValidateKeyCompatibility(t *testing.T) {
	tests := []struct {
		key   string
		valid bool
	}{
		{"weak-hash-md5", true},
		{"aws-access-key-id", true},
		{"terraform-rds-deletion-protection-disabled", true},
		{"quality-high-complexity", true},
		{"go:unhandled-error", true},
		{"", false},
		{" rule", false},
		{"rule ", false},
		{"rule key", false},
		{"go:unhandled error", false},
		{"rule\tkey", false},
		{"rule\nkey", false},
		{"rule/name", false},
		{"rule?x", false},
		{"rule#fragment", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			r := validRule()
			r.Key = rule.Key(tt.key)
			err := r.Validate()
			if tt.valid && err != nil {
				t.Errorf("expected valid key %q, got err: %v", tt.key, err)
			} else if !tt.valid && err == nil {
				t.Errorf("expected error for key %q", tt.key)
			}
		})
	}
}

func TestRuleValidateTypeQualityConsistency(t *testing.T) {
	tests := []struct {
		name      string
		typ       rule.Type
		qualities []rule.Quality
		valid     bool
	}{
		{"bug without reliability", rule.TypeBug, []rule.Quality{rule.QualitySecurity}, false},
		{"vulnerability without security", rule.TypeVulnerability, []rule.Quality{rule.QualityReliability}, false},
		{"security hotspot without security", rule.TypeSecurityHotspot, []rule.Quality{rule.QualityMaintainability}, false},
		{"code smell without maintainability", rule.TypeCodeSmell, []rule.Quality{rule.QualityReliability}, false},
		{"vulnerability with security + reliability", rule.TypeVulnerability, []rule.Quality{rule.QualitySecurity, rule.QualityReliability}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validRule()
			r.Type = tt.typ
			r.Qualities = tt.qualities
			err := r.Validate()
			if tt.valid && err != nil {
				t.Errorf("expected valid, got err: %v", err)
			} else if !tt.valid && err == nil {
				t.Errorf("expected error")
			}
		})
	}
}

func TestRuleValidateDuplicateMetadata(t *testing.T) {
	tests := []struct {
		name     string
		modifier func(*rule.Rule)
	}{
		{"duplicate quality", func(r *rule.Rule) { r.Qualities = []rule.Quality{rule.QualitySecurity, rule.QualitySecurity} }},
		{"duplicate tag", func(r *rule.Rule) { r.Tags = []string{"tag1", "tag1"} }},
		{"duplicate tag differing only by case", func(r *rule.Rule) { r.Tags = []string{"tag1", "TAG1"} }},
		{"tag with surrounding whitespace", func(r *rule.Rule) { r.Tags = []string{" tag1 "} }},
		{"empty tag", func(r *rule.Rule) { r.Tags = []string{"  "} }},
		{"duplicate CWE", func(r *rule.Rule) { r.CWE = []string{"CWE-1", "CWE-1"} }},
		{"CWE with surrounding whitespace", func(r *rule.Rule) { r.CWE = []string{" CWE-1 "} }},
		{"empty CWE", func(r *rule.Rule) { r.CWE = []string{"  "} }},
		{"duplicate OWASP", func(r *rule.Rule) { r.OWASP = []string{"A1", "A1"} }},
		{"OWASP with surrounding whitespace", func(r *rule.Rule) { r.OWASP = []string{" A1 "} }},
		{"empty OWASP", func(r *rule.Rule) { r.OWASP = []string{"  "} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validRule()
			tt.modifier(&r)
			if err := r.Validate(); err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func TestRuleValidateExamplesDiffer(t *testing.T) {
	r := validRule()
	r.CompliantExample = "  same  "
	r.NoncompliantExample = "same"
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "identical") {
		t.Errorf("expected error about identical examples, got %v", err)
	}
}
