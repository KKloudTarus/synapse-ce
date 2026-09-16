package rulecatalog

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
)

func TestAuditRuleMetadataReusesExistingCWEMapping(t *testing.T) {
	entries := []rule.Rule{
		{Key: "seed", CWE: []string{"CWE-79"}, OWASP: []string{"A03:2021"}},
		{Key: "target", Qualities: []rule.Quality{rule.QualitySecurity}, CWE: []string{"CWE-79"}},
	}

	got, err := auditRuleMetadata(entries)
	if err != nil {
		t.Fatalf("auditRuleMetadata() error: %v", err)
	}
	if len(got[1].OWASP) != 1 || got[1].OWASP[0] != "A03:2021" {
		t.Fatalf("OWASP mapping = %v, want [A03:2021]", got[1].OWASP)
	}
	if len(entries[1].OWASP) != 0 {
		t.Fatal("auditRuleMetadata mutated its input")
	}
}

func TestAuditRuleMetadataUsesDirectOWASPCrosswalk(t *testing.T) {
	entries := []rule.Rule{{
		Key:       "php-include",
		Qualities: []rule.Quality{rule.QualitySecurity},
		CWE:       []string{"CWE-98"},
	}}

	got, err := auditRuleMetadata(entries)
	if err != nil {
		t.Fatalf("auditRuleMetadata() error: %v", err)
	}
	if len(got[0].OWASP) != 1 || got[0].OWASP[0] != "A03:2021" {
		t.Fatalf("OWASP mapping = %v, want [A03:2021]", got[0].OWASP)
	}
}

func TestAuditRuleMetadataUsesReviewedFallback(t *testing.T) {
	entries := []rule.Rule{{
		Key:       "buffer-copy",
		Qualities: []rule.Quality{rule.QualitySecurity},
		CWE:       []string{"CWE-120"},
	}}

	got, err := auditRuleMetadata(entries)
	if err != nil {
		t.Fatalf("auditRuleMetadata() error: %v", err)
	}
	if len(got[0].OWASP) != 1 || got[0].OWASP[0] != "A04:2021" {
		t.Fatalf("OWASP mapping = %v, want [A04:2021]", got[0].OWASP)
	}
}

func TestAuditRuleMetadataPrefersDirectCrosswalkOverFallback(t *testing.T) {
	entries := []rule.Rule{{
		Key:       "mixed",
		Qualities: []rule.Quality{rule.QualitySecurity},
		CWE:       []string{"CWE-98", "CWE-120"},
	}}

	got, err := auditRuleMetadata(entries)
	if err != nil {
		t.Fatalf("auditRuleMetadata() error: %v", err)
	}
	if len(got[0].OWASP) != 1 || got[0].OWASP[0] != "A03:2021" {
		t.Fatalf("OWASP mapping = %v, want direct crosswalk [A03:2021]", got[0].OWASP)
	}
}

func TestAuditRuleMetadataRejectsUnmappedSecurityRule(t *testing.T) {
	_, err := auditRuleMetadata([]rule.Rule{{
		Key:       "unmapped",
		Qualities: []rule.Quality{rule.QualitySecurity},
	}})
	if err == nil || !strings.Contains(err.Error(), "unmapped") {
		t.Fatalf("error = %v, want unmapped rule failure", err)
	}
}
