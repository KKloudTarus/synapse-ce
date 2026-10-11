package ticketing

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestLinkRefusesCredentialBearingURLs(t *testing.T) {
	invalid := []string{
		"http://jira.example/browse/SEC-1",
		"https://user:secret@jira.example/browse/SEC-1",
		"https://jira.example/browse/SEC-1?token=secret",
		"https://jira.example/browse/SEC-1#token",
		"https://jira.example/browse/SEC-1?",
		"https://",
		"https://jira.example/browse/SEC-1" + strings.Repeat("a", 2050),
	}
	for _, candidate := range invalid {
		if _, err := CanonicalURL(candidate); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("accepted invalid link: %q", candidate)
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("URL validator disclosed a rejected credential")
		}
	}
	if got, err := CanonicalURL(" https://jira.example/browse/SEC-1 "); err != nil || got != "https://jira.example/browse/SEC-1" {
		t.Fatalf("canonicalize URL: %q %v", got, err)
	}
	manual := Link{ID: "link-a", TenantID: "tenant-a", EngagementID: "eng-a", FindingID: "finding-a",
		ExternalURL: "https://jira.example/browse/SEC-1", ExternalID: "SEC-1", CreatedAt: time.Now()}
	if err := manual.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("manual link claimed provider ID: %v", err)
	}
	manual.ExternalID = ""
	if err := manual.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMappingRejectsNonPersistableText(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := Mapping{ID: "mapping", TenantID: "tenant", IntegrationID: "integration",
		Scope: Engagement, ScopeID: "engagement", ProjectKey: "SEC", IssueType: "Bug",
		Version: 1, CreatedAt: now, UpdatedAt: now}
	fields := []struct {
		name string
		set  func(*Mapping, string)
	}{
		{"project key", func(m *Mapping, v string) { m.ProjectKey = v }},
		{"issue type", func(m *Mapping, v string) { m.IssueType = v }},
		{"component", func(m *Mapping, v string) { m.Component = v }},
		{"security level", func(m *Mapping, v string) { m.SecurityLevel = v }},
		{"label", func(m *Mapping, v string) { m.Labels = []string{v} }},
		{"priority key", func(m *Mapping, v string) { m.PriorityMap = map[string]string{v: "High"} }},
		{"priority value", func(m *Mapping, v string) { m.PriorityMap = map[string]string{"high": v} }},
	}
	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			for _, value := range []string{"text\x00", "text\xff"} {
				mapping := base.Clone()
				field.set(&mapping, value)
				if err := mapping.Validate(); !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("accepted unsupported text %q: %v", value, err)
				}
			}
			mapping := base.Clone()
			field.set(&mapping, "Ưu tiên")
			if err := mapping.Validate(); err != nil {
				t.Fatalf("rejected UTF-8 text: %v", err)
			}
		})
	}
}
