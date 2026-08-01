package rulecatalog

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestRubyPackSeedContract(t *testing.T) {
	cat, err := Default()
	if err != nil {
		t.Fatalf("rulecatalog.Default: %v", err)
	}
	rules, err := cat.List(context.Background())
	if err != nil {
		t.Fatalf("catalog.List: %v", err)
	}

	rubyCount := 0
	for _, entry := range rules {
		if entry.Language == "Ruby" {
			rubyCount++
		}
	}
	if rubyCount != 40 {
		t.Fatalf("Ruby catalog rules = %d, want 40", rubyCount)
	}

	wantSeverity := map[rule.Key]shared.Severity{
		"rb:rescue-nil":           shared.SeverityMedium,
		"rb:sql-interpolation":    shared.SeverityHigh,
		"rb:command-injection":    shared.SeverityHigh,
		"rb:unsafe-yaml-load":     shared.SeverityHigh,
		"rb:xss-html-safe":        shared.SeverityHigh,
		"rb:skip-csrf":            shared.SeverityMedium,
		"rb:open-redirect":        shared.SeverityMedium,
		"rb:weak-hash":            shared.SeverityMedium,
		"rb:cognitive-complexity": shared.SeverityMedium,
	}
	for key, want := range wantSeverity {
		entry, err := cat.Get(context.Background(), key)
		if err != nil {
			t.Fatalf("seed rule %q missing: %v", key, err)
		}
		if entry.Language != "Ruby" {
			t.Errorf("seed rule %q language = %q, want Ruby", key, entry.Language)
		}
		if entry.DefaultSeverity != want {
			t.Errorf("seed rule %q severity = %q, want %q", key, entry.DefaultSeverity, want)
		}
	}
}
