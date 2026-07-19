package issues

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type fakeCatalog struct {
	rules map[string]rule.Rule
	err   error
}

func (f fakeCatalog) Get(_ context.Context, key rule.Key) (rule.Rule, error) {
	if f.err != nil {
		return rule.Rule{}, f.err
	}
	r, ok := f.rules[string(key)]
	if !ok {
		return rule.Rule{}, shared.ErrNotFound
	}
	return r, nil
}

func TestProjectUsesCatalogTypeAndLanguage(t *testing.T) {
	cat := fakeCatalog{rules: map[string]rule.Rule{
		"java-x": {Key: "java-x", Type: rule.TypeBug, Language: "Java"},
	}}
	findings := []finding.Finding{{DedupKey: "sast:java-x:App.java:5", RuleKey: "java-x", Kind: finding.KindSAST, Severity: shared.SeverityHigh}}
	got, err := Project(context.Background(), findings, cat)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(got))
	}
	if got[0].Type != rule.TypeBug || got[0].Language != "Java" {
		t.Fatalf("want bug/Java from catalog, got %s/%s", got[0].Type, got[0].Language)
	}
	if got[0].File != "App.java" || got[0].Location != "App.java:5" {
		t.Fatalf("want file/location from dedupKey, got %s/%s", got[0].File, got[0].Location)
	}
}

func TestProjectFallsBackToKindType(t *testing.T) {
	cat := fakeCatalog{rules: map[string]rule.Rule{}} // unknown rule -> NotFound
	findings := []finding.Finding{
		{DedupKey: "q1", RuleKey: "unknown", Kind: finding.KindQuality, Severity: shared.SeverityLow},
		{DedupKey: "r1", RuleKey: "", Kind: finding.KindReliability, Severity: shared.SeverityMedium},
	}
	got, err := Project(context.Background(), findings, cat)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	types := map[string]rule.Type{}
	for _, c := range got {
		types[c.Key] = c.Type
	}
	if types["q1"] != rule.TypeCodeSmell {
		t.Errorf("quality should map to code_smell, got %s", types["q1"])
	}
	if types["r1"] != rule.TypeBug {
		t.Errorf("reliability should map to bug, got %s", types["r1"])
	}
}

func TestProjectFailsClosedOnCatalogError(t *testing.T) {
	cat := fakeCatalog{err: errors.New("catalog unavailable")}
	findings := []finding.Finding{{DedupKey: "x", RuleKey: "some-rule", Kind: finding.KindSAST, Severity: shared.SeverityHigh}}
	if _, err := Project(context.Background(), findings, cat); err == nil {
		t.Fatal("expected error when the catalog fails, got nil")
	}
}

func TestProjectDedupesByKey(t *testing.T) {
	cat := fakeCatalog{rules: map[string]rule.Rule{}}
	findings := []finding.Finding{
		{DedupKey: "dup", RuleKey: "", Kind: finding.KindQuality, Severity: shared.SeverityLow, Title: "first"},
		{DedupKey: "dup", RuleKey: "", Kind: finding.KindQuality, Severity: shared.SeverityLow, Title: "second"},
	}
	got, err := Project(context.Background(), findings, cat)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 deduped candidate, got %d", len(got))
	}
}
