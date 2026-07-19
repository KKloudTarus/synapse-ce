package hotspots

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type fakeCatalog struct {
	rules map[rule.Key]rule.Rule
	err   error
}

func (f fakeCatalog) List(context.Context) ([]rule.Rule, error) { return nil, nil }
func (f fakeCatalog) Get(_ context.Context, key rule.Key) (rule.Rule, error) {
	if f.err != nil {
		return rule.Rule{}, f.err
	}
	r, ok := f.rules[key]
	if !ok {
		return rule.Rule{}, shared.ErrNotFound
	}
	return r, nil
}

func testRule(key rule.Key, typ rule.Type, qualities ...rule.Quality) rule.Rule {
	return rule.Rule{Key: key, Type: typ, Qualities: qualities}
}

func testFinding(key, ruleKey string, kind finding.Kind) finding.Finding {
	return finding.Finding{ID: shared.ID(key), DedupKey: key, RuleKey: ruleKey, Kind: kind, Severity: shared.SeverityHigh, Title: "title", Description: "description", CWE: "CWE-1"}
}

func TestClassifyUsesCatalogTypeAndKeepsInputImmutable(t *testing.T) {
	hotspotRule := testRule("hotspot-rule", rule.TypeSecurityHotspot)
	bugRule := testRule("bug-rule", rule.TypeBug, rule.QualityReliability)
	input := []finding.Finding{
		testFinding("z", "hotspot-rule", finding.KindSAST),
		testFinding("a", "bug-rule", finding.KindSAST),
		testFinding("unknown", "missing", finding.KindSecret),
	}
	original := append([]finding.Finding(nil), input...)
	issues, candidates, err := Classify(context.Background(), input, fakeCatalog{rules: map[rule.Key]rule.Rule{hotspotRule.Key: hotspotRule, bugRule.Key: bugRule}})
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 2 || len(candidates) != 1 || candidates[0].Key != "z" {
		t.Fatalf("issues=%+v candidates=%+v", issues, candidates)
	}
	if input[0].Kind != original[0].Kind || input[0].RuleKey != original[0].RuleKey {
		t.Fatal("classifier mutated input")
	}
}

func TestClassifyUsesRuleTypeOnly(t *testing.T) {
	cases := []struct {
		name string
		item finding.Finding
		rule rule.Rule
	}{
		{"bug type", testFinding("bug", "bug-rule", finding.KindSAST), testRule("bug-rule", rule.TypeBug, rule.QualitySecurity)},
		{"security quality only", testFinding("quality", "quality-rule", finding.KindQuality), testRule("quality-rule", rule.TypeCodeSmell, rule.QualitySecurity)},
		{"secret kind", testFinding("secret", "secret-rule", finding.KindSecret), testRule("secret-rule", rule.TypeVulnerability, rule.QualitySecurity)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, candidates, err := Classify(context.Background(), []finding.Finding{tc.item}, fakeCatalog{rules: map[rule.Key]rule.Rule{tc.rule.Key: tc.rule}})
			if err != nil || len(issues) != 1 || len(candidates) != 0 {
				t.Fatalf("issues=%+v candidates=%+v err=%v", issues, candidates, err)
			}
		})
	}

	t.Run("hotspot type without security quality", func(t *testing.T) {
		item := testFinding("hotspot", "hotspot-rule", finding.KindQuality)
		r := testRule("hotspot-rule", rule.TypeSecurityHotspot, rule.QualityMaintainability)
		issues, candidates, err := Classify(context.Background(), []finding.Finding{item}, fakeCatalog{rules: map[rule.Key]rule.Rule{r.Key: r}})
		if err != nil || len(issues) != 0 || len(candidates) != 1 {
			t.Fatalf("issues=%+v candidates=%+v err=%v", issues, candidates, err)
		}
	})
}

func TestClassifyDeduplicatesAndSortsCandidates(t *testing.T) {
	r := testRule("hotspot", rule.TypeSecurityHotspot, rule.QualitySecurity)
	items := []finding.Finding{
		testFinding("b", "hotspot", finding.KindSAST),
		testFinding("a", "hotspot", finding.KindSAST),
		testFinding("b", "hotspot", finding.KindSAST),
	}
	_, candidates, err := Classify(context.Background(), items, fakeCatalog{rules: map[rule.Key]rule.Rule{r.Key: r}})
	if err != nil || len(candidates) != 2 || candidates[0].Key != "a" || candidates[1].Key != "b" {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
}

func TestClassifyCatalogErrorsFailClosedOnlyForUnknownRule(t *testing.T) {
	item := testFinding("id", "rule", finding.KindSAST)
	_, candidates, err := Classify(context.Background(), []finding.Finding{item}, fakeCatalog{rules: map[rule.Key]rule.Rule{}})
	if err != nil || len(candidates) != 0 {
		t.Fatalf("unknown rule candidates=%+v err=%v", candidates, err)
	}
	_, _, err = Classify(context.Background(), []finding.Finding{item}, fakeCatalog{err: errors.New("catalog unavailable")})
	if err == nil {
		t.Fatal("catalog failure should fail analysis classification")
	}
}
